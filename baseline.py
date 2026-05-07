# ============================================================
# AI-based Multi-Class Malicious URL Detection
# Adaptive Risk Token Dictionary + River Progressive Streaming Update
#
# Raw Baseline Version for Ablation / Comparison
#
# Key properties:
# - No fixed phishing gate
# - No bidirectional phishing gate
# - No phishing threshold tuning
# - No phishing expert model
# - No Transformer specialist
#
# Protocol:
# - Dataset has no timestamps.
# - We define one fixed pseudo-stream using random_state=SEED.
# - Prefix 20% is used as warm-up/pretrain data.
# - Suffix 80% is processed as progressive stream.
# - Stream evaluation follows strict test-before-train:
#       predict -> metric update -> model/risk-dictionary update
# ============================================================

import os
import re
import glob
import json
import math
import urllib.parse
from collections import Counter, deque

import numpy as np
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
from sklearn.utils.class_weight import compute_sample_weight

from river import metrics


# ============================================================
# 0. Config
# ============================================================

SEED = 42
np.random.seed(SEED)

PROJECT_DIR = os.getcwd()
DATA_PATH = os.path.join(PROJECT_DIR, "malicious_phish.csv")

URL_COL = "url"
LABEL_COL = "type"

BENIGN_LABEL = "benign"
PHISHING_LABEL = "phishing"

# River-style warm-start progressive validation
WARMUP_RATIO = 0.20

# Risk dictionary
TOP_K_COMMON_MALICIOUS = 1000
TOP_K_PER_MAL_CLASS = 800
MIN_TOKEN_DF = 5
MIN_MAL_CLASSES_FOR_COMMON = 2
ALPHA = 1.0

# TF-IDF
MAX_TFIDF_FEATURES = 50000
TFIDF_MIN_DF = 3
TFIDF_MAX_DF = 0.95

# Streaming
BATCH_SIZE = 5000
UPDATE_INTERVAL = 3
SLIDING_WINDOW_BATCHES = 6

# Output
RISK_DICT_DIR = "./risk_dict_raw_baseline"
RESULT_DIR = "./results_raw_baseline"

os.makedirs(RISK_DICT_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)


# ============================================================
# 1. Safe URL Tokenizer
# ============================================================

def clean_url_text(url):
    """
    어떤 URL 문자열이 들어와도 urlparse가 죽지 않도록 정리.
    특히 Invalid IPv6 URL을 유발하는 '[' ']' 제거.
    """
    if url is None:
        url = ""

    url = str(url).strip().lower()

    try:
        url = urllib.parse.unquote(url, errors="ignore")
    except Exception:
        pass

    url = url.replace("[", "")
    url = url.replace("]", "")
    url = re.sub(r"[\x00-\x1f\x7f]", "", url)

    return url


def split_by_separators(text):
    """
    URL 내부 문자열을 특수문자 기준으로 분리.
    """
    if text is None:
        return []

    text = clean_url_text(text)
    parts = re.split(r"[^a-zA-Z0-9]+", text)

    return [p for p in parts if len(p) >= 2]


def char_ngrams(token, n_min=3, n_max=4):
    """
    긴 문자열에 대해 character n-gram 생성.
    """
    token = str(token).lower()
    grams = []

    if len(token) < n_min:
        return grams

    for n in range(n_min, n_max + 1):
        if len(token) >= n:
            for i in range(len(token) - n + 1):
                grams.append(f"char:{token[i:i+n]}")

    return grams


def safe_parse_url(url):
    """
    urlparse를 안전하게 수행.
    실패하면 invalid.local로 대체.
    """
    cleaned = clean_url_text(url)

    try:
        parse_target = cleaned

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", parse_target):
            parse_target = "http://" + parse_target

        return urllib.parse.urlparse(parse_target)

    except Exception:
        try:
            return urllib.parse.urlparse("http://invalid.local/")
        except Exception:
            return None


def tokenize_url(url):
    """
    URL 구조 기반 보안 특화 tokenizer.
    어떤 URL이 들어와도 예외를 밖으로 던지지 않음.
    """
    try:
        decoded_url = clean_url_text(url)
        parsed = safe_parse_url(decoded_url)

        tokens = []

        if parsed is None:
            general_parts = split_by_separators(decoded_url)
            for p in general_parts:
                tokens.append(f"tok:{p}")
            return tokens if tokens else ["empty_or_invalid_url"]

        host = parsed.netloc.lower() if parsed.netloc else ""
        path = parsed.path.lower() if parsed.path else ""
        query = parsed.query.lower() if parsed.query else ""

        # user:pass@host
        if "@" in host:
            tokens.append("has_userinfo")
            host = host.split("@")[-1]

        # port 제거
        if ":" in host:
            host = host.split(":")[0]

        # www 제거
        if host.startswith("www."):
            host = host[4:]

        # IP host 여부
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            tokens.append("host_is_ip")

        # domain / subdomain / tld
        domain_parts = [p for p in host.split(".") if p]

        if domain_parts:
            tld = domain_parts[-1]
            tokens.append(f"tld:{tld}")

            for idx, part in enumerate(domain_parts):
                if idx == len(domain_parts) - 1:
                    tokens.append(f"tldpart:{part}")
                elif idx == len(domain_parts) - 2:
                    tokens.append(f"sld:{part}")
                else:
                    tokens.append(f"subdomain:{part}")

                tokens.append(f"domain:{part}")

                for sub in split_by_separators(part):
                    tokens.append(f"dpart:{sub}")

        # path
        path_segments = [seg for seg in path.split("/") if seg]

        for seg in path_segments:
            tokens.append(f"path:{seg}")

            for p in split_by_separators(seg):
                tokens.append(f"pseg:{p}")

        # extension
        if path_segments:
            last_seg = path_segments[-1]
            if "." in last_seg:
                ext = last_seg.split(".")[-1]
                if 1 <= len(ext) <= 8:
                    tokens.append(f"ext:{ext}")

        # query
        if query:
            tokens.append("has_query")

        try:
            query_pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        except Exception:
            query_pairs = []

        for k, v in query_pairs:
            if k:
                tokens.append(f"qkey:{k}")
                for p in split_by_separators(k):
                    tokens.append(f"qk:{p}")

            if v:
                for p in split_by_separators(v):
                    tokens.append(f"qv:{p}")

        # 전체 URL 기준 일반 토큰
        general_parts = split_by_separators(decoded_url)

        for p in general_parts:
            tokens.append(f"tok:{p}")

        # 긴 문자열에 character n-gram 추가
        for p in general_parts:
            if len(p) >= 6:
                tokens.extend(char_ngrams(p, 3, 4))

        # 구조적 패턴 토큰
        if "-" in decoded_url:
            tokens.append("has_hyphen")
        if "_" in decoded_url:
            tokens.append("has_underscore")
        if "%" in decoded_url:
            tokens.append("has_percent_encoding")
        if decoded_url.count(".") >= 4:
            tokens.append("many_dots")
        if len(decoded_url) >= 100:
            tokens.append("very_long_url")

        if not tokens:
            tokens.append("empty_or_invalid_url")

        return tokens

    except Exception:
        return ["tokenizer_error"]


def safe_tokenize(url):
    """
    외부에서 항상 이 tokenizer를 사용.
    """
    try:
        return tokenize_url(url)
    except Exception:
        return ["tokenizer_error"]


# Tokenizer test
test_urls = [
    "https://secure-login.example.com/account/verify?id=123",
    "http://abc.ru/download/app.apk",
    "paypal.com.verify-user-login-security.com/index.php",
    "http://[broken-ipv6-url",
    "[invalid]url.com/test",
]

print("Tokenizer test:")
for u in test_urls:
    print(u, "=>", safe_tokenize(u)[:20])


# ============================================================
# 2. Load Dataset
# ============================================================

print("\nCurrent working directory:", os.getcwd())
print("Dataset path:", DATA_PATH)

if not os.path.exists(DATA_PATH):
    print("\nDataset not found at default DATA_PATH.")
    print("Searching CSV files under current project directory...")

    csv_files = glob.glob(os.path.join(PROJECT_DIR, "*.csv"))
    csv_files += glob.glob(os.path.join(PROJECT_DIR, "**", "*.csv"), recursive=True)
    csv_files = sorted(list(set(csv_files)))

    print("\nFound CSV files:")
    for idx, path in enumerate(csv_files):
        print(f"[{idx}] {path}")

    matched = [
        path for path in csv_files
        if "malicious" in os.path.basename(path).lower()
        or "phish" in os.path.basename(path).lower()
    ]

    if len(matched) > 0:
        DATA_PATH = matched[0]
        print("\nAuto-selected dataset:", DATA_PATH)
    elif len(csv_files) > 0:
        DATA_PATH = csv_files[0]
        print("\nAuto-selected first CSV:", DATA_PATH)
    else:
        raise FileNotFoundError(
            "No CSV file found. Put malicious_phish.csv in the project directory."
        )

df = pd.read_csv(DATA_PATH)

print("\nOriginal shape:", df.shape)
print("Columns:", df.columns.tolist())

df.columns = [str(c).strip().lower() for c in df.columns]

if URL_COL not in df.columns or LABEL_COL not in df.columns:
    raise ValueError(
        f"Required columns not found. Current columns: {df.columns.tolist()}. "
        f"Expected columns: {URL_COL}, {LABEL_COL}"
    )

df = df[[URL_COL, LABEL_COL]].dropna()
df[URL_COL] = df[URL_COL].astype(str)
df[LABEL_COL] = df[LABEL_COL].astype(str).str.lower().str.strip()

print("\nLabel distribution:")
print(df[LABEL_COL].value_counts())


# ============================================================
# 3. River-style Warm-start Progressive Stream Construction
# ============================================================
# The Kaggle malicious URL dataset has no real arrival timestamps.
# Therefore, we do NOT claim a real chronological stream.
#
# Instead of random train/stream/test splitting, we follow a
# River-style progressive validation protocol:
#
#   1) Define ONE reproducible pseudo-stream order.
#   2) Use the prefix of the stream as warm-up/pretrain data.
#   3) Use the suffix as the progressive evaluation stream.
#   4) During the stream phase, each batch is processed as:
#        predict -> metric.update -> train/update

stream_df = df.sample(
    frac=1.0,
    random_state=SEED
).reset_index(drop=True)

warmup_size = int(len(stream_df) * WARMUP_RATIO)

initial_train_df = stream_df.iloc[:warmup_size].copy().reset_index(drop=True)
stream_update_df = stream_df.iloc[warmup_size:].copy().reset_index(drop=True)

print("\nRiver-style Warm-start Progressive Stream")
print("Full pseudo-stream:", stream_df.shape)
print("Warm-up prefix:", initial_train_df.shape)
print("Progressive stream suffix:", stream_update_df.shape)

print("\nWarm-up prefix label distribution")
print(initial_train_df[LABEL_COL].value_counts())

print("\nProgressive stream suffix label distribution")
print(stream_update_df[LABEL_COL].value_counts())


# ============================================================
# 4. Label Encoding
# ============================================================

label_encoder = LabelEncoder()

y_initial = label_encoder.fit_transform(initial_train_df[LABEL_COL])
y_stream = label_encoder.transform(stream_update_df[LABEL_COL])

class_names = list(label_encoder.classes_)
malicious_classes = [c for c in class_names if c != BENIGN_LABEL]
all_class_ids = np.arange(len(class_names))
label_to_id = {label: idx for idx, label in enumerate(class_names)}

benign_id = label_to_id.get(BENIGN_LABEL, None)
phishing_id = label_to_id.get(PHISHING_LABEL, None)

print("\nClass names:", class_names)
print("Malicious classes:", malicious_classes)
print("Benign id:", benign_id)
print("Phishing id:", phishing_id)


# ============================================================
# 5. Adaptive Risk Token Dictionary
# ============================================================

def build_adaptive_risk_dictionary(
    urls,
    labels,
    tokenizer,
    class_names,
    benign_label="benign",
    top_k_common=1000,
    top_k_per_class=800,
    min_df=5,
    min_mal_classes_for_common=2,
    alpha=1.0
):
    """
    위험 토큰 사전 생성.

    common_malicious:
        benign에서는 적게 나오고,
        여러 악성 클래스에서 공통적으로 많이 나오는 토큰.

    class_specific:
        특정 악성 클래스에서 다른 클래스보다 더 강하게 나타나는 토큰.
    """
    malicious_classes_local = [c for c in class_names if c != benign_label]

    class_token_df = {c: Counter() for c in class_names}
    total_token_df = Counter()
    class_doc_count = Counter()

    for url, label in zip(urls, labels):
        try:
            tokens = set(tokenizer(url))
        except Exception:
            tokens = {"tokenizer_error"}

        class_doc_count[label] += 1

        for t in tokens:
            class_token_df[label][t] += 1
            total_token_df[t] += 1

    total_docs = sum(class_doc_count.values())
    benign_docs = class_doc_count[benign_label]
    malicious_docs = total_docs - benign_docs

    # --------------------------------------------------------
    # 5-1. Common malicious tokens
    # --------------------------------------------------------
    common_scores = {}

    for token, total_df in total_token_df.items():
        if total_df < min_df:
            continue

        benign_df = class_token_df[benign_label][token]
        malicious_df = sum(class_token_df[c][token] for c in malicious_classes_local)

        mal_class_presence = sum(
            1 for c in malicious_classes_local
            if class_token_df[c][token] > 0
        )

        if mal_class_presence < min_mal_classes_for_common:
            continue

        p_token_mal = (malicious_df + alpha) / (malicious_docs + 2 * alpha)
        p_token_benign = (benign_df + alpha) / (benign_docs + 2 * alpha)

        score = math.log(p_token_mal / p_token_benign)

        if score > 0:
            common_scores[token] = score

    common_malicious = dict(
        sorted(common_scores.items(), key=lambda x: x[1], reverse=True)[:top_k_common]
    )

    # --------------------------------------------------------
    # 5-2. Class-specific malicious tokens
    # --------------------------------------------------------
    class_specific = {c: {} for c in malicious_classes_local}

    for c in malicious_classes_local:
        scores = {}

        n_c = class_doc_count[c]
        n_not_c = total_docs - n_c

        for token, total_df in total_token_df.items():
            if total_df < min_df:
                continue

            df_c = class_token_df[c][token]
            df_not_c = total_df - df_c

            p_token_c = (df_c + alpha) / (n_c + 2 * alpha)
            p_token_not_c = (df_not_c + alpha) / (n_not_c + 2 * alpha)

            score = math.log(p_token_c / p_token_not_c)

            if score > 0:
                scores[token] = score

        class_specific[c] = dict(
            sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_k_per_class]
        )

    return {
        "common_malicious": common_malicious,
        "class_specific": class_specific,
    }


def save_risk_dict(risk_dict, version):
    path = os.path.join(RISK_DICT_DIR, f"risk_token_dict_v{version}.json")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(risk_dict, f, ensure_ascii=False, indent=2)

    print(f"Saved risk dictionary: {path}")


def print_risk_dict_preview(risk_dict, top_n=15):
    print("\n===== Common Malicious Risk Tokens =====")
    for token, score in list(risk_dict["common_malicious"].items())[:top_n]:
        print(token, round(score, 4))

    print("\n===== Class-specific Risk Tokens =====")
    for c, d in risk_dict["class_specific"].items():
        print(f"\n[{c}]")
        for token, score in list(d.items())[:top_n]:
            print(token, round(score, 4))


# ============================================================
# 6. Build Initial Risk Dictionary
# ============================================================

print("\nBuilding initial risk dictionary...")

initial_urls = initial_train_df[URL_COL].tolist()
initial_labels = initial_train_df[LABEL_COL].tolist()

risk_dict = build_adaptive_risk_dictionary(
    urls=initial_urls,
    labels=initial_labels,
    tokenizer=safe_tokenize,
    class_names=class_names,
    benign_label=BENIGN_LABEL,
    top_k_common=TOP_K_COMMON_MALICIOUS,
    top_k_per_class=TOP_K_PER_MAL_CLASS,
    min_df=MIN_TOKEN_DF,
    min_mal_classes_for_common=MIN_MAL_CLASSES_FOR_COMMON,
    alpha=ALPHA,
)

save_risk_dict(risk_dict, version=0)
print_risk_dict_preview(risk_dict, top_n=20)


# ============================================================
# 7. Feature Engineering
# ============================================================

def risk_score_features(urls, risk_dict, tokenizer, malicious_classes):
    """
    URL 하나를 위험 토큰 사전 기반 feature로 변환.

    feature 구성:
    - common malicious score
    - common malicious match count
    - 각 악성 클래스별 score
    - 각 악성 클래스별 match count
    """
    rows = []

    common_dict = risk_dict["common_malicious"]
    class_dict = risk_dict["class_specific"]

    for url in urls:
        try:
            tokens = set(tokenizer(url))
        except Exception:
            tokens = {"tokenizer_error"}

        row = []

        common_score = 0.0
        common_count = 0

        for t in tokens:
            if t in common_dict:
                common_score += common_dict[t]
                common_count += 1

        row.append(common_score)
        row.append(common_count)

        for c in malicious_classes:
            c_score = 0.0
            c_count = 0

            c_dict = class_dict.get(c, {})

            for t in tokens:
                if t in c_dict:
                    c_score += c_dict[t]
                    c_count += 1

            row.append(c_score)
            row.append(c_count)

        rows.append(row)

    return np.array(rows, dtype=np.float32)


def lexical_features(urls):
    """
    URL 구조 통계 feature.
    """
    rows = []

    for url in urls:
        u = clean_url_text(url)
        length = len(u)

        digit_count = sum(ch.isdigit() for ch in u)
        alpha_count = sum(ch.isalpha() for ch in u)
        special_count = sum(not ch.isalnum() for ch in u)

        dot_count = u.count(".")
        slash_count = u.count("/")
        hyphen_count = u.count("-")
        underscore_count = u.count("_")
        question_count = u.count("?")
        equal_count = u.count("=")
        amp_count = u.count("&")
        percent_count = u.count("%")
        at_count = u.count("@")

        digit_ratio = digit_count / max(length, 1)
        alpha_ratio = alpha_count / max(length, 1)
        special_ratio = special_count / max(length, 1)

        has_ip = 1 if re.search(r"\d{1,3}(\.\d{1,3}){3}", u) else 0
        has_https = 1 if u.startswith("https://") else 0
        has_http = 1 if u.startswith("http://") else 0

        rows.append([
            length,
            digit_count,
            alpha_count,
            special_count,
            dot_count,
            slash_count,
            hyphen_count,
            underscore_count,
            question_count,
            equal_count,
            amp_count,
            percent_count,
            at_count,
            digit_ratio,
            alpha_ratio,
            special_ratio,
            has_ip,
            has_https,
            has_http,
        ])

    return np.array(rows, dtype=np.float32)


def build_train_features(urls, risk_dict, malicious_classes):
    """
    Initial train용 feature 생성.
    TF-IDF vectorizer와 scaler는 initial train에 대해서만 fit.
    """
    vectorizer = TfidfVectorizer(
        tokenizer=safe_tokenize,
        token_pattern=None,
        lowercase=False,
        max_features=MAX_TFIDF_FEATURES,
        min_df=TFIDF_MIN_DF,
        max_df=TFIDF_MAX_DF,
    )

    X_tfidf = vectorizer.fit_transform(urls)

    X_risk = risk_score_features(urls, risk_dict, safe_tokenize, malicious_classes)
    X_lex = lexical_features(urls)

    X_extra = np.hstack([X_risk, X_lex])

    scaler = StandardScaler()
    X_extra_scaled = scaler.fit_transform(X_extra)

    X = hstack([X_tfidf, csr_matrix(X_extra_scaled)])

    return X, vectorizer, scaler


def build_eval_features(urls, risk_dict, malicious_classes, vectorizer, scaler):
    """
    Stream용 feature 생성.
    vectorizer와 scaler는 initial train에서 fit한 것을 그대로 사용.
    """
    X_tfidf = vectorizer.transform(urls)

    X_risk = risk_score_features(urls, risk_dict, safe_tokenize, malicious_classes)
    X_lex = lexical_features(urls)

    X_extra = np.hstack([X_risk, X_lex])
    X_extra_scaled = scaler.transform(X_extra)

    X = hstack([X_tfidf, csr_matrix(X_extra_scaled)])

    return X


# ============================================================
# 8. Prediction
# ============================================================

def predict_raw(model, X):
    """
    비교실험용 raw baseline.
    phishing-specific gate/tuning 없이 multi-class model 그대로 예측.
    """
    return model.predict(X)


# ============================================================
# 9. Initial Model Training / Warm-up
# ============================================================

print("\nBuilding initial warm-up features...")

X_initial, vectorizer, scaler = build_train_features(
    urls=initial_train_df[URL_COL].tolist(),
    risk_dict=risk_dict,
    malicious_classes=malicious_classes,
)

print("X_initial shape:", X_initial.shape)

model = SGDClassifier(
    loss="log_loss",
    penalty="l2",
    alpha=1e-5,
    max_iter=1,
    tol=None,
    random_state=SEED,
    n_jobs=-1,
)

initial_sample_weight = compute_sample_weight(
    class_weight="balanced",
    y=y_initial,
)

model.partial_fit(
    X_initial,
    y_initial,
    classes=all_class_ids,
    sample_weight=initial_sample_weight,
)

print("\nInitial warm-up model trained.")
print("Warm-up ratio:", WARMUP_RATIO)
print("Prediction mode: raw multi-class model only")
print("Phishing-specific gate/tuning/expert/Transformer: disabled")


# ============================================================
# 10. Evaluation Function
# ============================================================

def evaluate_predictions(
    y_true,
    y_pred,
    title="Evaluation",
    verbose=True,
    prediction_mode="raw_base",
):
    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)

    report_dict = classification_report(
        y_true,
        y_pred,
        labels=np.arange(len(class_names)),
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )

    cm = confusion_matrix(y_true, y_pred, labels=np.arange(len(class_names)))

    if verbose:
        print(f"\n===== {title} =====")
        print("Prediction mode:", prediction_mode)
        print("Accuracy:", round(acc, 4))
        print("Macro-F1:", round(macro_f1, 4))
        print("Weighted-F1:", round(weighted_f1, 4))

        print("\nClassification Report")
        print(
            classification_report(
                y_true,
                y_pred,
                labels=np.arange(len(class_names)),
                target_names=class_names,
                zero_division=0,
            )
        )

        print("\nConfusion Matrix")
        print(cm)

        if PHISHING_LABEL in report_dict:
            print(
                f"\nPhishing only | "
                f"Precision={report_dict[PHISHING_LABEL]['precision']:.4f}, "
                f"Recall={report_dict[PHISHING_LABEL]['recall']:.4f}, "
                f"F1={report_dict[PHISHING_LABEL]['f1-score']:.4f}"
            )

        if benign_id is not None and phishing_id is not None:
            print("Benign -> Phishing:", cm[benign_id][phishing_id])
            print("Phishing -> Benign:", cm[phishing_id][benign_id])

    result = {
        "title": title,
        "accuracy": float(acc),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "prediction_mode": prediction_mode,
        "classification_report": report_dict,
        "confusion_matrix": cm.tolist(),
    }

    if PHISHING_LABEL in report_dict:
        result["phishing_precision"] = float(report_dict[PHISHING_LABEL]["precision"])
        result["phishing_recall"] = float(report_dict[PHISHING_LABEL]["recall"])
        result["phishing_f1"] = float(report_dict[PHISHING_LABEL]["f1-score"])

    if benign_id is not None and phishing_id is not None:
        result["benign_to_phishing"] = int(cm[benign_id][phishing_id])
        result["phishing_to_benign"] = int(cm[phishing_id][benign_id])

    return result


# ============================================================
# 11. Stream Utility Functions
# ============================================================

def make_batches(dataframe, batch_size):
    """
    Stream suffix를 순서 그대로 batch로 자른다.
    절대 shuffle하지 않는다.
    """
    batches = []

    n = len(dataframe)

    for start in range(0, n, batch_size):
        end = min(start + batch_size, n)
        batches.append(dataframe.iloc[start:end].copy())

    return batches


def summarize_risk_dict_change(old_dict, new_dict, malicious_classes):
    summary = {}

    old_common = set(old_dict["common_malicious"].keys())
    new_common = set(new_dict["common_malicious"].keys())

    summary["common_malicious"] = {
        "added": len(new_common - old_common),
        "removed": len(old_common - new_common),
        "kept": len(old_common & new_common),
        "sample_added": list(new_common - old_common)[:10],
        "sample_removed": list(old_common - new_common)[:10],
    }

    for c in malicious_classes:
        old_tokens = set(old_dict["class_specific"].get(c, {}).keys())
        new_tokens = set(new_dict["class_specific"].get(c, {}).keys())

        summary[c] = {
            "added": len(new_tokens - old_tokens),
            "removed": len(old_tokens - new_tokens),
            "kept": len(old_tokens & new_tokens),
            "sample_added": list(new_tokens - old_tokens)[:10],
            "sample_removed": list(old_tokens - new_tokens)[:10],
        }

    return summary


def print_change_summary(summary):
    print("\nRisk Dictionary Change Summary")

    for key, value in summary.items():
        print(f"\n[{key}]")
        print("added:", value["added"])
        print("removed:", value["removed"])
        print("kept:", value["kept"])
        print("sample_added:", value["sample_added"])
        print("sample_removed:", value["sample_removed"])


# ============================================================
# 12. River Progressive Streaming Update
# ============================================================

stream_batches = make_batches(stream_update_df, BATCH_SIZE)

print("\nNumber of progressive stream batches:", len(stream_batches))
print("Batch size:", BATCH_SIZE)
print("Update interval:", UPDATE_INTERVAL)
print("Sliding window batches:", SLIDING_WINDOW_BATCHES)

current_model = model
current_risk_dict = risk_dict
current_vectorizer = vectorizer
current_scaler = scaler

recent_stream_buffer = deque(maxlen=SLIDING_WINDOW_BATCHES)

stream_results = []
version = 0

# River online metrics: updated only with before-update predictions.
river_acc = metrics.Accuracy()
river_macro_f1 = metrics.MacroF1()
river_weighted_f1 = metrics.WeightedF1()

# Store all before-update predictions for final detailed report.
online_y_true_all = []
online_y_pred_all = []

for batch_idx, batch_df in enumerate(stream_batches, start=1):
    print(f"\n\n========== Progressive Stream Batch {batch_idx}/{len(stream_batches)} ==========")

    batch_urls = batch_df[URL_COL].tolist()
    batch_y = label_encoder.transform(batch_df[LABEL_COL])

    # 현재 batch feature 생성
    X_batch_eval = build_eval_features(
        urls=batch_urls,
        risk_dict=current_risk_dict,
        malicious_classes=malicious_classes,
        vectorizer=current_vectorizer,
        scaler=current_scaler,
    )

    # --------------------------------------------------------
    # 1) Predict before update
    # --------------------------------------------------------
    # 비교실험용 baseline:
    # phishing-specific gate/tuning 없이 raw multi-class prediction만 사용.
    batch_y_pred = predict_raw(
        model=current_model,
        X=X_batch_eval,
    )

    online_y_true_all.extend(batch_y.tolist())
    online_y_pred_all.extend(batch_y_pred.tolist())

    # --------------------------------------------------------
    # 2) Metric update before training
    # --------------------------------------------------------
    batch_acc = accuracy_score(batch_y, batch_y_pred)
    batch_macro_f1 = f1_score(batch_y, batch_y_pred, average="macro", zero_division=0)
    batch_weighted_f1 = f1_score(batch_y, batch_y_pred, average="weighted", zero_division=0)

    batch_report = classification_report(
        batch_y,
        batch_y_pred,
        labels=np.arange(len(class_names)),
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )

    if PHISHING_LABEL in batch_report:
        batch_phishing_precision = batch_report[PHISHING_LABEL]["precision"]
        batch_phishing_recall = batch_report[PHISHING_LABEL]["recall"]
        batch_phishing_f1 = batch_report[PHISHING_LABEL]["f1-score"]
    else:
        batch_phishing_precision = 0.0
        batch_phishing_recall = 0.0
        batch_phishing_f1 = 0.0

    cm_batch = confusion_matrix(
        batch_y,
        batch_y_pred,
        labels=np.arange(len(class_names)),
    )

    if benign_id is not None and phishing_id is not None:
        batch_benign_to_phishing = int(cm_batch[benign_id][phishing_id])
        batch_phishing_to_benign = int(cm_batch[phishing_id][benign_id])
    else:
        batch_benign_to_phishing = 0
        batch_phishing_to_benign = 0

    # River cumulative online metrics.
    # These are valid progressive metrics because the current batch has
    # not been used for training yet.
    for yt, yp in zip(batch_y, batch_y_pred):
        river_acc.update(int(yt), int(yp))
        river_macro_f1.update(int(yt), int(yp))
        river_weighted_f1.update(int(yt), int(yp))

    print(
        f"Before Update Batch {batch_idx} | "
        f"Batch ACC={batch_acc:.4f}, "
        f"Batch Macro-F1={batch_macro_f1:.4f}, "
        f"Batch Weighted-F1={batch_weighted_f1:.4f}, "
        f"Batch Phishing-P={batch_phishing_precision:.4f}, "
        f"Batch Phishing-R={batch_phishing_recall:.4f}, "
        f"Batch Phishing-F1={batch_phishing_f1:.4f} | "
        f"River Cumulative ACC={river_acc.get():.4f}, "
        f"River Cumulative Macro-F1={river_macro_f1.get():.4f}, "
        f"River Cumulative Weighted-F1={river_weighted_f1.get():.4f}"
    )

    batch_result = {
        "title": f"Before Update - Progressive Stream Batch {batch_idx}",
        "batch_idx": batch_idx,
        "dict_version": version,
        "batch_accuracy": float(batch_acc),
        "batch_macro_f1": float(batch_macro_f1),
        "batch_weighted_f1": float(batch_weighted_f1),
        "batch_phishing_precision": float(batch_phishing_precision),
        "batch_phishing_recall": float(batch_phishing_recall),
        "batch_phishing_f1": float(batch_phishing_f1),
        "batch_benign_to_phishing": int(batch_benign_to_phishing),
        "batch_phishing_to_benign": int(batch_phishing_to_benign),
        "river_cumulative_accuracy": float(river_acc.get()),
        "river_cumulative_macro_f1": float(river_macro_f1.get()),
        "river_cumulative_weighted_f1": float(river_weighted_f1.get()),
        "prediction_mode": "raw_base",
    }

    stream_results.append(batch_result)

    # --------------------------------------------------------
    # 3) Train/update after metric update
    # --------------------------------------------------------
    # 현재 batch로 classifier incremental update.
    X_batch = X_batch_eval

    batch_sample_weight = compute_sample_weight(
        class_weight="balanced",
        y=batch_y,
    )

    current_model.partial_fit(
        X_batch,
        batch_y,
        classes=all_class_ids,
        sample_weight=batch_sample_weight,
    )

    recent_stream_buffer.append(batch_df)

    # --------------------------------------------------------
    # 4) Risk dictionary update using observed stream only
    # --------------------------------------------------------
    if batch_idx % UPDATE_INTERVAL == 0:
        print(f"\n----- Risk Dictionary Update at Batch {batch_idx} -----")

        version += 1

        recent_df = pd.concat(list(recent_stream_buffer), axis=0)

        # Risk dictionary update uses only:
        # - initial warm-up prefix
        # - stream batches already observed so far
        # It never uses future stream batches.
        dict_update_df = pd.concat([initial_train_df, recent_df], axis=0)

        update_urls = dict_update_df[URL_COL].tolist()
        update_labels = dict_update_df[LABEL_COL].tolist()

        new_risk_dict = build_adaptive_risk_dictionary(
            urls=update_urls,
            labels=update_labels,
            tokenizer=safe_tokenize,
            class_names=class_names,
            benign_label=BENIGN_LABEL,
            top_k_common=TOP_K_COMMON_MALICIOUS,
            top_k_per_class=TOP_K_PER_MAL_CLASS,
            min_df=MIN_TOKEN_DF,
            min_mal_classes_for_common=MIN_MAL_CLASSES_FOR_COMMON,
            alpha=ALPHA,
        )

        change_summary = summarize_risk_dict_change(
            old_dict=current_risk_dict,
            new_dict=new_risk_dict,
            malicious_classes=malicious_classes,
        )

        print_change_summary(change_summary)
        save_risk_dict(new_risk_dict, version=version)

        current_risk_dict = new_risk_dict

        # 새 risk dictionary 기준으로 최근 stream window를 한 번 더 학습.
        # 이 역시 이미 관찰된 recent window만 사용한다.
        X_recent = build_eval_features(
            urls=recent_df[URL_COL].tolist(),
            risk_dict=current_risk_dict,
            malicious_classes=malicious_classes,
            vectorizer=current_vectorizer,
            scaler=current_scaler,
        )

        y_recent = label_encoder.transform(recent_df[LABEL_COL])

        recent_sample_weight = compute_sample_weight(
            class_weight="balanced",
            y=y_recent,
        )

        current_model.partial_fit(
            X_recent,
            y_recent,
            classes=all_class_ids,
            sample_weight=recent_sample_weight,
        )

        print(f"Dictionary version updated to v{version}")


# ============================================================
# 13. Final River Progressive Stream Summary
# ============================================================

print("\n\n================================================")
print("Final River Progressive Stream Performance")
print("================================================")

online_y_true_all = np.array(online_y_true_all)
online_y_pred_all = np.array(online_y_pred_all)

final_online_result = evaluate_predictions(
    y_true=online_y_true_all,
    y_pred=online_y_pred_all,
    title="Final Online Progressive Stream - Raw Baseline",
    verbose=True,
    prediction_mode="raw_base",
)

print("\nProtocol: River-style warm-start progressive validation")
print("Prediction mode: raw_base")
print("Warm-up ratio:", WARMUP_RATIO)
print("Warm-up size:", len(initial_train_df))
print("Progressive stream size:", len(stream_update_df))
print("Batch size:", BATCH_SIZE)
print("Cumulative Accuracy:", round(river_acc.get(), 4))
print("Cumulative Macro-F1:", round(river_macro_f1.get(), 4))
print("Cumulative Weighted-F1:", round(river_weighted_f1.get(), 4))

final_stream_summary = {
    "protocol": "River-style warm-start progressive validation",
    "prediction_mode": "raw_base",
    "warmup_ratio": WARMUP_RATIO,
    "warmup_size": len(initial_train_df),
    "progressive_stream_size": len(stream_update_df),
    "batch_size": BATCH_SIZE,
    "update_interval": UPDATE_INTERVAL,
    "sliding_window_batches": SLIDING_WINDOW_BATCHES,
    "river_cumulative_accuracy": float(river_acc.get()),
    "river_cumulative_macro_f1": float(river_macro_f1.get()),
    "river_cumulative_weighted_f1": float(river_weighted_f1.get()),
    "final_online_result": final_online_result,
    "stream_construction_note": (
        "The Kaggle malicious URL dataset has no real timestamps. "
        "We do not claim a real chronological stream. "
        "We define one reproducible pseudo-stream order using a fixed seed. "
        "The prefix 20% of the pseudo-stream is used as warm-up/pretrain data. "
        "The suffix 80% is evaluated with River-style test-before-train progressive validation. "
        "Every batch is evaluated before being used for model/risk-dictionary updates. "
        "No phishing-specific fixed gate, bidirectional gate, threshold tuning, expert model, "
        "or Transformer specialist is used in this baseline."
    ),
}


# ============================================================
# 14. Save Results
# ============================================================

stream_results_df = pd.DataFrame(stream_results)

stream_result_path = os.path.join(
    RESULT_DIR,
    "river_progressive_stream_results_raw_baseline.csv",
)

stream_results_df.to_csv(stream_result_path, index=False)

final_stream_summary_path = os.path.join(
    RESULT_DIR,
    "river_progressive_stream_summary_raw_baseline.json",
)

with open(final_stream_summary_path, "w", encoding="utf-8") as f:
    json.dump(final_stream_summary, f, ensure_ascii=False, indent=2)

final_online_result_path = os.path.join(
    RESULT_DIR,
    "final_online_classification_report_raw_baseline.json",
)

with open(final_online_result_path, "w", encoding="utf-8") as f:
    json.dump(final_online_result, f, ensure_ascii=False, indent=2)

print("\nSaved River progressive stream results:", stream_result_path)
print("Saved River progressive stream summary:", final_stream_summary_path)
print("Saved final online classification report:", final_online_result_path)

print("\nDone.")