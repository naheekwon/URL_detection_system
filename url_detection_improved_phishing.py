import os
import re
import json
import math
import time
import urllib.parse
import unicodedata
from collections import Counter, deque

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight


SEED = 42
np.random.seed(SEED)

DATA_PATH = "./malicious_phish.csv"
URL_COL = "url"
LABEL_COL = "type"
BENIGN_LABEL = "benign"
PHISHING_LABEL = "phishing"

TOP_K_COMMON_MALICIOUS = 1000
TOP_K_PER_MAL_CLASS = 800
MIN_TOKEN_DF = 5
MIN_MAL_CLASSES_FOR_COMMON = 2
ALPHA = 1.0

MAX_TFIDF_FEATURES = 50000
TFIDF_MIN_DF = 3
TFIDF_MAX_DF = 0.95

BATCH_SIZE = 5000
UPDATE_INTERVAL = 3
SLIDING_WINDOW_BATCHES = 6

# Less aggressive than the old gate. This protects phishing recall.
FIXED_PHISHING_DEMOTE_PROB = 0.45
FIXED_PHISHING_DEMOTE_MARGIN = 0.03

DEMOTE_PROB_GRID = [0.35, 0.40, 0.45, 0.50, 0.55]
DEMOTE_MARGIN_GRID = [0.00, 0.02, 0.03, 0.05, 0.08]
PROMOTE_PROB_GRID = [0.20, 0.25, 0.30, 0.35, 0.40, 0.45]
PROMOTE_MARGIN_GRID = [0.03, 0.06, 0.10, 0.15, 0.20]
STRUCTURAL_SCORE_GRID = [1.0, 1.5, 2.0, 2.5, 3.0]

# Objective now rewards phishing recall directly.
OBJECTIVE_PHISHING_F1_WEIGHT = 0.55
OBJECTIVE_PHISHING_RECALL_WEIGHT = 0.45
BENIGN_TO_PHISHING_PENALTY = 0.18
OTHER_MAL_TO_PHISHING_PENALTY = 0.06

# Extra training weight for phishing. Raise to 1.5 if recall is still low.
PHISHING_SAMPLE_WEIGHT_MULTIPLIER = 1.35

# Structural score is used both as one small model feature and in the gate.
USE_STRUCTURAL_SCORE_AS_MAIN_FEATURE = True

RISK_DICT_DIR = "./risk_dict_improved_phishing"
RESULT_DIR = "./results_improved_phishing"
ARTIFACT_DIR = "./saved_url_detector_model"

os.makedirs(RISK_DICT_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)
os.makedirs(ARTIFACT_DIR, exist_ok=True)

BRAND_KEYWORDS = [
    "google", "gmail", "youtube", "facebook", "instagram", "whatsapp",
    "apple", "icloud", "microsoft", "office", "outlook", "amazon",
    "paypal", "netflix", "twitter", "linkedin", "github", "dropbox",
    "adobe", "steam", "discord", "naver", "kakao", "daum", "nate",
    "coupang", "toss", "kbstar", "shinhan", "woori", "hana", "ibk",
    "samsung", "hyundai"
]

PHISHING_ACTION_WORDS = [
    "login", "signin", "account", "verify", "verification", "secure",
    "security", "update", "confirm", "password", "passwd", "auth",
    "authentication", "billing", "payment", "wallet", "unlock", "recover",
    "limited", "suspend", "suspended", "blocked", "alert", "notice",
    "support", "customer", "service"
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "icu",
    "work", "click", "link", "info", "biz", "zip", "mov", "rest",
    "cyou", "monster", "quest", "country"
}

KNOWN_MULTI_SUFFIXES = {
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "co.uk", "org.uk",
    "ac.uk", "com.au", "net.au", "org.au", "co.jp", "or.jp", "ne.jp",
    "com.cn", "net.cn", "org.cn", "com.br", "com.tr", "com.sg"
}

BRAND_SET = set(BRAND_KEYWORDS)
ACTION_SET = set(PHISHING_ACTION_WORDS)


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def to_jsonable(obj):
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, tuple):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    return obj


def clean_url_text(url):
    url = "" if url is None else str(url).strip().lower()
    try:
        url = urllib.parse.unquote(url, errors="ignore")
    except Exception:
        pass
    url = url.replace("[", "").replace("]", "")
    return re.sub(r"[\x00-\x1f\x7f]", "", url)


def split_by_separators(text):
    return [p for p in re.split(r"[^a-zA-Z0-9]+", clean_url_text(text)) if len(p) >= 2]


def char_ngrams(token, n_min=3, n_max=4):
    token = str(token).lower()
    grams = []
    for n in range(n_min, n_max + 1):
        if len(token) >= n:
            grams.extend(f"char:{token[i:i+n]}" for i in range(len(token) - n + 1))
    return grams


def safe_parse_url(url):
    cleaned = clean_url_text(url)
    try:
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned):
            cleaned = "http://" + cleaned
        return urllib.parse.urlparse(cleaned)
    except Exception:
        return urllib.parse.urlparse("http://invalid.local/")


def tokenize_url(url):
    try:
        decoded_url = clean_url_text(url)
        parsed = safe_parse_url(decoded_url)
        tokens = []
        host = parsed.netloc.lower() if parsed.netloc else ""
        path = parsed.path.lower() if parsed.path else ""
        query = parsed.query.lower() if parsed.query else ""

        if "@" in host:
            tokens.append("has_userinfo")
            host = host.split("@")[-1]
        if ":" in host:
            host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            tokens.append("host_is_ip")
        if "xn--" in host:
            tokens.append("has_punycode")

        domain_parts = [p for p in host.split(".") if p]
        if domain_parts:
            tokens.append(f"tld:{domain_parts[-1]}")
            for idx, part in enumerate(domain_parts):
                if idx == len(domain_parts) - 1:
                    tokens.append(f"tldpart:{part}")
                elif idx == len(domain_parts) - 2:
                    tokens.append(f"sld:{part}")
                else:
                    tokens.append(f"subdomain:{part}")
                tokens.append(f"domain:{part}")
                tokens.extend(f"dpart:{p}" for p in split_by_separators(part))

        path_segments = [seg for seg in path.split("/") if seg]
        for seg in path_segments:
            tokens.append(f"path:{seg}")
            tokens.extend(f"pseg:{p}" for p in split_by_separators(seg))

        if path_segments and "." in path_segments[-1]:
            ext = path_segments[-1].split(".")[-1]
            if 1 <= len(ext) <= 8:
                tokens.append(f"ext:{ext}")

        if query:
            tokens.append("has_query")
        try:
            query_pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        except Exception:
            query_pairs = []
        for k, v in query_pairs:
            if k:
                tokens.append(f"qkey:{k}")
                tokens.extend(f"qk:{p}" for p in split_by_separators(k))
            if v:
                tokens.extend(f"qv:{p}" for p in split_by_separators(v))

        general_parts = split_by_separators(decoded_url)
        tokens.extend(f"tok:{p}" for p in general_parts)
        for p in general_parts:
            if len(p) >= 6:
                tokens.extend(char_ngrams(p, 3, 4))

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
        if any(ord(ch) > 127 for ch in str(url)):
            tokens.append("has_non_ascii")

        return tokens if tokens else ["empty_or_invalid_url"]
    except Exception:
        return ["tokenizer_error"]


def safe_tokenize(url):
    try:
        return tokenize_url(url)
    except Exception:
        return ["tokenizer_error"]


def normalize_unicode_text(text):
    try:
        return unicodedata.normalize("NFKC", str(text))
    except Exception:
        return str(text)


def get_ascii_safe(text):
    try:
        return str(text).encode("ascii", errors="ignore").decode("ascii", errors="ignore")
    except Exception:
        return ""


def shannon_entropy(text):
    text = str(text)
    if not text:
        return 0.0
    counter = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counter.values())


def extract_url_parts_for_phishing(url):
    cleaned = clean_url_text(url)
    parsed = safe_parse_url(cleaned)
    host = parsed.netloc.lower() if parsed.netloc else ""
    if "@" in host:
        host = host.split("@")[-1]
    if ":" in host:
        host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]

    host_parts = [p for p in host.split(".") if p]
    subdomain, sld, tld, suffix = "", "", "", ""
    if len(host_parts) >= 3:
        last_two = ".".join(host_parts[-2:])
        if last_two in KNOWN_MULTI_SUFFIXES:
            suffix, tld, sld = last_two, host_parts[-1], host_parts[-3]
            subdomain = ".".join(host_parts[:-3])
        else:
            suffix, tld, sld = host_parts[-1], host_parts[-1], host_parts[-2]
            subdomain = ".".join(host_parts[:-2])
    elif len(host_parts) == 2:
        suffix, tld, sld = host_parts[-1], host_parts[-1], host_parts[-2]
    elif len(host_parts) == 1:
        sld = host_parts[0]

    path = parsed.path.lower() if parsed.path else ""
    query = parsed.query.lower() if parsed.query else ""
    return {
        "full_url": cleaned,
        "host": host,
        "subdomain": subdomain,
        "sld": sld,
        "tld": tld,
        "suffix": suffix,
        "path_query": path + "?" + query if query else path,
    }


def phishing_structural_score_single(url):
    u_raw = "" if url is None else str(url)
    u = clean_url_text(u_raw)
    u_norm = normalize_unicode_text(u)
    u_ascii = get_ascii_safe(u)
    parts = extract_url_parts_for_phishing(u)

    full_tokens = set(split_by_separators(parts["full_url"]))
    host_tokens = set(split_by_separators(parts["host"]))
    sld_tokens = set(split_by_separators(parts["sld"]))
    subdomain_tokens = set(split_by_separators(parts["subdomain"]))
    path_query_tokens = set(split_by_separators(parts["path_query"]))

    brand_in_full = int(bool(BRAND_SET & full_tokens))
    brand_in_sld = int(bool(BRAND_SET & sld_tokens))
    brand_in_subdomain = int(bool(BRAND_SET & subdomain_tokens))
    brand_in_path_query = int(bool(BRAND_SET & path_query_tokens))
    brand_mismatch = int(brand_in_full and not brand_in_sld)
    brand_only_outside_sld = int(brand_in_full and not brand_in_sld and (brand_in_subdomain or brand_in_path_query))

    suspicious_action_count = len(ACTION_SET & full_tokens)
    brand_action_combo = int(brand_in_full and suspicious_action_count > 0)
    brand_action_mismatch_combo = int(brand_mismatch and suspicious_action_count > 0)

    subdomain = parts["subdomain"]
    subdomain_depth = len([p for p in subdomain.split(".") if p])
    many_subdomains = int(subdomain_depth >= 3)
    long_subdomain = int(len(subdomain) >= 20)

    fake_domain_in_subdomain = 0
    if subdomain:
        for brand in BRAND_KEYWORDS:
            if any(x in subdomain for x in [f"{brand}.com", f"{brand}.net", f"{brand}.org", f"{brand}.co", f"{brand}.kr"]):
                fake_domain_in_subdomain = 1
                break

    deceptive_brand_subdomain = int(brand_in_subdomain and not brand_in_sld)
    non_ascii_count = sum(1 for ch in u_raw if ord(ch) > 127)
    homograph_suspicious = int(non_ascii_count > 0 or "xn--" in parts["host"] or u != u_norm or len(u) - len(u_ascii) > 0)
    tld_suspicious = int(parts["tld"] in SUSPICIOUS_TLDS or parts["suffix"] in SUSPICIOUS_TLDS)
    host_is_ip = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parts["host"])))
    high_host_entropy = int(shannon_entropy(parts["host"]) >= 4.0)

    return float(
        1.4 * brand_mismatch
        + 1.4 * brand_only_outside_sld
        + 0.6 * brand_action_combo
        + 1.6 * brand_action_mismatch_combo
        + 1.2 * deceptive_brand_subdomain
        + 1.3 * fake_domain_in_subdomain
        + 0.5 * many_subdomains
        + 0.3 * long_subdomain
        + 1.0 * homograph_suspicious
        + 0.4 * tld_suspicious
        + 0.4 * host_is_ip
        + 0.2 * high_host_entropy
    )


def phishing_structural_scores(urls):
    scores = np.zeros(len(urls), dtype=np.float32)
    for idx, url in enumerate(urls):
        scores[idx] = phishing_structural_score_single(url)
        if len(urls) >= 50000 and (idx + 1) % 50000 == 0:
            log(f"Structural phishing scores: {idx + 1}/{len(urls)}")
    return scores.reshape(-1, 1)


def build_adaptive_risk_dictionary(urls, labels, tokenizer, class_names, benign_label=BENIGN_LABEL):
    malicious_classes_local = [c for c in class_names if c != benign_label]
    class_token_df = {c: Counter() for c in class_names}
    total_token_df = Counter()
    class_doc_count = Counter()

    for idx, (url, label) in enumerate(zip(urls, labels), start=1):
        tokens = set(tokenizer(url))
        class_doc_count[label] += 1
        for token in tokens:
            class_token_df[label][token] += 1
            total_token_df[token] += 1
        if len(urls) >= 50000 and idx % 50000 == 0:
            log(f"Risk dictionary token counting: {idx}/{len(urls)}")

    total_docs = sum(class_doc_count.values())
    benign_docs = class_doc_count[benign_label]
    malicious_docs = total_docs - benign_docs
    common_scores = {}

    for token, total_df in total_token_df.items():
        if total_df < MIN_TOKEN_DF:
            continue
        benign_df = class_token_df[benign_label][token]
        malicious_df = sum(class_token_df[c][token] for c in malicious_classes_local)
        mal_class_presence = sum(1 for c in malicious_classes_local if class_token_df[c][token] > 0)
        if mal_class_presence < MIN_MAL_CLASSES_FOR_COMMON:
            continue
        p_mal = (malicious_df + ALPHA) / (malicious_docs + 2 * ALPHA)
        p_benign = (benign_df + ALPHA) / (benign_docs + 2 * ALPHA)
        score = math.log(p_mal / p_benign)
        if score > 0:
            common_scores[token] = score

    class_specific = {c: {} for c in malicious_classes_local}
    for c in malicious_classes_local:
        scores = {}
        n_c = class_doc_count[c]
        n_not_c = total_docs - n_c
        for token, total_df in total_token_df.items():
            if total_df < MIN_TOKEN_DF:
                continue
            df_c = class_token_df[c][token]
            df_not_c = total_df - df_c
            p_c = (df_c + ALPHA) / (n_c + 2 * ALPHA)
            p_not_c = (df_not_c + ALPHA) / (n_not_c + 2 * ALPHA)
            score = math.log(p_c / p_not_c)
            if score > 0:
                scores[token] = score
        class_specific[c] = dict(sorted(scores.items(), key=lambda x: x[1], reverse=True)[:TOP_K_PER_MAL_CLASS])

    return {
        "common_malicious": dict(sorted(common_scores.items(), key=lambda x: x[1], reverse=True)[:TOP_K_COMMON_MALICIOUS]),
        "class_specific": class_specific,
    }


def save_risk_dict(risk_dict, version):
    path = os.path.join(RISK_DICT_DIR, f"risk_token_dict_v{version}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_jsonable(risk_dict), f, ensure_ascii=False, indent=2)
    print("Saved risk dictionary:", path)


def risk_score_features(urls, risk_dict, tokenizer, malicious_classes):
    rows = []
    common_dict = risk_dict["common_malicious"]
    class_dict = risk_dict["class_specific"]
    for idx, url in enumerate(urls, start=1):
        tokens = set(tokenizer(url))
        row = []
        common_hits = [common_dict[t] for t in tokens if t in common_dict]
        row.extend([sum(common_hits), len(common_hits)])
        for c in malicious_classes:
            c_dict = class_dict.get(c, {})
            hits = [c_dict[t] for t in tokens if t in c_dict]
            row.extend([sum(hits), len(hits)])
        rows.append(row)
        if len(urls) >= 50000 and idx % 50000 == 0:
            log(f"Risk score features: {idx}/{len(urls)}")
    return np.array(rows, dtype=np.float32)


def lexical_features(urls):
    rows = []
    for url in urls:
        u = clean_url_text(url)
        length = len(u)
        digit_count = sum(ch.isdigit() for ch in u)
        alpha_count = sum(ch.isalpha() for ch in u)
        special_count = sum(not ch.isalnum() for ch in u)
        rows.append([
            length, digit_count, alpha_count, special_count,
            u.count("."), u.count("/"), u.count("-"), u.count("_"),
            u.count("?"), u.count("="), u.count("&"), u.count("%"), u.count("@"),
            digit_count / max(length, 1), alpha_count / max(length, 1),
            special_count / max(length, 1),
            int(bool(re.search(r"\d{1,3}(\.\d{1,3}){3}", u))),
            int(u.startswith("https://")), int(u.startswith("http://")),
        ])
    return np.array(rows, dtype=np.float32)


def extra_features(urls, risk_dict, malicious_classes):
    X_risk = risk_score_features(urls, risk_dict, safe_tokenize, malicious_classes)
    X_lex = lexical_features(urls)
    if USE_STRUCTURAL_SCORE_AS_MAIN_FEATURE:
        X_struct = phishing_structural_scores(urls)
        return np.hstack([X_risk, X_lex, X_struct])
    return np.hstack([X_risk, X_lex])


def build_train_features(urls, risk_dict, malicious_classes):
    log("[1/4] Fitting TF-IDF...")
    vectorizer = TfidfVectorizer(
        tokenizer=safe_tokenize,
        token_pattern=None,
        lowercase=False,
        max_features=MAX_TFIDF_FEATURES,
        min_df=TFIDF_MIN_DF,
        max_df=TFIDF_MAX_DF,
    )
    X_tfidf = vectorizer.fit_transform(urls)
    log(f"TF-IDF done: {X_tfidf.shape}")
    log("[2/4] Building extra features...")
    X_extra = extra_features(urls, risk_dict, malicious_classes)
    scaler = StandardScaler()
    X_extra_scaled = scaler.fit_transform(X_extra)
    X = hstack([X_tfidf, csr_matrix(X_extra_scaled)])
    print("Extra feature shape:", X_extra.shape)
    return X, vectorizer, scaler


def build_eval_features(urls, risk_dict, malicious_classes, vectorizer, scaler):
    X_tfidf = vectorizer.transform(urls)
    X_extra = extra_features(urls, risk_dict, malicious_classes)
    X_extra_scaled = scaler.transform(X_extra)
    return hstack([X_tfidf, csr_matrix(X_extra_scaled)])


def make_sample_weight(y, phishing_id):
    weights = compute_sample_weight(class_weight="balanced", y=y)
    if phishing_id is not None:
        weights[y == phishing_id] *= PHISHING_SAMPLE_WEIGHT_MULTIPLIER
    return weights


def apply_fixed_phishing_gate(proba, phishing_id):
    pred = np.argmax(proba, axis=1)
    for i in range(len(pred)):
        if pred[i] != phishing_id:
            continue
        sorted_ids = np.argsort(proba[i])[::-1]
        top2 = sorted_ids[1]
        margin = proba[i][sorted_ids[0]] - proba[i][top2]
        if proba[i][phishing_id] < FIXED_PHISHING_DEMOTE_PROB or margin < FIXED_PHISHING_DEMOTE_MARGIN:
            pred[i] = top2
    return pred


def apply_structural_gate(proba, phishing_id, structural_scores, config):
    pred = np.argmax(proba, axis=1)
    structural_scores = np.asarray(structural_scores).reshape(-1)
    for i in range(len(pred)):
        sorted_ids = np.argsort(proba[i])[::-1]
        top1, top2 = sorted_ids[0], sorted_ids[1]
        phish_prob = proba[i][phishing_id]
        top1_prob = proba[i][top1]
        struct_score = structural_scores[i]
        if top1 == phishing_id:
            margin = proba[i][top1] - proba[i][top2]
            if struct_score >= config["min_structural_score"]:
                if phish_prob < max(0.30, config["demote_prob"] - 0.15):
                    pred[i] = top2
            elif phish_prob < config["demote_prob"] or margin < config["demote_margin"]:
                pred[i] = top2
        else:
            gap_to_top1 = top1_prob - phish_prob
            if (
                phish_prob >= config["promote_prob"]
                and gap_to_top1 <= config["promote_margin"]
                and struct_score >= config["min_structural_score"]
            ):
                pred[i] = phishing_id
    return pred


def score_gate_config(y_true, y_pred, class_names, benign_id, phishing_id):
    report = classification_report(y_true, y_pred, target_names=class_names, output_dict=True, zero_division=0)
    phish_f1 = report[PHISHING_LABEL]["f1-score"]
    phish_recall = report[PHISHING_LABEL]["recall"]
    cm = confusion_matrix(y_true, y_pred, labels=np.arange(len(class_names)))
    benign_to_phish_rate = cm[benign_id][phishing_id] / max(cm[benign_id].sum(), 1)

    other_mal_to_phish = 0
    other_mal_total = 0
    for cid in range(len(class_names)):
        if cid not in [benign_id, phishing_id]:
            other_mal_to_phish += cm[cid][phishing_id]
            other_mal_total += cm[cid].sum()
    other_mal_to_phish_rate = other_mal_to_phish / max(other_mal_total, 1)

    objective = (
        OBJECTIVE_PHISHING_F1_WEIGHT * phish_f1
        + OBJECTIVE_PHISHING_RECALL_WEIGHT * phish_recall
        - BENIGN_TO_PHISHING_PENALTY * benign_to_phish_rate
        - OTHER_MAL_TO_PHISHING_PENALTY * other_mal_to_phish_rate
    )
    return objective, phish_f1, phish_recall, benign_to_phish_rate, other_mal_to_phish_rate


def tune_structural_gate(proba_list, y_true_list, url_list, phishing_id, benign_id, class_names):
    if not proba_list:
        return {"demote_prob": 0.45, "demote_margin": 0.03, "promote_prob": 0.30, "promote_margin": 0.10, "min_structural_score": 1.5}

    proba_all = np.vstack(proba_list)
    y_true_all = np.concatenate(y_true_list)
    urls_all = [url for urls in url_list for url in urls]
    struct_scores = phishing_structural_scores(urls_all)
    best = None

    for demote_prob in DEMOTE_PROB_GRID:
        for demote_margin in DEMOTE_MARGIN_GRID:
            for promote_prob in PROMOTE_PROB_GRID:
                for promote_margin in PROMOTE_MARGIN_GRID:
                    for min_structural_score in STRUCTURAL_SCORE_GRID:
                        config = {
                            "demote_prob": demote_prob,
                            "demote_margin": demote_margin,
                            "promote_prob": promote_prob,
                            "promote_margin": promote_margin,
                            "min_structural_score": min_structural_score,
                        }
                        y_pred = apply_structural_gate(proba_all, phishing_id, struct_scores, config)
                        obj, phish_f1, phish_recall, b2p, o2p = score_gate_config(
                            y_true_all, y_pred, class_names, benign_id, phishing_id
                        )
                        candidate = {
                            **config,
                            "objective": obj,
                            "phishing_f1": phish_f1,
                            "phishing_recall": phish_recall,
                            "benign_to_phishing_rate": b2p,
                            "other_mal_to_phishing_rate": o2p,
                        }
                        if best is None or candidate["objective"] > best["objective"]:
                            best = candidate
    print("\n===== Tuned Recall-Aware Structural Gate Config =====")
    print(best)
    return best


def predict_model(model, X, urls, mode, phishing_id, gate_config=None):
    if mode == "raw" or phishing_id is None:
        return model.predict(X)
    try:
        proba = model.predict_proba(X)
    except Exception:
        return model.predict(X)
    if mode == "fixed_gate":
        return apply_fixed_phishing_gate(proba, phishing_id)
    if mode == "tuned_structural_gate":
        if gate_config is None:
            gate_config = {"demote_prob": 0.45, "demote_margin": 0.03, "promote_prob": 0.30, "promote_margin": 0.10, "min_structural_score": 1.5}
        return apply_structural_gate(proba, phishing_id, phishing_structural_scores(urls), gate_config)
    return model.predict(X)


def evaluate_model(model, urls, y_true, risk_dict, malicious_classes, vectorizer, scaler, class_names, title, mode, phishing_id, gate_config=None):
    X = build_eval_features(urls, risk_dict, malicious_classes, vectorizer, scaler)
    y_pred = predict_model(model, X, urls, mode, phishing_id, gate_config)
    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    report = classification_report(y_true, y_pred, target_names=class_names, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=np.arange(len(class_names)))

    print(f"\n===== {title} =====")
    print("Mode:", mode)
    if gate_config:
        print("Gate config:", gate_config)
    print("Accuracy:", round(acc, 4))
    print("Macro-F1:", round(macro_f1, 4))
    print("Weighted-F1:", round(weighted_f1, 4))
    print(classification_report(y_true, y_pred, target_names=class_names, zero_division=0))
    print("Confusion Matrix")
    print(cm)

    result = {
        "title": title,
        "mode": mode,
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "classification_report": report,
        "confusion_matrix": cm.tolist(),
    }
    if PHISHING_LABEL in report:
        result["phishing_precision"] = report[PHISHING_LABEL]["precision"]
        result["phishing_recall"] = report[PHISHING_LABEL]["recall"]
        result["phishing_f1"] = report[PHISHING_LABEL]["f1-score"]
    return result


def make_batches(df, batch_size):
    return [df.iloc[start:min(start + batch_size, len(df))].copy() for start in range(0, len(df), batch_size)]


def summarize_risk_dict_change(old_dict, new_dict, malicious_classes):
    summary = {}
    old_common = set(old_dict["common_malicious"].keys())
    new_common = set(new_dict["common_malicious"].keys())
    summary["common_malicious"] = {"added": len(new_common - old_common), "removed": len(old_common - new_common), "kept": len(old_common & new_common)}
    for c in malicious_classes:
        old_tokens = set(old_dict["class_specific"].get(c, {}).keys())
        new_tokens = set(new_dict["class_specific"].get(c, {}).keys())
        summary[c] = {"added": len(new_tokens - old_tokens), "removed": len(old_tokens - new_tokens), "kept": len(old_tokens & new_tokens)}
    return summary


def main():
    log("Loading dataset...")
    df = pd.read_csv(DATA_PATH)
    df = df[[URL_COL, LABEL_COL]].dropna()
    df[URL_COL] = df[URL_COL].astype(str)
    df[LABEL_COL] = df[LABEL_COL].astype(str)
    print("Original shape:", df.shape)
    print(df[LABEL_COL].value_counts())

    log("Splitting dataset...")
    initial_train_df, temp_df = train_test_split(df, test_size=0.60, stratify=df[LABEL_COL], random_state=SEED)
    stream_update_df, final_test_df = train_test_split(temp_df, test_size=0.50, stratify=temp_df[LABEL_COL], random_state=SEED)

    label_encoder = LabelEncoder()
    y_initial = label_encoder.fit_transform(initial_train_df[LABEL_COL])
    y_final = label_encoder.transform(final_test_df[LABEL_COL])
    class_names = list(label_encoder.classes_)
    malicious_classes = [c for c in class_names if c != BENIGN_LABEL]
    label_to_id = {label: idx for idx, label in enumerate(class_names)}
    benign_id = label_to_id.get(BENIGN_LABEL)
    phishing_id = label_to_id.get(PHISHING_LABEL)
    all_class_ids = np.arange(len(class_names))

    print("Class names:", class_names)
    print("Phishing weight multiplier:", PHISHING_SAMPLE_WEIGHT_MULTIPLIER)
    print("Structural score as main feature:", USE_STRUCTURAL_SCORE_AS_MAIN_FEATURE)

    log("Building initial risk dictionary...")
    risk_dict = build_adaptive_risk_dictionary(
        initial_train_df[URL_COL].tolist(),
        initial_train_df[LABEL_COL].tolist(),
        safe_tokenize,
        class_names,
    )
    save_risk_dict(risk_dict, 0)

    log("Building initial features...")
    X_initial, vectorizer, scaler = build_train_features(initial_train_df[URL_COL].tolist(), risk_dict, malicious_classes)
    model = SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-5, max_iter=1, tol=None, random_state=SEED, n_jobs=-1)

    log("Training initial model...")
    model.partial_fit(X_initial, y_initial, classes=all_class_ids, sample_weight=make_sample_weight(y_initial, phishing_id))

    current_model = model
    current_risk_dict = risk_dict
    current_vectorizer = vectorizer
    current_scaler = scaler
    recent_stream_buffer = deque(maxlen=SLIDING_WINDOW_BATCHES)
    stream_results = []
    version = 0
    calibration_proba_list, calibration_y_list, calibration_url_list = [], [], []

    stream_batches = make_batches(stream_update_df, BATCH_SIZE)
    print("Number of stream batches:", len(stream_batches))

    for batch_idx, batch_df in enumerate(stream_batches, start=1):
        print(f"\n========== Stream Batch {batch_idx}/{len(stream_batches)} ==========")
        recent_stream_buffer.append(batch_df)
        batch_urls = batch_df[URL_COL].tolist()
        batch_y = label_encoder.transform(batch_df[LABEL_COL])
        X_batch = build_eval_features(batch_urls, current_risk_dict, malicious_classes, current_vectorizer, current_scaler)

        try:
            calibration_proba_list.append(current_model.predict_proba(X_batch))
            calibration_y_list.append(batch_y)
            calibration_url_list.append(batch_urls)
        except Exception:
            pass

        batch_pred = predict_model(current_model, X_batch, batch_urls, "fixed_gate", phishing_id)
        batch_result = {
            "batch_idx": batch_idx,
            "dict_version": version,
            "accuracy": accuracy_score(batch_y, batch_pred),
            "macro_f1": f1_score(batch_y, batch_pred, average="macro", zero_division=0),
            "weighted_f1": f1_score(batch_y, batch_pred, average="weighted", zero_division=0),
            "phishing_f1": f1_score(batch_y, batch_pred, labels=[phishing_id], average="macro", zero_division=0),
        }
        print(batch_result)
        stream_results.append(batch_result)

        current_model.partial_fit(X_batch, batch_y, classes=all_class_ids, sample_weight=make_sample_weight(batch_y, phishing_id))

        if batch_idx % UPDATE_INTERVAL == 0:
            version += 1
            recent_df = pd.concat(list(recent_stream_buffer), axis=0)
            dict_update_df = pd.concat([initial_train_df, recent_df], axis=0)
            new_risk_dict = build_adaptive_risk_dictionary(
                dict_update_df[URL_COL].tolist(),
                dict_update_df[LABEL_COL].tolist(),
                safe_tokenize,
                class_names,
            )
            print("Risk dictionary change:", summarize_risk_dict_change(current_risk_dict, new_risk_dict, malicious_classes))
            save_risk_dict(new_risk_dict, version)
            current_risk_dict = new_risk_dict
            X_recent = build_eval_features(recent_df[URL_COL].tolist(), current_risk_dict, malicious_classes, current_vectorizer, current_scaler)
            y_recent = label_encoder.transform(recent_df[LABEL_COL])
            current_model.partial_fit(X_recent, y_recent, classes=all_class_ids, sample_weight=make_sample_weight(y_recent, phishing_id))

    log("Tuning recall-aware structural phishing gate...")
    tuned_structural_gate_config = tune_structural_gate(
        calibration_proba_list,
        calibration_y_list,
        calibration_url_list,
        phishing_id,
        benign_id,
        class_names,
    )

    final_urls = final_test_df[URL_COL].tolist()
    final_raw = evaluate_model(current_model, final_urls, y_final, current_risk_dict, malicious_classes, current_vectorizer, current_scaler, class_names, "Final Test - RAW", "raw", phishing_id)
    final_fixed = evaluate_model(current_model, final_urls, y_final, current_risk_dict, malicious_classes, current_vectorizer, current_scaler, class_names, "Final Test - Fixed Gate", "fixed_gate", phishing_id)
    final_structural = evaluate_model(current_model, final_urls, y_final, current_risk_dict, malicious_classes, current_vectorizer, current_scaler, class_names, "Final Test - Recall-Aware Structural Gate", "tuned_structural_gate", phishing_id, tuned_structural_gate_config)

    pd.DataFrame(stream_results).to_csv(os.path.join(RESULT_DIR, "stream_update_results.csv"), index=False)
    outputs = {
        "raw": final_raw,
        "fixed_gate": final_fixed,
        "recall_aware_structural_gate": final_structural,
        "tuned_structural_gate_config": tuned_structural_gate_config,
        "improvement_config": {
            "fixed_phishing_demote_prob": FIXED_PHISHING_DEMOTE_PROB,
            "fixed_phishing_demote_margin": FIXED_PHISHING_DEMOTE_MARGIN,
            "phishing_sample_weight_multiplier": PHISHING_SAMPLE_WEIGHT_MULTIPLIER,
            "use_structural_score_as_main_feature": USE_STRUCTURAL_SCORE_AS_MAIN_FEATURE,
            "objective_phishing_f1_weight": OBJECTIVE_PHISHING_F1_WEIGHT,
            "objective_phishing_recall_weight": OBJECTIVE_PHISHING_RECALL_WEIGHT,
            "benign_to_phishing_penalty": BENIGN_TO_PHISHING_PENALTY,
            "other_mal_to_phishing_penalty": OTHER_MAL_TO_PHISHING_PENALTY,
        },
    }
    with open(os.path.join(RESULT_DIR, "final_test_comparison_recall_aware.json"), "w", encoding="utf-8") as f:
        json.dump(to_jsonable(outputs), f, ensure_ascii=False, indent=2)

    joblib.dump(current_model, os.path.join(ARTIFACT_DIR, "model.pkl"))
    joblib.dump(current_vectorizer, os.path.join(ARTIFACT_DIR, "vectorizer.pkl"))
    joblib.dump(current_scaler, os.path.join(ARTIFACT_DIR, "scaler.pkl"))
    joblib.dump(label_encoder, os.path.join(ARTIFACT_DIR, "label_encoder.pkl"))
    with open(os.path.join(ARTIFACT_DIR, "risk_dict.json"), "w", encoding="utf-8") as f:
        json.dump(to_jsonable(current_risk_dict), f, ensure_ascii=False, indent=2)
    with open(os.path.join(ARTIFACT_DIR, "tuned_structural_gate_config.json"), "w", encoding="utf-8") as f:
        json.dump(to_jsonable(tuned_structural_gate_config), f, ensure_ascii=False, indent=2)
    with open(os.path.join(ARTIFACT_DIR, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(to_jsonable({
            "class_names": class_names,
            "malicious_classes": malicious_classes,
            "benign_label": BENIGN_LABEL,
            "phishing_label": PHISHING_LABEL,
            "benign_id": benign_id,
            "phishing_id": phishing_id,
            "main_model_features": "TF-IDF + risk dictionary + lexical + structural_score",
            "gate_objective": "phishing F1 + phishing recall - false positive penalties",
        }), f, ensure_ascii=False, indent=2)

    print("\nSaved results to:", RESULT_DIR)
    print("Saved artifacts to:", ARTIFACT_DIR)
    print("Done.")


if __name__ == "__main__":
    main()
