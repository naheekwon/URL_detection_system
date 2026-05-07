# ============================================================
# LinkWatcher
# AI-based Multi-Class Malicious URL Detection
# + Adaptive Risk Token Dictionary
# + River Progressive Streaming Evaluation
# + Character-level Transformer Phishing Specialist
#
# Protocol:
# - 20% warm-up prefix
#   * train base 4-class detector
#   * build initial risk-token dictionary
#   * train phishing specialist Transformer using only benign/phishing warm-up samples
#
# - 80% progressive stream suffix
#   * base model predicts first
#   * phishing specialist is called only for benign/phishing gray-zone candidates
#   * final prediction is evaluated before training
#   * then base model and risk dictionary are updated
#
# Important:
# - The Kaggle dataset has no timestamps.
# - This is a fixed-seed pseudo-stream, not a real chronological stream.
# - Evaluation follows test-before-train progressive validation.
# ============================================================

import os
import re
import json
import math
import random
import urllib.parse
from collections import Counter, deque

import numpy as np
import pandas as pd
import joblib

from scipy.sparse import hstack, csr_matrix

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    confusion_matrix,
    classification_report,
)
from sklearn.utils.class_weight import compute_sample_weight

from river import metrics

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader


# ============================================================
# 0. Config
# ============================================================

SEED = 42

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()

DATA_PATH = os.path.join(PROJECT_DIR, "malicious_phish.csv")

URL_COL = "url"
LABEL_COL = "type"

BENIGN_LABEL = "benign"
PHISHING_LABEL = "phishing"

# Pseudo-stream split
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

# Fixed phishing gate for base model
FIXED_PHISHING_DEMOTE_PROB = 0.55
FIXED_PHISHING_DEMOTE_MARGIN = 0.08

# Transformer specialist
USE_PHISHING_TRANSFORMER = True

MAX_CHAR_LEN = 256
TRANSFORMER_MAX_TRAIN_SAMPLES = 60000
TRANSFORMER_EPOCHS = 2
TRANSFORMER_BATCH_SIZE = 256
TRANSFORMER_LR = 1e-3

CHAR_EMBED_DIM = 64
TRANSFORMER_NHEAD = 4
TRANSFORMER_NUM_LAYERS = 2
TRANSFORMER_FF_DIM = 128
TRANSFORMER_DROPOUT = 0.1

# Candidate selection for Transformer specialist
GRAY_ZONE_MARGIN = 0.20
MIN_BASE_PHISHING_PROB_FOR_SPECIALIST = 0.25

# Fusion thresholds
TRANSFORMER_PHISHING_THRESHOLD = 0.60
TRANSFORMER_BENIGN_THRESHOLD = 0.35

RISK_DICT_DIR = os.path.join(PROJECT_DIR, "risk_dict_river_progressive")
RESULT_DIR = os.path.join(PROJECT_DIR, "results_river_progressive")
ARTIFACT_DIR = os.path.join(PROJECT_DIR, "artifacts_transformer")

os.makedirs(RISK_DICT_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)
os.makedirs(ARTIFACT_DIR, exist_ok=True)


# ============================================================
# 1. Safe URL Processing and Tokenizer
# ============================================================

def clean_url_text(url):
    if url is None:
        url = ""

    url = str(url).strip().lower()

    try:
        url = urllib.parse.unquote(url, errors="ignore")
    except Exception:
        pass

    url = url.replace("[", "").replace("]", "")
    url = re.sub(r"[\x00-\x1f\x7f]", "", url)

    return url


def split_by_separators(text):
    if text is None:
        return []

    text = clean_url_text(text)
    parts = re.split(r"[^a-zA-Z0-9]+", text)

    return [p for p in parts if len(p) >= 2]


def char_ngrams(token, n_min=3, n_max=4):
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

        if "@" in host:
            tokens.append("has_userinfo")
            host = host.split("@")[-1]

        if ":" in host:
            host = host.split(":")[0]

        if host.startswith("www."):
            host = host[4:]

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            tokens.append("host_is_ip")

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

        path_segments = [seg for seg in path.split("/") if seg]

        for seg in path_segments:
            tokens.append(f"path:{seg}")

            for p in split_by_separators(seg):
                tokens.append(f"pseg:{p}")

        if path_segments:
            last_seg = path_segments[-1]
            if "." in last_seg:
                ext = last_seg.split(".")[-1]
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
                for p in split_by_separators(k):
                    tokens.append(f"qk:{p}")

            if v:
                for p in split_by_separators(v):
                    tokens.append(f"qv:{p}")

        general_parts = split_by_separators(decoded_url)

        for p in general_parts:
            tokens.append(f"tok:{p}")

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

        if not tokens:
            tokens.append("empty_or_invalid_url")

        return tokens

    except Exception:
        return ["tokenizer_error"]


def safe_tokenize(url):
    try:
        return tokenize_url(url)
    except Exception:
        return ["tokenizer_error"]


# ============================================================
# 2. Load Dataset
# ============================================================

df = pd.read_csv(DATA_PATH)

print("\nOriginal shape:", df.shape)
print("Columns:", df.columns.tolist())

df = df[[URL_COL, LABEL_COL]].dropna()
df[URL_COL] = df[URL_COL].astype(str)
df[LABEL_COL] = df[LABEL_COL].astype(str)

print("\nLabel distribution:")
print(df[LABEL_COL].value_counts())


# ============================================================
# 3. Pseudo-stream Construction
# ============================================================

stream_df = df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)

warmup_size = int(len(stream_df) * WARMUP_RATIO)

initial_train_df = stream_df.iloc[:warmup_size].copy().reset_index(drop=True)
stream_update_df = stream_df.iloc[warmup_size:].copy().reset_index(drop=True)

print("\nRiver-style Warm-start Progressive Stream")
print("Full pseudo-stream:", stream_df.shape)
print("Warm-up prefix:", initial_train_df.shape)
print("Progressive stream suffix:", stream_update_df.shape)

print("\nWarm-up prefix label distribution:")
print(initial_train_df[LABEL_COL].value_counts())

print("\nProgressive stream suffix label distribution:")
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
    malicious_classes = [c for c in class_names if c != benign_label]

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

    common_scores = {}

    for token, total_df in total_token_df.items():
        if total_df < min_df:
            continue

        benign_df = class_token_df[benign_label][token]
        malicious_df = sum(class_token_df[c][token] for c in malicious_classes)

        mal_class_presence = sum(
            1 for c in malicious_classes
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

    class_specific = {c: {} for c in malicious_classes}

    for c in malicious_classes:
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
        "class_specific": class_specific
    }


def save_risk_dict(risk_dict, version):
    path = os.path.join(RISK_DICT_DIR, f"risk_token_dict_v{version}.json")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(risk_dict, f, ensure_ascii=False, indent=2)

    print(f"Saved risk dictionary: {path}")


def print_risk_dict_preview(risk_dict, top_n=10):
    print("\n===== Common Malicious Risk Tokens =====")
    for token, score in list(risk_dict["common_malicious"].items())[:top_n]:
        print(token, round(score, 4))

    print("\n===== Class-specific Risk Tokens =====")
    for c, d in risk_dict["class_specific"].items():
        print(f"\n[{c}]")
        for token, score in list(d.items())[:top_n]:
            print(token, round(score, 4))


print("\nBuilding initial risk dictionary...")

risk_dict = build_adaptive_risk_dictionary(
    urls=initial_train_df[URL_COL].tolist(),
    labels=initial_train_df[LABEL_COL].tolist(),
    tokenizer=safe_tokenize,
    class_names=class_names,
    benign_label=BENIGN_LABEL,
    top_k_common=TOP_K_COMMON_MALICIOUS,
    top_k_per_class=TOP_K_PER_MAL_CLASS,
    min_df=MIN_TOKEN_DF,
    min_mal_classes_for_common=MIN_MAL_CLASSES_FOR_COMMON,
    alpha=ALPHA
)

save_risk_dict(risk_dict, version=0)
print_risk_dict_preview(risk_dict, top_n=10)


# ============================================================
# 6. Base Model Features
# ============================================================

def risk_score_features(urls, risk_dict, tokenizer, malicious_classes):
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
            has_http
        ])

    return np.array(rows, dtype=np.float32)


def build_train_features(urls, risk_dict, malicious_classes):
    vectorizer = TfidfVectorizer(
        tokenizer=safe_tokenize,
        token_pattern=None,
        lowercase=False,
        max_features=MAX_TFIDF_FEATURES,
        min_df=TFIDF_MIN_DF,
        max_df=TFIDF_MAX_DF
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
    X_tfidf = vectorizer.transform(urls)

    X_risk = risk_score_features(urls, risk_dict, safe_tokenize, malicious_classes)
    X_lex = lexical_features(urls)

    X_extra = np.hstack([X_risk, X_lex])
    X_extra_scaled = scaler.transform(X_extra)

    X = hstack([X_tfidf, csr_matrix(X_extra_scaled)])

    return X


# ============================================================
# 7. Character-level Transformer Phishing Specialist
# ============================================================

PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"
CLS_TOKEN = "<CLS>"

PAD_ID = 0
UNK_ID = 1
CLS_ID = 2


def build_char_vocab(urls, max_vocab_size=None):
    counter = Counter()

    for url in urls:
        u = clean_url_text(url)
        for ch in u:
            counter[ch] += 1

    vocab = {
        PAD_TOKEN: PAD_ID,
        UNK_TOKEN: UNK_ID,
        CLS_TOKEN: CLS_ID,
    }

    most_common = counter.most_common(max_vocab_size)

    for ch, _ in most_common:
        if ch not in vocab:
            vocab[ch] = len(vocab)

    return vocab


def encode_url_chars(url, char_vocab, max_len=256):
    u = clean_url_text(url)

    ids = [CLS_ID]

    for ch in u:
        ids.append(char_vocab.get(ch, UNK_ID))

    ids = ids[:max_len]

    if len(ids) < max_len:
        ids = ids + [PAD_ID] * (max_len - len(ids))

    return ids


class URLCharDataset(Dataset):
    def __init__(self, urls, labels, char_vocab, max_len=256):
        self.urls = list(urls)
        self.labels = np.array(labels, dtype=np.int64)
        self.char_vocab = char_vocab
        self.max_len = max_len

    def __len__(self):
        return len(self.urls)

    def __getitem__(self, idx):
        x = encode_url_chars(self.urls[idx], self.char_vocab, self.max_len)
        y = int(self.labels[idx])

        return torch.tensor(x, dtype=torch.long), torch.tensor(y, dtype=torch.long)


class CharTransformerPhishingModel(nn.Module):
    def __init__(
        self,
        vocab_size,
        max_len=256,
        embed_dim=64,
        nhead=4,
        num_layers=2,
        ff_dim=128,
        dropout=0.1
    ):
        super().__init__()

        self.token_embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embed_dim,
            padding_idx=PAD_ID
        )

        self.position_embedding = nn.Embedding(
            num_embeddings=max_len,
            embedding_dim=embed_dim
        )

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=nhead,
            dim_feedforward=ff_dim,
            dropout=dropout,
            batch_first=True,
            activation="gelu"
        )

        self.encoder = nn.TransformerEncoder(
            encoder_layer=encoder_layer,
            num_layers=num_layers
        )

        self.classifier = nn.Sequential(
            nn.LayerNorm(embed_dim),
            nn.Linear(embed_dim, 2)
        )

        self.max_len = max_len

    def forward(self, input_ids):
        batch_size, seq_len = input_ids.shape

        positions = torch.arange(seq_len, device=input_ids.device).unsqueeze(0)
        positions = positions.expand(batch_size, seq_len)

        x = self.token_embedding(input_ids) + self.position_embedding(positions)

        padding_mask = input_ids.eq(PAD_ID)

        encoded = self.encoder(
            x,
            src_key_padding_mask=padding_mask
        )

        cls_repr = encoded[:, 0, :]

        logits = self.classifier(cls_repr)

        return logits


def prepare_phishing_specialist_data(train_df):
    bp_df = train_df[
        train_df[LABEL_COL].isin([BENIGN_LABEL, PHISHING_LABEL])
    ].copy()

    bp_df["binary_label"] = bp_df[LABEL_COL].apply(
        lambda x: 1 if x == PHISHING_LABEL else 0
    )

    benign_df = bp_df[bp_df["binary_label"] == 0]
    phish_df = bp_df[bp_df["binary_label"] == 1]

    if len(benign_df) == 0 or len(phish_df) == 0:
        raise ValueError("Not enough benign/phishing samples for Transformer specialist.")

    # Balanced sampling for binary specialist
    max_each = TRANSFORMER_MAX_TRAIN_SAMPLES // 2
    n_each = min(len(benign_df), len(phish_df), max_each)

    benign_sample = benign_df.sample(n=n_each, random_state=SEED)
    phish_sample = phish_df.sample(n=n_each, random_state=SEED)

    sampled_df = pd.concat([benign_sample, phish_sample], axis=0)
    sampled_df = sampled_df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)

    urls = sampled_df[URL_COL].tolist()
    labels = sampled_df["binary_label"].values

    return urls, labels


def train_phishing_transformer(train_df):
    if not USE_PHISHING_TRANSFORMER:
        return None, None

    print("\nPreparing phishing specialist Transformer data...")

    train_urls, train_labels = prepare_phishing_specialist_data(train_df)

    print("Transformer specialist train samples:", len(train_urls))
    print("Benign:", int(np.sum(train_labels == 0)))
    print("Phishing:", int(np.sum(train_labels == 1)))

    char_vocab = build_char_vocab(train_urls)

    print("Character vocab size:", len(char_vocab))

    train_dataset = URLCharDataset(
        urls=train_urls,
        labels=train_labels,
        char_vocab=char_vocab,
        max_len=MAX_CHAR_LEN
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=TRANSFORMER_BATCH_SIZE,
        shuffle=True,
        num_workers=0
    )

    model = CharTransformerPhishingModel(
        vocab_size=len(char_vocab),
        max_len=MAX_CHAR_LEN,
        embed_dim=CHAR_EMBED_DIM,
        nhead=TRANSFORMER_NHEAD,
        num_layers=TRANSFORMER_NUM_LAYERS,
        ff_dim=TRANSFORMER_FF_DIM,
        dropout=TRANSFORMER_DROPOUT
    ).to(DEVICE)

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=TRANSFORMER_LR,
        weight_decay=1e-4
    )

    criterion = nn.CrossEntropyLoss()

    model.train()

    for epoch in range(1, TRANSFORMER_EPOCHS + 1):
        total_loss = 0.0
        total_correct = 0
        total_count = 0

        for input_ids, labels in train_loader:
            input_ids = input_ids.to(DEVICE)
            labels = labels.to(DEVICE)

            optimizer.zero_grad()

            logits = model(input_ids)
            loss = criterion(logits, labels)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            total_loss += loss.item() * labels.size(0)

            preds = torch.argmax(logits, dim=1)
            total_correct += (preds == labels).sum().item()
            total_count += labels.size(0)

        avg_loss = total_loss / max(total_count, 1)
        acc = total_correct / max(total_count, 1)

        print(
            f"Transformer Epoch {epoch}/{TRANSFORMER_EPOCHS} | "
            f"Loss={avg_loss:.4f}, Train ACC={acc:.4f}"
        )

    model.eval()

    return model, char_vocab


@torch.no_grad()
def predict_phishing_transformer_probs(model, char_vocab, urls):
    if model is None or char_vocab is None or len(urls) == 0:
        return np.array([], dtype=np.float32)

    dataset = URLCharDataset(
        urls=urls,
        labels=np.zeros(len(urls), dtype=np.int64),
        char_vocab=char_vocab,
        max_len=MAX_CHAR_LEN
    )

    loader = DataLoader(
        dataset,
        batch_size=TRANSFORMER_BATCH_SIZE,
        shuffle=False,
        num_workers=0
    )

    all_probs = []

    model.eval()

    for input_ids, _ in loader:
        input_ids = input_ids.to(DEVICE)

        logits = model(input_ids)
        probs = torch.softmax(logits, dim=1)[:, 1]

        all_probs.extend(probs.detach().cpu().numpy().tolist())

    return np.array(all_probs, dtype=np.float32)


# ============================================================
# 8. Base Prediction and Hybrid Fusion
# ============================================================

def predict_with_fixed_phishing_gate(
    model,
    X,
    phishing_id,
    min_phish_prob=0.55,
    min_margin=0.08
):
    if phishing_id is None:
        return model.predict(X)

    try:
        proba = model.predict_proba(X)
    except Exception:
        return model.predict(X)

    pred = np.argmax(proba, axis=1)

    for i in range(len(pred)):
        if pred[i] != phishing_id:
            continue

        sorted_ids = np.argsort(proba[i])[::-1]
        top1 = sorted_ids[0]
        top2 = sorted_ids[1]

        phish_prob = proba[i][phishing_id]
        margin = proba[i][top1] - proba[i][top2]

        if phish_prob < min_phish_prob or margin < min_margin:
            pred[i] = top2

    return pred


def hybrid_predict(
    base_model,
    X,
    urls,
    benign_id,
    phishing_id,
    transformer_model=None,
    char_vocab=None
):
    """
    Hybrid decision:
    1. Base 4-class model predicts first.
    2. Transformer specialist is called only for benign/phishing candidates.
    3. Specialist adjusts only benign <-> phishing decisions.
       Malware/defacement decisions are not overwritten.
    """

    try:
        base_proba = base_model.predict_proba(X)
    except Exception:
        base_proba = None

    base_pred = predict_with_fixed_phishing_gate(
        model=base_model,
        X=X,
        phishing_id=phishing_id,
        min_phish_prob=FIXED_PHISHING_DEMOTE_PROB,
        min_margin=FIXED_PHISHING_DEMOTE_MARGIN
    )

    final_pred = np.array(base_pred, copy=True)

    transformer_used_count = 0
    transformer_promote_count = 0
    transformer_demote_count = 0

    mean_transformer_phish_prob = 0.0

    if (
        USE_PHISHING_TRANSFORMER
        and transformer_model is not None
        and char_vocab is not None
        and base_proba is not None
        and benign_id is not None
        and phishing_id is not None
    ):
        benign_prob = base_proba[:, benign_id]
        phishing_prob = base_proba[:, phishing_id]

        boundary_margin = np.abs(benign_prob - phishing_prob)

        candidate_mask = (
            ((base_pred == benign_id) | (base_pred == phishing_id))
            & (
                (boundary_margin <= GRAY_ZONE_MARGIN)
                | (phishing_prob >= MIN_BASE_PHISHING_PROB_FOR_SPECIALIST)
                | (base_pred == phishing_id)
            )
        )

        candidate_indices = np.where(candidate_mask)[0]

        if len(candidate_indices) > 0:
            candidate_urls = [urls[i] for i in candidate_indices]
            transformer_probs = predict_phishing_transformer_probs(
                model=transformer_model,
                char_vocab=char_vocab,
                urls=candidate_urls
            )

            transformer_used_count = len(candidate_indices)
            mean_transformer_phish_prob = float(np.mean(transformer_probs))

            for local_idx, global_idx in enumerate(candidate_indices):
                t_prob = transformer_probs[local_idx]

                # If specialist strongly says phishing, promote to phishing.
                if t_prob >= TRANSFORMER_PHISHING_THRESHOLD:
                    if final_pred[global_idx] != phishing_id:
                        transformer_promote_count += 1
                    final_pred[global_idx] = phishing_id

                # If specialist strongly says benign, demote phishing to benign.
                elif t_prob <= TRANSFORMER_BENIGN_THRESHOLD:
                    if final_pred[global_idx] == phishing_id:
                        transformer_demote_count += 1
                    final_pred[global_idx] = benign_id

                # Otherwise, keep base prediction.
                else:
                    pass

    fusion_stats = {
        "transformer_used_count": transformer_used_count,
        "transformer_promote_count": transformer_promote_count,
        "transformer_demote_count": transformer_demote_count,
        "mean_transformer_phish_prob": mean_transformer_phish_prob,
    }

    return final_pred, fusion_stats


# ============================================================
# 9. Initial Base Model Training
# ============================================================

print("\nBuilding initial warm-up features...")

X_initial, vectorizer, scaler = build_train_features(
    urls=initial_train_df[URL_COL].tolist(),
    risk_dict=risk_dict,
    malicious_classes=malicious_classes
)

print("X_initial shape:", X_initial.shape)

base_model = SGDClassifier(
    loss="log_loss",
    penalty="l2",
    alpha=1e-5,
    max_iter=1,
    tol=None,
    random_state=SEED,
    n_jobs=1
)

initial_sample_weight = compute_sample_weight(
    class_weight="balanced",
    y=y_initial
)

base_model.partial_fit(
    X_initial,
    y_initial,
    classes=all_class_ids,
    sample_weight=initial_sample_weight
)

print("\nInitial base model trained.")
print("Warm-up ratio:", WARMUP_RATIO)


# ============================================================
# 10. Train Transformer Specialist
# ============================================================

phishing_transformer_model = None
char_vocab = None

if USE_PHISHING_TRANSFORMER:
    phishing_transformer_model, char_vocab = train_phishing_transformer(initial_train_df)
else:
    print("\nPhishing Transformer specialist disabled.")


# ============================================================
# 11. Stream Utility Functions
# ============================================================

def make_batches(df, batch_size):
    batches = []

    for start in range(0, len(df), batch_size):
        end = min(start + batch_size, len(df))
        batches.append(df.iloc[start:end].copy())

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
        "sample_removed": list(old_common - new_common)[:10]
    }

    for c in malicious_classes:
        old_tokens = set(old_dict["class_specific"].get(c, {}).keys())
        new_tokens = set(new_dict["class_specific"].get(c, {}).keys())

        summary[c] = {
            "added": len(new_tokens - old_tokens),
            "removed": len(old_tokens - new_tokens),
            "kept": len(old_tokens & new_tokens),
            "sample_added": list(new_tokens - old_tokens)[:10],
            "sample_removed": list(old_tokens - new_tokens)[:10]
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
print("Device:", DEVICE)

current_model = base_model
current_risk_dict = risk_dict
current_vectorizer = vectorizer
current_scaler = scaler

recent_stream_buffer = deque(maxlen=SLIDING_WINDOW_BATCHES)

stream_results = []
version = 0

river_acc = metrics.Accuracy()
river_macro_f1 = metrics.MacroF1()
river_weighted_f1 = metrics.WeightedF1()

stream_y_true_all = []
stream_y_pred_all = []

total_transformer_used = 0
total_transformer_promote = 0
total_transformer_demote = 0

for batch_idx, batch_df in enumerate(stream_batches, start=1):
    print(f"\n\n========== Progressive Stream Batch {batch_idx}/{len(stream_batches)} ==========")

    batch_urls = batch_df[URL_COL].tolist()
    batch_y = label_encoder.transform(batch_df[LABEL_COL])

    X_batch_eval = build_eval_features(
        urls=batch_urls,
        risk_dict=current_risk_dict,
        malicious_classes=malicious_classes,
        vectorizer=current_vectorizer,
        scaler=current_scaler
    )

    # --------------------------------------------------------
    # 1. Predict before update
    # --------------------------------------------------------
    batch_y_pred, fusion_stats = hybrid_predict(
        base_model=current_model,
        X=X_batch_eval,
        urls=batch_urls,
        benign_id=benign_id,
        phishing_id=phishing_id,
        transformer_model=phishing_transformer_model,
        char_vocab=char_vocab
    )

    total_transformer_used += fusion_stats["transformer_used_count"]
    total_transformer_promote += fusion_stats["transformer_promote_count"]
    total_transformer_demote += fusion_stats["transformer_demote_count"]

    # Accumulate predictions for final class-specific metrics
    stream_y_true_all.extend(batch_y.tolist())
    stream_y_pred_all.extend(batch_y_pred.tolist())

    # --------------------------------------------------------
    # 2. Metric update before training
    # --------------------------------------------------------
    batch_acc = accuracy_score(batch_y, batch_y_pred)
    batch_macro_f1 = f1_score(batch_y, batch_y_pred, average="macro", zero_division=0)
    batch_weighted_f1 = f1_score(batch_y, batch_y_pred, average="weighted", zero_division=0)

    if phishing_id is not None:
        batch_phishing_precision = precision_score(
            batch_y,
            batch_y_pred,
            labels=[phishing_id],
            average="macro",
            zero_division=0
        )

        batch_phishing_recall = recall_score(
            batch_y,
            batch_y_pred,
            labels=[phishing_id],
            average="macro",
            zero_division=0
        )

        batch_phishing_f1 = f1_score(
            batch_y,
            batch_y_pred,
            labels=[phishing_id],
            average="macro",
            zero_division=0
        )
    else:
        batch_phishing_precision = 0.0
        batch_phishing_recall = 0.0
        batch_phishing_f1 = 0.0

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
        f"River Cumulative Weighted-F1={river_weighted_f1.get():.4f}, "
        f"Transformer Used={fusion_stats['transformer_used_count']}, "
        f"Promote={fusion_stats['transformer_promote_count']}, "
        f"Demote={fusion_stats['transformer_demote_count']}"
    )

    stream_results.append({
        "title": f"Before Update - Progressive Stream Batch {batch_idx}",
        "batch_idx": batch_idx,
        "dict_version": version,
        "batch_accuracy": batch_acc,
        "batch_macro_f1": batch_macro_f1,
        "batch_weighted_f1": batch_weighted_f1,
        "batch_phishing_precision": batch_phishing_precision,
        "batch_phishing_recall": batch_phishing_recall,
        "batch_phishing_f1": batch_phishing_f1,
        "river_cumulative_accuracy": river_acc.get(),
        "river_cumulative_macro_f1": river_macro_f1.get(),
        "river_cumulative_weighted_f1": river_weighted_f1.get(),
        "transformer_used_count": fusion_stats["transformer_used_count"],
        "transformer_promote_count": fusion_stats["transformer_promote_count"],
        "transformer_demote_count": fusion_stats["transformer_demote_count"],
        "mean_transformer_phish_prob": fusion_stats["mean_transformer_phish_prob"],
        "prediction_mode": "hybrid_base_plus_transformer_specialist"
    })

    # --------------------------------------------------------
    # 3. Train/update after metric update
    # --------------------------------------------------------
    batch_sample_weight = compute_sample_weight(
        class_weight="balanced",
        y=batch_y
    )

    current_model.partial_fit(
        X_batch_eval,
        batch_y,
        classes=all_class_ids,
        sample_weight=batch_sample_weight
    )

    recent_stream_buffer.append(batch_df)

    # --------------------------------------------------------
    # 4. Risk dictionary update using observed stream only
    # --------------------------------------------------------
    if batch_idx % UPDATE_INTERVAL == 0:
        print(f"\n----- Risk Dictionary Update at Batch {batch_idx} -----")

        version += 1

        recent_df = pd.concat(list(recent_stream_buffer), axis=0)

        dict_update_df = pd.concat([initial_train_df, recent_df], axis=0)

        new_risk_dict = build_adaptive_risk_dictionary(
            urls=dict_update_df[URL_COL].tolist(),
            labels=dict_update_df[LABEL_COL].tolist(),
            tokenizer=safe_tokenize,
            class_names=class_names,
            benign_label=BENIGN_LABEL,
            top_k_common=TOP_K_COMMON_MALICIOUS,
            top_k_per_class=TOP_K_PER_MAL_CLASS,
            min_df=MIN_TOKEN_DF,
            min_mal_classes_for_common=MIN_MAL_CLASSES_FOR_COMMON,
            alpha=ALPHA
        )

        change_summary = summarize_risk_dict_change(
            old_dict=current_risk_dict,
            new_dict=new_risk_dict,
            malicious_classes=malicious_classes
        )

        print_change_summary(change_summary)
        save_risk_dict(new_risk_dict, version=version)

        current_risk_dict = new_risk_dict

        # Re-train lightly on recent observed window with updated risk dictionary
        X_recent = build_eval_features(
            urls=recent_df[URL_COL].tolist(),
            risk_dict=current_risk_dict,
            malicious_classes=malicious_classes,
            vectorizer=current_vectorizer,
            scaler=current_scaler
        )

        y_recent = label_encoder.transform(recent_df[LABEL_COL])

        recent_sample_weight = compute_sample_weight(
            class_weight="balanced",
            y=y_recent
        )

        current_model.partial_fit(
            X_recent,
            y_recent,
            classes=all_class_ids,
            sample_weight=recent_sample_weight
        )

        print(f"Dictionary version updated to v{version}")


# ============================================================
# 13. Final Cumulative Metrics
# ============================================================

stream_y_true_all = np.array(stream_y_true_all)
stream_y_pred_all = np.array(stream_y_pred_all)

final_accuracy = accuracy_score(stream_y_true_all, stream_y_pred_all)
final_macro_f1 = f1_score(
    stream_y_true_all,
    stream_y_pred_all,
    average="macro",
    zero_division=0
)
final_weighted_f1 = f1_score(
    stream_y_true_all,
    stream_y_pred_all,
    average="weighted",
    zero_division=0
)

if phishing_id is not None:
    final_phishing_precision = precision_score(
        stream_y_true_all,
        stream_y_pred_all,
        labels=[phishing_id],
        average="macro",
        zero_division=0
    )

    final_phishing_recall = recall_score(
        stream_y_true_all,
        stream_y_pred_all,
        labels=[phishing_id],
        average="macro",
        zero_division=0
    )

    final_phishing_f1 = f1_score(
        stream_y_true_all,
        stream_y_pred_all,
        labels=[phishing_id],
        average="macro",
        zero_division=0
    )
else:
    final_phishing_precision = 0.0
    final_phishing_recall = 0.0
    final_phishing_f1 = 0.0

cm = confusion_matrix(
    stream_y_true_all,
    stream_y_pred_all,
    labels=np.arange(len(class_names))
)

if benign_id is not None and phishing_id is not None:
    benign_to_phishing = int(cm[benign_id][phishing_id])
    phishing_to_benign = int(cm[phishing_id][benign_id])
else:
    benign_to_phishing = 0
    phishing_to_benign = 0


# ============================================================
# 14. Final Summary
# ============================================================

print("\n\n================================================")
print("Final River Progressive Stream Performance")
print("================================================")
print("Protocol: River-style warm-start progressive validation")
print("Model: Base 4-class streaming detector + Char-level Transformer phishing specialist")
print("Warm-up ratio:", WARMUP_RATIO)
print("Warm-up size:", len(initial_train_df))
print("Progressive stream size:", len(stream_update_df))
print("Batch size:", BATCH_SIZE)

print("\n[Overall]")
print("Cumulative Accuracy:", round(final_accuracy, 4))
print("Cumulative Macro-F1:", round(final_macro_f1, 4))
print("Cumulative Weighted-F1:", round(final_weighted_f1, 4))

print("\n[Phishing]")
print("Cumulative Phishing Precision:", round(final_phishing_precision, 4))
print("Cumulative Phishing Recall:", round(final_phishing_recall, 4))
print("Cumulative Phishing-F1:", round(final_phishing_f1, 4))
print("Benign -> Phishing:", benign_to_phishing)
print("Phishing -> Benign:", phishing_to_benign)

print("\n[Transformer Specialist]")
print("Total Transformer Used:", total_transformer_used)
print("Total Transformer Promote to Phishing:", total_transformer_promote)
print("Total Transformer Demote to Benign:", total_transformer_demote)

print("\nClassification Report:")
print(
    classification_report(
        stream_y_true_all,
        stream_y_pred_all,
        target_names=class_names,
        zero_division=0
    )
)

print("\nConfusion Matrix:")
print(cm)

final_stream_summary = {
    "protocol": "River-style warm-start progressive validation",
    "model": "base_4class_streaming_detector_plus_char_transformer_phishing_specialist",
    "warmup_ratio": WARMUP_RATIO,
    "warmup_size": len(initial_train_df),
    "progressive_stream_size": len(stream_update_df),
    "batch_size": BATCH_SIZE,
    "update_interval": UPDATE_INTERVAL,
    "sliding_window_batches": SLIDING_WINDOW_BATCHES,

    "river_cumulative_accuracy": final_accuracy,
    "river_cumulative_macro_f1": final_macro_f1,
    "river_cumulative_weighted_f1": final_weighted_f1,

    "river_cumulative_phishing_precision": final_phishing_precision,
    "river_cumulative_phishing_recall": final_phishing_recall,
    "river_cumulative_phishing_f1": final_phishing_f1,

    "benign_to_phishing": benign_to_phishing,
    "phishing_to_benign": phishing_to_benign,

    "total_transformer_used": total_transformer_used,
    "total_transformer_promote_to_phishing": total_transformer_promote,
    "total_transformer_demote_to_benign": total_transformer_demote,

    "transformer_config": {
        "max_char_len": MAX_CHAR_LEN,
        "max_train_samples": TRANSFORMER_MAX_TRAIN_SAMPLES,
        "epochs": TRANSFORMER_EPOCHS,
        "batch_size": TRANSFORMER_BATCH_SIZE,
        "embed_dim": CHAR_EMBED_DIM,
        "nhead": TRANSFORMER_NHEAD,
        "num_layers": TRANSFORMER_NUM_LAYERS,
        "ff_dim": TRANSFORMER_FF_DIM,
        "gray_zone_margin": GRAY_ZONE_MARGIN,
        "min_base_phishing_prob_for_specialist": MIN_BASE_PHISHING_PROB_FOR_SPECIALIST,
        "phishing_threshold": TRANSFORMER_PHISHING_THRESHOLD,
        "benign_threshold": TRANSFORMER_BENIGN_THRESHOLD,
        "device": str(DEVICE)
    },

    "stream_construction_note": (
        "The Kaggle malicious URL dataset has no real timestamps. "
        "We do not claim a real chronological stream. "
        "We define one reproducible pseudo-stream order using a fixed seed. "
        "The prefix 20% of the pseudo-stream is used as warm-up/pretrain data. "
        "The suffix 80% is evaluated with River-style test-before-train progressive validation. "
        "Every batch is evaluated before being used for model/risk-dictionary updates."
    ),

    "hybrid_detection_note": (
        "The base detector performs 4-class URL classification. "
        "The character-level Transformer specialist is trained only on benign/phishing warm-up samples "
        "and is applied only to benign-phishing boundary or phishing-suspicious URLs. "
        "The specialist can adjust only benign and phishing predictions; malware and defacement predictions "
        "are preserved from the base model."
    )
}


# ============================================================
# 15. Save Results
# ============================================================

stream_results_df = pd.DataFrame(stream_results)
stream_result_path = os.path.join(RESULT_DIR, "river_progressive_stream_results.csv")
stream_results_df.to_csv(stream_result_path, index=False)

final_stream_summary_path = os.path.join(
    RESULT_DIR,
    "river_progressive_stream_summary.json"
)

with open(final_stream_summary_path, "w", encoding="utf-8") as f:
    json.dump(final_stream_summary, f, ensure_ascii=False, indent=2)

print("\nSaved River progressive stream results:", stream_result_path)
print("Saved River progressive stream summary:", final_stream_summary_path)


# ============================================================
# 16. Save Flask API Artifacts
# ============================================================

api_artifact_config = {
    "model_family": "base_4class_streaming_detector_plus_char_transformer_phishing_specialist",
    "url_col": URL_COL,
    "label_col": LABEL_COL,
    "class_names": class_names,
    "malicious_classes": malicious_classes,
    "benign_label": BENIGN_LABEL,
    "phishing_label": PHISHING_LABEL,
    "benign_id": int(benign_id) if benign_id is not None else None,
    "phishing_id": int(phishing_id) if phishing_id is not None else None,
    "risk_feature_order": {
        "common": ["common_score", "common_count"],
        "per_malicious_class": malicious_classes,
        "per_class_features": ["class_score", "class_count"]
    },
    "tfidf_config": {
        "max_features": MAX_TFIDF_FEATURES,
        "min_df": TFIDF_MIN_DF,
        "max_df": TFIDF_MAX_DF,
        "lowercase": False,
        "token_pattern": None
    },
    "fixed_phishing_gate": {
        "demote_prob": FIXED_PHISHING_DEMOTE_PROB,
        "demote_margin": FIXED_PHISHING_DEMOTE_MARGIN
    },
    "transformer_config": {
        "use_phishing_transformer": USE_PHISHING_TRANSFORMER,
        "max_char_len": MAX_CHAR_LEN,
        "max_train_samples": TRANSFORMER_MAX_TRAIN_SAMPLES,
        "epochs": TRANSFORMER_EPOCHS,
        "batch_size": TRANSFORMER_BATCH_SIZE,
        "embed_dim": CHAR_EMBED_DIM,
        "nhead": TRANSFORMER_NHEAD,
        "num_layers": TRANSFORMER_NUM_LAYERS,
        "ff_dim": TRANSFORMER_FF_DIM,
        "dropout": TRANSFORMER_DROPOUT,
        "gray_zone_margin": GRAY_ZONE_MARGIN,
        "min_base_phishing_prob_for_specialist": MIN_BASE_PHISHING_PROB_FOR_SPECIALIST,
        "phishing_threshold": TRANSFORMER_PHISHING_THRESHOLD,
        "benign_threshold": TRANSFORMER_BENIGN_THRESHOLD
    },
    "artifact_files": {
        "base_model": "base_model.joblib",
        "vectorizer": "vectorizer.joblib",
        "scaler": "scaler.joblib",
        "label_encoder": "label_encoder.joblib",
        "risk_dict": "risk_dict.json",
        "char_vocab": "char_vocab.json",
        "transformer_state": "transformer_state.pt",
        "config": "config.json"
    },
    "note": (
        "These artifacts are intended for Flask inference. The API code must reuse "
        "the same tokenizer, lexical feature, risk feature, character encoder, and "
        "CharTransformerPhishingModel definitions as transformer_final.py."
    )
}

base_model_path = os.path.join(ARTIFACT_DIR, "base_model.joblib")
vectorizer_path = os.path.join(ARTIFACT_DIR, "vectorizer.joblib")
scaler_path = os.path.join(ARTIFACT_DIR, "scaler.joblib")
label_encoder_path = os.path.join(ARTIFACT_DIR, "label_encoder.joblib")
risk_dict_path = os.path.join(ARTIFACT_DIR, "risk_dict.json")
char_vocab_path = os.path.join(ARTIFACT_DIR, "char_vocab.json")
transformer_state_path = os.path.join(ARTIFACT_DIR, "transformer_state.pt")
config_path = os.path.join(ARTIFACT_DIR, "config.json")

joblib.dump(current_model, base_model_path)
joblib.dump(current_vectorizer, vectorizer_path)
joblib.dump(current_scaler, scaler_path)
joblib.dump(label_encoder, label_encoder_path)

with open(risk_dict_path, "w", encoding="utf-8") as f:
    json.dump(current_risk_dict, f, ensure_ascii=False, indent=2)

with open(char_vocab_path, "w", encoding="utf-8") as f:
    json.dump(char_vocab if char_vocab is not None else {}, f, ensure_ascii=False, indent=2)

if phishing_transformer_model is not None:
    torch.save(phishing_transformer_model.state_dict(), transformer_state_path)
else:
    print("\nWarning: phishing_transformer_model is None, transformer_state.pt was not saved.")

with open(config_path, "w", encoding="utf-8") as f:
    json.dump(api_artifact_config, f, ensure_ascii=False, indent=2)

print("\nSaved Flask API artifacts:", ARTIFACT_DIR)
print(" -", base_model_path)
print(" -", vectorizer_path)
print(" -", scaler_path)
print(" -", label_encoder_path)
print(" -", risk_dict_path)
print(" -", char_vocab_path)
if phishing_transformer_model is not None:
    print(" -", transformer_state_path)
print(" -", config_path)

print("\nDone.")
