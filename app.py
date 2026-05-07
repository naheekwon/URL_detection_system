import json
import math
import os
import re
import sys
import urllib.parse
from collections import Counter

import joblib
import numpy as np
import torch
import torch.nn as nn
from flask import Flask, jsonify, request, send_from_directory
from scipy.sparse import csr_matrix, hstack


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_DIR = os.path.join(PROJECT_DIR, "artifacts_transformer")
FRONTEND_DIR = os.path.join(PROJECT_DIR, "frontend")

PAD_ID = 0
UNK_ID = 1
CLS_ID = 2

KNOWN_SAFE_DOMAINS = {
    "google.com",
    "naver.com",
    "11st.co.kr",
    "safebrowsing.google.com",
    "youtube.com",
    "gmail.com",
    "microsoft.com",
    "office.com",
    "apple.com",
    "icloud.com",
    "kakao.com",
    "daum.net",
    "github.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "wikipedia.org",
}

KNOWN_SAFE_STRONG_RISK_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "passwd",
    "credential",
    "wallet",
    "billing",
    "payment",
    "secure",
    "security",
    "update",
    "confirm",
    "unlock",
    "suspended",
}

KNOWN_SAFE_RISK_EXTENSIONS = {
    "exe",
    "scr",
    "bat",
    "cmd",
    "msi",
    "apk",
    "jar",
    "vbs",
    "ps1",
}


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


def get_normalized_host(url):
    parsed = safe_parse_url(url)

    if parsed is None:
        return ""

    host = parsed.netloc.lower() if parsed.netloc else ""

    if "@" in host:
        host = host.split("@")[-1]

    if ":" in host:
        host = host.split(":")[0]

    if host.startswith("www."):
        host = host[4:]

    return host.strip(".")


def is_same_or_subdomain(host, domain):
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")

    return host == domain or host.endswith("." + domain)


def matched_known_safe_domain(host):
    if not host:
        return None

    matches = [
        domain for domain in KNOWN_SAFE_DOMAINS
        if is_same_or_subdomain(host, domain)
    ]

    if not matches:
        return None

    return max(matches, key=len)


def has_strong_known_safe_risk_signal(url):
    cleaned = clean_url_text(url)
    parsed = safe_parse_url(cleaned)

    path = parsed.path.lower() if parsed is not None and parsed.path else ""
    query = parsed.query.lower() if parsed is not None and parsed.query else ""
    path_query = path + " " + query

    parts = split_by_separators(path_query)
    token_set = set(parts)

    if token_set & KNOWN_SAFE_STRONG_RISK_WORDS:
        return True

    if "@" in cleaned or "%" in cleaned:
        return True

    if cleaned.count("//") >= 2:
        return True

    path_segments = [seg for seg in path.split("/") if seg]
    if path_segments:
        last = path_segments[-1]
        if "." in last:
            ext = last.rsplit(".", 1)[-1]
            if ext in KNOWN_SAFE_RISK_EXTENSIONS:
                return True

    return False


def apply_known_safe_domain_guard(result):
    host = get_normalized_host(result["url"])
    safe_domain = matched_known_safe_domain(host)

    result["known_safe_domain"] = safe_domain
    result["known_safe_guard_applied"] = False

    if safe_domain is None:
        return result

    if has_strong_known_safe_risk_signal(result["url"]):
        result["known_safe_guard_reason"] = "known_safe_domain_but_risky_path_or_query"
        return result

    if result["prediction"] != config["benign_label"]:
        result["prediction_before_known_safe_guard"] = result["prediction"]
        result["prediction"] = config["benign_label"]
        result["is_malicious"] = False
        result["known_safe_guard_applied"] = True
        result["known_safe_guard_reason"] = "trusted_domain_without_strong_risk_signal"
    else:
        result["known_safe_guard_reason"] = "already_benign"

    return result


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


# The vectorizer was saved from a training script. Register the tokenizer on
# __main__ too, so joblib can reload it both via `python app.py` and imports.
setattr(sys.modules["__main__"], "safe_tokenize", safe_tokenize)


def risk_score_features(urls, risk_dict, malicious_classes):
    rows = []
    common_dict = risk_dict["common_malicious"]
    class_dict = risk_dict["class_specific"]

    for url in urls:
        try:
            tokens = set(safe_tokenize(url))
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

        rows.append([
            length,
            digit_count,
            alpha_count,
            special_count,
            u.count("."),
            u.count("/"),
            u.count("-"),
            u.count("_"),
            u.count("?"),
            u.count("="),
            u.count("&"),
            u.count("%"),
            u.count("@"),
            digit_count / max(length, 1),
            alpha_count / max(length, 1),
            special_count / max(length, 1),
            1 if re.search(r"\d{1,3}(\.\d{1,3}){3}", u) else 0,
            1 if u.startswith("https://") else 0,
            1 if u.startswith("http://") else 0,
        ])

    return np.array(rows, dtype=np.float32)


def build_features(urls):
    x_tfidf = vectorizer.transform(urls)
    x_risk = risk_score_features(urls, risk_dict, malicious_classes)
    x_lex = lexical_features(urls)
    x_extra = np.hstack([x_risk, x_lex])
    x_extra_scaled = scaler.transform(x_extra)

    return hstack([x_tfidf, csr_matrix(x_extra_scaled)])


def encode_url_chars(url, char_vocab, max_len):
    u = clean_url_text(url)
    ids = [CLS_ID]

    for ch in u:
        ids.append(char_vocab.get(ch, UNK_ID))

    ids = ids[:max_len]

    if len(ids) < max_len:
        ids = ids + [PAD_ID] * (max_len - len(ids))

    return ids


class CharTransformerPhishingModel(nn.Module):
    def __init__(
        self,
        vocab_size,
        max_len=256,
        embed_dim=64,
        nhead=4,
        num_layers=2,
        ff_dim=128,
        dropout=0.1,
    ):
        super().__init__()

        self.token_embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embed_dim,
            padding_idx=PAD_ID,
        )
        self.position_embedding = nn.Embedding(
            num_embeddings=max_len,
            embedding_dim=embed_dim,
        )

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=nhead,
            dim_feedforward=ff_dim,
            dropout=dropout,
            batch_first=True,
            activation="gelu",
        )
        self.encoder = nn.TransformerEncoder(
            encoder_layer=encoder_layer,
            num_layers=num_layers,
        )
        self.classifier = nn.Sequential(
            nn.LayerNorm(embed_dim),
            nn.Linear(embed_dim, 2),
        )

    def forward(self, input_ids):
        batch_size, seq_len = input_ids.shape
        positions = torch.arange(seq_len, device=input_ids.device).unsqueeze(0)
        positions = positions.expand(batch_size, seq_len)

        x = self.token_embedding(input_ids) + self.position_embedding(positions)
        padding_mask = input_ids.eq(PAD_ID)
        encoded = self.encoder(x, src_key_padding_mask=padding_mask)

        return self.classifier(encoded[:, 0, :])


def load_json(filename):
    with open(os.path.join(ARTIFACT_DIR, filename), "r", encoding="utf-8") as f:
        return json.load(f)


def require_artifacts():
    required = [
        "base_model.joblib",
        "vectorizer.joblib",
        "scaler.joblib",
        "label_encoder.joblib",
        "risk_dict.json",
        "char_vocab.json",
        "transformer_state.pt",
        "config.json",
    ]
    missing = [
        name for name in required
        if not os.path.exists(os.path.join(ARTIFACT_DIR, name))
    ]

    if missing:
        raise FileNotFoundError(
            "Missing required model artifacts: " + ", ".join(missing)
        )


def load_artifacts():
    require_artifacts()

    cfg = load_json("config.json")
    t_cfg = cfg["transformer_config"]

    loaded = {
        "config": cfg,
        "base_model": joblib.load(os.path.join(ARTIFACT_DIR, "base_model.joblib")),
        "vectorizer": joblib.load(os.path.join(ARTIFACT_DIR, "vectorizer.joblib")),
        "scaler": joblib.load(os.path.join(ARTIFACT_DIR, "scaler.joblib")),
        "label_encoder": joblib.load(os.path.join(ARTIFACT_DIR, "label_encoder.joblib")),
        "risk_dict": load_json("risk_dict.json"),
        "char_vocab": load_json("char_vocab.json"),
    }

    model = CharTransformerPhishingModel(
        vocab_size=len(loaded["char_vocab"]),
        max_len=t_cfg["max_char_len"],
        embed_dim=t_cfg["embed_dim"],
        nhead=t_cfg["nhead"],
        num_layers=t_cfg["num_layers"],
        ff_dim=t_cfg["ff_dim"],
        dropout=t_cfg["dropout"],
    )
    state = torch.load(
        os.path.join(ARTIFACT_DIR, "transformer_state.pt"),
        map_location=torch.device("cpu"),
    )
    model.load_state_dict(state)
    model.eval()
    loaded["transformer_model"] = model

    return loaded


ARTIFACTS = load_artifacts()
config = ARTIFACTS["config"]
base_model = ARTIFACTS["base_model"]
vectorizer = ARTIFACTS["vectorizer"]
scaler = ARTIFACTS["scaler"]
label_encoder = ARTIFACTS["label_encoder"]
risk_dict = ARTIFACTS["risk_dict"]
char_vocab = ARTIFACTS["char_vocab"]
transformer_model = ARTIFACTS["transformer_model"]

class_names = config["class_names"]
malicious_classes = config["malicious_classes"]
benign_id = config["benign_id"]
phishing_id = config["phishing_id"]
transformer_config = config["transformer_config"]
fixed_gate_config = config["fixed_phishing_gate"]

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


def apply_fixed_phishing_gate(proba):
    pred = np.argmax(proba, axis=1)

    for i in range(len(pred)):
        if pred[i] != phishing_id:
            continue

        sorted_ids = np.argsort(proba[i])[::-1]
        top1 = sorted_ids[0]
        top2 = sorted_ids[1]

        phish_prob = proba[i][phishing_id]
        margin = proba[i][top1] - proba[i][top2]

        if (
            phish_prob < fixed_gate_config["demote_prob"]
            or margin < fixed_gate_config["demote_margin"]
        ):
            pred[i] = top2

    return pred


@torch.no_grad()
def predict_transformer_phishing_probs(urls):
    if not urls:
        return np.array([], dtype=np.float32)

    max_len = transformer_config["max_char_len"]
    encoded = [
        encode_url_chars(url, char_vocab, max_len)
        for url in urls
    ]
    input_ids = torch.tensor(encoded, dtype=torch.long)
    logits = transformer_model(input_ids)
    probs = torch.softmax(logits, dim=1)[:, 1]

    return probs.detach().cpu().numpy().astype(np.float32)


def hybrid_predict(urls):
    x = build_features(urls)
    base_proba = base_model.predict_proba(x)
    base_pred = apply_fixed_phishing_gate(base_proba)
    final_pred = np.array(base_pred, copy=True)

    benign_prob = base_proba[:, benign_id]
    phishing_prob = base_proba[:, phishing_id]
    boundary_margin = np.abs(benign_prob - phishing_prob)

    candidate_mask = (
        ((base_pred == benign_id) | (base_pred == phishing_id))
        & (
            (boundary_margin <= transformer_config["gray_zone_margin"])
            | (
                phishing_prob
                >= transformer_config["min_base_phishing_prob_for_specialist"]
            )
            | (base_pred == phishing_id)
        )
    )
    candidate_indices = np.where(candidate_mask)[0]
    transformer_probs_by_index = {}
    promote_count = 0
    demote_count = 0

    if len(candidate_indices) > 0:
        candidate_urls = [urls[i] for i in candidate_indices]
        transformer_probs = predict_transformer_phishing_probs(candidate_urls)

        for local_idx, global_idx in enumerate(candidate_indices):
            t_prob = float(transformer_probs[local_idx])
            transformer_probs_by_index[int(global_idx)] = t_prob

            if t_prob >= transformer_config["phishing_threshold"]:
                if final_pred[global_idx] != phishing_id:
                    promote_count += 1
                final_pred[global_idx] = phishing_id
            elif t_prob <= transformer_config["benign_threshold"]:
                if final_pred[global_idx] == phishing_id:
                    demote_count += 1
                final_pred[global_idx] = benign_id

    results = []

    for idx, url in enumerate(urls):
        base_label = class_names[int(base_pred[idx])]
        final_label = class_names[int(final_pred[idx])]
        class_probabilities = {
            class_names[class_idx]: float(base_proba[idx][class_idx])
            for class_idx in range(len(class_names))
        }
        confidence = float(max(class_probabilities.values()))
        transformer_phishing_probability = transformer_probs_by_index.get(idx)

        result = {
            "url": url,
            "prediction": final_label,
            "is_malicious": final_label != config["benign_label"],
            "confidence": confidence,
            "base_prediction": base_label,
            "class_probabilities": class_probabilities,
            "transformer_used": transformer_phishing_probability is not None,
            "transformer_phishing_probability": transformer_phishing_probability,
        }

        results.append(apply_known_safe_domain_guard(result))

    stats = {
        "transformer_used_count": int(len(candidate_indices)),
        "transformer_promote_count": int(promote_count),
        "transformer_demote_count": int(demote_count),
    }

    return results, stats


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "model_family": config["model_family"],
        "classes": class_names,
        "artifact_dir": ARTIFACT_DIR,
    })


@app.route("/api/predict", methods=["POST", "OPTIONS"])
def predict():
    if request.method == "OPTIONS":
        return ("", 204)

    payload = request.get_json(silent=True) or {}
    urls = payload.get("urls")

    if urls is None:
        url = payload.get("url")
        urls = [url] if url is not None else []

    if isinstance(urls, str):
        urls = [urls]

    urls = [str(url).strip() for url in urls if str(url).strip()]

    if not urls:
        return jsonify({
            "error": "url or urls field is required",
        }), 400

    try:
        results, stats = hybrid_predict(urls)
    except Exception as exc:
        return jsonify({
            "error": "prediction_failed",
            "detail": str(exc),
        }), 500

    response = {
        "results": results,
        "stats": stats,
    }

    if len(results) == 1:
        response.update(results[0])

    return jsonify(response)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
