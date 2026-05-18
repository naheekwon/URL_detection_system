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

from evidence_detector import classify_with_evidence
from page_evidence import inspect_url_page
from xai import (
    build_xai_explanation,
    compute_transformer_lexicon_alignment,
    load_case_index,
)


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_DIR = os.path.join(PROJECT_DIR, "artifacts_transformer")
META_GATE_ARTIFACT_DIR = os.path.join(PROJECT_DIR, "artifacts_phiusiil_meta_gate")
FRONTEND_DIR = os.path.join(PROJECT_DIR, "frontend")
DATASET_PATH = os.path.join(os.path.dirname(PROJECT_DIR), "PhiUSIIL_Phishing_URL_Dataset.csv")

PAD_ID = 0
UNK_ID = 1
CLS_ID = 2

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


def load_json_from_dir(directory, filename):
    with open(os.path.join(directory, filename), "r", encoding="utf-8") as f:
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


def load_meta_gate_artifacts():
    required = [
        "meta_gate.joblib",
        "meta_gate_scaler.joblib",
        "config.json",
    ]

    if not os.path.isdir(META_GATE_ARTIFACT_DIR):
        return {
            "enabled": False,
            "reason": "meta_gate_artifact_dir_not_found",
        }

    missing = [
        name for name in required
        if not os.path.exists(os.path.join(META_GATE_ARTIFACT_DIR, name))
    ]

    if missing:
        return {
            "enabled": False,
            "reason": "missing_meta_gate_artifacts",
            "missing": missing,
        }

    cfg = load_json_from_dir(META_GATE_ARTIFACT_DIR, "config.json")

    return {
        "enabled": True,
        "config": cfg,
        "meta_gate": joblib.load(os.path.join(META_GATE_ARTIFACT_DIR, "meta_gate.joblib")),
        "meta_gate_scaler": joblib.load(os.path.join(META_GATE_ARTIFACT_DIR, "meta_gate_scaler.joblib")),
        "threshold": float(cfg["threshold"]),
    }


ARTIFACTS = load_artifacts()
META_GATE_ARTIFACTS = load_meta_gate_artifacts()
XAI_CASE_INDEX = load_case_index(DATASET_PATH, safe_tokenize)
config = ARTIFACTS["config"]
base_model = ARTIFACTS["base_model"]
vectorizer = ARTIFACTS["vectorizer"]
scaler = ARTIFACTS["scaler"]
label_encoder = ARTIFACTS["label_encoder"]
risk_dict = ARTIFACTS["risk_dict"]
char_vocab = ARTIFACTS["char_vocab"]
transformer_model = ARTIFACTS["transformer_model"]
meta_gate_enabled = bool(META_GATE_ARTIFACTS.get("enabled"))
meta_gate = META_GATE_ARTIFACTS.get("meta_gate")
meta_gate_scaler = META_GATE_ARTIFACTS.get("meta_gate_scaler")
meta_gate_config = META_GATE_ARTIFACTS.get("config", {})
meta_gate_threshold = META_GATE_ARTIFACTS.get("threshold")

class_names = config["class_names"]
malicious_classes = config["malicious_classes"]
benign_id = config["benign_id"]
phishing_id = config["phishing_id"]
transformer_config = config["transformer_config"]
fixed_gate_config = config["fixed_phishing_gate"]

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.cache_control.no_store = True
    response.cache_control.no_cache = True
    response.cache_control.must_revalidate = True
    response.cache_control.max_age = 0
    response.headers["Pragma"] = "no-cache"
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


def url_policy_features(urls):
    rows = []

    for url in urls:
        u = clean_url_text(url)
        parsed = safe_parse_url(u)
        host = get_normalized_host(u)
        path = parsed.path or "" if parsed is not None else ""
        query = parsed.query or "" if parsed is not None else ""
        domain_parts = [p for p in host.split(".") if p]

        rows.append([
            float(len(u)),
            float(len(host)),
            float(len(path)),
            float(len(query)),
            float(u.count(".")),
            float(u.count("-")),
            float(u.count("_")),
            float(u.count("@")),
            float(u.count("%")),
            float(u.count("=")),
            float(u.count("&")),
            float(len(domain_parts)),
            1.0 if query else 0.0,
            1.0 if path and path != "/" else 0.0,
            1.0 if (not path or path == "/") and not query else 0.0,
            1.0 if len(u) <= 35 else 0.0,
            1.0 if len(u) <= 50 else 0.0,
            0.0,
            0.0,
            1.0 if host.endswith(".ac.kr") or host.endswith(".edu") else 0.0,
            1.0 if host.endswith(".go.kr") or host.endswith(".gov") else 0.0,
            1.0 if host.endswith(".co.kr") else 0.0,
        ])

    return np.array(rows, dtype=np.float32)


def build_meta_gate_features(urls, base_proba, raw_base_pred, transformer_probs):
    sorted_probs = np.sort(base_proba, axis=1)
    top_margin = sorted_probs[:, -1] - sorted_probs[:, -2]
    policy = url_policy_features(urls)

    rows = []

    for i in range(len(urls)):
        base_benign = float(base_proba[i][benign_id])
        base_phishing = float(base_proba[i][phishing_id])
        transformer_phishing = float(transformer_probs[i])

        row = [
            base_benign,
            base_phishing,
            base_phishing - base_benign,
            abs(base_phishing - base_benign),
            float(np.max(base_proba[i])),
            float(top_margin[i]),
            1.0 if raw_base_pred[i] == benign_id else 0.0,
            1.0 if raw_base_pred[i] == phishing_id else 0.0,
            transformer_phishing,
            transformer_phishing - base_phishing,
            abs(transformer_phishing - base_phishing),
        ]
        row.extend(policy[i].tolist())
        rows.append(row)

    x_meta = np.array(rows, dtype=np.float32)

    expected_count = meta_gate_config.get("feature_count")
    if expected_count is not None and x_meta.shape[1] != int(expected_count):
        raise ValueError(
            f"Meta-gate feature count mismatch: expected {expected_count}, got {x_meta.shape[1]}"
        )

    return x_meta


def hybrid_predict(urls, inspect_pages=False, include_debug=False):
    x = build_features(urls)
    base_proba = base_model.predict_proba(x)
    raw_base_pred = np.argmax(base_proba, axis=1)
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

    meta_scores_by_index = {}
    meta_transformer_probs_by_index = {}
    meta_used_count = 0
    meta_to_phishing_count = 0
    meta_to_benign_count = 0

    if meta_gate_enabled:
        meta_candidate_mask = (
            (raw_base_pred == benign_id)
            | (raw_base_pred == phishing_id)
            | (final_pred == benign_id)
            | (final_pred == phishing_id)
        )
        meta_candidate_indices = np.where(meta_candidate_mask)[0]
        meta_used_count = int(len(meta_candidate_indices))

        if len(meta_candidate_indices) > 0:
            meta_candidate_urls = [urls[i] for i in meta_candidate_indices]
            meta_candidate_base_proba = base_proba[meta_candidate_indices]
            meta_candidate_raw_base_pred = raw_base_pred[meta_candidate_indices]
            meta_transformer_probs = []

            missing_transformer_url_indices = []
            missing_transformer_urls = []

            for global_idx in meta_candidate_indices:
                global_idx_int = int(global_idx)
                if global_idx_int in transformer_probs_by_index:
                    meta_transformer_probs.append(transformer_probs_by_index[global_idx_int])
                else:
                    meta_transformer_probs.append(None)
                    missing_transformer_url_indices.append(len(meta_transformer_probs) - 1)
                    missing_transformer_urls.append(urls[global_idx_int])

            if missing_transformer_urls:
                computed_probs = predict_transformer_phishing_probs(missing_transformer_urls)
                for local_missing_idx, computed_prob in zip(missing_transformer_url_indices, computed_probs):
                    meta_transformer_probs[local_missing_idx] = float(computed_prob)

            meta_transformer_probs = np.array(meta_transformer_probs, dtype=np.float32)

            x_meta = build_meta_gate_features(
                urls=meta_candidate_urls,
                base_proba=meta_candidate_base_proba,
                raw_base_pred=meta_candidate_raw_base_pred,
                transformer_probs=meta_transformer_probs,
            )
            x_meta_scaled = meta_gate_scaler.transform(x_meta)
            meta_scores = meta_gate.predict_proba(x_meta_scaled)[:, 1]

            for local_idx, global_idx in enumerate(meta_candidate_indices):
                global_idx_int = int(global_idx)
                old_pred = final_pred[global_idx_int]
                meta_score = float(meta_scores[local_idx])
                meta_scores_by_index[global_idx_int] = meta_score
                meta_transformer_probs_by_index[global_idx_int] = float(meta_transformer_probs[local_idx])

                # In the web service, the PhiUSIIL meta-gate is used
                # conservatively to reduce benign -> phishing false alarms.
                # It can demote an existing phishing decision to benign, but
                # it does not newly promote benign URLs to phishing.
                if old_pred == phishing_id and meta_score < meta_gate_threshold:
                    final_pred[global_idx_int] = benign_id
                    meta_to_benign_count += 1

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
        meta_transformer_probability = meta_transformer_probs_by_index.get(idx)
        if transformer_phishing_probability is None:
            transformer_phishing_probability = meta_transformer_probability

        integrated_debug = {
            "prediction": final_label,
            "is_malicious": final_label != config["benign_label"],
            "confidence": confidence,
            "transformer_used": transformer_phishing_probability is not None,
            "transformer_phishing_probability": transformer_phishing_probability,
            "meta_gate_used": idx in meta_scores_by_index,
            "meta_gate_phishing_score": meta_scores_by_index.get(idx),
            "meta_gate_threshold": meta_gate_threshold if meta_gate_enabled else None,
            "meta_gate_enabled": meta_gate_enabled,
        }

        result = {
            "url": url,
            "prediction": final_label,
            "is_malicious": final_label != config["benign_label"],
            "confidence": confidence,
        }

        if inspect_pages:
            result["page_evidence"] = inspect_url_page(url)

        transformer_alignment = compute_transformer_lexicon_alignment(
            url=url,
            risk_dict=risk_dict,
            tokenizer=safe_tokenize,
            transformer_model=transformer_model,
            encode_url_chars=encode_url_chars,
            char_vocab=char_vocab,
            max_char_len=transformer_config["max_char_len"],
        )

        evidence_decision = classify_with_evidence(
            url=url,
            page_evidence=result.get("page_evidence"),
            learned_risk_dict=risk_dict,
            transformer_alignment=transformer_alignment,
        )
        result["evidence_decision"] = evidence_decision
        result["prediction"] = evidence_decision["prediction"]
        result["is_malicious"] = evidence_decision["is_malicious"]
        result["confidence"] = evidence_decision["confidence"]
        result["model_method"] = evidence_decision["method"]

        result["xai"] = build_xai_explanation(
            url=url,
            prediction_result=result,
            risk_dict=risk_dict,
            tokenizer=safe_tokenize,
            transformer_model=transformer_model,
            encode_url_chars=encode_url_chars,
            char_vocab=char_vocab,
            max_char_len=transformer_config["max_char_len"],
            case_index=XAI_CASE_INDEX,
        )

        if include_debug:
            result["debug_integrated_pipeline"] = integrated_debug

        results.append(result)

    stats = {
        "transformer_used_count": int(len(candidate_indices)),
        "transformer_promote_count": int(promote_count),
        "transformer_demote_count": int(demote_count),
        "meta_gate_enabled": meta_gate_enabled,
        "meta_gate_used_count": int(meta_used_count),
        "meta_gate_to_phishing_count": int(meta_to_phishing_count),
        "meta_gate_to_benign_count": int(meta_to_benign_count),
    }

    return results, stats


@app.route("/")
def index():
    """Serve the web frontend from the same Flask backend used for inference."""
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "model_family": config["model_family"],
        "classes": class_names,
        "artifact_dir": ARTIFACT_DIR,
        "meta_gate_enabled": meta_gate_enabled,
        "meta_gate_artifact_dir": META_GATE_ARTIFACT_DIR,
        "meta_gate_model_family": meta_gate_config.get("model_family"),
        "meta_gate_threshold": meta_gate_threshold,
    })


@app.route("/api/backend-info")
def backend_info():
    return jsonify({
        "backend_role": "Flask web backend and model inference API",
        "frontend_serving": {
            "route": "GET /",
            "directory": FRONTEND_DIR,
            "entrypoint": "index.html",
        },
        "api_endpoints": {
            "health": "GET /health",
            "predict": "POST /api/predict",
            "backend_info": "GET /api/backend-info",
        },
        "prediction_pipeline": [
            "URL request from frontend",
            "model artifacts loaded in app.py",
            "feature extraction and Transformer alignment",
            "Lexicon-Context evidence decision",
            "XAI JSON response",
            "frontend result card and XAI detail rendering",
        ],
        "classes": class_names,
        "xai_modules": [
            "evidence_detector.py",
            "page_evidence.py",
            "xai.py",
        ],
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
        inspect_pages = bool(payload.get("inspect_page", True))
        include_debug = bool(payload.get("debug", False))
        results, stats = hybrid_predict(
            urls,
            inspect_pages=inspect_pages,
            include_debug=include_debug,
        )
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
