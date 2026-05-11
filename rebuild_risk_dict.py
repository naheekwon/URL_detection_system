import argparse
import json
import math
import os
import re
import urllib.parse
from collections import Counter

import pandas as pd


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATA_PATH = os.path.join(PROJECT_DIR, "malicious_phish.csv")
DEFAULT_OUTPUT_PATH = os.path.join(PROJECT_DIR, "artifacts_transformer", "risk_dict.json")

URL_COL = "url"
LABEL_COL = "type"
BENIGN_LABEL = "benign"

TOP_K_COMMON_MALICIOUS = 1400
TOP_K_PER_MAL_CLASS = 1200
MIN_TOKEN_DF = 3
MIN_MAL_CLASSES_FOR_COMMON = 2
ALPHA = 1.0

DOMAIN_SEED_TERMS = {
    "phishing": {
        "account",
        "auth",
        "check",
        "confirm",
        "credential",
        "login",
        "password",
        "secure",
        "security",
        "signin",
        "unlock",
        "verify",
    },
    "defacement": {
        "deface",
        "defaced",
        "hacked",
        "hacker",
        "index_old",
        "owned",
        "pwned",
        "upload",
        "uploads",
        "wp",
        "wp-content",
    },
    "malware": {
        "crack",
        "download",
        "driver",
        "free",
        "install",
        "keygen",
        "patch",
        "setup",
        "tool",
        "update",
    },
}

DOMAIN_SEED_EXTENSIONS = {
    "malware": {"apk", "bat", "cmd", "exe", "jar", "msi", "ps1", "rar", "scr", "vbs", "zip"},
}


def clean_url_text(url):
    value = str(url or "").strip().lower()
    try:
        value = urllib.parse.unquote(value, errors="ignore")
    except Exception:
        pass
    value = value.replace("[", "").replace("]", "")
    return re.sub(r"[\x00-\x1f\x7f]", "", value)


def split_by_separators(text):
    return [p for p in re.split(r"[^a-zA-Z0-9]+", clean_url_text(text)) if len(p) >= 2]


def char_ngrams(token, n_min=3, n_max=4):
    grams = []
    token = str(token).lower()
    for n in range(n_min, n_max + 1):
        if len(token) >= n:
            for i in range(len(token) - n + 1):
                grams.append(f"char:{token[i:i+n]}")
    return grams


def safe_parse_url(url):
    cleaned = clean_url_text(url)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned):
        cleaned = "http://" + cleaned
    return urllib.parse.urlparse(cleaned)


def tokenize_url(url):
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
            for sub in split_by_separators(part):
                tokens.append(f"dpart:{sub}")

    path_segments = [seg for seg in path.split("/") if seg]
    for seg in path_segments:
        tokens.append(f"path:{seg}")
        for part in split_by_separators(seg):
            tokens.append(f"pseg:{part}")

    if path_segments:
        last_seg = path_segments[-1]
        if "." in last_seg:
            ext = last_seg.split(".")[-1]
            if 1 <= len(ext) <= 8:
                tokens.append(f"ext:{ext}")

    if query:
        tokens.append("has_query")

    for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        if key:
            tokens.append(f"qkey:{key}")
            for part in split_by_separators(key):
                tokens.append(f"qk:{part}")
        if value:
            for part in split_by_separators(value):
                tokens.append(f"qv:{part}")

    general_parts = split_by_separators(decoded_url)
    for part in general_parts:
        tokens.append(f"tok:{part}")
    for part in general_parts:
        if len(part) >= 6:
            tokens.extend(char_ngrams(part, 3, 4))

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

    return tokens or ["empty_or_invalid_url"]


def seed_tokens_for_label(label):
    tokens = set()
    for term in DOMAIN_SEED_TERMS.get(label, set()):
        tokens.update({
            f"tok:{term}",
            f"dpart:{term}",
            f"path:{term}",
            f"pseg:{term}",
            f"qk:{term}",
            f"qv:{term}",
        })
    for ext in DOMAIN_SEED_EXTENSIONS.get(label, set()):
        tokens.update({f"ext:{ext}", f"tok:{ext}", f"pseg:{ext}"})
    return tokens


def build_risk_dictionary(urls, labels, class_names):
    malicious_classes = [label for label in class_names if label != BENIGN_LABEL]
    class_token_df = {label: Counter() for label in class_names}
    total_token_df = Counter()
    class_doc_count = Counter()

    for url, label in zip(urls, labels):
        tokens = set(tokenize_url(url))
        class_doc_count[label] += 1
        for token in tokens:
            class_token_df[label][token] += 1
            total_token_df[token] += 1

    total_docs = sum(class_doc_count.values())
    benign_docs = class_doc_count[BENIGN_LABEL]
    malicious_docs = total_docs - benign_docs

    common_scores = {}
    for token, total_df in total_token_df.items():
        if total_df < MIN_TOKEN_DF:
            continue
        benign_df = class_token_df[BENIGN_LABEL][token]
        malicious_df = sum(class_token_df[label][token] for label in malicious_classes)
        mal_class_presence = sum(1 for label in malicious_classes if class_token_df[label][token] > 0)
        if mal_class_presence < MIN_MAL_CLASSES_FOR_COMMON:
            continue

        p_mal = (malicious_df + ALPHA) / (malicious_docs + 2 * ALPHA)
        p_benign = (benign_df + ALPHA) / (benign_docs + 2 * ALPHA)
        score = math.log(p_mal / p_benign)
        if score > 0:
            common_scores[token] = score

    class_specific = {label: {} for label in malicious_classes}
    for label in malicious_classes:
        scores = {}
        n_c = class_doc_count[label]
        n_not_c = total_docs - n_c
        for token, total_df in total_token_df.items():
            if total_df < MIN_TOKEN_DF:
                continue
            df_c = class_token_df[label][token]
            df_not_c = total_df - df_c
            p_c = (df_c + ALPHA) / (n_c + 2 * ALPHA)
            p_not_c = (df_not_c + ALPHA) / (n_not_c + 2 * ALPHA)
            score = math.log(p_c / p_not_c)
            if score > 0:
                scores[token] = score

        class_specific[label] = dict(
            sorted(scores.items(), key=lambda item: item[1], reverse=True)[:TOP_K_PER_MAL_CLASS]
        )
        for seed_token in seed_tokens_for_label(label):
            learned_score = class_specific[label].get(seed_token, 0.0)
            class_specific[label][seed_token] = max(learned_score, 6.0)

    common_malicious = dict(
        sorted(common_scores.items(), key=lambda item: item[1], reverse=True)[:TOP_K_COMMON_MALICIOUS]
    )

    return {
        "common_malicious": common_malicious,
        "class_specific": class_specific,
        "metadata": {
            "builder": "rebuild_risk_dict.py",
            "source_dataset": os.path.basename(DEFAULT_DATA_PATH),
            "domain_seed_policy": "seed terms are injected only into the learned risk dictionary artifact, not used as a runtime whitelist or guard",
            "domain_seed_terms": {
                label: sorted(terms)
                for label, terms in DOMAIN_SEED_TERMS.items()
            },
            "domain_seed_extensions": {
                label: sorted(extensions)
                for label, extensions in DOMAIN_SEED_EXTENSIONS.items()
            },
            "lookalike_digit_map": {
                "0": "o",
                "1": "l",
                "3": "e",
                "4": "a",
                "5": "s",
                "7": "t"
            },
            "impersonation_targets": [
                "amazon",
                "apple",
                "daum",
                "facebook",
                "github",
                "gmail",
                "google",
                "instagram",
                "kakao",
                "microsoft",
                "naver",
                "netflix",
                "office",
                "paypal",
                "youtube"
            ],
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=DEFAULT_DATA_PATH)
    parser.add_argument("--output", default=DEFAULT_OUTPUT_PATH)
    args = parser.parse_args()

    df = pd.read_csv(args.data)
    df = df[[URL_COL, LABEL_COL]].dropna()
    df[URL_COL] = df[URL_COL].astype(str)
    df[LABEL_COL] = df[LABEL_COL].astype(str)
    class_names = sorted(df[LABEL_COL].unique().tolist())
    risk_dict = build_risk_dictionary(df[URL_COL].tolist(), df[LABEL_COL].tolist(), class_names)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(risk_dict, f, ensure_ascii=False, indent=2)

    print(f"Saved rebuilt risk dictionary: {args.output}")
    for label, entries in risk_dict["class_specific"].items():
        print(f"{label}: {len(entries)} tokens")


if __name__ == "__main__":
    main()
