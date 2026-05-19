import csv
import os
from collections import Counter

import numpy as np
import torch


ALPHA_TRANSFORMER = 0.45
BETA_DICTIONARY = 0.30
GAMMA_CASE = 0.25

RISK_AMPLIFIER_WORDS = {
    "account",
    "admin",
    "bank",
    "billing",
    "confirm",
    "credential",
    "download",
    "free",
    "login",
    "password",
    "pay",
    "payment",
    "secure",
    "signin",
    "unlock",
    "update",
    "verify",
    "wallet",
}

HIGH_RISK_FEATURES = {
    "has_userinfo",
    "host_is_ip",
    "has_percent_encoding",
    "many_dots",
    "very_long_url",
    "ext:apk",
    "ext:bat",
    "ext:cmd",
    "ext:exe",
    "ext:jar",
    "ext:msi",
    "ext:ps1",
    "ext:scr",
    "ext:vbs",
}

LOW_INFORMATION_DISPLAYS = {
    "api",
    "asp",
    "aspx",
    "by",
    "com",
    "co",
    "example",
    "html",
    "http",
    "https",
    "id",
    "index",
    "message",
    "net",
    "news",
    "org",
    "page",
    "php",
    "test",
    "www",
}


def _clip01(value):
    return max(0.0, min(float(value), 1.0))


def _is_char_ngram(feature):
    return str(feature).startswith("char:")


def _evidence_strength(item):
    dictionary_score = float(item.get("dictionary_score", 0.0))
    case_score = float(item.get("case_score", 0.0))
    rule_factor = float(item.get("rule_factor", 1.0))
    rule_reasons = set(item.get("rule_reasons") or [])

    if dictionary_score > 0 and rule_factor > 1.0:
        return "strong"
    if dictionary_score > 0 or case_score > 0:
        return "strong"
    if (
        rule_factor > 1.0
        and str(item.get("display", "")).lower() not in LOW_INFORMATION_DISPLAYS
        and rule_reasons - {"query-string context"}
    ):
        return "medium"
    return "weak"


def _is_human_meaningful(item):
    display = str(item.get("display", "")).strip()
    if not display:
        return False
    if item.get("category") == "character_ngram":
        return False
    if display.lower() in LOW_INFORMATION_DISPLAYS:
        return False
    if len(display) <= 1:
        return False

    return True


def _feature_display(feature):
    if ":" not in feature:
        return feature

    prefix, value = feature.split(":", 1)
    if prefix == "char":
        return value

    return value


def _feature_category(feature):
    if ":" not in feature:
        return "url_rule"

    prefix = feature.split(":", 1)[0]
    mapping = {
        "tld": "domain",
        "tldpart": "domain",
        "sld": "domain",
        "subdomain": "domain",
        "domain": "domain",
        "dpart": "domain",
        "path": "path",
        "pseg": "path",
        "ext": "file_extension",
        "qkey": "query",
        "qk": "query",
        "qv": "query",
        "tok": "lexical",
        "char": "character_ngram",
    }

    return mapping.get(prefix, "lexical")


def _dictionary_scores(tokens, risk_dict, prediction):
    common_dict = risk_dict.get("common_malicious", {})
    class_dict = risk_dict.get("class_specific", {}).get(prediction, {})
    scores = {}
    max_reference = 1.0

    if common_dict:
        max_reference = max(max_reference, max(abs(v) for v in common_dict.values()))
    if class_dict:
        max_reference = max(max_reference, max(abs(v) for v in class_dict.values()))

    for token in set(tokens):
        common_score = float(common_dict.get(token, 0.0))
        class_score = float(class_dict.get(token, 0.0))
        raw_score = max(common_score, class_score)

        if raw_score > 0:
            scores[token] = {
                "score": _clip01(raw_score / max_reference),
                "raw_score": raw_score,
                "source": "class_specific" if class_score >= common_score and class_score > 0 else "common_malicious",
            }

    return scores


def _char_saliency(url, model, encode_url_chars, char_vocab, max_len):
    cleaned = str(url).strip().lower()
    if not cleaned:
        return []

    model.eval()
    model.zero_grad()

    input_ids = torch.tensor(
        [encode_url_chars(cleaned, char_vocab, max_len)],
        dtype=torch.long,
    )
    batch_size, seq_len = input_ids.shape
    positions = torch.arange(seq_len, device=input_ids.device).unsqueeze(0)
    positions = positions.expand(batch_size, seq_len)
    padding_mask = input_ids.eq(0)

    embeddings = model.token_embedding(input_ids) + model.position_embedding(positions)
    embeddings.retain_grad()
    encoded = model.encoder(embeddings, src_key_padding_mask=padding_mask)
    logits = model.classifier(encoded[:, 0, :])
    phishing_logit = logits[0, 1]
    phishing_logit.backward()

    grad = embeddings.grad.detach()[0]
    emb = embeddings.detach()[0]
    saliency = torch.sum(torch.abs(grad * emb), dim=1).cpu().numpy()

    usable_len = min(len(cleaned), max_len - 1)
    char_scores = saliency[1:usable_len + 1].astype(np.float32)

    if char_scores.size == 0:
        return []

    max_score = float(np.max(char_scores))
    if max_score > 0:
        char_scores = char_scores / max_score

    return char_scores.tolist()


def _substring_score(cleaned_url, display, char_scores):
    display = str(display).lower()
    if not display or not char_scores:
        return 0.0

    start = 0
    scores = []
    while True:
        idx = cleaned_url.find(display, start)
        if idx < 0:
            break

        end = min(idx + len(display), len(char_scores))
        if idx < len(char_scores) and end > idx:
            scores.append(float(np.mean(char_scores[idx:end])))

        start = idx + 1

    return max(scores, default=0.0)


def compute_transformer_lexicon_alignment(
    url,
    risk_dict,
    tokenizer,
    transformer_model,
    encode_url_chars,
    char_vocab,
    max_char_len,
):
    tokens = tokenizer(url)
    if not tokens:
        return {
            "score": 0.0,
            "type_scores": {
                "phishing": 0.0,
                "defacement": 0.0,
                "malware": 0.0,
            },
            "top_matches": [],
        }

    cleaned_url = str(url).strip().lower()
    char_scores = _char_saliency(
        url=url,
        model=transformer_model,
        encode_url_chars=encode_url_chars,
        char_vocab=char_vocab,
        max_len=max_char_len,
    )
    common_dict = risk_dict.get("common_malicious", {})
    class_dict = risk_dict.get("class_specific", {})
    max_reference = 1.0

    for values in [common_dict] + list(class_dict.values()):
        if values:
            max_reference = max(max_reference, max(abs(v) for v in values.values()))

    aligned = []
    type_scores = {
        "phishing": 0.0,
        "defacement": 0.0,
        "malware": 0.0,
    }

    for token in set(tokens):
        display = _feature_display(token)
        saliency = _substring_score(cleaned_url, display, char_scores)
        common_value = float(common_dict.get(token, 0.0))
        class_values = {
            label: float(class_dict.get(label, {}).get(token, 0.0))
            for label in type_scores
        }
        best_label = max(class_values, key=class_values.get)
        best_class_value = class_values[best_label]
        learned_value = max(common_value, best_class_value)

        if saliency <= 0 or learned_value <= 0:
            continue

        learned_norm = _clip01(learned_value / max_reference)
        alignment = _clip01(saliency * learned_norm)
        aligned.append({
            "token": token,
            "display": display,
            "saliency": round(float(saliency), 4),
            "learned_score": round(float(learned_norm), 4),
            "alignment": round(float(alignment), 4),
            "label": best_label if best_class_value >= common_value else "common",
        })

        if best_class_value > 0:
            type_scores[best_label] = max(type_scores[best_label], alignment)

    aligned.sort(key=lambda item: item["alignment"], reverse=True)
    top_scores = [item["alignment"] for item in aligned[:5]]
    score = float(np.mean(top_scores)) if top_scores else 0.0

    return {
        "score": round(_clip01(score), 4),
        "type_scores": {
            label: round(_clip01(value), 4)
            for label, value in type_scores.items()
        },
        "top_matches": aligned[:5],
    }


def _context_rule_factor(feature, display):
    factor = 1.0
    reasons = []

    lower_display = str(display).lower()

    if feature in HIGH_RISK_FEATURES:
        factor += 0.25
        reasons.append("high-risk URL structure")

    if lower_display in RISK_AMPLIFIER_WORDS:
        factor += 0.20
        reasons.append("risk-intent keyword")

    if feature.startswith("qkey:") or feature.startswith("qv:"):
        factor += 0.08
        reasons.append("query-string context")

    if feature == "tok:https" or feature == "tld:https":
        factor -= 0.05
        reasons.append("HTTPS context")

    return max(0.45, min(1.45, factor)), reasons


def load_case_index(dataset_path, tokenizer, max_cases=2500):
    if not dataset_path or not os.path.exists(dataset_path):
        return []

    cases = []
    try:
        with open(dataset_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            url_column = "URL" if "URL" in (reader.fieldnames or []) else "url"
            label_column = "label" if "label" in (reader.fieldnames or []) else "type"

            for row in reader:
                url = (row.get(url_column) or "").strip()
                if not url:
                    continue

                label = str(row.get(label_column, "")).strip()
                tokens = set(tokenizer(url))
                cases.append({
                    "url": url,
                    "label": label,
                    "tokens": tokens,
                })

                if len(cases) >= max_cases:
                    break
    except Exception:
        return []

    return cases


def _similar_cases(tokens, cases, prediction, top_k=3):
    if not cases:
        return [], {}

    token_set = set(tokens)
    scored = []
    for case in cases:
        case_tokens = case["tokens"]
        union_count = len(token_set | case_tokens)
        if union_count == 0:
            continue

        similarity = len(token_set & case_tokens) / union_count
        if similarity <= 0:
            continue

        scored.append((similarity, case))

    scored.sort(key=lambda item: item[0], reverse=True)
    top = scored[:top_k]
    case_score_by_token = {}

    for similarity, case in top:
        label = case.get("label")
        label_matches_prediction = (
            str(label).lower() == str(prediction).lower()
            or (str(label) == "0" and str(prediction).lower() == "benign")
            or (str(label) == "1" and str(prediction).lower() != "benign")
        )
        label_weight = 1.0 if label_matches_prediction else 0.72

        for token in token_set & case["tokens"]:
            case_score_by_token[token] = max(
                case_score_by_token.get(token, 0.0),
                similarity * label_weight,
            )

    public_cases = [
        {
            "url": case["url"],
            "label": case["label"],
            "similarity": round(float(similarity), 4),
        }
        for similarity, case in top
    ]

    return public_cases, case_score_by_token


def build_xai_explanation(
    url,
    prediction_result,
    risk_dict,
    tokenizer,
    transformer_model,
    encode_url_chars,
    char_vocab,
    max_char_len,
    case_index=None,
):
    tokens = tokenizer(url)
    token_counts = Counter(tokens)
    cleaned_url = str(url).strip().lower()
    final_prediction = prediction_result.get("prediction")
    explanation_target = final_prediction
    confidence = float(prediction_result.get("confidence") or 0.0)

    dictionary_by_token = _dictionary_scores(tokens, risk_dict, explanation_target)
    char_scores = _char_saliency(
        url=url,
        model=transformer_model,
        encode_url_chars=encode_url_chars,
        char_vocab=char_vocab,
        max_len=max_char_len,
    )
    similar_cases, case_score_by_token = _similar_cases(
        tokens=tokens,
        cases=case_index or [],
        prediction=explanation_target,
    )

    candidate_tokens = set(tokens)
    candidate_tokens.update(dictionary_by_token.keys())
    candidate_tokens.update(case_score_by_token.keys())

    evidence = []
    for feature in candidate_tokens:
        display = _feature_display(feature)
        transformer_score = _substring_score(cleaned_url, display, char_scores)
        dictionary_entry = dictionary_by_token.get(feature, {})
        dictionary_score = float(dictionary_entry.get("score", 0.0))
        case_score = float(case_score_by_token.get(feature, 0.0))
        rule_factor, rule_reasons = _context_rule_factor(
            feature=feature,
            display=display,
        )
        has_external_evidence = dictionary_score > 0 or case_score > 0 or rule_factor > 1.0

        if str(display).lower() in LOW_INFORMATION_DISPLAYS and not has_external_evidence:
            continue

        if str(display).lower() in LOW_INFORMATION_DISPLAYS and dictionary_score <= 0 and case_score <= 0:
            continue

        if len(str(display)) <= 1 and not has_external_evidence:
            continue

        if _is_char_ngram(feature) and not has_external_evidence:
            continue

        explanation_score = (
            ALPHA_TRANSFORMER * transformer_score
            + BETA_DICTIONARY * dictionary_score
            + GAMMA_CASE * case_score
        ) * rule_factor
        explanation_score = _clip01(explanation_score)

        if explanation_score <= 0 and dictionary_score <= 0:
            continue

        evidence_item = {
            "feature": feature,
            "display": display,
            "category": _feature_category(feature),
            "count": int(token_counts.get(feature, 1)),
            "transformer_score": round(transformer_score, 4),
            "dictionary_score": round(dictionary_score, 4),
            "dictionary_raw_score": round(float(dictionary_entry.get("raw_score", 0.0)), 4),
            "dictionary_source": dictionary_entry.get("source"),
            "case_score": round(case_score, 4),
            "rule_factor": round(rule_factor, 4),
            "rule_reasons": rule_reasons,
            "explanation_score": round(explanation_score, 4),
        }
        evidence_item["strength"] = _evidence_strength(evidence_item)
        evidence_item["human_meaningful"] = _is_human_meaningful(evidence_item)
        evidence.append(evidence_item)

    evidence.sort(key=lambda item: item["explanation_score"], reverse=True)
    meaningful_evidence = [item for item in evidence if item["human_meaningful"]]
    internal_saliency_evidence = [
        item for item in evidence
        if item["category"] == "character_ngram" and not item["human_meaningful"]
    ][:10]
    deduplicated_evidence = []
    seen_display = set()
    for item in meaningful_evidence:
        display_key = str(item["display"]).lower()
        if display_key in seen_display:
            continue

        seen_display.add(display_key)
        deduplicated_evidence.append(item)

    top_evidence = deduplicated_evidence[:10]
    top_scores = [
        item["explanation_score"]
        for item in top_evidence[:5]
        if item["strength"] in {"strong", "medium"}
    ]
    mean_top_score = float(np.mean(top_scores)) if top_scores else 0.0

    strong_terms = [
        item["display"]
        for item in top_evidence
        if item["strength"] == "strong"
    ][:3]
    top_terms = ", ".join(strong_terms) or ", ".join(
        item["display"] for item in top_evidence[:3]
    ) or "no dominant token"
    decision_evidence = prediction_result.get("evidence_decision") or {}
    url_reasons = decision_evidence.get("url_reasons") or []
    page_reasons = decision_evidence.get("page_reasons") or []
    primary_reasons = url_reasons[:2] or page_reasons[:2]
    decision_risk_score = _clip01(decision_evidence.get("risk_score", 0.0))
    decision_url_score = _clip01(decision_evidence.get("url_score", 0.0))
    decision_page_score = _clip01(decision_evidence.get("page_score", 0.0))
    decision_transformer_score = _clip01(decision_evidence.get("transformer_alignment_score", 0.0))
    decision_items = []

    for reason in url_reasons[:4]:
        decision_items.append({
            "source": "URL context",
            "reason": reason,
            "score": round(decision_url_score, 4),
        })

    for reason in page_reasons[:3]:
        decision_items.append({
            "source": "Static page evidence",
            "reason": reason,
            "score": round(decision_page_score, 4),
        })

    if decision_transformer_score > 0:
        decision_items.append({
            "source": "Transformer alignment",
            "reason": "Transformer-token alignment supported the URL-level evidence.",
            "score": round(decision_transformer_score, 4),
        })

    if explanation_target == "benign":
        xai_confidence = _clip01(max(confidence * mean_top_score, 1.0 - decision_risk_score))
    else:
        xai_confidence = _clip01(max(confidence * mean_top_score, decision_risk_score))

    if explanation_target == "benign":
        if primary_reasons:
            reason_text = " ".join(primary_reasons)
            summary = (
                f"The model classified the URL as benign because the integrated evidence score "
                f"remained below the risk threshold. Main evidence: {reason_text}"
            )
        else:
            summary = (
                f"The model classified the URL as benign because no strong contextual URL, "
                f"Transformer-alignment, or static page risk evidence was found."
            )
    elif primary_reasons:
        reason_text = " ".join(primary_reasons)
        summary = (
            f"The model classified the URL as {explanation_target}. Main decision evidence: "
            f"{reason_text} Main token evidence: {top_terms}."
        )
    else:
        summary = (
            f"The model classified the URL as {explanation_target}. The strongest explanation signals "
            f"were {top_terms}, combining URL token saliency, risk dictionary evidence, "
            f"context rules, static page evidence, and similar URL cases."
        )

    return {
        "method": "Lexicon-Context Guided XAI",
        "formula": "E_i = (0.45*A_i + 0.30*D_i + 0.25*K_i) * R_i",
        "confidence_formula": "XAI(x) = P(y|x) * mean(top-k E_i)",
        "decision_module": "Lexicon-Context Evidence Model",
        "weights": {
            "token_saliency": ALPHA_TRANSFORMER,
            "dictionary": BETA_DICTIONARY,
            "similar_case": GAMMA_CASE,
        },
        "prediction": final_prediction,
        "final_prediction": final_prediction,
        "explanation_target_prediction": explanation_target,
        "model_confidence": round(confidence, 4),
        "xai_confidence": round(xai_confidence, 4),
        "mean_top_evidence_score": round(mean_top_score, 4),
        "top_evidence": top_evidence,
        "internal_saliency_evidence": internal_saliency_evidence,
        "primary_decision_reasons": primary_reasons,
        "decision_evidence": decision_items,
        "similar_cases": similar_cases,
        "summary": summary,
    }
