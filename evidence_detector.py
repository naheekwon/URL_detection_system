import json
import os
import re
import urllib.parse


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_LEXICON_PATH = os.path.join(
    PROJECT_DIR,
    "artifacts_transformer",
    "evidence_lexicon.json",
)


def _load_evidence_lexicon(path=EVIDENCE_LEXICON_PATH):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        "risk_terms": set(data.get("risk_terms", [])),
        "phishing_intent_terms": set(data.get("phishing_intent_terms", [])),
        "defacement_terms": set(data.get("defacement_terms", [])),
        "malware_terms": set(data.get("malware_terms", [])),
        "risk_extensions": set(data.get("risk_extensions", [])),
        "compressed_extensions": set(data.get("compressed_extensions", [])),
        "risk_tlds": set(data.get("risk_tlds", [])),
        "impersonation_targets": set(data.get("impersonation_targets", [])),
        "lookalike_digit_map": str.maketrans(data.get("lookalike_digit_map", {})),
    }


EVIDENCE_LEXICON = _load_evidence_lexicon()


def _feature_value(feature):
    if ":" not in feature:
        return feature

    return feature.split(":", 1)[1]


def _valid_learned_term(value):
    value = str(value or "").lower()
    if len(value) < 3 or len(value) > 32:
        return False
    if value.isdigit():
        return False

    return bool(re.search(r"[a-z]", value))


def _lexicon_from_learned_risk_dict(learned_risk_dict):
    if not learned_risk_dict:
        return EVIDENCE_LEXICON

    common_dict = learned_risk_dict.get("common_malicious", {})
    class_dict = learned_risk_dict.get("class_specific", {})
    metadata = learned_risk_dict.get("metadata", {})

    learned = {
        "risk_terms": set(),
        "phishing_intent_terms": set(),
        "defacement_terms": set(),
        "malware_terms": set(),
        "risk_extensions": set(),
        "compressed_extensions": {"zip", "rar"},
        "risk_tlds": set(),
        "impersonation_targets": set(metadata.get("impersonation_targets", [])),
        "lookalike_digit_map": str.maketrans(
            metadata.get("lookalike_digit_map", {})
            or {
                "0": "o",
                "1": "l",
                "3": "e",
                "4": "a",
                "5": "s",
                "7": "t",
            }
        ),
    }

    for label, terms in metadata.get("domain_seed_terms", {}).items():
        if label in learned:
            learned[label].update(terms)
        elif label == "phishing":
            learned["phishing_intent_terms"].update(terms)

    for label, extensions in metadata.get("domain_seed_extensions", {}).items():
        if label == "malware":
            learned["risk_extensions"].update(extensions)

    def absorb(features, target_terms, threshold=4.0):
        for feature, score in features.items():
            try:
                numeric_score = float(score)
            except (TypeError, ValueError):
                continue

            if numeric_score < threshold:
                continue

            prefix = feature.split(":", 1)[0] if ":" in feature else feature
            value = _feature_value(feature)

            if prefix == "ext":
                learned["risk_extensions"].add(value)
                continue

            if prefix == "tld":
                learned["risk_tlds"].add(value)
                continue

            if prefix in {"tok", "path", "pseg", "qkey", "qk", "qv", "sld", "dpart", "domain", "subdomain"}:
                if _valid_learned_term(value):
                    target_terms.add(value)
                    learned["risk_terms"].add(value)

    absorb(common_dict, learned["risk_terms"], threshold=5.0)
    absorb(class_dict.get("phishing", {}), learned["phishing_intent_terms"], threshold=4.0)
    absorb(class_dict.get("defacement", {}), learned["defacement_terms"], threshold=4.0)
    absorb(class_dict.get("malware", {}), learned["malware_terms"], threshold=4.0)

    return learned


def _clip01(value):
    return max(0.0, min(float(value), 1.0))


def _calibrated_confidence(risk_score, threshold, prediction, page_evidence=None):
    """Return a conservative confidence score instead of saturating at 100%."""
    risk_score = _clip01(risk_score)

    if prediction != "benign":
        distance = (risk_score - threshold) / max(1.0 - threshold, 1e-6)
    else:
        distance = (threshold - risk_score) / max(threshold, 1e-6)

    confidence = 0.55 + 0.35 * _clip01(distance)

    if not page_evidence or not page_evidence.get("fetched"):
        confidence = min(confidence, 0.75)
    elif not page_evidence.get("html_analyzed"):
        confidence = min(confidence, 0.80)

    return _clip01(confidence)


def _clean_url(url):
    value = str(url or "").strip().lower()
    try:
        value = urllib.parse.unquote(value, errors="ignore")
    except Exception:
        pass
    return value


def _parse_url(url):
    clean = _clean_url(url)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", clean):
        clean = "https://" + clean
    return clean, urllib.parse.urlparse(clean)


def _split_parts(text):
    return [part for part in re.split(r"[^a-zA-Z0-9]+", text or "") if part]


def _second_level_domain(host_parts):
    if len(host_parts) < 2:
        return ""

    return host_parts[-2]


def _learned_risk_features(parsed, host, host_parts, path, query):
    features = set()
    path_parts = _split_parts(path)
    query_pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)

    if host_parts:
        features.add(f"tld:{host_parts[-1]}")

    if len(host_parts) >= 2:
        features.add(f"sld:{host_parts[-2]}")

    if len(host_parts) >= 3:
        features.add("subdomain:" + ".".join(host_parts[:-2]))

    if host:
        features.add(f"domain:{host}")

    for part in host_parts:
        features.add(f"dpart:{part}")
        features.add(f"domain:{part}")
        features.add(f"tok:{part}")

    for part in path_parts:
        features.add(f"path:{part}")
        features.add(f"pseg:{part}")
        features.add(f"tok:{part}")

    last_segment = path.rsplit("/", 1)[-1].lower()
    if "." in last_segment:
        features.add(f"ext:{last_segment.rsplit('.', 1)[-1]}")

    for key, value in query_pairs:
        for part in _split_parts(key):
            features.add(f"qkey:{part}")
            features.add(f"qk:{part}")
            features.add(f"tok:{part}")
        for part in _split_parts(value):
            features.add(f"qv:{part}")
            features.add(f"tok:{part}")

    if re.search(r"\d{1,3}(\.\d{1,3}){3}", host):
        features.add("host_is_ip")

    if parsed.scheme == "http":
        features.add("scheme:http")

    return features


def _feature_context_weight(feature, host_parts):
    prefix = feature.split(":", 1)[0] if ":" in feature else feature
    value = _feature_value(feature)
    sld = _second_level_domain(host_parts)
    tld = host_parts[-1] if host_parts else ""

    if prefix in {"path", "pseg", "qkey", "qk", "qv"}:
        return 1.0, "contextual path/query token"

    if prefix == "subdomain":
        return 0.85, "subdomain token"

    if prefix in {"ext", "scheme", "host_is_ip"}:
        return 1.0, "structural URL token"

    if prefix == "tld":
        return 0.65, "TLD token"

    if prefix in {"sld", "domain", "dpart"}:
        if value == sld or value == tld:
            return 0.18, "registered-domain token with low standalone evidence"
        return 0.35, "host token"

    if prefix == "tok":
        return 0.30, "context-free token"

    return 0.50, "generic token"


def _learned_dictionary_evidence(parsed, host, host_parts, path, query, learned_risk_dict):
    if not learned_risk_dict:
        return 0.0, {}, []

    features = _learned_risk_features(parsed, host, host_parts, path, query)
    common_dict = learned_risk_dict.get("common_malicious", {})
    class_dict = learned_risk_dict.get("class_specific", {})

    matched = []
    common_score = 0.0
    type_scores = {
        "phishing": 0.0,
        "defacement": 0.0,
        "malware": 0.0,
    }

    for feature in features:
        context_weight, context_name = _feature_context_weight(feature, host_parts)
        if feature in common_dict:
            value = float(common_dict[feature]) * context_weight
            common_score = max(common_score, value)
            matched.append((value, "common", feature, context_name))

        for label in type_scores:
            raw_value = float(class_dict.get(label, {}).get(feature, 0.0))
            if raw_value > 0:
                value = raw_value * context_weight
                type_scores[label] = max(type_scores[label], value)
                matched.append((value, label, feature, context_name))

    matched.sort(reverse=True)
    learned_score = min(0.35, max([common_score] + list(type_scores.values())) / 20.0)
    normalized_type_scores = {
        label: min(0.45, value / 18.0)
        for label, value in type_scores.items()
    }

    reasons = []
    if matched:
        top = [
            f"{label}:{feature} ({context_name})"
            for _, label, feature, context_name in matched[:5]
        ]
        reasons.append(
            "Learned risk dictionary matched URL tokens with context weighting: "
            + ", ".join(top)
            + "."
        )

    return learned_score, normalized_type_scores, reasons


def _url_evidence(url, learned_risk_dict=None):
    lexicon = _lexicon_from_learned_risk_dict(learned_risk_dict)
    clean, parsed = _parse_url(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    last_path_segment = path.rsplit("/", 1)[-1].lower()
    host_parts = [part for part in host.split(".") if part]
    sld = _second_level_domain(host_parts)
    host_subparts = []
    for part in host_parts:
        host_subparts.extend(_split_parts(part))
    subdomain_parts = host_parts[:-2] if len(host_parts) >= 3 else []
    subdomain_subparts = []
    for part in subdomain_parts:
        subdomain_subparts.extend(_split_parts(part))
    path_parts = _split_parts(path)
    query_parts = _split_parts(query)
    all_parts = set(host_parts + host_subparts + path_parts + query_parts)
    contextual_parts = set(subdomain_parts + subdomain_subparts + path_parts + query_parts)

    reasons = []
    type_scores = {
        "phishing": 0.0,
        "defacement": 0.0,
        "malware": 0.0,
    }
    score = 0.0

    if "@" in clean:
        score += 0.25
        type_scores["phishing"] += 0.18
        reasons.append("URL contains user-info marker '@'.")

    if "%" in clean:
        score += 0.10
        type_scores["phishing"] += 0.04
        reasons.append("URL contains percent-encoded characters.")

    if re.search(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 0.30
        reasons.append("Host is represented as an IP address.")

    if len(clean) >= 120:
        score += 0.10
        reasons.append("URL is unusually long.")

    if len(host_parts) >= 4:
        score += 0.08
        reasons.append("Host contains many domain parts.")

    sld_letters = sum(ch.isalpha() for ch in sld)
    sld_digits = sum(ch.isdigit() for ch in sld)
    if sld_letters >= 3 and sld_digits > 0:
        score += 0.14
        reasons.append("Second-level domain mixes letters with look-alike digits.")

        normalized_sld = sld.translate(lexicon["lookalike_digit_map"])
        if normalized_sld != sld and normalized_sld.isalpha():
            score += 0.05
            reasons.append(
                f"Second-level domain becomes '{normalized_sld}' after common look-alike digit normalization."
            )

            if sld_digits >= 2 or re.search(r"(\d)\1", sld):
                score += 0.15
                reasons.append("Second-level domain contains repeated or multiple look-alike digits.")

            if normalized_sld in lexicon["impersonation_targets"]:
                score += 0.22
                type_scores["phishing"] += 0.22
                reasons.append(
                    f"Look-alike normalized domain matches a high-value impersonation target: {normalized_sld}."
                )

    if host_parts and host_parts[-1] in lexicon["risk_tlds"]:
        score += 0.16
        reasons.append(f"TLD '.{host_parts[-1]}' is commonly abused in phishing campaigns.")

    if "." in last_path_segment:
        ext = last_path_segment.rsplit(".", 1)[-1]
        if ext in lexicon["risk_extensions"]:
            if ext in lexicon["compressed_extensions"]:
                score += 0.28
                type_scores["malware"] += 0.22
                reasons.append(f"URL points to a compressed download file '.{ext}'.")
            else:
                score += 0.40
                type_scores["malware"] += 0.34
                reasons.append(f"URL points to a risky executable file extension '.{ext}'.")

    matched_terms = sorted(contextual_parts & lexicon["risk_terms"])
    if matched_terms:
        score += min(0.30, 0.08 * len(matched_terms))
        reasons.append("Contextual risk-intent terms in URL: " + ", ".join(matched_terms[:5]) + ".")

    phishing_terms = sorted(contextual_parts & lexicon["phishing_intent_terms"])
    if len(phishing_terms) >= 2:
        score += 0.18
        type_scores["phishing"] += 0.24
        reasons.append("Multiple credential-phishing intent terms: " + ", ".join(phishing_terms[:5]) + ".")

    defacement_terms = sorted(contextual_parts & lexicon["defacement_terms"])
    if defacement_terms:
        defacement_score = min(0.44, 0.28 + 0.06 * (len(defacement_terms) - 1))
        score += defacement_score
        type_scores["defacement"] += defacement_score
        reasons.append("Defacement-related terms in URL: " + ", ".join(defacement_terms[:5]) + ".")
        if last_path_segment.endswith((".html", ".htm", ".php")):
            score += 0.08
            type_scores["defacement"] += 0.08
            reasons.append("Defacement term appears in a web page filename.")

    malware_terms = sorted(contextual_parts & lexicon["malware_terms"])
    if malware_terms and "." in last_path_segment:
        malware_lure_score = min(0.30, 0.12 + 0.06 * len(malware_terms))
        score += malware_lure_score
        type_scores["malware"] += malware_lure_score
        reasons.append("Download/malware lure terms near a file path: " + ", ".join(malware_terms[:5]) + ".")

    host_brand_terms = sorted(set(subdomain_subparts + path_parts + query_parts) & lexicon["impersonation_targets"])
    if host_brand_terms and phishing_terms:
        brand_phishing_score = 0.30 if len(phishing_terms) == 1 else 0.24
        score += brand_phishing_score
        type_scores["phishing"] += brand_phishing_score
        reasons.append(
            "Brand term appears with credential-phishing terms outside the registered service domain: "
            + ", ".join(host_brand_terms[:3])
            + "."
        )

    if parsed.scheme == "http":
        score += 0.08
        reasons.append("URL uses HTTP rather than HTTPS.")

    learned_score, learned_type_scores, learned_reasons = _learned_dictionary_evidence(
        parsed=parsed,
        host=host,
        host_parts=host_parts,
        path=path,
        query=query,
        learned_risk_dict=learned_risk_dict,
    )
    score += learned_score
    for label, value in learned_type_scores.items():
        type_scores[label] += value
    reasons.extend(learned_reasons)

    return _clip01(score), reasons, type_scores


def _page_evidence_score(page_evidence):
    if not page_evidence:
        return 0.0, ["Live page evidence was not collected."]

    if not page_evidence.get("fetched"):
        return 0.08, [f"Live page could not be fetched: {page_evidence.get('error') or 'unknown error'}."]

    if not page_evidence.get("html_analyzed"):
        return 0.05, ["Fetched resource was not HTML, so page-level phishing signals were limited."]

    score = 0.0
    reasons = []
    password_count = int(page_evidence.get("password_input_count") or 0)
    form_count = int(page_evidence.get("form_count") or 0)
    external_form_count = int(page_evidence.get("external_form_action_count") or 0)
    insecure_form_count = int(page_evidence.get("insecure_form_action_count") or 0)
    iframe_count = int(page_evidence.get("iframe_count") or 0)
    js_obfuscation_score = float(page_evidence.get("js_obfuscation_score") or 0.0)
    suspicious_keywords = page_evidence.get("suspicious_text_keywords") or []
    defacement_keywords = page_evidence.get("defacement_text_keywords") or []
    malware_keywords = page_evidence.get("malware_text_keywords") or []

    if password_count > 0:
        score += 0.35
        reasons.append(f"Page contains {password_count} password input field(s).")

    if external_form_count > 0:
        score += 0.30
        reasons.append(f"Page has {external_form_count} form action(s) posting to another host.")

    if insecure_form_count > 0:
        score += 0.20
        reasons.append(f"Page has {insecure_form_count} insecure HTTP form action(s).")

    if iframe_count > 0 and (password_count > 0 or form_count > 0):
        score += 0.12
        reasons.append("Page combines iframe usage with form/login surface.")

    has_sensitive_interaction = (
        password_count > 0
        or external_form_count > 0
        or insecure_form_count > 0
    )

    if suspicious_keywords and has_sensitive_interaction:
        score += min(0.18, 0.04 * len(suspicious_keywords))
        reasons.append(
            "Suspicious page terms near a sensitive interaction surface: "
            + ", ".join(suspicious_keywords[:6])
            + "."
        )

    if defacement_keywords:
        score += min(0.42, 0.24 + 0.06 * len(defacement_keywords))
        reasons.append(
            "Defacement-related text was found on the page: "
            + ", ".join(defacement_keywords[:6])
            + "."
        )

    if malware_keywords and not has_sensitive_interaction:
        score += min(0.20, 0.06 * len(malware_keywords))
        reasons.append(
            "Download/malware lure text was found on the page: "
            + ", ".join(malware_keywords[:6])
            + "."
        )

    if js_obfuscation_score >= 0.25:
        score += min(0.24, 0.18 * js_obfuscation_score)
        reasons.append("Inline JavaScript shows obfuscation-like patterns.")

    if page_evidence.get("ssl_checked"):
        if page_evidence.get("ssl_host_matches_cert") is False:
            score += 0.30
            reasons.append("SSL certificate does not appear to match the requested host.")

        days_until_expiry = page_evidence.get("ssl_days_until_expiry")
        if days_until_expiry is not None and days_until_expiry < 7:
            score += 0.08
            reasons.append("SSL certificate expires very soon.")
    elif page_evidence.get("ssl_error") and page_evidence.get("ssl_error") != "not_https":
        score += 0.08
        reasons.append(f"SSL certificate check failed: {page_evidence.get('ssl_error')}.")

    if form_count == 0 and password_count == 0 and external_form_count == 0:
        score -= 0.18
        reasons.append("No login form, password field, or external form action was found.")

    if page_evidence.get("status_code") == 200 and page_evidence.get("title"):
        score -= 0.05
        reasons.append("Page loaded normally with a visible title.")

    return _clip01(score), reasons


def classify_with_evidence(
    url,
    page_evidence=None,
    learned_risk_dict=None,
    transformer_alignment=None,
):
    url_score, url_reasons, type_scores = _url_evidence(
        url,
        learned_risk_dict=learned_risk_dict,
    )
    page_score, page_reasons = _page_evidence_score(page_evidence)
    transformer_alignment = transformer_alignment or {}
    transformer_score = _clip01(transformer_alignment.get("score", 0.0))
    transformer_type_scores = transformer_alignment.get("type_scores", {})
    for label, value in transformer_type_scores.items():
        if label in type_scores:
            type_scores[label] += 0.35 * float(value or 0.0)

    weighted_score = _clip01(
        0.40 * url_score
        + 0.25 * transformer_score
        + 0.35 * page_score
    )
    final_score = weighted_score

    if not page_evidence or not page_evidence.get("fetched"):
        final_score = max(final_score, url_score)

    if url_score >= 0.35:
        final_score = max(final_score, 0.85 * url_score)

    if page_score >= 0.35:
        final_score = max(final_score, 0.85 * page_score)

    threshold = 0.35
    if final_score >= threshold:
        prediction = max(type_scores, key=type_scores.get)
        if type_scores.get(prediction, 0.0) <= 0:
            prediction = "phishing"
    else:
        prediction = "benign"

    confidence = _calibrated_confidence(
        risk_score=final_score,
        threshold=threshold,
        prediction=prediction,
        page_evidence=page_evidence,
    )

    return {
        "method": "Learned Lexicon-Context Evidence Model",
        "prediction": prediction,
        "is_malicious": prediction != "benign",
        "risk_score": round(final_score, 4),
        "weighted_score": round(weighted_score, 4),
        "decision_threshold": threshold,
        "confidence": round(confidence, 4),
        "url_score": round(url_score, 4),
        "transformer_alignment_score": round(transformer_score, 4),
        "transformer_alignment_top_matches": transformer_alignment.get("top_matches", []),
        "page_score": round(page_score, 4),
        "type_scores": {
            label: round(score, 4)
            for label, score in type_scores.items()
        },
        "url_reasons": url_reasons,
        "page_reasons": page_reasons,
        "formula": "Risk(x) = max(0.40*LearnedURLLexicon(x) + 0.25*TransformerLexiconAlignment(x) + 0.35*StaticPageEvidence(x), strong evidence floor)",
        "confidence_formula": "Conf(x) = 0.55 + 0.35 * normalized_distance_from_threshold, capped by evidence availability",
    }
