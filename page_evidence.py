import html
import json
import os
import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser


MAX_HTML_BYTES = 250_000
TIMEOUT_SECONDS = 4

SUSPICIOUS_TEXT_KEYWORDS = {
    "account",
    "bank",
    "billing",
    "confirm",
    "credential",
    "login",
    "password",
    "payment",
    "secure",
    "signin",
    "suspended",
    "update",
    "verify",
    "wallet",
}

LOW_INFORMATION_PAGE_TERMS = {
    "align",
    "blank",
    "block",
    "body",
    "border",
    "button",
    "center",
    "class",
    "color",
    "content",
    "display",
    "div",
    "font",
    "font-size",
    "form",
    "head",
    "height",
    "hidden",
    "hit",
    "href",
    "html",
    "image",
    "img",
    "inline",
    "input",
    "label",
    "left",
    "line",
    "link",
    "main",
    "margin",
    "meta",
    "none",
    "padding",
    "page",
    "right",
    "script",
    "scr",
    "span",
    "src",
    "style",
    "table",
    "tcolor",
    "text",
    "title",
    "type",
    "value",
    "width",
}

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_LEXICON_PATH = os.path.join(
    PROJECT_DIR,
    "artifacts_transformer",
    "evidence_lexicon.json",
)
LEARNED_RISK_DICT_PATH = os.path.join(
    PROJECT_DIR,
    "artifacts_transformer",
    "risk_dict.json",
)


def _feature_value(feature):
    if ":" not in feature:
        return feature

    return feature.split(":", 1)[1]


def _valid_text_term(value):
    value = str(value or "").lower()
    if len(value) < 3 or len(value) > 32:
        return False
    if value.isdigit():
        return False
    if value in LOW_INFORMATION_PAGE_TERMS:
        return False
    if re.fullmatch(r"[a-z]{1,4}", value) and value not in SUSPICIOUS_TEXT_KEYWORDS:
        return False

    return bool(re.search(r"[a-z]", value))


def _keyword_in_text(keyword, text):
    keyword = str(keyword or "").strip().lower()
    if not keyword:
        return False
    if keyword in LOW_INFORMATION_PAGE_TERMS:
        return False
    if " " in keyword:
        return keyword in text
    return re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", text) is not None


def _terms_from_learned_dict(features, threshold=4.0):
    terms = set()
    for feature, score in features.items():
        try:
            numeric_score = float(score)
        except (TypeError, ValueError):
            continue

        if numeric_score < threshold:
            continue

        prefix = feature.split(":", 1)[0] if ":" in feature else feature
        if prefix not in {"tok", "path", "pseg", "qkey", "qk", "qv", "sld", "dpart", "domain", "subdomain"}:
            continue

        value = _feature_value(feature)
        if _valid_text_term(value):
            terms.add(value)

    return terms


def _load_text_lexicon():
    try:
        with open(LEARNED_RISK_DICT_PATH, "r", encoding="utf-8") as f:
            learned = json.load(f)
    except Exception:
        learned = {}

    class_dict = learned.get("class_specific", {})
    if class_dict:
        return {
            "phishing": _terms_from_learned_dict(class_dict.get("phishing", {})) | SUSPICIOUS_TEXT_KEYWORDS,
            "defacement": _terms_from_learned_dict(class_dict.get("defacement", {})),
            "malware": _terms_from_learned_dict(class_dict.get("malware", {})),
        }

    try:
        with open(EVIDENCE_LEXICON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}

    return {
        "phishing": set(data.get("phishing_intent_terms", [])) | SUSPICIOUS_TEXT_KEYWORDS,
        "defacement": set(data.get("defacement_terms", [])) | {"hacked by", "defaced by", "owned by"},
        "malware": set(data.get("malware_terms", [])),
    }


TEXT_LEXICON = _load_text_lexicon()


def _normalize_url(url):
    value = str(url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", value):
        value = "https://" + value
    return value


def _is_public_http_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False, "unsupported_scheme"
    if not parsed.hostname:
        return False, "missing_host"

    try:
        addresses = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        return False, "dns_resolution_failed"

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False, "blocked_private_or_local_address"

    return True, None


class PageSignalParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.in_title = False
        self.title_parts = []
        self.form_count = 0
        self.external_form_action_count = 0
        self.insecure_form_action_count = 0
        self.password_input_count = 0
        self.input_count = 0
        self.iframe_count = 0
        self.script_count = 0
        self.external_script_count = 0
        self.inline_script_count = 0
        self.in_script = False
        self.inline_script_parts = []
        self.link_count = 0
        self.external_link_count = 0
        self.visible_text_parts = []

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()

        if tag == "title":
            self.in_title = True
        elif tag == "form":
            self.form_count += 1
            action = urllib.parse.urljoin(self.base_url, attrs.get("action", ""))
            if action:
                parsed_action = urllib.parse.urlparse(action)
                parsed_base = urllib.parse.urlparse(self.base_url)
                if parsed_action.scheme == "http":
                    self.insecure_form_action_count += 1
                if parsed_action.hostname and parsed_action.hostname != parsed_base.hostname:
                    self.external_form_action_count += 1
        elif tag == "input":
            self.input_count += 1
            if attrs.get("type", "").lower() == "password":
                self.password_input_count += 1
        elif tag == "iframe":
            self.iframe_count += 1
        elif tag == "script":
            self.script_count += 1
            src = attrs.get("src")
            if src:
                script_url = urllib.parse.urljoin(self.base_url, src)
                parsed_script = urllib.parse.urlparse(script_url)
                parsed_base = urllib.parse.urlparse(self.base_url)
                if parsed_script.hostname and parsed_script.hostname != parsed_base.hostname:
                    self.external_script_count += 1
            else:
                self.inline_script_count += 1
                self.in_script = True
        elif tag == "a":
            href = attrs.get("href")
            if href:
                self.link_count += 1
                link_url = urllib.parse.urljoin(self.base_url, href)
                parsed_link = urllib.parse.urlparse(link_url)
                parsed_base = urllib.parse.urlparse(self.base_url)
                if parsed_link.hostname and parsed_link.hostname != parsed_base.hostname:
                    self.external_link_count += 1

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False
        elif tag.lower() == "script":
            self.in_script = False

    def handle_data(self, data):
        text = data.strip()
        if not text:
            return

        if self.in_title:
            self.title_parts.append(text)
        elif self.in_script:
            if len(self.inline_script_parts) < 60:
                self.inline_script_parts.append(text[:4000])
        elif len(self.visible_text_parts) < 80:
            self.visible_text_parts.append(text)

    def to_dict(self):
        title = html.unescape(" ".join(self.title_parts)).strip()
        visible_text = " ".join(self.visible_text_parts).lower()
        inline_script = "\n".join(self.inline_script_parts)
        text_surface = visible_text + " " + title.lower()
        suspicious_keywords = sorted(
            keyword for keyword in TEXT_LEXICON["phishing"]
            if _keyword_in_text(keyword, text_surface)
        )
        defacement_keywords = sorted(
            keyword for keyword in TEXT_LEXICON["defacement"]
            if _keyword_in_text(keyword, text_surface)
        )
        malware_keywords = sorted(
            keyword for keyword in TEXT_LEXICON["malware"]
            if _keyword_in_text(keyword, text_surface)
        )
        js_eval_count = len(re.findall(r"\beval\s*\(", inline_script))
        js_document_write_count = len(re.findall(r"document\.write\s*\(", inline_script))
        js_atob_count = len(re.findall(r"\batob\s*\(", inline_script))
        js_long_string_count = len(re.findall(r"['\"][A-Za-z0-9+/=]{120,}['\"]", inline_script))
        js_obfuscation_score = min(
            1.0,
            0.25 * js_eval_count
            + 0.18 * js_document_write_count
            + 0.15 * js_atob_count
            + 0.12 * js_long_string_count,
        )

        return {
            "title": title[:180],
            "form_count": self.form_count,
            "external_form_action_count": self.external_form_action_count,
            "insecure_form_action_count": self.insecure_form_action_count,
            "password_input_count": self.password_input_count,
            "input_count": self.input_count,
            "iframe_count": self.iframe_count,
            "script_count": self.script_count,
            "external_script_count": self.external_script_count,
            "inline_script_count": self.inline_script_count,
            "js_eval_count": js_eval_count,
            "js_document_write_count": js_document_write_count,
            "js_atob_count": js_atob_count,
            "js_long_string_count": js_long_string_count,
            "js_obfuscation_score": round(js_obfuscation_score, 4),
            "link_count": self.link_count,
            "external_link_count": self.external_link_count,
            "suspicious_text_keywords": suspicious_keywords,
            "defacement_text_keywords": defacement_keywords,
            "malware_text_keywords": malware_keywords,
        }


def _inspect_ssl_certificate(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {
            "ssl_checked": False,
            "ssl_error": "not_https",
        }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:
        return {
            "ssl_checked": False,
            "ssl_error": type(exc).__name__,
        }

    not_after = cert.get("notAfter")
    days_until_expiry = None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_until_expiry = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            days_until_expiry = None

    issuer = ""
    issuer_parts = cert.get("issuer", [])
    for group in issuer_parts:
        for key, value in group:
            if key in {"organizationName", "commonName"}:
                issuer = value
                break
        if issuer:
            break

    san_hosts = [
        value.lower()
        for key, value in cert.get("subjectAltName", [])
        if key.lower() == "dns"
    ]
    host = parsed.hostname.lower()
    host_matches_cert = any(
        san == host or (san.startswith("*.") and host.endswith(san[1:]))
        for san in san_hosts
    )

    return {
        "ssl_checked": True,
        "ssl_issuer": issuer,
        "ssl_not_after": not_after,
        "ssl_days_until_expiry": days_until_expiry,
        "ssl_host_matches_cert": host_matches_cert,
    }


def inspect_url_page(url):
    normalized_url = _normalize_url(url)
    ssl_evidence = _inspect_ssl_certificate(normalized_url)
    allowed, block_reason = _is_public_http_url(normalized_url)
    if not allowed:
        return {
            "enabled": True,
            "fetched": False,
            "url": normalized_url,
            "error": block_reason,
            **ssl_evidence,
        }

    request = urllib.request.Request(
        normalized_url,
        headers={
            "User-Agent": "LinkWatcherEvidenceBot/1.0",
            "Accept": "text/html,application/xhtml+xml",
        },
        method="GET",
    )

    try:
        context = ssl.create_default_context()
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS, context=context) as response:
            final_url = response.geturl()
            status_code = response.getcode()
            content_type = response.headers.get("Content-Type", "")
            body = response.read(MAX_HTML_BYTES)
    except urllib.error.HTTPError as exc:
        return {
            "enabled": True,
            "fetched": False,
            "url": normalized_url,
            "status_code": exc.code,
            "error": "http_error",
            **ssl_evidence,
        }
    except Exception as exc:
        return {
            "enabled": True,
            "fetched": False,
            "url": normalized_url,
            "error": type(exc).__name__,
            **ssl_evidence,
        }

    if "html" not in content_type.lower():
        return {
            "enabled": True,
            "fetched": True,
            "url": normalized_url,
            "final_url": final_url,
            "status_code": status_code,
            "content_type": content_type,
            "redirected": final_url != normalized_url,
            "html_analyzed": False,
            **ssl_evidence,
        }

    charset_match = re.search(r"charset=([\w\-]+)", content_type, re.I)
    charset = charset_match.group(1) if charset_match else "utf-8"
    text = body.decode(charset, errors="ignore")

    parser = PageSignalParser(final_url)
    parser.feed(text)
    signals = parser.to_dict()

    return {
        "enabled": True,
        "fetched": True,
        "url": normalized_url,
        "final_url": final_url,
        "status_code": status_code,
        "content_type": content_type,
        "redirected": final_url != normalized_url,
        "html_analyzed": True,
        **ssl_evidence,
        **signals,
    }
