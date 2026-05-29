import re

from .errors import APIError


CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def normalize_prediction_request(payload, settings):
    if not isinstance(payload, dict):
        raise APIError(
            "invalid_json",
            "Request body must be a JSON object.",
            status_code=400,
        )

    urls = payload.get("urls")
    if urls is None:
        url = payload.get("url")
        urls = [url] if url is not None else []

    if isinstance(urls, str):
        urls = [urls]

    if not isinstance(urls, list):
        raise APIError(
            "invalid_urls",
            "The urls field must be a string or a list of strings.",
            status_code=400,
        )

    normalized = []
    for raw_url in urls:
        if raw_url is None:
            continue

        url = str(raw_url).strip()
        if not url:
            continue

        if CONTROL_CHARS.search(url):
            raise APIError(
                "invalid_url",
                "URL contains unsupported control characters.",
                status_code=400,
            )

        if len(url) > settings.max_url_length:
            raise APIError(
                "url_too_long",
                f"URL length must be {settings.max_url_length} characters or less.",
                status_code=400,
            )

        normalized.append(url)

    if not normalized:
        raise APIError(
            "missing_url",
            "Provide a url string or a non-empty urls list.",
            status_code=400,
        )

    if len(normalized) > settings.max_urls_per_request:
        raise APIError(
            "too_many_urls",
            f"Analyze at most {settings.max_urls_per_request} URLs per request.",
            status_code=400,
        )

    debug_requested = bool(payload.get("debug", False))
    options = {
        "inspect_page": bool(
            payload.get("inspect_page", settings.inspect_page_default)
        ),
        "debug": debug_requested and settings.debug_responses_enabled,
    }

    return normalized, options
