import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]


def _get_bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name, default):
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


def _get_list(name, default):
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class BackendSettings:
    project_dir: Path
    frontend_dir: Path
    host: str
    port: int
    environment: str
    log_level: str
    cors_origins: list
    max_urls_per_request: int
    max_url_length: int
    max_content_length: int
    inspect_page_default: bool
    debug_responses_enabled: bool
    rate_limit_enabled: bool
    rate_limit_requests: int
    rate_limit_window_seconds: int

    @classmethod
    def from_env(cls):
        project_dir = Path(os.environ.get("PROJECT_DIR", PROJECT_DIR)).resolve()
        return cls(
            project_dir=project_dir,
            frontend_dir=Path(
                os.environ.get("FRONTEND_DIR", project_dir / "frontend")
            ).resolve(),
            host=os.environ.get("HOST", "0.0.0.0"),
            port=_get_int("PORT", 8765),
            environment=os.environ.get("APP_ENV", "production"),
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
            cors_origins=_get_list("CORS_ORIGINS", ["*"]),
            max_urls_per_request=_get_int("MAX_URLS_PER_REQUEST", 10),
            max_url_length=_get_int("MAX_URL_LENGTH", 2048),
            max_content_length=_get_int("MAX_CONTENT_LENGTH", 64 * 1024),
            inspect_page_default=_get_bool("INSPECT_PAGE_DEFAULT", True),
            debug_responses_enabled=_get_bool("DEBUG_RESPONSES_ENABLED", False),
            rate_limit_enabled=_get_bool("RATE_LIMIT_ENABLED", True),
            rate_limit_requests=_get_int("RATE_LIMIT_REQUESTS", 60),
            rate_limit_window_seconds=_get_int("RATE_LIMIT_WINDOW_SECONDS", 60),
        )
