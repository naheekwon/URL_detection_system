import logging
import time
from uuid import uuid4

from flask import Flask, g, request

from .config import BackendSettings
from .errors import APIError, register_error_handlers
from .rate_limit import InMemoryRateLimiter
from .routes import create_api_blueprint


def create_app(settings=None):
    settings = settings or BackendSettings.from_env()

    app = Flask(
        __name__,
        static_folder=str(settings.frontend_dir),
        static_url_path="",
    )
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = settings.max_content_length
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.config["BACKEND_SETTINGS"] = settings

    configure_logging(settings)
    register_error_handlers(app)

    rate_limiter = InMemoryRateLimiter(
        max_requests=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )

    @app.before_request
    def before_request():
        g.request_id = request.headers.get("X-Request-ID", str(uuid4()))
        g.started_at = time.time()

        if request.method == "OPTIONS":
            return None

        if settings.rate_limit_enabled:
            client_id = request.headers.get(
                "X-Forwarded-For",
                request.remote_addr or "local",
            ).split(",")[0].strip()
            allowed, retry_after = rate_limiter.allow(client_id)
            if not allowed:
                raise APIError(
                    "rate_limit_exceeded",
                    "Too many requests. Please try again later.",
                    status_code=429,
                    extra={"retry_after_seconds": retry_after},
                )

        return None

    @app.after_request
    def after_request(response):
        apply_http_headers(response, settings)
        response.headers["X-Request-ID"] = g.get("request_id", "")

        elapsed_ms = int((time.time() - g.get("started_at", time.time())) * 1000)
        app.logger.info(
            "%s %s %s %sms request_id=%s",
            request.method,
            request.path,
            response.status_code,
            elapsed_ms,
            g.get("request_id", ""),
        )
        return response

    app.register_blueprint(create_api_blueprint(settings))

    return app


def configure_logging(settings):
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def apply_http_headers(response, settings):
    origin = request.headers.get("Origin")

    if settings.cors_origins == ["*"]:
        response.headers["Access-Control-Allow-Origin"] = "*"
    elif origin in settings.cors_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"

    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Request-ID"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.cache_control.no_store = True
    response.cache_control.no_cache = True
    response.cache_control.must_revalidate = True
    response.cache_control.max_age = 0
    response.headers["Pragma"] = "no-cache"

    return response
