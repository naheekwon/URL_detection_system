from flask import Blueprint, current_app, jsonify, request, send_from_directory

from .errors import APIError
from .validation import normalize_prediction_request


def create_api_blueprint(settings):
    bp = Blueprint("backend", __name__)

    @bp.route("/")
    def index():
        return send_from_directory(settings.frontend_dir, "index.html")

    @bp.route("/architecture.png")
    def frontend_architecture_image():
        return send_from_directory(settings.frontend_dir, "architecture.png")

    @bp.route("/health")
    @bp.route("/api/health")
    def health():
        runtime = get_model_runtime()
        return jsonify({
            "status": "ok",
            "service": "linkwatcher-backend",
            "environment": settings.environment,
            "model_loaded": True,
            "model_family": runtime.config["model_family"],
            "classes": runtime.class_names,
            "meta_gate_enabled": runtime.meta_gate_enabled,
            "meta_gate_model_family": runtime.meta_gate_config.get("model_family"),
            "meta_gate_threshold": runtime.meta_gate_threshold,
        })

    @bp.route("/api/backend-info")
    def backend_info():
        runtime = get_model_runtime()
        return jsonify({
            "backend_role": "Production-ready Flask web backend for URL risk analysis",
            "deployment_status": "ready_for_wsgi_deployment",
            "frontend_serving": {
                "route": "GET /",
                "directory": str(settings.frontend_dir),
                "entrypoint": "index.html",
            },
            "api_endpoints": {
                "health": "GET /api/health",
                "predict": "POST /api/predict",
                "backend_info": "GET /api/backend-info",
            },
            "operational_features": [
                "application factory",
                "environment-based configuration",
                "centralized JSON error handling",
                "request validation",
                "basic rate limiting",
                "security headers",
                "request logging",
                "WSGI entrypoint",
            ],
            "prediction_pipeline": [
                "URL request from frontend",
                "request validation",
                "model inference",
                "evidence decision",
                "XAI JSON response",
            ],
            "classes": runtime.class_names,
        })

    @bp.route("/api/predict", methods=["POST", "OPTIONS"])
    def predict():
        if request.method == "OPTIONS":
            return ("", 204)

        payload = request.get_json(silent=True)
        urls, options = normalize_prediction_request(payload, settings)

        try:
            runtime = get_model_runtime()
            results, stats = runtime.hybrid_predict(
                urls,
                inspect_pages=options["inspect_page"],
                include_debug=options["debug"],
            )
        except APIError:
            raise
        except Exception:
            current_app.logger.exception("Prediction failed")
            raise APIError(
                "prediction_failed",
                "The backend failed while analyzing the requested URL.",
                status_code=500,
            )

        response = {
            "results": results,
            "stats": stats,
            "request": {
                "url_count": len(urls),
                "inspect_page": options["inspect_page"],
                "debug": options["debug"],
            },
        }

        if len(results) == 1:
            response.update(results[0])

        return jsonify(response)

    return bp


def get_model_runtime():
    import app as model_runtime

    return model_runtime
