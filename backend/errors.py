from werkzeug.exceptions import HTTPException, RequestEntityTooLarge


class APIError(Exception):
    def __init__(self, code, message, status_code=400, extra=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.extra = extra or {}


def register_error_handlers(app):
    @app.errorhandler(APIError)
    def handle_api_error(error):
        payload = {
            "error": {
                "code": error.code,
                "message": error.message,
            }
        }
        payload["error"].update(error.extra)
        return payload, error.status_code

    @app.errorhandler(RequestEntityTooLarge)
    def handle_payload_too_large(error):
        return {
            "error": {
                "code": "payload_too_large",
                "message": "Request body is too large.",
            }
        }, 413

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return {
            "error": {
                "code": error.name.lower().replace(" ", "_"),
                "message": error.description,
            }
        }, error.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        app.logger.exception("Unhandled backend error")
        return {
            "error": {
                "code": "internal_server_error",
                "message": "The backend could not complete the request.",
            }
        }, 500
