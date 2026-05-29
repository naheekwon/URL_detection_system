from backend import create_app
from backend.config import BackendSettings


settings = BackendSettings.from_env()
app = create_app(settings)


if __name__ == "__main__":
    app.run(
        host=settings.host,
        port=settings.port,
        debug=False,
        use_reloader=False,
    )
