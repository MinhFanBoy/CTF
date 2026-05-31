from flask import Flask, send_from_directory

from backend import config
from backend.middleware.error_handler import register_error_handlers
from backend.routers import admin_bp, auth_bp, user_bp
from backend.services.auth_service import AuthService


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["FRONTEND_DIR"] = config.FRONTEND_DIR
    app.auth_service = AuthService()

    register_error_handlers(app)
    app.register_blueprint(user_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    @app.get("/public/<path:path>")
    def public_assets(path: str):
        return send_from_directory(config.FRONTEND_DIR, path)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
