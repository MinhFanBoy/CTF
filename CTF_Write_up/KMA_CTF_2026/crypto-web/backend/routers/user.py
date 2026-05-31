from flask import Blueprint, current_app, send_from_directory


user_bp = Blueprint("user", __name__)


@user_bp.get("/")
def index():
    return send_from_directory(current_app.config["FRONTEND_DIR"], "index.html")


@user_bp.get("/dashboard")
def dashboard():
    return send_from_directory(current_app.config["FRONTEND_DIR"], "dashboard.html")
