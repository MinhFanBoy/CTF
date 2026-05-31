from flask import Blueprint, jsonify

from backend.models.schemas import ApiError


admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.get("/health")
def health():
    return jsonify({"ok": True})


@admin_bp.post("/reset")
def reset():
    raise ApiError("Not found.", 404)