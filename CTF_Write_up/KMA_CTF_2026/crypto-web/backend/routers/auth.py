from flask import Blueprint, current_app, jsonify, request

from backend.middleware.auth_middleware import reject_large_payload, require_json
from backend.models.schemas import ApiError


auth_bp = Blueprint("auth", __name__, url_prefix="/api")


@auth_bp.post("/register")
@reject_large_payload
@require_json
def register():
    data = request.get_json() or {}
    for key in ["email", "username", "account_id", "device_id"]:
        if key not in data:
            raise ApiError("email, username, account_id, and device_id are required.")
    return jsonify(
        current_app.auth_service.register_client(
            data["email"],
            data["username"],
            data["account_id"],
            data["device_id"],
        )
    )


@auth_bp.get("/material")
def material():
    raise ApiError("Registration receipt is only available after login.", 403)


@auth_bp.post("/wait_login")
@reject_large_payload
@require_json
def wait_login():
    data = request.get_json() or {}
    for key in ["username", "account_id", "device_id"]:
        if key not in data:
            raise ApiError("username, account_id, and device_id are required.")
    return jsonify(current_app.auth_service.create_login(data["username"], data["account_id"], data["device_id"]))


@auth_bp.post("/send_login")
@reject_large_payload
@require_json
def send_login():
    data = request.get_json() or {}
    for key in ["username", "login_id", "share_key_enc", "master_key_enc", "tag"]:
        if key not in data:
            raise ApiError("username, login_id, share_key_enc, master_key_enc, and tag are required.")

    return jsonify(
        current_app.auth_service.process_login(
            username=data["username"],
            login_id=data["login_id"],
            share_key_enc_hex=data["share_key_enc"],
            master_key_enc_hex=data["master_key_enc"],
            tag_hex=data["tag"],
        )
    )
