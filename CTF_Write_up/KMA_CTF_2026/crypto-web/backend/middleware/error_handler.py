from flask import jsonify
from backend.models.schemas import ApiError


def register_error_handlers(app):
    @app.errorhandler(ApiError)
    def handle_api_error(error: ApiError):
        return jsonify({"ok": False, "error": error.message}), error.status_code

    @app.errorhandler(404)
    def handle_not_found(_):
        return jsonify({"ok": False, "error": "Not found."}), 404

    @app.errorhandler(500)
    def handle_internal_error(_):
        return jsonify({"ok": False, "error": "Internal server error."}), 500
