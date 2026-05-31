from functools import wraps
from flask import request
from backend.config import MAX_PAYLOAD_HEX_CHARS
from backend.models.schemas import ApiError


def require_json(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not request.is_json:
            raise ApiError("Expected JSON request body.", 415)
        return fn(*args, **kwargs)
    return wrapper


def reject_large_payload(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.content_length and request.content_length > MAX_PAYLOAD_HEX_CHARS:
            raise ApiError("Payload is too large.", 413)
        return fn(*args, **kwargs)
    return wrapper
