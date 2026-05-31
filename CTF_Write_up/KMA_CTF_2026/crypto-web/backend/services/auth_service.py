from __future__ import annotations

import hmac
import threading
import uuid
from Crypto.Util.number import long_to_bytes

from backend import config
from backend.database import InMemoryDatabase, UserRecord
from backend.models.schemas import ApiError, LoginSession
from backend.models.user import UserProfile
from backend.services.crypto_service import (
    LoginVerifier,
    RegisteredClient,
    encode_sid,
    encrypt_flag,
    random_sid_state,
)


class AuthService:
    def __init__(self):
        self.db = InMemoryDatabase()
        self._register_lock = threading.Lock()

    @staticmethod
    def _normalize_text(value: str, field_name: str, limit: int = 80) -> str:
        value = (value or "").strip()
        if not value:
            raise ApiError(f"{field_name} is required.")
        if len(value) > limit:
            raise ApiError(f"{field_name} is too long.")
        return value

    def _get_user_record(self, username_key: str) -> UserRecord:
        record = self.db.users_by_username.get(username_key)
        if record is None:
            raise ApiError("No registered device for this username.", 404)
        return record

    @staticmethod
    def _normalize_account_id(value) -> int:
        if isinstance(value, bool):
            raise ApiError("account_id must be a decimal integer.")
        if isinstance(value, int):
            raw_account_id = value
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                raise ApiError("account_id is required.")
            try:
                raw_account_id = int(text, 10)
            except ValueError as exc:
                raise ApiError("account_id must be a decimal integer.") from exc
        else:
            raise ApiError("account_id must be a decimal integer.")

        if not (0 <= raw_account_id < config.ACCOUNT_ID_MAX):
            raise ApiError(
                f"account_id must be a decimal integer between 0 and {config.ACCOUNT_ID_MAX - 1}."
            )
        return raw_account_id

    @staticmethod
    def _normalize_device_id(value) -> int:
        if isinstance(value, bool):
            raise ApiError("device_id must be a decimal integer.")
        if isinstance(value, int):
            raw_device_id = value
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                raise ApiError("device_id is required.")
            try:
                raw_device_id = int(text, 10)
            except ValueError as exc:
                raise ApiError("device_id must be a decimal integer.") from exc
        else:
            raise ApiError("device_id must be a decimal integer.")

        if not (0 <= raw_device_id < config.DEVICE_ID_MAX):
            raise ApiError(
                f"device_id must be a decimal integer between 0 and {config.DEVICE_ID_MAX - 1}."
            )
        return raw_device_id

    @staticmethod
    def _hex_to_bytes(value: str, field_name: str) -> bytes:
        try:
            return bytes.fromhex((value or "").strip())
        except ValueError as exc:
            raise ApiError(f"{field_name} must be valid hex.") from exc

    @staticmethod
    def _material_payload(
        record: UserRecord,
        include_ok: bool = False,
        message: str | None = None,
        login_id: str | None = None,
    ) -> dict:
        material = record.client.public_material()
        n, e = material.share_key_pub

        payload = {
            "user": {
                "email": record.profile.email,
                "username": record.profile.username,
                "account_id": str(record.profile.account_id),
                "device_id": str(record.profile.device_id),
            },
            "auth_key_hashed": material.auth_key_hashed,
            "master_key_enc": material.master_key_enc.hex(),
            "share_key_pub": [str(n), int(e)],
            "share_key_nonce": material.share_key_nonce.hex(),
            "share_key_enc": material.share_key_enc.hex(),
            "tag": material.share_key_tag.hex(),
        }
        if login_id:
            payload["login_id"] = login_id
        if include_ok:
            payload["ok"] = True
        if message:
            payload["message"] = message
        return payload

    @staticmethod
    def _registration_response(record: UserRecord, message: str) -> dict:
        return {
            "ok": True,
            "message": message,
            "user": {
                "email": record.profile.email,
                "username": record.profile.username,
                "account_id": str(record.profile.account_id),
                "device_id": str(record.profile.device_id),
            },
        }

    def register_client(self, email: str, username: str, account_id, device_id) -> dict:
        email = self._normalize_text(email, "email")
        username = self._normalize_text(username, "username")
        account_id = self._normalize_account_id(account_id)
        device_id = self._normalize_device_id(device_id)

        if "@" not in email or "." not in email.split("@")[-1]:
            raise ApiError("email must look like a valid email address.")

        email_key = email.lower()
        username_key = username.lower()

        with self._register_lock:
            existing_record = self.db.users_by_username.get(username_key)
            if existing_record is not None:
                if existing_record.profile.email.lower() != email_key:
                    raise ApiError("username is already linked to another email.", 409)
                if existing_record.profile.account_id != account_id:
                    raise ApiError("username is already registered with a different account_id.", 409)
                if existing_record.profile.device_id != device_id:
                    raise ApiError("username is already registered with a different device_id.", 409)
                return self._registration_response(
                    existing_record,
                    "Account already registered. Login with username, account_id, and device_id to obtain the registration receipt.",
                )

            existing_username = self.db.usernames_by_email.get(email_key)
            if existing_username and existing_username != username_key:
                raise ApiError("email is already linked to another username.", 409)

            existing_account_username = self.db.account_ids.get(account_id)
            if existing_account_username and existing_account_username != username_key:
                raise ApiError("account_id is already registered.", 409)

            existing_device_username = self.db.device_ids.get(device_id)
            if existing_device_username and existing_device_username != username_key:
                raise ApiError("device_id is already registered.", 409)

            record = UserRecord(
                profile=UserProfile(email=email, username=username, account_id=account_id, device_id=device_id),
                client=RegisteredClient(config.PASSWORD, config.SALT, account_id, device_id),
            )

            self.db.users_by_username[username_key] = record
            self.db.usernames_by_email[email_key] = username_key
            self.db.account_ids[account_id] = username_key
            self.db.device_ids[device_id] = username_key

            return self._registration_response(
                record,
                "Account registered. Login with username, account_id, and device_id to obtain the registration receipt.",
            )

    def registration_material(
        self,
        username: str,
        include_ok: bool = False,
        message: str | None = None,
    ) -> dict:
        username_key = self._normalize_text(username, "username").lower()
        record = self._get_user_record(username_key)
        return self._material_payload(record, include_ok=include_ok, message=message)

    def create_login(self, username: str, account_id, device_id) -> dict:
        username_key = self._normalize_text(username, "username").lower()
        account_id = self._normalize_account_id(account_id)
        device_id = self._normalize_device_id(device_id)
        record = self._get_user_record(username_key)

        if record.profile.account_id != account_id:
            raise ApiError("account_id does not match this username.")
        if record.profile.device_id != device_id:
            raise ApiError("device_id does not match this username.")

        if record.login_remaining <= 0:
            raise ApiError("This account has no login attempts remaining. Please create a new account.")
        record.login_remaining -= 1

        n, e = record.client.share_key_pub

        state = random_sid_state()
        sid_int = encode_sid(state)
        sid_plain = long_to_bytes(sid_int)
        sid_enc = long_to_bytes(pow(sid_int, e, n), config.RSA_BITS // 8)

        iv, encrypted_flag = encrypt_flag(record.client.share_key.p)

        login_id = uuid.uuid4().hex
        record.sessions[login_id] = LoginSession(
            sid_enc=sid_enc,
            sid_plain=sid_plain,
            iv=iv,
            encrypted_flag=encrypted_flag,
        )


        return {
            "ok": True,
            "login_id": login_id,
            "message": f"{record.profile.username} is signing in from a new device.",
            "auth_key_hashed": record.client.auth_key_hashed,
            "encrypted_flag": encrypted_flag.hex(),
            "iv": iv.hex(),
            "registration_receipt": self._material_payload(record, login_id=login_id),
        }

    def process_login(
        self,
        username: str,
        login_id: str,
        share_key_enc_hex: str,
        master_key_enc_hex: str,
        tag_hex: str,
    ) -> dict:
        username_key = self._normalize_text(username, "username").lower()
        login_id = self._normalize_text(login_id, "login_id", limit=128)

        record = self._get_user_record(username_key)

        if login_id not in record.sessions:
            raise ApiError("Unknown or expired login_id.", 404)

        session = record.sessions[login_id]

        share_key_enc = self._hex_to_bytes(share_key_enc_hex, "share_key_enc")
        master_key_enc = self._hex_to_bytes(master_key_enc_hex, "master_key_enc")
        tag = self._hex_to_bytes(tag_hex, "tag")

        if len(share_key_enc) != config.KEY_BLOB_LEN:
            raise ApiError(f"share_key_enc must be exactly {config.KEY_BLOB_LEN} bytes.")
        if len(master_key_enc) != 16:
            raise ApiError("master_key_enc must be exactly 16 bytes.")
        if len(tag) != config.GCM_TAG_SIZE:
            raise ApiError(f"tag must be exactly {config.GCM_TAG_SIZE} bytes.")

        registered_master_key_enc = record.client.master_key_enc

        if not hmac.compare_digest(master_key_enc, registered_master_key_enc):
            return {
                "ok": False,
                "status": "Client material rejected.",
            }

        verifier = LoginVerifier(config.PASSWORD, config.SALT)

        try:
            sid = verifier.login_step2(
                session.sid_enc,
                share_key_enc,
                tag,
                record.client.share_key_nonce,
                record.client.share_key_mask,
                master_key_enc,
            )
        except Exception:
            raise ApiError("An error occurred during login.")

        del record.sessions[login_id]

        if sid == session.sid_plain:
            return {
                "ok": True,
                "status": "Login accepted.",
            }

        return {
            "ok": False,
            "status": "Login rejected by session verifier.",
            "debug": sid.hex(),
        }
        
    def reset(self) -> dict:
        self.db.reset()
        return {"ok": True, "message": "Challenge state reset."}
