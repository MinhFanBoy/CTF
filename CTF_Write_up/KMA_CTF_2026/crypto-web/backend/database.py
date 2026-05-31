from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from backend import config
from backend.models.schemas import LoginSession
from backend.models.user import UserProfile
from backend.services.crypto_service import RegisteredClient


@dataclass
class UserRecord:
    profile: UserProfile
    client: RegisteredClient
    sessions: Dict[str, LoginSession] = field(default_factory=dict)
    login_remaining: int = config.MAX_LOGIN_ATTEMPTS


@dataclass
class InMemoryDatabase:
    users_by_username: Dict[str, UserRecord] = field(default_factory=dict)
    usernames_by_email: Dict[str, str] = field(default_factory=dict)
    account_ids: Dict[int, str] = field(default_factory=dict)
    device_ids: Dict[int, str] = field(default_factory=dict)

    def reset(self) -> None:
        self.users_by_username.clear()
        self.usernames_by_email.clear()
        self.account_ids.clear()
        self.device_ids.clear()
