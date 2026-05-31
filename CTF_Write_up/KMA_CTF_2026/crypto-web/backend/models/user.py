from dataclasses import dataclass


@dataclass
class UserProfile:
    email: str
    username: str
    account_id: int
    device_id: int


DEFAULT_USER = UserProfile(email="alice@kma.local", username="Alice", account_id=123456, device_id=789012)
