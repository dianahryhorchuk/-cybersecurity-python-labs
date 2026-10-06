from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re

PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900

EMAIL_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+$")


class User:
    """Базовий клас користувача з інкапсуляцією пароля та валідацією пошти."""

    def __init__(self, username: str, email: str, role: str = "user", active: bool = True):
        self.username = username
        self.role = role
        self.active = active
        self._email = ""
        self.email = email
        self.__password_salt = os.urandom(16)
        self.__password_hash = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not EMAIL_REGEX.match(value):
            raise ValueError(f"Некоректний формат email-адреси: {value}")
        self._email = value

    def set_password(self, password: str) -> None:
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash:
            return False
        computed = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(self.__password_hash, computed)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        return f"User(username='{self.username}', email='{self.email}', role='{self.role}', active={self.active})"


class Admin(User):
    """Клас адміністратора, що наслідує User і додає права доступу."""

    def __init__(self, username: str, email: str, permissions=None, active: bool = True):
        super().__init__(username, email, role="admin", active=active)
        # Використання None замість змінюваної колекції в аргументах
        self.permissions = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        return f"Admin(username='{self.username}', email='{self.email}', permissions={list(self.permissions)})"


class Session:
    """Клас активної сесії користувача з контролем таймауту в часовому поясі UTC."""

    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec повинен бути додатним числом")
        elapsed = datetime.now(timezone.utc) - self.last_activity
        return elapsed < timedelta(seconds=timeout_sec)


@dataclass
class AuditRecord:
    """Незмінний запис журналу безпеки."""
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту подій безпеки."""

    def __init__(self):
        self._records = []

    def add_log(self, username: str, action: str) -> None:
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action
        )
        self._records.append(record)

    def show_all(self):
        return list(self._records)


class UserAccount:
    """Обліковий запис, що реалізує композицію User, Session та AuditLog."""

    def __init__(self, user: User, audit_log=None):
        self._user = user
        self._session = None
        self._audit = audit_log if audit_log else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if self._user.username == username and self._user.active and self._user.check_password(password):
            self._session = Session(ip)
            self._session.touch()
            self._audit.add_log(username, "login_success")
            return True
        
        self._audit.add_log(username, "login_failure")
        return False

    def is_authenticated(self) -> bool:
        if self._session:
            return self._session.is_active(SESSION_TIMEOUT_SEC)
        return False

    def logout(self) -> None:
        if self._session:
            self._audit.add_log(self._user.username, "logout")
            self._session = None

    def __getitem__(self, key: str):
        if key == "user":
            return self._user
        elif key == "session":
            return self._session
        elif key == "audit":
            return self._audit
        else:
            raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key: str, value) -> None:
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення має бути типу User")
            self._user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Значення має бути типу Session або None")
            self._session = value
        elif key == "audit":
            if not isinstance(value, AuditLog):
                raise TypeError("Значення має бути типу AuditLog")
            self._audit = value
        else:
            raise KeyError(f"Невідомий ключ: {key}")