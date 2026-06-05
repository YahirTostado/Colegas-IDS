"""
Autenticación simple para la sección de configuración de administrador.
Usa PBKDF2-SHA256 con sal — sin dependencias externas.
"""
import hashlib
import json
import os

SETTINGS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "settings.json")

DEFAULT_SALT = "ids_salt_2024"


def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 100_000
    ).hex()


def verify_password(password: str) -> bool:
    settings = _load()
    stored = settings.get("admin_password_hash", "")
    salt = settings.get("admin_salt", DEFAULT_SALT)
    return _hash(password, salt) == stored


def change_password(new_password: str) -> None:
    settings = _load()
    settings["admin_password_hash"] = _hash(new_password, DEFAULT_SALT)
    settings["admin_salt"] = DEFAULT_SALT
    _save(settings)


def _load() -> dict:
    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict) -> None:
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
