"""
Autenticación del administrador del IDS.

Principios de seguridad:
  - La contraseña NUNCA se almacena en texto plano: solo su hash PBKDF2-SHA256
    con una sal ALEATORIA generada por instalación (no hardcodeada).
  - NO existe ninguna credencial por defecto en el código.
  - Las credenciales iniciales (usuario + contraseña) se aprovisionan UNA sola
    vez desde el archivo .env (IDS_ADMIN_USER / IDS_ADMIN_PASSWORD) y se
    convierten en hash dentro de config/settings.json en el primer arranque.
    El texto plano vive únicamente en el .env (cifrado con OpenSSL y fuera de
    git); settings.json solo contiene el hash y la sal.
"""
import hashlib
import hmac
import json
import os
import secrets

ROOT          = os.path.dirname(os.path.dirname(__file__))
SETTINGS_PATH = os.path.join(ROOT, "config", "settings.json")
ENV_PATH      = os.path.join(ROOT, ".env")

PBKDF2_ITERATIONS = 200_000


# ──────────────────────────────────────────────────────────────
# Utilidades internas
# ──────────────────────────────────────────────────────────────
def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS
    ).hex()


def _load() -> dict:
    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict) -> None:
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _read_env_bootstrap() -> dict:
    """Lee IDS_ADMIN_USER / IDS_ADMIN_PASSWORD del .env (si existe)."""
    creds = {"user": "", "password": ""}
    if not os.path.exists(ENV_PATH):
        return creds
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            if key.strip() == "IDS_ADMIN_USER":
                creds["user"] = val.strip()
            elif key.strip() == "IDS_ADMIN_PASSWORD":
                creds["password"] = val.strip()
    return creds


# ──────────────────────────────────────────────────────────────
# API pública
# ──────────────────────────────────────────────────────────────
def is_configured() -> bool:
    """True si ya existe un administrador con contraseña establecida."""
    s = _load()
    return bool(s.get("admin_password_hash")) and bool(s.get("admin_salt"))


def set_credentials(user: str, password: str) -> None:
    """Crea/actualiza usuario + contraseña (hash con sal aleatoria NUEVA)."""
    salt = secrets.token_hex(16)
    s = _load()
    s["admin_user"]          = user.strip()
    s["admin_salt"]          = salt
    s["admin_password_hash"] = _hash(password, salt)
    _save(s)


def ensure_admin_bootstrapped() -> bool:
    """
    Primer arranque: si aún no hay administrador configurado, lo crea a partir
    de las credenciales del .env (IDS_ADMIN_USER / IDS_ADMIN_PASSWORD).
    Devuelve True si quedó un administrador configurado, False si faltan las
    credenciales en el .env (el manual indica definirlas antes del primer uso).
    """
    if is_configured():
        return True
    boot = _read_env_bootstrap()
    if not boot["user"] or not boot["password"]:
        return False
    set_credentials(boot["user"], boot["password"])
    return True


def verify_credentials(user: str, password: str) -> bool:
    """Verifica usuario + contraseña (comparación en tiempo constante)."""
    s = _load()
    stored_user = s.get("admin_user", "")
    stored_hash = s.get("admin_password_hash", "")
    salt        = s.get("admin_salt", "")
    if not stored_hash or not salt:
        return False
    user_ok = hmac.compare_digest(user.strip(), stored_user)
    pass_ok = hmac.compare_digest(_hash(password, salt), stored_hash)
    return user_ok and pass_ok


def verify_password(password: str) -> bool:
    """
    Verifica solo la contraseña (se usa al cambiar contraseña ya dentro de la
    sesión, donde el usuario ya está autenticado).
    """
    s = _load()
    stored_hash = s.get("admin_password_hash", "")
    salt        = s.get("admin_salt", "")
    if not stored_hash or not salt:
        return False
    return hmac.compare_digest(_hash(password, salt), stored_hash)


def change_password(new_password: str) -> None:
    """Cambia la contraseña conservando el usuario, con sal aleatoria nueva."""
    s = _load()
    user = s.get("admin_user", "")
    set_credentials(user, new_password)
