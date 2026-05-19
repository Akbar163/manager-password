"""
crypto.py — модуль криптографии
Отвечает за:
  - деривацию ключа из мастер-пароля (PBKDF2 / scrypt)
  - шифрование / дешифрование данных (Fernet / AES-128-CBC)
  - хранение и верификацию хэша мастер-пароля
"""

import os
import base64
import hashlib
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes


# ─── Константы ────────────────────────────────────────────────────────────────

PBKDF2_ITERATIONS = 600_000   # NIST рекомендует ≥ 600 000 для SHA-256 (2023)
SCRYPT_N          = 2**14     # CPU/memory cost (16 384 — баланс скорость/память)
SCRYPT_R          = 8         # block size
SCRYPT_P          = 1         # parallelisation factor
SALT_SIZE         = 32        # байт (256 бит)
KDF_ALGO          = "pbkdf2"  # "pbkdf2" | "scrypt"


# ─── Деривация ключа ──────────────────────────────────────────────────────────

def derive_key(master_password: str, salt: bytes, algo: str = KDF_ALGO) -> bytes:
    """
    Выводит 256-битный ключ из мастер-пароля с помощью KDF.

    PBKDF2-HMAC-SHA256:
        Применяет HMAC-SHA256 PBKDF2_ITERATIONS раз.
        Устойчив к bruteforce, поддерживается везде.

    scrypt:
        Memory-hard функция — требует больше RAM при атаке,
        что значительно удорожает перебор на GPU/ASIC.
    """
    password_bytes = master_password.encode("utf-8")

    if algo == "scrypt":
        kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        key_raw = kdf.derive(password_bytes)
    else:  # pbkdf2 (default)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key_raw = kdf.derive(password_bytes)

    # Fernet требует 32 байта в base64url-кодировке
    return base64.urlsafe_b64encode(key_raw)


def new_salt() -> bytes:
    """Генерирует криптостойкую соль через os.urandom."""
    return os.urandom(SALT_SIZE)


# ─── Fernet-шифрование ────────────────────────────────────────────────────────

def encrypt(data: str, fernet_key: bytes) -> str:
    """
    Шифрует строку через Fernet (AES-128-CBC + HMAC-SHA256).
    Возвращает зашифрованное значение как base64-строку.
    """
    f = Fernet(fernet_key)
    return f.encrypt(data.encode("utf-8")).decode("utf-8")


def decrypt(token: str, fernet_key: bytes) -> str:
    """
    Дешифрует Fernet-токен. Бросает InvalidToken при неверном ключе.
    """
    f = Fernet(fernet_key)
    return f.decrypt(token.encode("utf-8")).decode("utf-8")


def encrypt_dict(data: dict, fernet_key: bytes) -> str:
    """Сериализует словарь в JSON и шифрует."""
    return encrypt(json.dumps(data, ensure_ascii=False), fernet_key)


def decrypt_dict(token: str, fernet_key: bytes) -> dict:
    """Дешифрует и десериализует JSON-словарь."""
    return json.loads(decrypt(token, fernet_key))


# ─── Мастер-пароль: хранение хэша ────────────────────────────────────────────

def hash_master_password(master_password: str, salt: bytes) -> str:
    """
    Создаёт верификационный хэш мастер-пароля для аутентификации.
    Используем отдельный PBKDF2 с другим числом итераций,
    чтобы хэш для проверки и ключ шифрования были независимы.

    Возвращает hex-строку хэша (256 бит).
    """
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt + b"_auth",       # domain separation: к соли добавляем суффикс
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    return dk.hex()


def verify_master_password(master_password: str, salt: bytes, stored_hash: str) -> bool:
    """Сравнивает хэш в постоянное время (hmac.compare_digest) — защита от timing-атак."""
    import hmac
    expected = hash_master_password(master_password, salt)
    # compare_digest не допускает раннего выхода при несовпадении
    return hmac.compare_digest(expected, stored_hash)
