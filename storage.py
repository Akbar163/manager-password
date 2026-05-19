"""
storage.py — модуль хранения данных

Структура файла vault.json (всё чувствительное — зашифровано):
{
    "version": "1.0",
    "kdf": "pbkdf2",
    "salt": "<base64>",
    "master_hash": "<hex>",
    "entries": "<fernet_token>"   ← зашифрованный JSON-массив записей
}

Ни один пароль, ни один логин никогда не хранятся в открытом виде.
"""

import os
import json
import base64
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any

from cryptography.fernet import InvalidToken

import crypto as _crypto


# ─── Пути к файлам ────────────────────────────────────────────────────────────

DEFAULT_VAULT_PATH = Path.home() / ".password_manager" / "vault.json"
DEFAULT_LOG_PATH   = Path.home() / ".password_manager" / "activity.log"


def _ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


# ─── Vault: инициализация ────────────────────────────────────────────────────

def vault_exists(path: Path = DEFAULT_VAULT_PATH) -> bool:
    return path.exists()


def init_vault(master_password: str,
               path: Path = DEFAULT_VAULT_PATH,
               kdf: str = "pbkdf2") -> None:
    """
    Создаёт новое хранилище:
      1. Генерирует криптостойкую соль (32 байта).
      2. Вычисляет хэш мастер-пароля для последующей верификации.
      3. Шифрует пустой список записей и сохраняет.
    """
    _ensure_dir(path)

    salt = _crypto.new_salt()
    master_hash = _crypto.hash_master_password(master_password, salt)
    fernet_key = _crypto.derive_key(master_password, salt, kdf)

    # Шифруем пустой список записей
    encrypted_entries = _crypto.encrypt("[]", fernet_key)

    vault_data = {
        "version":     "1.0",
        "kdf":         kdf,
        "salt":        base64.b64encode(salt).decode(),
        "master_hash": master_hash,
        "entries":     encrypted_entries,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(vault_data, f, indent=2, ensure_ascii=False)


# ─── Vault: загрузка / сохранение ────────────────────────────────────────────

def _load_raw(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_raw(data: dict, path: Path) -> None:
    _ensure_dir(path)
    # Атомарная запись: пишем во временный файл, затем переименовываем
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)   # атомарно на POSIX и Windows


def _get_fernet_key(master_password: str, vault_data: dict) -> bytes:
    salt = base64.b64decode(vault_data["salt"])
    kdf  = vault_data.get("kdf", "pbkdf2")
    return _crypto.derive_key(master_password, salt, kdf)


# ─── Аутентификация ───────────────────────────────────────────────────────────

def authenticate(master_password: str, path: Path = DEFAULT_VAULT_PATH) -> bool:
    """
    Верифицирует мастер-пароль, не расшифровывая записи.
    Использует compare_digest для защиты от timing-атак.
    """
    try:
        vault_data = _load_raw(path)
        salt = base64.b64decode(vault_data["salt"])
        stored_hash = vault_data["master_hash"]
        return _crypto.verify_master_password(master_password, salt, stored_hash)
    except (KeyError, json.JSONDecodeError, FileNotFoundError):
        return False


# ─── Записи (CRUD) ────────────────────────────────────────────────────────────

def _read_entries(master_password: str, path: Path) -> List[Dict]:
    vault_data = _load_raw(path)
    fernet_key = _get_fernet_key(master_password, vault_data)
    try:
        return json.loads(_crypto.decrypt(vault_data["entries"], fernet_key))
    except (InvalidToken, json.JSONDecodeError) as e:
        raise ValueError(f"Не удалось расшифровать данные: {e}") from e


def _write_entries(entries: List[Dict], master_password: str, path: Path) -> None:
    vault_data = _load_raw(path)
    fernet_key = _get_fernet_key(master_password, vault_data)
    vault_data["entries"] = _crypto.encrypt(
        json.dumps(entries, ensure_ascii=False), fernet_key
    )
    _save_raw(vault_data, path)


def list_entries(master_password: str,
                 path: Path = DEFAULT_VAULT_PATH) -> List[Dict]:
    """Возвращает список всех записей (расшифрованных)."""
    return _read_entries(master_password, path)


def add_entry(master_password: str,
              site: str,
              login: str,
              password: str,
              notes: str = "",
              path: Path = DEFAULT_VAULT_PATH) -> str:
    """
    Добавляет запись. Возвращает уникальный ID.
    ID генерируется через secrets для невозможности предсказания.
    """
    import secrets as _sec
    entries = _read_entries(master_password, path)

    entry_id = _sec.token_hex(8)   # 16-символьный hex ID
    entry = {
        "id":         entry_id,
        "site":       site,
        "login":      login,
        "password":   password,
        "notes":      notes,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }
    entries.append(entry)
    _write_entries(entries, master_password, path)
    return entry_id


def get_entry(master_password: str,
              entry_id: str,
              path: Path = DEFAULT_VAULT_PATH) -> Optional[Dict]:
    """Возвращает запись по ID или None."""
    for e in _read_entries(master_password, path):
        if e["id"] == entry_id:
            return e
    return None


def update_entry(master_password: str,
                 entry_id: str,
                 path: Path = DEFAULT_VAULT_PATH,
                 **kwargs) -> bool:
    """Обновляет поля существующей записи."""
    entries = _read_entries(master_password, path)
    allowed = {"site", "login", "password", "notes"}
    for e in entries:
        if e["id"] == entry_id:
            for k, v in kwargs.items():
                if k in allowed:
                    e[k] = v
            e["updated_at"] = datetime.utcnow().isoformat()
            _write_entries(entries, master_password, path)
            return True
    return False


def delete_entry(master_password: str,
                 entry_id: str,
                 path: Path = DEFAULT_VAULT_PATH) -> bool:
    """Удаляет запись по ID. Возвращает True при успехе."""
    entries = _read_entries(master_password, path)
    new_entries = [e for e in entries if e["id"] != entry_id]
    if len(new_entries) == len(entries):
        return False
    _write_entries(new_entries, master_password, path)
    return True


def search_entries(master_password: str,
                   query: str,
                   path: Path = DEFAULT_VAULT_PATH) -> List[Dict]:
    """
    Ищет записи по подстроке в полях site и login
    (регистронезависимо).
    """
    q = query.lower()
    return [
        e for e in _read_entries(master_password, path)
        if q in e.get("site", "").lower() or q in e.get("login", "").lower()
    ]


# ─── Смена мастер-пароля ─────────────────────────────────────────────────────

def change_master_password(old_password: str,
                           new_password: str,
                           path: Path = DEFAULT_VAULT_PATH) -> None:
    """
    Перешифровывает хранилище с новым мастер-паролем:
      1. Декодирует записи старым ключом.
      2. Генерирует новую соль.
      3. Перешифровывает записи новым ключом.
    """
    if not authenticate(old_password, path):
        raise PermissionError("Неверный текущий мастер-пароль.")

    entries = _read_entries(old_password, path)
    vault_data = _load_raw(path)

    new_salt = _crypto.new_salt()
    new_hash = _crypto.hash_master_password(new_password, new_salt)
    new_key  = _crypto.derive_key(new_password, new_salt, vault_data.get("kdf", "pbkdf2"))

    vault_data["salt"]        = base64.b64encode(new_salt).decode()
    vault_data["master_hash"] = new_hash
    vault_data["entries"]     = _crypto.encrypt(
        json.dumps(entries, ensure_ascii=False), new_key
    )
    _save_raw(vault_data, path)
