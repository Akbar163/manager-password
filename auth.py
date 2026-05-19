"""
auth.py — аутентификация и защита от брутфорса

Применяется экспоненциальная задержка (lockout):
  попытка 1-3: мгновенно
  попытка 4:   +2 сек
  попытка 5:   +4 сек
  попытка N:   +2^(N-3) сек (до MAX_DELAY)
"""

import time
import getpass
import sys
from pathlib import Path

import storage
from logger import log_event


MAX_ATTEMPTS = 10     # после — блокировка сессии
BASE_DELAY   = 2.0    # базовая задержка (сек)
MAX_DELAY    = 60.0   # максимальная задержка (сек)
FREE_TRIES   = 3      # первые N попыток без задержки


def _compute_delay(attempt: int) -> float:
    """Экспоненциальная задержка, начиная с FREE_TRIES+1 попытки."""
    if attempt <= FREE_TRIES:
        return 0.0
    exp = attempt - FREE_TRIES
    return min(BASE_DELAY ** exp, MAX_DELAY)


def prompt_master_password(prompt_text: str = "🔑 Мастер-пароль: ") -> str:
    """Безопасный ввод пароля без эха."""
    try:
        return getpass.getpass(prompt_text)
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Отмена.")
        sys.exit(0)


def validate_master_password_strength(password: str) -> list[str]:
    """
    Проверяет соответствие мастер-пароля требованиям безопасности.
    Возвращает список нарушений (пустой — если пароль допустим).
    """
    issues = []
    if len(password) < 10:
        issues.append("Длина должна быть не менее 10 символов.")
    if not any(c.isupper() for c in password):
        issues.append("Нужна хотя бы одна заглавная буква.")
    if not any(c.isdigit() for c in password):
        issues.append("Нужна хотя бы одна цифра.")
    if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password):
        issues.append("Нужен хотя бы один спецсимвол.")
    return issues


def login(vault_path: Path) -> str:
    """
    Интерактивный вход с защитой от брутфорса.
    Возвращает мастер-пароль при успехе или завершает процесс.
    """
    print("\n" + "─" * 50)
    print("  🔒 Менеджер паролей — Вход")
    print("─" * 50)

    for attempt in range(1, MAX_ATTEMPTS + 1):
        delay = _compute_delay(attempt)
        if delay > 0:
            print(f"  ⏳ Подождите {delay:.0f} сек перед следующей попыткой...")
            time.sleep(delay)

        master_pwd = prompt_master_password()

        if storage.authenticate(master_pwd, vault_path):
            log_event("LOGIN_SUCCESS", f"attempt={attempt}")
            print("  ✅ Аутентификация успешна.")
            return master_pwd
        else:
            remaining = MAX_ATTEMPTS - attempt
            print(f"  ❌ Неверный пароль. Осталось попыток: {remaining}")
            log_event("LOGIN_FAILED", f"attempt={attempt}")

    # Исчерпаны все попытки
    log_event("LOGIN_BLOCKED", "max_attempts_reached")
    print("\n  🚫 Превышено число попыток. Сессия заблокирована.")
    sys.exit(1)


def register(vault_path: Path) -> None:
    """
    Интерактивная регистрация: создание нового хранилища.
    """
    print("\n" + "─" * 50)
    print("  🆕 Создание нового хранилища")
    print("─" * 50)
    print("  Придумайте мастер-пароль. Требования:")
    print("    • Минимум 10 символов")
    print("    • Заглавные и строчные буквы")
    print("    • Цифры и спецсимволы")
    print()

    while True:
        pwd1 = prompt_master_password("  Новый мастер-пароль: ")
        issues = validate_master_password_strength(pwd1)
        if issues:
            print("  ⚠️  Пароль не отвечает требованиям:")
            for i in issues:
                print(f"     • {i}")
            continue

        pwd2 = prompt_master_password("  Повторите пароль:    ")
        if pwd1 != pwd2:
            print("  ❌ Пароли не совпадают. Попробуйте ещё раз.\n")
            continue

        break

    print("\n  ⚙️  Создание хранилища (деривация ключа — займёт секунду)...")
    storage.init_vault(pwd1, vault_path)
    log_event("VAULT_CREATED", str(vault_path))
    print(f"  ✅ Хранилище создано: {vault_path}")
