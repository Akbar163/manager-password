"""
logger.py — журнал активности

Записывает события (вход, добавление/удаление записей, ошибки) в текстовый лог.
Лог не содержит паролей и чувствительных данных.
"""

from pathlib import Path
from datetime import datetime


LOG_PATH = Path.home() / ".password_manager" / "activity.log"
_MAX_LOG_LINES = 10_000   # ротация: обрезаем старые строки


def _ensure_log():
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not LOG_PATH.exists():
        LOG_PATH.touch()


def log_event(event: str, detail: str = "") -> None:
    """
    Записывает событие в лог-файл.
    Формат: ISO-timestamp | EVENT | detail
    """
    try:
        _ensure_log()
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"{ts} | {event:<22} | {detail}\n"
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
        _rotate_if_needed()
    except OSError:
        pass   # не падаем, если лог недоступен


def _rotate_if_needed() -> None:
    """Если лог превышает _MAX_LOG_LINES строк — оставляем последние 8000."""
    try:
        lines = LOG_PATH.read_text(encoding="utf-8").splitlines(keepends=True)
        if len(lines) > _MAX_LOG_LINES:
            LOG_PATH.write_text("".join(lines[-8000:]), encoding="utf-8")
    except OSError:
        pass


def read_log(last_n: int = 50) -> list[str]:
    """Читает последние N строк лога."""
    try:
        _ensure_log()
        lines = LOG_PATH.read_text(encoding="utf-8").splitlines()
        return lines[-last_n:]
    except OSError:
        return []
