"""
cli.py — консольный интерфейс менеджера паролей

Меню:
  1. Посмотреть все записи
  2. Добавить запись
  3. Сгенерировать пароль
  4. Сгенерировать парольную фразу
  5. Найти запись
  6. Редактировать запись
  7. Удалить запись
  8. Сменить мастер-пароль
  9. Показать журнал активности
  0. Выход
"""

import sys
import os
from pathlib import Path

# pyperclip — опциональная зависимость (копирование в буфер обмена)
try:
    import pyperclip as _pyperclip
    _PYPERCLIP_OK = True
except ImportError:
    _pyperclip = None
    _PYPERCLIP_OK = False
from typing import Optional

import storage
import auth
import generator as gen
import logger as log
from generator import PasswordParams


# ─── Вспомогательные функции ─────────────────────────────────────────────────

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def pause(msg: str = "  [Enter для продолжения]"):
    try:
        input(msg)
    except (KeyboardInterrupt, EOFError):
        pass


def print_header(title: str = "Менеджер паролей"):
    print()
    print("╔" + "═" * 52 + "╗")
    print(f"║  🔐  {title:<46}║")
    print("╚" + "═" * 52 + "╝")


def print_separator():
    print("  " + "─" * 48)


def safe_input(prompt: str, default: str = "") -> str:
    try:
        val = input(prompt).strip()
        return val if val else default
    except (KeyboardInterrupt, EOFError):
        return default


def safe_int(prompt: str, default: int, min_val: int = 1, max_val: int = 9999) -> int:
    s = safe_input(prompt, str(default))
    try:
        v = int(s)
        return max(min_val, min(max_val, v))
    except ValueError:
        return default


def yn(prompt: str, default: bool = True) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    ans = safe_input(f"{prompt} {hint}: ", "y" if default else "n").lower()
    return ans in ("y", "yes", "д", "да", "")


def try_copy(text: str) -> bool:
    """Пробует скопировать в буфер обмена. Возвращает True при успехе."""
    if not _PYPERCLIP_OK:
        return False
    try:
        _pyperclip.copy(text)
        return True
    except Exception:
        return False


# ─── Форматирование записей ───────────────────────────────────────────────────

def format_entry(entry: dict, show_password: bool = False) -> str:
    lines = [
        f"  ID:       {entry['id']}",
        f"  Сайт:     {entry['site']}",
        f"  Логин:    {entry['login']}",
        f"  Пароль:   {'*' * 12 if not show_password else entry['password']}",
    ]
    if entry.get("notes"):
        lines.append(f"  Заметка:  {entry['notes']}")
    lines.append(f"  Добавлен: {entry.get('created_at', '—')[:19].replace('T',' ')}")
    return "\n".join(lines)


def print_entries_table(entries: list, show_passwords: bool = False):
    if not entries:
        print("  (записей нет)")
        return
    for i, e in enumerate(entries, 1):
        print(f"\n  [{i}] {e['site']}  /  {e['login']}")
        if show_passwords:
            print(f"      Пароль: {e['password']}")
            a = gen.analyze_password(e["password"])
            print(f"      Энтропия: {a['entropy']} бит  {a['strength']}")


# ─── Генерация пароля (интерактивно) ─────────────────────────────────────────

def interactive_generate() -> Optional[str]:
    print_header("Генератор паролей")
    print()
    print("  Пресеты:")
    print("    1. weak   (8 символов, только буквы+цифры)")
    print("    2. medium (12 символов, буквы+цифры)")
    print("    3. strong (16 символов, все классы) ← рекомендуется")
    print("    4. ultra  (24 символа, все классы)")
    print("    5. Свои параметры")
    print()

    choice = safe_input("  Выбор [3]: ", "3")

    presets_map = {"1": "weak", "2": "medium", "3": "strong", "4": "ultra"}

    if choice in presets_map:
        params = PasswordParams(preset=presets_map[choice])
    else:
        length  = safe_int("  Длина [16]: ", 16, 4, 128)
        upper   = yn("  Заглавные буквы?",  True)
        digits  = yn("  Цифры?",            True)
        symbols = yn("  Спецсимволы?",      True)
        params  = PasswordParams(length=length, use_upper=upper,
                                 use_digits=digits, use_symbols=symbols)

    password = gen.generate_password(params)
    analysis = gen.analyze_password(password)

    print()
    print_separator()
    print(f"  Пароль:   {password}")
    print(f"  Длина:    {analysis['length']} символов")
    print(f"  Энтропия: {analysis['entropy']} бит")
    print(f"  Оценка:   {analysis['strength']}")
    print_separator()

    if try_copy(password):
        print("  📋 Скопировано в буфер обмена.")

    log.log_event("PASSWORD_GENERATED", f"len={analysis['length']} entropy={analysis['entropy']}")
    return password


# ─── Генерация парольной фразы ────────────────────────────────────────────────

def interactive_passphrase() -> Optional[str]:
    print_header("Парольная фраза (Diceware)")
    print()
    words = safe_int("  Количество слов [5]: ", 5, 3, 12)
    sep   = safe_input("  Разделитель [-]: ", "-")
    cap   = yn("  Начинать каждое слово с заглавной?", True)

    phrase = gen.generate_passphrase(words, sep, cap)
    ent = words * 9.96   # log2(1000) ≈ 9.96 бит/слово

    print()
    print_separator()
    print(f"  Фраза:    {phrase}")
    print(f"  Энтропия: ≈{ent:.1f} бит ({words} слов × ≈9.96 бит/слово)")
    print_separator()

    if try_copy(phrase):
        print("  📋 Скопировано в буфер обмена.")

    log.log_event("PASSPHRASE_GENERATED", f"words={words}")
    return phrase


# ─── CRUD-операции ────────────────────────────────────────────────────────────

def cmd_list(master_pwd: str, vault_path: Path):
    entries = storage.list_entries(master_pwd, vault_path)
    print_header(f"Записи ({len(entries)})")
    show = yn("\n  Показать пароли?", False)
    print_entries_table(entries, show)
    log.log_event("LIST_ENTRIES", f"count={len(entries)}")
    pause()


def cmd_add(master_pwd: str, vault_path: Path):
    print_header("Добавить запись")
    site  = safe_input("\n  Сайт/сервис:  ")
    login = safe_input("  Логин/email:  ")

    if not site or not login:
        print("  ❌ Сайт и логин обязательны.")
        pause()
        return

    if yn("  Сгенерировать пароль автоматически?", True):
        password = interactive_generate()
        if not password:
            return
    else:
        import getpass
        password = getpass.getpass("  Введите пароль: ")
        analysis = gen.analyze_password(password)
        print(f"  Энтропия: {analysis['entropy']} бит  {analysis['strength']}")

    notes = safe_input("  Заметка (необязательно): ")

    entry_id = storage.add_entry(master_pwd, site, login, password, notes, vault_path)
    log.log_event("ENTRY_ADDED", f"id={entry_id} site={site}")
    print(f"\n  ✅ Запись добавлена (ID: {entry_id})")
    pause()


def cmd_search(master_pwd: str, vault_path: Path):
    print_header("Поиск записей")
    query = safe_input("\n  Поисковый запрос: ")
    if not query:
        return

    results = storage.search_entries(master_pwd, query, vault_path)
    print(f"\n  Найдено: {len(results)}")

    if not results:
        pause()
        return

    show = yn("  Показать пароли?", False)
    for e in results:
        print()
        print_separator()
        print(format_entry(e, show))

    log.log_event("SEARCH", f"query='{query}' results={len(results)}")
    pause()


def cmd_edit(master_pwd: str, vault_path: Path):
    print_header("Редактировать запись")
    entries = storage.list_entries(master_pwd, vault_path)
    if not entries:
        print("  Записей нет.")
        pause()
        return

    print_entries_table(entries, False)
    entry_id = safe_input("\n  Введите ID записи: ")

    entry = storage.get_entry(master_pwd, entry_id, vault_path)
    if not entry:
        print("  ❌ Запись не найдена.")
        pause()
        return

    print(f"\n  Текущие данные:\n")
    print(format_entry(entry, True))
    print()

    new_site  = safe_input(f"  Новый сайт [{entry['site']}]: ", entry["site"])
    new_login = safe_input(f"  Новый логин [{entry['login']}]: ", entry["login"])
    new_notes = safe_input(f"  Новая заметка [{entry.get('notes','')}]: ", entry.get("notes",""))

    if yn("  Сгенерировать новый пароль?", False):
        new_password = interactive_generate()
    else:
        import getpass
        new_password = getpass.getpass("  Новый пароль (Enter = оставить): ")
        if not new_password:
            new_password = entry["password"]

    storage.update_entry(master_pwd, entry_id, vault_path,
                         site=new_site, login=new_login,
                         password=new_password, notes=new_notes)
    log.log_event("ENTRY_UPDATED", f"id={entry_id}")
    print("\n  ✅ Запись обновлена.")
    pause()


def cmd_delete(master_pwd: str, vault_path: Path):
    print_header("Удалить запись")
    entries = storage.list_entries(master_pwd, vault_path)
    if not entries:
        print("  Записей нет.")
        pause()
        return

    print_entries_table(entries, False)
    entry_id = safe_input("\n  Введите ID записи для удаления: ")

    entry = storage.get_entry(master_pwd, entry_id, vault_path)
    if not entry:
        print("  ❌ Запись не найдена.")
        pause()
        return

    print(f"\n  Будет удалено: {entry['site']}  /  {entry['login']}")
    if not yn("  Вы уверены?", False):
        print("  Отмена.")
        pause()
        return

    storage.delete_entry(master_pwd, entry_id, vault_path)
    log.log_event("ENTRY_DELETED", f"id={entry_id} site={entry['site']}")
    print("  ✅ Запись удалена.")
    pause()


def cmd_change_master(master_pwd: str, vault_path: Path) -> str:
    print_header("Смена мастер-пароля")
    print("  ⚠️  Хранилище будет перешифровано новым ключом.")
    print()

    new_pwd1 = auth.prompt_master_password("  Новый мастер-пароль: ")
    issues = auth.validate_master_password_strength(new_pwd1)
    if issues:
        print("  ❌ Пароль не отвечает требованиям:")
        for i in issues:
            print(f"     • {i}")
        pause()
        return master_pwd

    new_pwd2 = auth.prompt_master_password("  Повторите пароль:    ")
    if new_pwd1 != new_pwd2:
        print("  ❌ Пароли не совпадают.")
        pause()
        return master_pwd

    print("  ⚙️  Перешифрование...")
    storage.change_master_password(master_pwd, new_pwd1, vault_path)
    log.log_event("MASTER_PASSWORD_CHANGED")
    print("  ✅ Мастер-пароль успешно изменён.")
    pause()
    return new_pwd1


def cmd_show_log():
    print_header("Журнал активности")
    lines = log.read_log(50)
    if not lines:
        print("  (журнал пуст)")
    else:
        for line in lines:
            print("  " + line)
    pause()


# ─── Главное меню ─────────────────────────────────────────────────────────────

MENU = """
  ┌──────────────────────────────────────────────┐
  │  1. Просмотр всех записей                    │
  │  2. Добавить запись                          │
  │  3. Сгенерировать пароль                     │
  │  4. Сгенерировать парольную фразу            │
  │  5. Поиск по записям                         │
  │  6. Редактировать запись                     │
  │  7. Удалить запись                           │
  │  8. Сменить мастер-пароль                    │
  │  9. Журнал активности                        │
  │  0. Выход                                    │
  └──────────────────────────────────────────────┘"""


def run_app(vault_path: Path):
    """Основной цикл приложения."""
    clear_screen()

    # ─── Инициализация или вход ────────────────────────────────────────────
    if not storage.vault_exists(vault_path):
        auth.register(vault_path)
        print()
        print("  Теперь войдите в созданное хранилище.")

    master_pwd = auth.login(vault_path)

    # ─── Главный цикл ────────────────────────────────────────────────────
    while True:
        clear_screen()
        print_header()
        print(MENU)
        print()

        choice = safe_input("  Ваш выбор: ", "0")

        if choice == "0":
            log.log_event("LOGOUT")
            print("\n  👋 До свидания!")
            sys.exit(0)
        elif choice == "1":
            cmd_list(master_pwd, vault_path)
        elif choice == "2":
            cmd_add(master_pwd, vault_path)
        elif choice == "3":
            interactive_generate()
            pause()
        elif choice == "4":
            interactive_passphrase()
            pause()
        elif choice == "5":
            cmd_search(master_pwd, vault_path)
        elif choice == "6":
            cmd_edit(master_pwd, vault_path)
        elif choice == "7":
            cmd_delete(master_pwd, vault_path)
        elif choice == "8":
            master_pwd = cmd_change_master(master_pwd, vault_path)
        elif choice == "9":
            cmd_show_log()
        else:
            print("  ❓ Неверный выбор.")
            pause()
