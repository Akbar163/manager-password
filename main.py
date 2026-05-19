"""
main.py — точка входа в менеджер паролей

Использование:
    python main.py                        # хранилище в ~/.password_manager/vault.json
    python main.py --vault /path/to.json  # произвольный путь к хранилищу
    python main.py --demo                 # демо-режим: анализ/генерация без хранилища
"""

import sys
import argparse
from pathlib import Path

import storage
import cli
import generator as gen
from generator import PasswordParams


def demo_mode():
    """Демонстрация генератора и анализатора без хранилища."""
    print("\n" + "═" * 54)
    print("  ДЕМО-РЕЖИМ: генерация и анализ паролей")
    print("═" * 54)

    presets = ["weak", "medium", "strong", "ultra"]
    for preset in presets:
        p = PasswordParams(preset=preset)
        pwd = gen.generate_password(p)
        a   = gen.analyze_password(pwd)
        print(f"\n  [{preset:6s}] {pwd}")
        print(f"           Энтропия: {a['entropy']} бит  {a['strength']}")

    print("\n  ─── Парольные фразы ───")
    for n in (4, 5, 6):
        phrase = gen.generate_passphrase(n)
        ent = n * 9.96
        print(f"  {n} слова:  {phrase}")
        print(f"            Энтропия: ≈{ent:.0f} бит")

    print("\n  ─── secrets vs random ───")
    print("  secrets: ", gen.generate_password(PasswordParams(length=16)))
    print("  random:  ", gen.insecure_generate_password(16), " ← ⚠️ НЕ ИСПОЛЬЗОВАТЬ")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="🔐 Менеджер паролей с криптостойкой генерацией"
    )
    parser.add_argument(
        "--vault",
        type=Path,
        default=storage.DEFAULT_VAULT_PATH,
        help="Путь к файлу хранилища (по умолчанию: ~/.password_manager/vault.json)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Запустить демонстрационный режим без хранилища",
    )
    args = parser.parse_args()

    if args.demo:
        demo_mode()
        return

    try:
        cli.run_app(args.vault)
    except KeyboardInterrupt:
        print("\n\n  👋 Завершено.")
        sys.exit(0)


if __name__ == "__main__":
    main()
