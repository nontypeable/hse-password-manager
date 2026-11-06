import argparse
import getpass
import sys

from .generator import MIN_PASSWORD_LENGTH, PasswordGenerator
from .manager import DEFAULT_PATH, PasswordManager


def _ask_new_master() -> str:
    while True:
        password = getpass.getpass("Новый мастер-пароль: ")
        if not password:
            print("Пароль не может быть пустым.")
            continue
        if password == getpass.getpass("Повторите пароль: "):
            return password
        print("Пароли не совпадают.")


def _add_entry(pm: PasswordManager, name: str) -> None:
    login = input("Логин: ")
    password = getpass.getpass("Пароль (пусто — сгенерировать): ")
    if not password:
        password = PasswordGenerator.generate_password(MIN_PASSWORD_LENGTH)
        print(f"Сгенерирован пароль: {password}")
    pm.add_entry(name, login, password)
    print("Добавлено.")


def _get_entry(pm: PasswordManager, name: str) -> None:
    if name not in pm.list_entries():
        print("Запись не найдена.")
    elif not pm.verify_master(getpass.getpass("Подтвердите мастер-пароль: ")):
        print("Неверный мастер-пароль.")
    else:
        login, password = pm.get_entry(name)
        print(f"Логин: {login}\nПароль: {password}")


def _menu(pm: PasswordManager) -> None:
    print("Команды: add, list, get <name>, delete <name>, generate [длина], exit")
    while True:
        try:
            parts = input("> ").split(maxsplit=1)
        except EOFError:
            print()
            return
        if not parts:
            continue
        command, arg = parts[0].lower(), (parts[1].strip() if len(parts) > 1 else "")
        try:
            match command, arg:
                case "exit", _:
                    return
                case "add", "":
                    _add_entry(pm, input("Название: ").strip())
                case "add", name:
                    _add_entry(pm, name)
                case "list", _:
                    names = pm.list_entries()
                    print("\n".join(names) if names else "(пусто)")
                case "get", "":
                    print("Использование: get <name>")
                case "get", name:
                    _get_entry(pm, name)
                case "delete", "":
                    print("Использование: delete <name>")
                case "delete", name:
                    pm.delete_entry(name)
                    print("Удалено.")
                case "generate", "":
                    print(PasswordGenerator.generate_password(MIN_PASSWORD_LENGTH))
                case "generate", length:
                    print(PasswordGenerator.generate_password(int(length)))
                case _:
                    print("Неизвестная команда.")
        except KeyError:
            print("Запись не найдена.")
        except (ValueError, OSError) as exc:
            print(f"Ошибка: {exc}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="password-manager", description="Менеджер паролей"
    )
    parser.add_argument(
        "--file", default=str(DEFAULT_PATH), help="путь к файлу хранилища"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--init", action="store_true", help="создать мастер-пароль")
    group.add_argument("--unlock", action="store_true", help="войти в хранилище")
    group.add_argument(
        "--generate",
        nargs="?",
        const=MIN_PASSWORD_LENGTH,
        type=int,
        metavar="LEN",
        help=f"сгенерировать пароль (по умолчанию {MIN_PASSWORD_LENGTH} символов)",
    )
    args = parser.parse_args(argv)

    if args.generate is not None:
        try:
            print(PasswordGenerator.generate_password(args.generate))
        except ValueError as exc:
            print(f"Ошибка: {exc}", file=sys.stderr)
            return 1
        return 0

    try:
        pm = PasswordManager(args.file)
        if args.init:
            if pm.initialized:
                print(
                    "Хранилище уже создано. Перезапись без пароля запрещена.",
                    file=sys.stderr,
                )
                return 1
            pm.init_master(_ask_new_master())
            print("Мастер-пароль создан.")
            return 0

        if not pm.initialized:
            print("Хранилище не создано. Выполните --init.", file=sys.stderr)
            return 1
        if not pm.unlock(getpass.getpass("Мастер-пароль: ")):
            print("Неверный мастер-пароль.", file=sys.stderr)
            return 1
        _menu(pm)
    except ValueError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Ошибка доступа к файлу хранилища: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nПрервано.", file=sys.stderr)
        return 130
    return 0
