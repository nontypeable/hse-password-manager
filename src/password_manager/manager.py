import base64
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any, Final

from crypto import SALT_SIZE, PasswordDecryptor, PasswordEncryptor, generate_salt
from storage import JsonStorage

DEFAULT_PATH: Final[Path] = Path("vault.json")
CHECK_PHRASE: Final[str] = "password-manager-check-phrase"


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _decode(data: str) -> bytes:
    return base64.b64decode(data)


def require_unlocked(func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(func)
    def wrapper(self: PasswordManager, *args: Any, **kwargs: Any) -> Any:
        if not self.unlocked:
            raise ValueError("Хранилище заблокировано")
        return func(self, *args, **kwargs)

    return wrapper


class PasswordManager:
    def __init__(self, path: str | Path = DEFAULT_PATH):
        """
        Args:
            path (str | Path): путь к файлу хранилища.

        Raises:
            ValueError: если файл хранилища повреждён или имеет старый формат.
        """

        self._storage = JsonStorage(path)
        self._session: tuple[PasswordEncryptor, PasswordDecryptor] | None = None
        self._entries: dict[str, dict[str, str]] = {}
        self._meta: dict[str, str] = {}
        self._load()

    @property
    def path(self) -> Path:
        """Путь к файлу хранилища."""

        return self._storage.path

    @property
    def initialized(self) -> bool:
        """Задан ли уже мастер-пароль."""

        return bool(self._meta)

    @property
    def unlocked(self) -> bool:
        """Разблокировано ли хранилище."""

        return self._session is not None

    @property
    def _encryptor(self) -> PasswordEncryptor:
        if self._session is None:
            raise ValueError("Хранилище заблокировано")
        return self._session[0]

    @property
    def _decryptor(self) -> PasswordDecryptor:
        if self._session is None:
            raise ValueError("Хранилище заблокировано")
        return self._session[1]

    def init_master(self, password: str) -> None:
        """
        Создать хранилище с мастер-паролем и сразу разблокировать его.

        Args:
            password (str): мастер-пароль.

        Raises:
            ValueError: если хранилище уже инициализировано или пароль пустой.
        """

        if self.initialized:
            raise ValueError("Хранилище уже инициализировано")
        if not password:
            raise ValueError("Мастер-пароль не может быть пустым")

        encryptor = PasswordEncryptor(password, generate_salt())
        self._meta = {"check": _encode(encryptor.encrypt(CHECK_PHRASE))}
        self._entries = {}
        self._session = (encryptor, PasswordDecryptor(password))
        self._save()

    def verify_master(self, password: str) -> bool:
        """
        Проверить мастер-пароль, не меняя состояние хранилища.

        Args:
            password (str): проверяемый пароль.

        Returns:
            bool: `True`, если пароль верный, и `False`, если он неверный или хранилище ещё не инициализировано.
        """

        if not self.initialized:
            return False
        try:
            PasswordDecryptor(password).decrypt(_decode(self._meta["check"]))
        except ValueError:
            return False
        return True

    def unlock(self, password: str) -> bool:
        """
        Разблокировать хранилище.

        Args:
            password (str): мастер-пароль.

        Returns:
            bool: `True`, если пароль верный и хранилище разблокировано, иначе `False`.
        """

        if not self.verify_master(password):
            return False
        salt = _decode(self._meta["check"])[:SALT_SIZE]
        self._session = (PasswordEncryptor(password, salt), PasswordDecryptor(password))
        return True

    def lock(self) -> None:
        """Заблокировать хранилище: ключи шифрования забываются."""

        self._session = None

    @require_unlocked
    def add_entry(self, name: str, login: str, password: str) -> None:
        """
        Добавить запись и сохранить хранилище.

        Args:
            name (str): имя записи, уникальное в хранилище.
            login (str): логин.
            password (str): пароль.

        Raises:
            ValueError: если хранилище заблокировано, имя пустое или запись с таким именем уже есть.
        """

        if not name:
            raise ValueError("Имя записи не может быть пустым")
        if name in self._entries:
            raise ValueError(f"Запись '{name}' уже существует")
        self._entries[name] = {
            "login": _encode(self._encryptor.encrypt(login)),
            "password": _encode(self._encryptor.encrypt(password)),
        }
        self._save()

    @require_unlocked
    def list_entries(self) -> list[str]:
        """
        Получить имена записей.

        Returns:
            list[str]: имена записей в алфавитном порядке.

        Raises:
            ValueError: если хранилище заблокировано.
        """

        return sorted(self._entries)

    @require_unlocked
    def get_entry(self, name: str) -> tuple[str, str]:
        """
        Получить логин и пароль записи.

        Args:
            name (str): имя записи.

        Returns:
            tuple[str, str]: логин и пароль.

        Raises:
            ValueError: если хранилище заблокировано или данные записи повреждены.
            KeyError: если записи с таким именем нет.
        """

        if name not in self._entries:
            raise KeyError(name)
        entry = self._entries[name]
        return (
            self._decryptor.decrypt(_decode(entry["login"])),
            self._decryptor.decrypt(_decode(entry["password"])),
        )

    @require_unlocked
    def delete_entry(self, name: str) -> None:
        """
        Удалить запись и сохранить хранилище.

        Args:
            name (str): имя записи.

        Raises:
            ValueError: если хранилище заблокировано.
            KeyError: если записи с таким именем нет.
        """

        if name not in self._entries:
            raise KeyError(name)
        del self._entries[name]
        self._save()

    def _save(self) -> None:
        self._storage.save({"meta": self._meta, "entries": self._entries})

    def _load(self) -> None:
        data = self._storage.load()
        if not data:
            return
        try:
            meta, entries = data["meta"], data["entries"]
        except KeyError as exc:
            raise ValueError(f"Файл хранилища повреждён: {self.path}") from exc
        if meta and "check" not in meta:
            raise ValueError(
                f"Файл хранилища повреждён или старого формата: {self.path}"
            )
        self._meta, self._entries = meta, entries
