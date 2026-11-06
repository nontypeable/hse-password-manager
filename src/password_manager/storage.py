import json
import os
from pathlib import Path
from typing import Any, Protocol


class IStorage(Protocol):
    def load(self) -> dict[str, Any]:
        """
        Прочитать данные хранилища.

        Returns:
            dict: содержимое хранилища, пустой словарь, если оно ещё не создано.

        Raises:
            ValueError: если сохранённые данные повреждены.
        """

        ...

    def save(self, data: dict[str, Any]) -> None:
        """
        Записать данные хранилища.

        Args:
            data (dict): данные, которые надо сохранить.
        """

        ...


class JsonStorage:
    def __init__(self, path: str | Path):
        """
        Args:
            path (str | Path): путь к файлу хранилища, сам файл может ещё не существовать.
        """

        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        """
        Прочитать данные хранилища.

        Returns:
            dict: содержимое файла, пустой словарь, если файла нет.

        Raises:
            ValueError: если файл не является корректным JSON в UTF-8.
            OSError: если файл не удаётся прочитать.
        """

        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError(f"Файл хранилища повреждён: {self.path}")  # noqa: TRY004
            return data
        except json.JSONDecodeError as exc:
            raise ValueError(f"Файл хранилища повреждён: {self.path}") from exc

    def save(self, data: dict[str, Any]) -> None:
        """
        Записать данные хранилища в файл.

        Args:
            data (dict): данные, которые можно сериализовать в JSON.

        Raises:
            TypeError: если в `data` есть значения, которые нельзя сериализовать в JSON.
            OSError: если файл не удаётся записать.
        """

        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
