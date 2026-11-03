import secrets
import string
from typing import Final, Protocol

MIN_PASSWORD_LENGTH: Final[int] = 8


class IPasswordGenerator(Protocol):
    @staticmethod
    def generate_password(length: int) -> str:
        """
        Сгенерировать случайный пароль.

        Args:
            length (int): длина пароля, не меньше `MIN_PASSWORD_LENGTH`

        Raises:
            ValueError: если длина пароля меньше `MIN_PASSWORD_LENGTH`
        """

        ...


class PasswordGenerator:
    @staticmethod
    def generate_password(length: int) -> str:
        """
        Сгенерировать случайный пароль.

        Args:
            length (int): длина пароля, не меньше `MIN_PASSWORD_LENGTH`

        Raises:
            ValueError: если длина пароля меньше `MIN_PASSWORD_LENGTH`
        """

        if length < MIN_PASSWORD_LENGTH:
            raise ValueError("Длина пароля должна быть не меньше 8")

        alphabet = f"{string.ascii_lowercase}{string.ascii_uppercase}{string.digits}{string.punctuation}"
        return "".join([secrets.choice(alphabet) for _ in range(length)])
