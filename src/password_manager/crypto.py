import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
ITERATIONS: Final[int] = 600_000
KEY_LENGTH: Final[int] = 32
SALT_SIZE: Final[int] = 16
NONCE_SIZE: Final[int] = 12
TAG_SIZE: Final[int] = 16


def generate_salt() -> bytes:
    """
    Сгенерировать случайную соль.

    Returns:
        bytes: случайная соль длиной `SALT_SIZE`.
    """

    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Вывести ключ шифрования из пароля.

    Args:
        password (str): мастер-пароль.
        salt (bytes): соль.

    Returns:
        bytes: ключ длиной `KEY_LENGTH`.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


class PasswordEncryptor:
    def __init__(self, password: str, salt: bytes) -> None:
        """
        Args:
            password (str): мастер-пароль.
            salt (bytes): соль, не короче `SALT_SIZE`.

        Raises:
            ValueError: если соль короче `SALT_SIZE`.
        """

        if len(salt) < SALT_SIZE:
            raise ValueError(f"Соль должна быть не короче {SALT_SIZE} байт")

        self._salt = salt
        self._key = derive_key(password, salt)

    def encrypt(self, plaintext: str) -> bytes:
        """
        Зашифровать пароль (AES-GCM, новый nonce на каждый вызов).

        Args:
            plaintext (str): пароль, который надо зашифровать.

        Returns:
            bytes: salt + nonce + шифротекст.
        """

        nonce = self._generate_nonce()
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return self._salt + nonce + ciphertext

    @staticmethod
    def _generate_nonce() -> bytes:
        """
        Сгенерировать случайны nonce.

        Returns:
            bytes: случайный nonce длиной `NONCE_SIZE`.
        """

        return os.urandom(NONCE_SIZE)


class PasswordDecryptor:
    def __init__(self, password: str) -> None:
        """
        Args:
            password (str): мастер-пароль.
        """

        self._password = password

    def decrypt(self, password_cipher: bytes) -> str:
        """
        Расшифровать пароль.

        Args:
            password_cipher (bytes): salt + nonce + шифротекст.

        Returns:
            str: расшифрованный пароль.

        Raises:
            ValueError: если мастер-пароль неверный или данные повреждены.
        """

        if len(password_cipher) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
            raise ValueError("Данные повреждены")

        salt, nonce, ciphertext = (
            password_cipher[:SALT_SIZE],
            password_cipher[SALT_SIZE : SALT_SIZE + NONCE_SIZE],
            password_cipher[SALT_SIZE + NONCE_SIZE :],
        )

        key = derive_key(self._password, salt)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError("Неверный пароль или данные повреждены") from exc
        return plaintext.decode("utf-8")
