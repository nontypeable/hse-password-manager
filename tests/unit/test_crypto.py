import os
from typing import Final

import pytest

from password_manager.crypto import (
    KEY_LENGTH,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
    PasswordDecryptor,
    PasswordEncryptor,
    derive_key,
    generate_salt,
)

MASTER_PASSWORD: Final[str] = "m@ster_p@ssw0rD"
MIN_CIPHER_LENGTH: Final[int] = SALT_SIZE + NONCE_SIZE + TAG_SIZE


@pytest.fixture
def password_encryptor() -> PasswordEncryptor:
    return PasswordEncryptor(MASTER_PASSWORD, generate_salt())


@pytest.fixture
def password_decryptor() -> PasswordDecryptor:
    return PasswordDecryptor(MASTER_PASSWORD)


class TestGenerateSalt:
    def test_salts_are_unique(self) -> None:
        salts = {generate_salt() for _ in range(100)}

        assert len(salts) == 100

    def test_salt_length(self) -> None:
        assert len(generate_salt()) == SALT_SIZE


class TestDeriveKey:
    @pytest.mark.parametrize(
        ["password", "salt"],
        [
            ["p@ssw0rD", b"s@1t"],
            ["\n\t", b"s@1t"],
            ["p@ssw0rD", b"\n\t"],
            ["\n\t", b"\n\t"],
            ["🌚", b"s@1t"],
        ],
    )
    def test_key_deriving_deterministic(self, password: str, salt: bytes) -> None:
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)

        assert key1 == key2

    def test_key_length(self) -> None:
        assert len(derive_key("p@ssw0rD", generate_salt())) == KEY_LENGTH

    def test_different_salt_gives_different_key(self) -> None:
        key1 = derive_key("p@ssw0rD", b"a" * SALT_SIZE)
        key2 = derive_key("p@ssw0rD", b"b" * SALT_SIZE)

        assert key1 != key2

    def test_different_password_gives_different_key(self) -> None:
        salt = generate_salt()
        key1 = derive_key("p@ssw0rD1", salt)
        key2 = derive_key("p@ssw0rD2", salt)

        assert key1 != key2


class TestPasswordEncryptor:
    def test_output_starts_with_salt(self) -> None:
        salt = generate_salt()
        password_cipher = PasswordEncryptor(MASTER_PASSWORD, salt).encrypt("p@ssw0rD")

        assert password_cipher[:SALT_SIZE] == salt

    @pytest.mark.parametrize("password", ["p@ssw0rD", "🌚", "", "\n\t"])
    def test_output_length(
        self, password_encryptor: PasswordEncryptor, password: str
    ) -> None:
        password_cipher = password_encryptor.encrypt(password)

        assert len(password_cipher) == MIN_CIPHER_LENGTH + len(password.encode("utf-8"))

    @pytest.mark.parametrize("password", ["p@ssw0rD", "🌚", "", "\n\t"])
    def test_output_unique(
        self, password_encryptor: PasswordEncryptor, password: str
    ) -> None:
        password_cipher1 = password_encryptor.encrypt(password)
        password_cipher2 = password_encryptor.encrypt(password)

        assert password_cipher1 != password_cipher2

    def test_nonce_is_unique(self, password_encryptor: PasswordEncryptor) -> None:
        nonces = {
            password_encryptor.encrypt("p@ssw0rD")[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
            for _ in range(100)
        }

        assert len(nonces) == 100

    @pytest.mark.parametrize("password", ["p@ssw0rD", "🌚", "\n\t"])
    def test_secret_not_in_output(
        self, password_encryptor: PasswordEncryptor, password: str
    ) -> None:
        password_cipher = password_encryptor.encrypt(password)

        assert password.encode("utf-8") not in password_cipher

    def test_two_encryptors_return_different_output(self) -> None:
        salt = generate_salt()
        password_cipher1 = PasswordEncryptor(MASTER_PASSWORD, salt).encrypt("p@ssw0rD")
        password_cipher2 = PasswordEncryptor(MASTER_PASSWORD, salt).encrypt("p@ssw0rD")

        assert password_cipher1 != password_cipher2

    @pytest.mark.parametrize("length", [0, 4, SALT_SIZE - 1])
    def test_too_short_salt_raises(self, length: int) -> None:
        with pytest.raises(ValueError):
            PasswordEncryptor(MASTER_PASSWORD, b"s" * length)

    @pytest.mark.parametrize("length", [SALT_SIZE + 1, SALT_SIZE * 2, 1000])
    def test_too_long_salt_raises(self, length: int) -> None:
        with pytest.raises(ValueError):
            PasswordEncryptor(MASTER_PASSWORD, b"s" * length)


class TestPasswordDecryptor:
    @pytest.mark.parametrize(
        "password", ["p@ssw0rD", "🌚", "", "\n\t", "пароль", "a" * 1000]
    )
    def test_round_trip(
        self,
        password_encryptor: PasswordEncryptor,
        password_decryptor: PasswordDecryptor,
        password: str,
    ) -> None:
        password_cipher = password_encryptor.encrypt(password)

        assert password_decryptor.decrypt(password_cipher) == password

    @pytest.mark.parametrize(
        "master_password", ["m@ster", "", "пароль", "🌚", "\n\t", "a" * 500]
    )
    def test_round_trip_with_different_master_passwords(
        self, master_password: str
    ) -> None:
        password_cipher = PasswordEncryptor(master_password, generate_salt()).encrypt(
            "p@ssw0rD"
        )

        assert PasswordDecryptor(master_password).decrypt(password_cipher) == "p@ssw0rD"

    @pytest.mark.parametrize(
        "wrong_password", ["wrong", "", f"{MASTER_PASSWORD} ", MASTER_PASSWORD.upper()]
    )
    def test_wrong_master_password_raises(
        self, password_encryptor: PasswordEncryptor, wrong_password: str
    ) -> None:
        password_cipher = password_encryptor.encrypt("p@ssw0rD")

        with pytest.raises(ValueError):
            PasswordDecryptor(wrong_password).decrypt(password_cipher)

    @pytest.mark.parametrize(
        "position",
        [0, SALT_SIZE, SALT_SIZE + NONCE_SIZE, -1],
        ids=["salt", "nonce", "ciphertext", "tag"],
    )
    def test_tampered_cipher_raises(
        self,
        password_encryptor: PasswordEncryptor,
        password_decryptor: PasswordDecryptor,
        position: int,
    ) -> None:
        password_cipher = bytearray(password_encryptor.encrypt("p@ssw0rD"))
        password_cipher[position] ^= 1

        with pytest.raises(ValueError):
            password_decryptor.decrypt(bytes(password_cipher))

    @pytest.mark.parametrize(
        "length", [0, 1, SALT_SIZE, SALT_SIZE + NONCE_SIZE, MIN_CIPHER_LENGTH - 1]
    )
    def test_too_short_cipher_raises(
        self, password_decryptor: PasswordDecryptor, length: int
    ) -> None:
        with pytest.raises(ValueError):
            password_decryptor.decrypt(b"x" * length)

    def test_minimum_length_cipher_is_valid(
        self,
        password_encryptor: PasswordEncryptor,
        password_decryptor: PasswordDecryptor,
    ) -> None:
        password_cipher = password_encryptor.encrypt("")

        assert len(password_cipher) == MIN_CIPHER_LENGTH
        assert password_decryptor.decrypt(password_cipher) == ""

    def test_truncated_cipher_raises(
        self,
        password_encryptor: PasswordEncryptor,
        password_decryptor: PasswordDecryptor,
    ) -> None:
        password_cipher = password_encryptor.encrypt("p@ssw0rD")

        with pytest.raises(ValueError):
            password_decryptor.decrypt(password_cipher[:-1])

    def test_cipher_with_extra_bytes_raises(
        self,
        password_encryptor: PasswordEncryptor,
        password_decryptor: PasswordDecryptor,
    ) -> None:
        password_cipher = password_encryptor.encrypt("p@ssw0rD")

        with pytest.raises(ValueError):
            password_decryptor.decrypt(password_cipher + b"\x00")

    def test_random_bytes_raise(self, password_decryptor: PasswordDecryptor) -> None:
        with pytest.raises(ValueError):
            password_decryptor.decrypt(os.urandom(100))

    def test_one_decryptor_decrypts_many_ciphers(
        self,
        password_encryptor: PasswordEncryptor,
        password_decryptor: PasswordDecryptor,
    ) -> None:
        passwords = ["p@ssw0rD", "🌚", "", "\n\t"]
        password_ciphers = [password_encryptor.encrypt(p) for p in passwords]

        assert [password_decryptor.decrypt(c) for c in password_ciphers] == passwords

    def test_decrypts_ciphers_with_different_salts(
        self, password_decryptor: PasswordDecryptor
    ) -> None:
        password_cipher1 = PasswordEncryptor(MASTER_PASSWORD, b"a" * SALT_SIZE).encrypt(
            "first"
        )
        password_cipher2 = PasswordEncryptor(MASTER_PASSWORD, b"b" * SALT_SIZE).encrypt(
            "second"
        )

        assert password_decryptor.decrypt(password_cipher1) == "first"
        assert password_decryptor.decrypt(password_cipher2) == "second"
