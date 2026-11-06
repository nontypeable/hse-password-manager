import pytest

from password_manager.crypto import KEY_LENGTH, SALT_SIZE, derive_key, generate_salt


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
