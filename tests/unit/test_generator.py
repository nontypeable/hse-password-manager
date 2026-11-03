import pytest

from password_manager.generator import (
    MIN_PASSWORD_LENGTH,
    IPasswordGenerator,
    PasswordGenerator,
)


@pytest.fixture
def generator() -> IPasswordGenerator:
    return PasswordGenerator()


class TestPasswordGenerator:
    @pytest.mark.parametrize(
        "length",
        [
            MIN_PASSWORD_LENGTH,
            MIN_PASSWORD_LENGTH * 2,
            MIN_PASSWORD_LENGTH * 4,
            MIN_PASSWORD_LENGTH * 8,
        ],
    )
    def test_generate_password_has_requested_length(
        self, generator: IPasswordGenerator, length: int
    ) -> None:
        password = generator.generate_password(length)

        assert len(password) == length

    @pytest.mark.parametrize(
        "length", [MIN_PASSWORD_LENGTH - 1, 0, -MIN_PASSWORD_LENGTH]
    )
    def test_generate_password_with_too_small_length_raises(
        self, generator: IPasswordGenerator, length: int
    ) -> None:
        with pytest.raises(ValueError):
            generator.generate_password(length)

    def test_generate_password_is_random(self, generator: IPasswordGenerator) -> None:
        password1 = generator.generate_password(MIN_PASSWORD_LENGTH)
        password2 = generator.generate_password(MIN_PASSWORD_LENGTH)

        assert len(password1) == MIN_PASSWORD_LENGTH
        assert len(password2) == MIN_PASSWORD_LENGTH
        assert password1 != password2
