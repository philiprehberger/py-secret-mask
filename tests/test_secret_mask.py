from philiprehberger_secret_mask import (
    is_secret_key,
    mask_secrets,
    mask_value,
    register_key,
    register_pattern,
    _SECRET_KEY_NAMES,
    _SECRET_PATTERNS,
)


class TestMaskValue:
    def test_basic(self) -> None:
        result = mask_value("supersecretvalue")
        assert result == "************alue"

    def test_short_value(self) -> None:
        result = mask_value("abc")
        assert result == "***"

    def test_custom_mask_char(self) -> None:
        result = mask_value("mysecret", mask_char="#")
        assert result == "####cret"

    def test_custom_reveal_last(self) -> None:
        result = mask_value("mysecretvalue", reveal_last=6)
        assert result == "*******tvalue"


class TestIsSecretKey:
    def test_matches_password(self) -> None:
        assert is_secret_key("db_password") is True

    def test_matches_api_key(self) -> None:
        assert is_secret_key("API_KEY") is True

    def test_matches_token(self) -> None:
        assert is_secret_key("access_token") is True

    def test_matches_secret(self) -> None:
        assert is_secret_key("client_secret") is True

    def test_matches_credential(self) -> None:
        assert is_secret_key("user_credential") is True

    def test_no_match(self) -> None:
        assert is_secret_key("username") is False

    def test_no_match_name(self) -> None:
        assert is_secret_key("display_name") is False


class TestMaskSecretsDict:
    def test_masks_secret_keys(self) -> None:
        data = {"username": "alice", "password": "hunter2", "api_key": "sk-abc123"}
        result = mask_secrets(data)
        assert result["username"] == "alice"
        assert result["password"] == "***ter2"
        assert result["api_key"] == "*****c123"

    def test_nested_dict(self) -> None:
        data = {
            "config": {
                "host": "localhost",
                "secret": "topsecretvalue",
            }
        }
        result = mask_secrets(data)
        assert isinstance(result, dict)
        config = result["config"]
        assert isinstance(config, dict)
        assert config["host"] == "localhost"
        assert config["secret"] == "**********alue"


class TestMaskSecretsString:
    def test_bearer_token(self) -> None:
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        result = mask_secrets(text)
        assert isinstance(result, str)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert result.endswith("VCJ9")

    def test_api_key_pattern(self) -> None:
        text = "key is sk-1234567890abcdefghij"
        result = mask_secrets(text)
        assert isinstance(result, str)
        assert "sk-1234567890abcdefghij" not in result


class TestRegisterPattern:
    def test_custom_pattern_masks_string(self) -> None:
        original_len = len(_SECRET_PATTERNS)
        register_pattern(r"CUSTOM-[A-Za-z0-9]{8,}")
        try:
            text = "my key is CUSTOM-abcdefghij"
            result = mask_secrets(text)
            assert isinstance(result, str)
            assert "CUSTOM-abcdefghij" not in result
            assert result.endswith("ghij")
        finally:
            _SECRET_PATTERNS.pop()
            assert len(_SECRET_PATTERNS) == original_len

    def test_custom_pattern_no_false_positive(self) -> None:
        original_len = len(_SECRET_PATTERNS)
        register_pattern(r"CUSTOM-[A-Za-z0-9]{8,}")
        try:
            text = "CUSTOM-ab"
            result = mask_secrets(text)
            assert result == "CUSTOM-ab"
        finally:
            _SECRET_PATTERNS.pop()
            assert len(_SECRET_PATTERNS) == original_len


class TestRegisterKey:
    def test_custom_key_detected(self) -> None:
        register_key("my_custom_field")
        try:
            assert is_secret_key("my_custom_field") is True
            assert is_secret_key("MY_CUSTOM_FIELD") is True
        finally:
            _SECRET_KEY_NAMES.discard("my_custom_field")

    def test_custom_key_masks_dict_value(self) -> None:
        register_key("ssn")
        try:
            data = {"name": "alice", "ssn": "123-45-6789"}
            result = mask_secrets(data)
            assert result["name"] == "alice"
            assert result["ssn"] != "123-45-6789"
            assert isinstance(result["ssn"], str)
            assert result["ssn"].endswith("6789")
        finally:
            _SECRET_KEY_NAMES.discard("ssn")

    def test_case_insensitive_registration(self) -> None:
        register_key("FooBar")
        try:
            assert "foobar" in _SECRET_KEY_NAMES
            assert is_secret_key("FOOBAR") is True
        finally:
            _SECRET_KEY_NAMES.discard("foobar")


class TestNonSecretUnchanged:
    def test_plain_string(self) -> None:
        assert mask_secrets("hello world") == "hello world"

    def test_plain_dict(self) -> None:
        data = {"name": "alice", "age": 30}
        result = mask_secrets(data)
        assert result == {"name": "alice", "age": 30}

    def test_list_with_non_secrets(self) -> None:
        data = ["hello", "world"]
        result = mask_secrets(data)
        assert result == ["hello", "world"]
