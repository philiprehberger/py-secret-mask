from philiprehberger_secret_mask import is_secret_key, mask_secrets, mask_value


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
