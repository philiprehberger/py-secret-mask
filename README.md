# philiprehberger-secret-mask

[![Tests](https://github.com/philiprehberger/py-secret-mask/actions/workflows/publish.yml/badge.svg)](https://github.com/philiprehberger/py-secret-mask/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/philiprehberger-secret-mask.svg)](https://pypi.org/project/philiprehberger-secret-mask/)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/py-secret-mask)](https://github.com/philiprehberger/py-secret-mask/commits/main)

Automatically detect and mask secrets in strings and dicts.

## Installation

```bash
pip install philiprehberger-secret-mask
```

## Usage

```python
from philiprehberger_secret_mask import mask_secrets

data = {"username": "alice", "password": "hunter2", "api_key": "sk-abc123def456ghi789jk"}
safe = mask_secrets(data)
# {"username": "alice", "password": "***ter2", "api_key": "******************89jk"}
```

### Masking Strings

```python
from philiprehberger_secret_mask import mask_secrets

log_line = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw"
safe_log = mask_secrets(log_line)
# Bearer token is replaced with asterisks, last 4 chars visible
```

### Checking Key Names

```python
from philiprehberger_secret_mask import is_secret_key

is_secret_key("db_password")   # True
is_secret_key("api_key")       # True
is_secret_key("username")      # False
```

### Custom Masking

```python
from philiprehberger_secret_mask import mask_value

mask_value("supersecret", mask_char="#", reveal_last=2)
# "#########et"
```

## API

| Function / Constant | Description |
|----------------------|-------------|
| `mask_secrets(data, *, mask_char, reveal_last)` | Detect and mask secrets in a string, dict, or list |
| `mask_value(value, *, mask_char, reveal_last)` | Mask a single string value |
| `is_secret_key(key)` | Check if a key name matches known secret patterns |
| `_SECRET_PATTERNS` | Compiled regexes for secret patterns in strings |
| `_SECRET_KEY_NAMES` | Set of key name substrings that indicate secrets |

## Development

```bash
pip install -e .
python -m pytest tests/ -v
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/py-secret-mask)

🐛 [Report issues](https://github.com/philiprehberger/py-secret-mask/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/py-secret-mask/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
