# Changelog

## 0.1.1 (2026-03-31)

- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility
- Add GitHub issue templates, dependabot config, and PR template

## 0.1.0 (2026-03-21)

- Initial release
- Auto-detect and mask secrets in strings using regex patterns
- Mask dict values whose keys match known secret key names
- Recursive masking for nested dicts and lists
- Configurable mask character and reveal length
