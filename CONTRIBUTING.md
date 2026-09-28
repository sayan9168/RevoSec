# Contributing to RevoSec

Thank you for your interest in contributing!

## Code of Conduct
- Be respectful and constructive.
- Only contribute features that are **ethical and defensive**.
- Do not submit tools or code intended for unauthorized access or illegal activity.

## How to Contribute

1. **Fork** the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests and linting:
   ```bash
   ruff check src/
   pytest
   ```
5. Commit with a clear message
6. Open a Pull Request

## Development Setup
```bash
git clone https://github.com/sayan9168/RevoSec.git
cd RevoSec
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Feature Ideas
- Real-time FIM improvements
- More export formats
- Additional hash algorithms
- Better web dashboard
- Plugin system

## Reporting Bugs
Use the Bug Report issue template and include:
- OS and Python version
- Exact command that failed
- Full error traceback
