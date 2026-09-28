# 🔥 RevoSec — Revolutionary Ethical Cybersecurity Toolkit

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Production Ready](https://img.shields.io/badge/status-production-brightgreen.svg)]()

**RevoSec** is a production-grade, modern, ethical cybersecurity toolkit built for security researchers, system administrators, and students who want powerful defensive and authorized-assessment capabilities in a beautiful CLI.

> ⚠️ **LEGAL & ETHICAL DISCLAIMER**  
> This tool is intended **ONLY** for:
> - Systems you own
> - Systems you have **explicit written authorization** to test
> - Educational and defensive security research
>
> Unauthorized scanning, access, or attacks are **illegal**. The authors assume no liability for misuse. Use responsibly.

---

## ✨ Features

| Module | Description | Safety Level |
|--------|-------------|--------------|
| **File Encryption** | AES-256-GCM & ChaCha20-Poly1305 with Scrypt KDF | Fully Safe |
| **Password Tools** | Cryptographically secure generator + strength analyzer | Fully Safe |
| **System Audit** | Local host audit (CPU, memory, disks, listening ports, processes) | Fully Safe |
| **Network Interfaces** | Passive listing of local interfaces | Fully Safe |
| **Port Scanner** | TCP connect scanner with mandatory authorization confirmation | Authorization Required |
| **Report Export** | JSON / CSV / Markdown reports saved to `~/.revosec/reports/` | Fully Safe |

### Why RevoSec is different
- Modern cryptography only (no MD5, no ECB, no home-grown crypto)
- Beautiful Rich-powered terminal UI
- Explicit authorization gates for any active network operation
- Structured logging to `~/.revosec/logs/`
- Clean modular architecture — easy to extend
- Fully typed, production-ready packaging

---

## 🚀 Installation

### From source (recommended)

```bash
git clone https://github.com/sayan9168/RevoSec.git
cd RevoSec
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

### Run without installing

```bash
pip install -r requirements.txt
python -m revosec
```

---

## 📖 Usage

```bash
# Show banner + help
revosec

# Encrypt a file
revosec encrypt secret.pdf
revosec encrypt secret.pdf --algo chacha20 -o secret.enc

# Decrypt
revosec decrypt secret.pdf.revosec

# Generate strong passwords
revosec password
revosec password --length 32 --count 5
revosec password --analyze "MyP@ssw0rd123"

# Local system audit
revosec audit
revosec audit --export

# Network interfaces (passive)
revosec interfaces

# Authorized port scan (will ask for confirmation)
revosec scan 192.168.1.10
revosec scan 192.168.1.10 --ports 22,80,443,8080
revosec scan example.com --ports 1-1000 --yes   # skip prompt (still logged)

# Version
revosec version
```

---

## 🏗️ Architecture

```
src/revosec/
├── cli.py              # Typer CLI entrypoint
├── core/
│   ├── encryption.py   # AES-GCM / ChaCha20-Poly1305
│   ├── password.py     # Generator + strength analysis
│   ├── audit.py        # Local system audit
│   └── network.py      # Interfaces + authorized scanner
└── utils/
    ├── banner.py
    ├── logger.py
    └── export.py
```

---

## 🔒 Security Design Decisions

- **Key derivation**: Scrypt (memory-hard) — resistant to GPU/ASIC attacks
- **Encryption**: Only authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- **Randomness**: `secrets` and `os.urandom` only
- **Scanning**: TCP connect scan only (no SYN stealth). Mandatory confirmation + logging
- **No credential storage**: Passwords are never saved
- **Logging**: All sensitive actions are logged locally

---

## 📦 Requirements

- Python 3.10+
- See `requirements.txt` / `pyproject.toml` for full list

Optional system dependencies:
- `nmap` (if you later extend the scanner)
- Root/admin privileges only needed for certain low-level packet operations (not required for current features)

---

## 🛠️ Development

```bash
pip install -e ".[dev]"
ruff check src/
mypy src/
pytest
```

---

## 🗺️ Roadmap

- [ ] File Integrity Monitoring (watchdog + hashing)
- [ ] Optional local web dashboard (Streamlit / FastAPI)
- [ ] Hash identification & educational cracker (for your own hashes)
- [ ] Secure note vault
- [ ] Plugin system

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

## 🙏 Credits

Built with ❤️ by [Sayan the researcher](https://github.com/sayan9168)  
Stack: Python • Typer • Rich • cryptography • psutil • scapy

**Stay ethical. Stay curious. Stay secure.**
