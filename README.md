# 🔥 RevoSec — Revolutionary Ethical Cybersecurity Toolkit

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/sayan9168/RevoSec/actions/workflows/ci.yml/badge.svg)](https://github.com/sayan9168/RevoSec/actions)
[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](https://github.com/sayan9168/RevoSec)
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
| **Hash Tools** | Multi-algo hashing, verification, hash identification | Fully Safe |
| **File Integrity Monitor** | Baseline + change detection + **real-time watch** (watchdog) | Fully Safe |
| **Secure Vault** | AES-GCM encrypted personal notes & secrets | Fully Safe |
| **Web Dashboard** | Streamlit dashboard (`streamlit run dashboard/app.py`) | Fully Safe |
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

# Hash tools
revosec hash secret.pdf
revosec hash secret.pdf --multi
revosec hash "hello world" --text --algo sha512
revosec hash secret.pdf --verify abc123...
revosec hash --identify 5d41402abc4b2a76b9719d911017c592

# File Integrity Monitoring
revosec fim create /etc --name system
revosec fim check --name system
revosec fim list
revosec fim watch ~/Documents          # Real-time

# Secure Vault
revosec vault add --title "Secrets" --content "key=value"
revosec vault list
revosec vault read --id 20260928

# Web Dashboard
streamlit run dashboard/app.py

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
│   ├── network.py      # Interfaces + authorized scanner
│   ├── hashing.py      # Multi-algo hash + identify + verify
│   ├── integrity.py    # File Integrity Monitoring (FIM + real-time)
│   └── vault.py        # Secure encrypted notes
├── dashboard/
│   └── app.py          # Streamlit web dashboard
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

- [x] File Integrity Monitoring (baseline + change detection)
- [x] Hash tools (multi-algo + identify + verify)
- [x] Real-time FIM with watchdog
- [x] Secure note vault (encrypted)
- [x] Optional local web dashboard (Streamlit)
- [ ] Plugin system
- [ ] More export formats & reporting

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

## 🙏 Credits

Built with ❤️ by [Sayan the researcher](https://github.com/sayan9168)  
Stack: Python • Typer • Rich • cryptography • psutil • scapy • Streamlit

**Stay ethical. Stay curious. Stay secure.**
