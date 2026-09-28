"""
RevoSec - Revolutionary Ethical Cybersecurity Toolkit
=====================================================

Production-grade toolkit for authorized security research, auditing,
encryption, and network analysis.

WARNING: This tool is intended ONLY for educational purposes, authorized
penetration testing, and defensive security research. Unauthorized use
against systems you do not own or have explicit permission to test is
illegal and unethical.
"""

__version__ = "1.2.0"
__author__ = "Sayan the researcher"
__license__ = "MIT"

from revosec.cli import app

__all__ = ["app", "__version__"]
