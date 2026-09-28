"""
RevoSec Web Dashboard (Streamlit)

Run with:
    streamlit run dashboard/app.py
"""

import streamlit as st
import subprocess
import sys
from pathlib import Path

st.set_page_config(
    page_title="RevoSec Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ RevoSec Dashboard")
st.caption("Revolutionary Ethical Cybersecurity Toolkit — Web Interface")

st.sidebar.title("Modules")
module = st.sidebar.radio(
    "Select Module",
    ["Overview", "Password Generator", "System Audit", "Hash Tools", "About"],
)

if module == "Overview":
    st.header("Welcome to RevoSec")
    st.markdown("""
    **RevoSec** is a production-grade ethical cybersecurity toolkit.

    ### Available CLI Commands
    - `revosec encrypt / decrypt` — Modern authenticated encryption
    - `revosec password` — Strong password generation & analysis
    - `revosec audit` — Local system security audit
    - `revosec scan` — Authorized port scanner
    - `revosec hash` — Multi-algorithm hashing
    - `revosec fim` — File Integrity Monitoring (baseline + real-time watch)
    - `revosec vault` — Secure encrypted notes

    Use the sidebar to try interactive features.
    """)
    st.info("For full power, use the CLI: `revosec --help`")

elif module == "Password Generator":
    st.header("Password Generator")
    length = st.slider("Length", 8, 64, 20)
    count = st.number_input("How many", 1, 20, 1)
    if st.button("Generate"):
        try:
            from revosec.core.password import generate_password, analyze_strength
            for _ in range(count):
                pwd = generate_password(length=length)
                st.code(pwd, language=None)
                result = analyze_strength(pwd)
                st.write(f"Strength: **{result['level']}** (score {result['score']})")
        except Exception as e:
            st.error(str(e))

elif module == "System Audit":
    st.header("Local System Audit")
    st.warning("This runs a local audit of the machine running Streamlit.")
    if st.button("Run Audit"):
        with st.spinner("Running audit..."):
            try:
                from revosec.core.audit import run_full_audit
                report = run_full_audit(export=False)
                st.success("Audit completed")
                st.json({
                    "hostname": report["system"]["hostname"],
                    "platform": report["system"]["platform"],
                    "memory_used_percent": report["memory"]["used_percent"],
                    "listening_ports": len(report["listening_ports"]),
                })
            except Exception as e:
                st.error(str(e))

elif module == "Hash Tools":
    st.header("Hash Tools")
    text = st.text_input("Text to hash")
    algo = st.selectbox("Algorithm", ["sha256", "sha512", "sha1", "md5", "blake2b"])
    if st.button("Hash") and text:
        try:
            from revosec.core.hashing import hash_string
            digest = hash_string(text, algo)
            st.code(digest)
        except Exception as e:
            st.error(str(e))

elif module == "About":
    st.header("About RevoSec")
    st.markdown("""
    **Version:** 1.2.0  
    **Author:** Sayan the researcher  
    **License:** MIT  
    **Repo:** [github.com/sayan9168/RevoSec](https://github.com/sayan9168/RevoSec)

    Built for educational and authorized defensive security use only.
    """)
    st.warning("Unauthorized scanning or attacks are illegal.")
