import os
import ssl
import subprocess
import logging

CERT_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(CERT_DIR, "rdp.key")
CRT_PATH = os.path.join(CERT_DIR, "rdp.crt")


def _ensure_cert():
    if os.path.exists(KEY_PATH) and os.path.exists(CRT_PATH):
        return
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", KEY_PATH, "-out", CRT_PATH, "-days", "365",
        "-subj", "/CN=rdp-local",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info("self-signed cert generated")


def build_ssl_context():
    _ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CRT_PATH, KEY_PATH)
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    return ctx


SSL_CTX = build_ssl_context()
