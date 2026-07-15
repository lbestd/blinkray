"""Self-signed TLS certificate generation via the openssl CLI.

Used both for the panel's own HTTPS listener and for the xray VLESS+TLS
inbound, so it takes no dependency on the `cryptography` package.
"""
import subprocess
from pathlib import Path


def ensure_self_signed_cert(cert_path: Path, key_path: Path, cn: str, sans=None, days: int = 3650,
                             key_mode: int = 0o600) -> bool:
    """Create a self-signed cert/key pair at the given paths if missing.

    Returns True if a new cert/key pair was generated, False if one already
    existed and was left untouched.
    """
    cert_path = Path(cert_path)
    key_path = Path(key_path)
    if cert_path.exists() and key_path.exists():
        return False

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    sans = sans or []
    alt_names = [f"DNS:{cn}"] + [
        f"IP:{s}" if _looks_like_ip(s) else f"DNS:{s}" for s in sans if s != cn
    ]
    san_ext = "subjectAltName=" + ",".join(dict.fromkeys(alt_names))

    cmd = [
        "openssl", "req", "-x509", "-nodes",
        "-newkey", "rsa:2048",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", str(days),
        "-subj", f"/CN={cn}",
        "-addext", san_ext,
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    key_path.chmod(key_mode)
    cert_path.chmod(0o644)
    return True


def ensure_ca(cert_path: Path, key_path: Path, cn: str = "Blinkray CA", days: int = 3650,
              key_mode: int = 0o600) -> bool:
    """Create a self-signed root CA cert/key pair if missing. Used to sign
    per-client certificates for mTLS (see ensure_signed_cert) — kept
    separate from the server's own leaf cert so the CA key never needs to
    leave this function's callers."""
    cert_path = Path(cert_path)
    key_path = Path(key_path)
    if cert_path.exists() and key_path.exists():
        return False

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "openssl", "req", "-x509", "-nodes",
        "-newkey", "rsa:2048",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", str(days),
        "-subj", f"/CN={cn}",
        "-addext", "basicConstraints=critical,CA:true",
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    key_path.chmod(key_mode)
    cert_path.chmod(0o644)
    return True


def ensure_signed_cert(cert_path: Path, key_path: Path, cn: str, ca_cert_path: Path, ca_key_path: Path,
                        days: int = 825, key_mode: int = 0o600) -> bool:
    """Create a leaf cert/key pair signed by the given CA, if missing. Used
    for per-client mTLS certificates — the CA's own key never touches the
    client's key file, only signs it."""
    cert_path = Path(cert_path)
    key_path = Path(key_path)
    if cert_path.exists() and key_path.exists():
        return False

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    csr_path = key_path.with_suffix(".csr")
    try:
        subprocess.run(
            [
                "openssl", "req", "-new", "-nodes",
                "-newkey", "rsa:2048",
                "-keyout", str(key_path),
                "-out", str(csr_path),
                "-subj", f"/CN={cn}",
            ],
            check=True, capture_output=True,
        )
        subprocess.run(
            [
                "openssl", "x509", "-req",
                "-in", str(csr_path),
                "-CA", str(ca_cert_path),
                "-CAkey", str(ca_key_path),
                "-CAcreateserial",
                "-out", str(cert_path),
                "-days", str(days),
                "-sha256",
            ],
            check=True, capture_output=True,
        )
    finally:
        csr_path.unlink(missing_ok=True)
    key_path.chmod(key_mode)
    cert_path.chmod(0o644)
    return True


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def cert_sha256_fingerprint(cert_path: Path) -> str:
    """Return the lowercase hex SHA-256 fingerprint of a cert (no colons),
    suitable for VLESS `pinnedPeerCertSha256`."""
    out = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-fingerprint", "-sha256"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    # format: "sha256 Fingerprint=AA:BB:...:CC"
    value = out.split("=", 1)[1]
    return value.replace(":", "").lower()
