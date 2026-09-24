"""Create a local synthetic TLS identity, with no user or vault credentials."""
from pathlib import Path
import subprocess

directory = Path(__file__).resolve().parents[1] / ".build/guest-cache/browser/fixture"
directory.mkdir(mode=0o700, parents=True, exist_ok=True)
certificate, key = directory / "cert.pem", directory / "key.pem"
current = certificate.exists() and key.exists() and subprocess.run(
    ["openssl", "x509", "-in", str(certificate), "-noout", "-checkend", "86400"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
).returncode == 0
if current:
    current = "DNS:auth.shadow.test" in subprocess.check_output(["openssl", "x509", "-in", str(certificate), "-noout", "-ext", "subjectAltName"], text=True)
if not current:
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
        "-subj", "/CN=Shadow synthetic fixture", "-addext", "subjectAltName=DNS:app.shadow.test,DNS:auth.shadow.test",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "extendedKeyUsage=serverAuth",
        "-keyout", str(key), "-out", str(certificate),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
print("synthetic_tls_fixture_ready")
