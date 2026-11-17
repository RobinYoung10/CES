# CES - Cyber Security Engineering (UFCE87-15-3) Assessment

Security assessment and hardening of a browser-based file encryption/decryption
service (Flask + Nginx, containerised with Docker).

## Repository structure

| Path | Contents |
| --- | --- |
| `original/` | The provided app, **unmodified** - the insecure baseline ("before") |
| `secure/` | The hardened implementation ("after") |
| `assessment/` | Scan outputs, screenshots, evidence |
| `docs/` | Slides, diagrams |

## Summary of changes (original -> secure)

- Removed malicious start-up code (backdoor: Fernet-decrypted shell command).
- Replaced XOR / 1-byte key with **AES-256-GCM** (authenticated encryption).
- Server-side key management; key never returned to the client or logged.
- Input validation: `secure_filename`, 10 MB upload cap, proper error handling.
- Implemented a working, integrity-checked **decrypt/download** route.
- TLS 1.2/1.3 with NIST SP 800-52 cipher suites; HTTP->HTTPS redirect; HSTS + security headers.
- Non-root containers, `no-new-privileges`, known base image, pinned dependencies.
- STIG-aligned logging (INFO, rotated, no secrets).

## Running the ORIGINAL (insecure - isolated VM only)

> Contains a backdoor. Run only inside an isolated VM.

    cd original
    docker compose up --build
    # http://localhost:443/   (plain HTTP on 443 - no TLS)

## Running the SECURE version

    cd secure
    cp .env.example .env
    # put a real key in .env:
    python3 -c "import os,base64;print('FILE_ENCRYPTION_KEY='+base64.b64encode(os.urandom(32)).decode())" >> .env
    ./gen-cert.sh                 # generate self-signed TLS cert
    docker compose up --build
    # https://localhost/   (HTTP redirects to HTTPS)

## Compliance references

DISA Application Security and Development STIG; DISA Web Server SRG;
NIST SP 800-52 Rev 2; NIST FIPS 140-3; CIS Docker Benchmark; OWASP Top 10.
