import os
import base64
import logging
from io import BytesIO
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, send_file, abort
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Key management: load from an injected secret, never hard-code ---
# Generate once (outside the image) and inject via environment/secret:
#   python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
_key_b64 = os.environ.get("FILE_ENCRYPTION_KEY")
if not _key_b64:
    raise RuntimeError("FILE_ENCRYPTION_KEY not set")
AES_KEY = base64.b64decode(_key_b64)  # 32 bytes = AES-256
if len(AES_KEY) != 32:
    raise RuntimeError("FILE_ENCRYPTION_KEY must decode to 32 bytes")

STORAGE_DIR = "/app/data"
os.makedirs(STORAGE_DIR, exist_ok=True)
MAX_BYTES = 10 * 1024 * 1024  # 10 MB upload cap

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES

# --- STIG-aligned logging: INFO, structured, rotated, no secrets ---
os.makedirs("/app/logs", exist_ok=True)
_handler = RotatingFileHandler("/app/logs/flask_app.log", maxBytes=1_000_000, backupCount=5)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s : %(message)s",
    handlers=[_handler, logging.StreamHandler()],
)
log = app.logger


def encrypt_bytes(data: bytes) -> bytes:
    nonce = os.urandom(12)                              # 96-bit nonce for GCM
    ct = AESGCM(AES_KEY).encrypt(nonce, data, None)     # authenticated encryption
    return nonce + ct


def decrypt_bytes(blob: bytes) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(AES_KEY).decrypt(nonce, ct, None)     # raises on tamper


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files or request.files["file"].filename == "":
        abort(400, "No file provided")
    f = request.files["file"]
    name = secure_filename(f.filename)                  # strips path traversal
    if not name:
        abort(400, "Invalid filename")
    enc = encrypt_bytes(f.read())
    path = os.path.join(STORAGE_DIR, name + ".enc")
    with open(path, "wb") as out:
        out.write(enc)
    log.info("Encrypted upload stored: %s (%d bytes)", name + ".enc", len(enc))
    return render_template("index.html", message="Encrypted and stored as %s.enc" % name)


@app.route("/files")
def list_files():
    files = [x for x in os.listdir(STORAGE_DIR) if x.endswith(".enc")]
    return render_template("decrypt.html", files=files)


@app.route("/decrypt", methods=["POST"])
def decrypt():
    name = secure_filename(request.form.get("filename", ""))
    path = os.path.join(STORAGE_DIR, name)
    if not name or not os.path.isfile(path):
        abort(404, "File not found")
    try:
        plaintext = decrypt_bytes(open(path, "rb").read())
    except Exception:
        log.warning("Decryption/integrity failure for %s", name)
        abort(400, "Decryption failed (file may be corrupt or tampered)")
    original = name[:-4] if name.endswith(".enc") else name
    log.info("Decrypted download served: %s", name)
    return send_file(BytesIO(plaintext), as_attachment=True, download_name=original)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
