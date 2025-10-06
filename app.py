from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
import os, json, secrets
from pathlib import Path

APP_SECRET = secrets.token_hex(16)
VAULT_PATH = Path("vault.json")

app = Flask(__name__)
app.secret_key = APP_SECRET

def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    return urlsafe_b64encode(kdf.derive(password_bytes))

def load_vault():
    if not VAULT_PATH.exists():
        data = {
            "salt": secrets.token_bytes(16).hex(),
            "master_hash": None,
            "entries": [],
            "name": None
        }
        VAULT_PATH.write_text(json.dumps(data, indent=2))
        return data
    else:
        return json.loads(VAULT_PATH.read_text())

def save_vault(data):
    VAULT_PATH.write_text(json.dumps(data, indent=2))

@app.route("/", methods=["GET"])
def index():
    vault = load_vault()
    logged_in = session.get("unlocked", False)
    entries = []
    vault_name = vault.get("name")
    if logged_in:
        entries = [{"name": e["name"], "username": e["username"]} for e in vault.get("entries", [])]
    return render_template("index.html", logged_in=logged_in, entries=entries, vault_name=vault_name)

@app.route("/setup", methods=["POST"])
def setup():
    vault = load_vault()
    if vault.get("master_hash") is not None:
        return "Master already set", 400
    pw = request.form.get("password")
    name = request.form.get("name")
    if not pw or len(pw) < 6:
        return "Password too short", 400
    if not name or len(name.strip()) < 1:
        return "Name required", 400
    salt = bytes.fromhex(vault["salt"])
    key = derive_key(pw, salt)
    f = Fernet(key)
    token = f.encrypt(b"master-token").hex()
    vault["master_hash"] = token
    vault["name"] = name.strip()
    save_vault(vault)
    return redirect(url_for("index"))

@app.route("/unlock", methods=["POST"])
def unlock():
    pw = request.form.get("password")
    if not pw:
        return "Missing password", 400
    vault = load_vault()
    if not vault.get("master_hash"):
        return "No master set", 400
    salt = bytes.fromhex(vault["salt"])
    try:
        key = derive_key(pw, salt)
        f = Fernet(key)
        _ = f.decrypt(bytes.fromhex(vault["master_hash"]))
        session["unlocked"] = True
        session["pw_key"] = key.decode()
        return redirect(url_for("index"))
    except Exception:
        return "Incorrect password", 403

@app.route("/add", methods=["POST"])
def add_entry():
    if not session.get("unlocked"):
        return "Locked", 403
    name = request.form.get("name")
    username = request.form.get("username")
    password = request.form.get("password")
    if not (name and username and password):
        return "Missing fields", 400
    vault = load_vault()
    key = session.get("pw_key").encode()
    f = Fernet(key)
    encrypted = f.encrypt(password.encode()).hex()
    vault.setdefault("entries", []).append({
        "name": name,
        "username": username,
        "password": encrypted
    })
    save_vault(vault)
    return redirect(url_for("index"))

@app.route("/show/<int:idx>", methods=["GET"])
def show_password(idx):
    if not session.get("unlocked"):
        return "Locked", 403
    vault = load_vault()
    try:
        entry = vault["entries"][idx]
    except Exception:
        return "Not found", 404
    key = session.get("pw_key").encode()
    f = Fernet(key)
    try:
        pwd = f.decrypt(bytes.fromhex(entry["password"]))
        return jsonify({"password": pwd.decode()})
    except Exception:
        return "Decryption failed", 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
