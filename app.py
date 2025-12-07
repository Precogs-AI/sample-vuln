import os
import pickle
import sqlite3
import yaml
from flask import Flask, request

app = Flask(__name__)

# --- VULN 1: Hard-coded secret ---
API_KEY = "SUPER_SECRET_API_KEY_12345"  # Snyk should flag this


# --- VULN 2: SQL Injection ---
def get_user_by_name(username):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # Intentionally vulnerable query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result


@app.route("/user")
def user():
    username = request.args.get("username", "test")
    data = get_user_by_name(username)
    return {"data": str(data)}


# --- VULN 3: Command Injection ---
@app.route("/ping")
def ping():
    ip = request.args.get("ip", "127.0.0.1")
    # Intentionally dangerous: using user input in shell command
    os.system(f"ping -c 1 {ip}")
    return {"status": "ok"}


# --- VULN 4: Insecure Deserialization ---
@app.route("/load")
def load():
    raw = request.args.get("data", None)
    if not raw:
        return {"error": "no data"}, 400

    # Intentionally insecure: untrusted pickle.loads
    obj = pickle.loads(bytes.fromhex(raw))
    return {"loaded": str(obj)}


# --- VULN 5: Unsafe YAML load ---
@app.route("/yaml")
def yaml_load():
    data = request.args.get("data", "a: 1")
    # Unsafe loader (yaml.load instead of safe_load)
    loaded = yaml.load(data, Loader=yaml.Loader)  # vulnerable usage
    return {"parsed": str(loaded)}


if __name__ == "__main__":
    # Simple DB init to avoid runtime errors
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT)")
    c.execute("INSERT OR IGNORE INTO users (id, username) VALUES (1, 'test')")
    conn.commit()
    conn.close()

    app.run(debug=True)
