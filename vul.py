import os
import random
import hashlib
import requests
from flask import Flask, request

app = Flask(__name__)

# --- VULN 1: Hard-coded secret / API key pattern ---
AWS_ACCESS_KEY_ID = "AKIA1234567890FAKEKEY"        # secret detection
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY"  # secret detection


# --- VULN 2: Weak crypto (MD5) for password hashing ---
def hash_password_md5(password: str) -> str:
    # Snyk should flag use of MD5 for passwords
    return hashlib.md5(password.encode("utf-8")).hexdigest()


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "test")
    password = request.form.get("password", "password")

    hashed = hash_password_md5(password)
    print(f"[DEBUG] Saving user={username} hash={hashed}")  # pretend DB

    return {"status": "ok", "user": username}


# --- VULN 3: Path traversal with user-controlled file path ---
@app.route("/read-log")
def read_log():
    filename = request.args.get("file", "app.log")
    # ❌ direct user-controlled file path, no validation
    log_path = os.path.join("logs", filename)
    try:
        with open(log_path, "r") as f:
            content = f.read()
        return {"file": filename, "content": content}
    except Exception as e:
        return {"error": str(e)}, 500


# --- VULN 4: Command injection via os.popen ---
@app.route("/list")
def list_dir():
    path = request.args.get("path", ".")
    # ❌ user input passed directly into shell command
    cmd = f"ls -la {path}"
    stream = os.popen(cmd)
    output = stream.read()
    return {"command": cmd, "output": output}


# --- VULN 5: SSRF (Server-Side Request Forgery) style pattern ---
@app.route("/fetch-url")
def fetch_url():
    url = request.args.get("url", "http://example.com")
    # ❌ unvalidated, server-side HTTP request with user URL
    r = requests.get(url, timeout=5)
    return {"status_code": r.status_code, "content": r.text[:200]}


# --- VULN 6: Insecure random token ---
@app.route("/token")
def insecure_token():
    # ❌ random is not cryptographically secure
    token = "".join(str(random.randint(0, 9)) for _ in range(16))
    return {"token": token}


# --- VULN 7: Dangerous eval on user input ---
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    # ❌ Remote code execution pattern
    try:
        result = eval(expr)  # Snyk should scream here
        return {"expr": expr, "result": result}
    except Exception as e:
        return {"error": str(e)}, 400


if __name__ == "__main__":
    # Simple demo startup
    os.makedirs("logs", exist_ok=True)
    with open("logs/app.log", "w") as f:
        f.write("demo log\n")

    app.run(debug=True, host="0.0.0.0", port=5000)
