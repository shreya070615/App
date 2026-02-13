"""
AI-Powered Cyber Incident Response Platform
Single File GitHub-Friendly Version
"""

import os
import json
import sqlite3
import hashlib
import datetime
import threading
import time
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import numpy as np

# ==========================
# BASIC CONFIGURATION
# ==========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_FOLDER = os.path.join(BASE_DIR, "instance")
TEMPLATE_FOLDER = os.path.join(BASE_DIR, "templates")

os.makedirs(INSTANCE_FOLDER, exist_ok=True)
os.makedirs(TEMPLATE_FOLDER, exist_ok=True)

DB_PATH = os.path.join(INSTANCE_FOLDER, "soc_platform.db")

app = Flask(__name__, template_folder=TEMPLATE_FOLDER)
app.secret_key = os.environ.get("SECRET_KEY", "super-secret-dev-key")
CORS(app)

# ==========================
# DATABASE INITIALIZATION
# ==========================

def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            title TEXT,
            severity TEXT,
            attack_type TEXT,
            confidence REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    create_default_admin()


def create_default_admin():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        password_hash = hashlib.sha256("Admin@123".encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username,password_hash,role) VALUES (?,?,?)",
            ("admin", password_hash, "admin"),
        )
        conn.commit()
    conn.close()

# ==========================
# SIMPLE AI ANALYSIS
# ==========================

def analyze_log(log_text):
    log_text = log_text.lower()
    attack = "unknown"
    confidence = 0.2

    if "failed password" in log_text:
        attack = "bruteforce"
        confidence = 0.85
    elif "select" in log_text or "union" in log_text:
        attack = "sqli"
        confidence = 0.8
    elif "scan" in log_text:
        attack = "port_scan"
        confidence = 0.7

    severity = "low"
    if confidence > 0.8:
        severity = "high"
    elif confidence > 0.6:
        severity = "medium"

    return attack, confidence, severity

# ==========================
# LOGIN DECORATOR
# ==========================

def login_required(f):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# ==========================
# ROUTES
# ==========================

@app.route("/")
def home():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hashlib.sha256(request.form["password"].encode()).hexdigest()

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id,role FROM users WHERE username=? AND password_hash=?",
                       (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["role"] = user[1]
            return redirect("/dashboard")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/dashboard")
@login_required
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC")
    incidents = cursor.fetchall()
    conn.close()
    return render_template("dashboard.html", incidents=incidents)


@app.route("/api/analyze", methods=["POST"])
@login_required
def analyze():
    data = request.json
    attack, confidence, severity = analyze_log(data["log"])

    alert_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO incidents (alert_id,title,severity,attack_type,confidence)
        VALUES (?,?,?,?,?)
    """, (alert_id, "Security Alert", severity, attack, confidence))
    conn.commit()
    conn.close()

    return jsonify({
        "attack": attack,
        "confidence": confidence,
        "severity": severity
    })

# ==========================
# AUTO-CREATE HTML FILES
# ==========================

def create_templates():
    login_path = os.path.join(TEMPLATE_FOLDER, "login.html")
    dashboard_path = os.path.join(TEMPLATE_FOLDER, "dashboard.html")

    if not os.path.exists(login_path):
        with open(login_path, "w") as f:
            f.write("""
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<h2>AI SOC Login</h2>
<form method="POST">
Username:<input name="username"><br><br>
Password:<input type="password" name="password"><br><br>
<button type="submit">Login</button>
</form>
<p>Default: admin / Admin@123</p>
</body>
</html>
""")

    if not os.path.exists(dashboard_path):
        with open(dashboard_path, "w") as f:
            f.write("""
<!DOCTYPE html>
<html>
<head>
<title>Dashboard</title>
<script>
function analyzeLog(){
    let log=prompt("Enter log:");
    fetch("/api/analyze",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({log:log})
    }).then(r=>r.json()).then(d=>{
        alert("Attack:"+d.attack+"\\nSeverity:"+d.severity+"\\nConfidence:"+d.confidence);
        location.reload();
    });
}
</script>
</head>
<body>
<h2>AI SOC Dashboard</h2>
<button onclick="analyzeLog()">Analyze Log</button>
<a href="/logout">Logout</a>
<hr>
<table border="1">
<tr><th>ID</th><th>Alert</th><th>Severity</th><th>Type</th><th>Confidence</th></tr>
{% for i in incidents %}
<tr>
<td>{{i[0]}}</td>
<td>{{i[1]}}</td>
<td>{{i[3]}}</td>
<td>{{i[4]}}</td>
<td>{{i[5]}}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
""")

# ==========================
# MAIN
# ==========================

if __name__ == "__main__":
    create_templates()
    init_database()
    app.run(host="0.0.0.0", port=5000)
