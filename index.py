import os
import sqlite3
import bcrypt
import jwt
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for
import PyPDF2
import openai
import spacy
import smtplib
from email.message import EmailMessage

# Load spaCy NLP model
nlp = spacy.load("en_core_web_sm")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")

# OpenAI API key from env
openai.api_key = os.environ.get("OPENAI_API_KEY")

# Database setup (SQLite)
DB_PATH = "users.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            username TEXT,
            password_hash TEXT,
            google_id TEXT UNIQUE,
            reset_token TEXT,
            reset_expiry DATETIME
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper: create JWT token
def create_jwt(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    return token

# Helper: decode JWT token
def decode_jwt(token):
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return payload["user_id"]
    except Exception:
        return None

# Helper: extract text from PDF
def extract_text_from_pdf(file):
    reader = PyPDF2.PdfReader(file)
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""
    return text

# Helper: call OpenAI to analyze resume
def analyze_resume(resume_text, job_desc):
    prompt = f"""
You are an expert career coach.
Analyze the following resume and give ONLY a JSON response with:
{{
    "resume_score": int,
    "job_fit_score": int,
    "suggestions": ["point1", "point2", "point3", "point4", "point5"]
}}

Resume:
{resume_text}

Job Description:
{job_desc}
"""
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
    )
    return eval(response.choices[0].message["content"])

# Signup
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    if not email or not username or not password:
        return jsonify({"error": "Missing fields"}), 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 409
    finally:
        conn.close()

    return jsonify({"message": "User created"}), 201

# Login
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    if not bcrypt.checkpw(password.encode(), user["password_hash"]):
        return jsonify({"error": "Invalid password"}), 401

    token = create_jwt(user["id"])
    return jsonify({"token": token})

# Google OAuth login
@app.route("/auth/google", methods=["POST"])
def google_auth():
    token = request.json.get("token")
    if not token:
        return jsonify({"error": "Missing token"}), 400

    # Verify token with Google
    resp = requests.get(
        f"https://oauth2.googleapis.com/tokeninfo?id_token={token}"
    )
    if resp.status_code != 200:
        return jsonify({"error": "Invalid token"}), 401

    user_info = resp.json()
    google_id = user_info["sub"]
    email = user_info["email"]

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE google_id = ?", (google_id,)
    ).fetchone()
    if not user:
        # Create user
        conn.execute(
            "INSERT INTO users (email, username, google_id) VALUES (?, ?, ?)",
            (email, email.split("@")[0], google_id),
        )
        conn.commit()
        user = conn.execute(
            "SELECT * FROM users WHERE google_id = ?", (google_id,)
        ).fetchone()
    conn.close()

    token = create_jwt(user["id"])
    return jsonify({"token": token})

# Password reset request
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Missing email"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    # Create a reset token and expiry (1 hour)
    reset_token = jwt.encode(
        {"user_id": user["id"], "exp": datetime.utcnow() + timedelta(hours=1)},
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    conn.execute(
        "UPDATE users SET reset_token = ?, reset_expiry = ? WHERE id = ?",
        (reset_token, datetime.utcnow() + timedelta(hours=1), user["id"]),
    )
    conn.commit()
    conn.close()

    # Send email with reset link (update SMTP details below)
    reset_link = f"http://localhost:3000/reset-password?token={reset_token}"  # Update frontend URL here

    # Simple SMTP email example (configure your SMTP server!)
    try:
        msg = EmailMessage()
        msg.set_content(f"Click this link to reset your password: {reset_link}")
        msg["Subject"] = "Password Reset"
        msg["From"] = "no-reply@yourdomain.com"
        msg["To"] = email

        with smtplib.SMTP("smtp.yourserver.com", 587) as smtp:
            smtp.starttls()
            smtp.login("your_email_username", "your_email_password")
            smtp.send_message(msg)
    except Exception as e:
        print("Failed to send email:", e)

    return jsonify({"message": "Password reset email sent"})

# Reset password
@app.route("/reset-password", methods=["POST"])
def reset_password():
    token = request.json.get("token")
    new_password = request.json.get("new_password")

    if not token or not new_password:
        return jsonify({"error": "Missing token or new password"}), 400

    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = payload["user_id"]
    except Exception:
        return jsonify({"error": "Invalid or expired token"}), 400

    password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user["reset_token"] != token:
        conn.close()
        return jsonify({"error": "Invalid token"}), 400

    conn.execute(
        "UPDATE users SET password_hash = ?, reset_token = NULL, reset_expiry = NULL WHERE id = ?",
        (password_hash, user_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Password reset successful"})

# Auth-required decorator
from functools import wraps

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return jsonify({"error": "Token missing"}), 401

        user_id = decode_jwt(token)
        if not user_id:
            return jsonify({"error": "Invalid token"}), 401
        return f(user_id=user_id, *args, **kwargs)
    return decorated

# Resume analyze endpoint (auth required)
@app.route("/analyze", methods=["POST"])
@auth_required
def analyze(user_id):
    if "resume" not in request.files:
        return jsonify({"error": "No resume uploaded"}), 400
    resume_file = request.files["resume"]
    job_desc = request.form.get("job_desc", "")

    resume_text = extract_text_from_pdf(resume_file)
    result = analyze_resume(resume_text, job_desc)
    return jsonify(result)

# Serve frontend static files and index.html (optional)
@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)

