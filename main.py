from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import hashlib
import os
import random
import logging
import json
import requests
from datetime import datetime
from collections import defaultdict

# Flask app and config
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

# Track failed logins
failed_login_attempts = defaultdict(int)

# Load IDS URL from config
def get_ids_url():
    try:
        with open("config.json") as f:
            config = json.load(f)
        return config.get("ids_server_url", "")
    except Exception as e:
        print(f"[!] Failed to load IDS config: {e}")
        return ""

# Send alert to IDS
def send_ids_alert(alert_msg, ip):
    try:
        ids_url = get_ids_url() + "/log_alert"
        requests.post(ids_url, json={"alert": alert_msg, "ip": ip})
    except Exception as e:
        print(f"[!] Could not send alert to IDS: {e}")

# Check if IP is blocked
def is_ip_blocked(ip):
    try:
        ids_url = get_ids_url() + "/check_ip"
        response = requests.post(ids_url, json={"ip": ip})
        if response.status_code == 200:
            return response.json().get("status") == "BLOCK"
    except Exception as e:
        print(f"[!] Could not contact IDS: {e}")
    return False

# DB setup
def setup_database():
    conn = sqlite3.connect('rps_game.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        wins INTEGER DEFAULT 0,
                        losses INTEGER DEFAULT 0,
                        draws INTEGER DEFAULT 0)''')
    conn.commit()
    return conn

# Password hashing
def generate_salt():
    return os.urandom(16).hex()

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Logging helpers
def log_failed_login(username, ip):
    failed_login_attempts[ip] += 1
    logging.warning(f"[SECURITY ALERT] Failed login for {username} from {ip} | Attempt #{failed_login_attempts[ip]}")

def log_security_alert(alert_type, message):
    logging.warning(f"[{alert_type}] {message}")

# Cache prevention
@app.after_request
def add_cache_control(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = setup_database()
    cursor = conn.cursor()
    cursor.execute("SELECT username, wins, losses, draws FROM users WHERE id = ?", (session['user_id'],))
    user_data = cursor.fetchone()
    conn.close()

    if user_data:
        username, wins, losses, draws = user_data
        total = wins + losses + draws
        win_rate = (wins / total * 100) if total > 0 else 0
    else:
        username = session.get('username', 'Unknown')
        wins = losses = draws = win_rate = 0

    return render_template('dashboard.html', username=username, wins=wins, losses=losses, draws=draws, win_rate=win_rate)

@app.route('/stats')
def view_stats():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = setup_database()
    cursor = conn.cursor()
    cursor.execute("SELECT wins, losses, draws FROM users WHERE id = ?", (session['user_id'],))
    stats = cursor.fetchone()
    conn.close()

    wins, losses, draws = stats if stats else (0, 0, 0)
    total = wins + losses + draws
    win_rate = (wins / total * 100) if total > 0 else 0
    return render_template('stats.html', wins=wins, losses=losses, draws=draws, win_rate=win_rate)

@app.route('/leaderboard')
def leaderboard():
    conn = setup_database()
    cursor = conn.cursor()
    cursor.execute("SELECT username, wins FROM users ORDER BY wins DESC LIMIT 10")
    top_users = cursor.fetchall()
    conn.close()
    return render_template('leaderboard.html', top_users=top_users)

@app.route('/security_alerts')
def security_alerts():
    return render_template('security_alerts.html', sql_injection_attempts=[], brute_force_warnings=[], suspicious_ips=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip_address = request.remote_addr

    # Global block check via IDS
    if is_ip_blocked(ip_address):
        return redirect(url_for('security_blocked'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # SQL injection detection
        sql_patterns = ["' OR '1'='1", "'--", "' OR 1=1", "\" OR \"1\"=\"1", "' OR ''='", "' OR 'x'='x"]
        if any(p.lower() in username.lower() or p.lower() in password.lower() for p in sql_patterns):
            alert = f"SQL Injection detected from IP {ip_address} with username: {username}"
            log_security_alert("SQL Injection", alert)
            send_ids_alert(alert, ip_address)
            return redirect(url_for('security_blocked'))  # 🔁 redirect prevents repeated logging

        # Brute force check
        if failed_login_attempts[ip_address] > 5:
            alert = f"Too many failed logins from IP {ip_address}"
            log_security_alert("Brute Force", alert)
            return "Too many failed login attempts. Try again later."

        # Authenticate
        conn = setup_database()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            user_id, stored_hash, salt = user

            # Check again in case blocked during login process
            if is_ip_blocked(ip_address):
                return redirect(url_for('security_blocked'))

            if hash_password(password, salt) == stored_hash:
                session['user_id'] = user_id
                session['username'] = username
                failed_login_attempts[ip_address] = 0
                return redirect(url_for('dashboard'))

        # Login failed
        failed_login_attempts[ip_address] += 1
        log_failed_login(username, ip_address)
        if failed_login_attempts[ip_address] == 3:
            log_security_alert("Suspicious", f"Suspicious login activity from {ip_address}")
        return "Invalid username or password."

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            return "Passwords do not match."

        salt = generate_salt()
        hashed = hash_password(password, salt)

        conn = setup_database()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                           (username, hashed, salt))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already exists."

    return render_template('register.html')

@app.route('/play_game', methods=['GET', 'POST'])
def play_game():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_choice = request.form['user_choice']
        comp_choice = random.choice(['rock', 'paper', 'scissors'])

        if user_choice == comp_choice:
            result = 'draw'
        elif (user_choice == 'rock' and comp_choice == 'scissors') or \
             (user_choice == 'scissors' and comp_choice == 'paper') or \
             (user_choice == 'paper' and comp_choice == 'rock'):
            result = 'user'
        else:
            result = 'computer'

        conn = setup_database()
        cursor = conn.cursor()
        if result == 'user':
            cursor.execute("UPDATE users SET wins = wins + 1 WHERE id = ?", (session['user_id'],))
        elif result == 'computer':
            cursor.execute("UPDATE users SET losses = losses + 1 WHERE id = ?", (session['user_id'],))
        else:
            cursor.execute("UPDATE users SET draws = draws + 1 WHERE id = ?", (session['user_id'],))
        conn.commit()
        conn.close()

        return render_template('game_result.html', result=result, user_choice=user_choice, computer_choice=comp_choice)

    return render_template('play_game.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/blocked')
def security_blocked():
    ip = request.remote_addr
    return render_template("security_blocked.html", ip=ip)

# Run the app
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
