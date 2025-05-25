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

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler()]
)

# Brute force tracking
failed_login_attempts = defaultdict(int)

def send_ids_alert(alert_msg):
    try:
      with open("config.json") as f:
            config = json.load(f)
      ids_url = config.get("ids_server_url", "") + "/log_alert"
      requests.post(ids_url, json={"alert": alert_msg})
    except Exception as e:
        print(f"[!] Could not send alert to IDS: {e}")

def log_failed_login(username, ip_address):
    failed_login_attempts[ip_address] += 1
    logging.warning(f"[SECURITY ALERT] Failed login from {username} @ {ip_address} | Attempt #{failed_login_attempts[ip_address]}")

def log_security_alert(alert_type, message):
    logging.warning(f"[{alert_type}] {message}")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

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

def generate_salt():
    return os.urandom(16).hex()

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

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
        total_games = wins + losses + draws
        win_rate = (wins / total_games * 100) if total_games > 0 else 0
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

    if stats:
        wins, losses, draws = stats
        total_games = wins + losses + draws
        win_rate = (wins / total_games * 100) if total_games > 0 else 0
    else:
        wins = losses = draws = win_rate = 0

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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr

        # SQL injection detection
        sql_injection_patterns = ["' OR '1'='1", "'--", "' OR 1=1", "\" OR \"1\"=\"1", "' OR ''='", "' OR 'x'='x"]
        for pattern in sql_injection_patterns:
            if pattern.lower() in username.lower() or pattern.lower() in password.lower():
                alert_message = f"SQL Injection detected from IP {ip_address} with username: {username}"
                log_security_alert("SQL Injection", alert_message)
                send_ids_alert(alert_message)
                return render_template('sql_injection_alert.html')

        # Brute force detection
        if failed_login_attempts[ip_address] > 5:
            log_security_alert("Brute Force", f"Too many failed logins from IP {ip_address}")
            return "Too many failed login attempts. Try again later."

        # Authenticate user
        conn = setup_database()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            user_id, stored_hash, salt = user_data
            if hash_password(password, salt) == stored_hash:
                session['user_id'] = user_id
                session['username'] = username
                failed_login_attempts[ip_address] = 0  # Reset on success
                return redirect(url_for('dashboard'))

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
        password_hash = hash_password(password, salt)

        conn = setup_database()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", 
                           (username, password_hash, salt))
            conn.commit()
            conn.close()
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
        computer_choice = random.choice(['rock', 'paper', 'scissors'])

        if user_choice == computer_choice:
            result = 'draw'
        elif (user_choice == 'rock' and computer_choice == 'scissors') or \
             (user_choice == 'scissors' and computer_choice == 'paper') or \
             (user_choice == 'paper' and computer_choice == 'rock'):
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

        return render_template('game_result.html', result=result, user_choice=user_choice, computer_choice=computer_choice)

    return render_template('play_game.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
