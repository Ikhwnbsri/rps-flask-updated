from flask import Flask, render_template, request, redirect, url_for, flash
from ids_monitor import is_sql_injection, log_attack  # <-- Import the IDS functions here

from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import hashlib
import os
import random
import logging
from datetime import datetime
from collections import defaultdict

# test commit to check Git tracking

import requests

def send_ids_alert(alert_msg):
    try:
        requests.post("http://abc123.ngrok.io/log_alert", json={"alert": alert_msg})
    except Exception as e:
        print(f"[!] Could not send alert to IDS: {e}")


# Set up logging to stdout for Railway compatibility
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler()]
)

# For brute force detection: Keep track of failed login attempts
failed_login_attempts = defaultdict(int)

def log_failed_login(username, ip_address):
    failed_login_attempts[ip_address] += 1
    logging.warning(f"[SECURITY ALERT] Failed login attempt from {username} @ {ip_address} | Attempt #{failed_login_attempts[ip_address]}")

def log_security_alert(alert_type, message):
    logging.warning(f"[{alert_type}] {message}")

app = Flask(__name__)
# Use an environment variable for the secret key with a fallback
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Database setup function
def setup_database():
    # For Railway, use an in-memory database or set up a proper DB URL
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

# Security functions
def generate_salt():
    return os.urandom(16).hex()

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Home route (for showing dashboard or main menu after login)
@app.route('/')
def home():
    return redirect(url_for('login'))  # Redirect to the login page

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = setup_database()
    cursor = conn.cursor()
    cursor.execute("SELECT username, wins, losses, draws FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        username, wins, losses, draws = user_data
        total_games = wins + losses + draws
        win_rate = (wins / total_games * 100) if total_games > 0 else 0
    else:
        username = session.get('username', 'Unknown')
        wins = losses = draws = 0
        win_rate = 0
    
    return render_template('dashboard.html', 
                           username=username,
                           wins=wins, 
                           losses=losses, 
                           draws=draws, 
                           win_rate=win_rate)

@app.route('/stats')
def view_stats():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = setup_database()
    cursor = conn.cursor()
    cursor.execute("SELECT wins, losses, draws FROM users WHERE id = ?", (user_id,))
    stats = cursor.fetchone()
    conn.close()
    
    if stats:
        wins, losses, draws = stats
        total_games = wins + losses + draws
        win_rate = (wins / total_games * 100) if total_games > 0 else 0
    else:
        wins = losses = draws = 0
        win_rate = 0
    
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
    # For Railway, we won't read from physical files
    return render_template(
        'security_alerts.html',
        sql_injection_attempts=[],
        brute_force_warnings=[],
        suspicious_ips=[]
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr  # Get the user's IP

        # --- Detect SQL Injection ---
        sql_injection_patterns = ["' OR '1'='1", "'--", "' OR 1=1", "\" OR \"1\"=\"1", "' OR ''='", "' OR 'x'='x"]
       
    for pattern in sql_injection_patterns:
     if pattern.lower() in username.lower() or pattern.lower() in password.lower():
        alert_message = f"SQL Injection detected from IP {ip_address} with username: {username}"
        log_security_alert("SQL Injection", alert_message)
        send_ids_alert(alert_message)
        return render_template('sql_injection_alert.html')





        # --- Detect brute force: more than 5 failed attempts ---
        if failed_login_attempts.get(ip_address, 0) > 5:
            log_security_alert("Brute Force", f"Excessive failed logins from IP {ip_address}")
            return "Too many failed attempts."

        # Database lookup
        conn = setup_database()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            user_id, stored_hash, salt = user_data
            computed_hash = hash_password(password, salt)

            if computed_hash == stored_hash:
                session['user_id'] = user_id
                session['username'] = username

                # Reset failed login attempts on success
                failed_login_attempts[ip_address] = 0
                return redirect(url_for('dashboard'))

        # If login fails
        failed_login_attempts[ip_address] = failed_login_attempts.get(ip_address, 0) + 1

        # Log failed login
        log_failed_login(username, ip_address)

        # Optional: suspicious activity log
        if failed_login_attempts[ip_address] == 3:
            log_security_alert("Suspicious", f"Suspicious activity from IP {ip_address} (3 failed logins)")

        return "Invalid username or password."

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return "Passwords do not match!"
        
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
        except sqlite3.Error:
            return "Username already exists!"
    
    return render_template('register.html')

@app.route('/play_game', methods=['GET', 'POST'])
def play_game():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user_choice = request.form['user_choice']
        computer_choice = random.choice(['rock', 'paper', 'scissors'])
        
        # Determine winner logic
        if user_choice == computer_choice:
            result = 'draw'
        elif (user_choice == 'rock' and computer_choice == 'scissors') or \
             (user_choice == 'scissors' and computer_choice == 'paper') or \
             (user_choice == 'paper' and computer_choice == 'rock'):
            result = 'user'
        else:
            result = 'computer'
        
        # Update stats
        user_id = session['user_id']
        conn = setup_database()
        cursor = conn.cursor()
        if result == 'user':
            cursor.execute("UPDATE users SET wins = wins + 1 WHERE id = ?", (user_id,))
        elif result == 'computer':
            cursor.execute("UPDATE users SET losses = losses + 1 WHERE id = ?", (user_id,))
        else:
            cursor.execute("UPDATE users SET draws = draws + 1 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        return render_template('game_result.html', 
                               result=result, 
                               user_choice=user_choice, 
                               computer_choice=computer_choice)
    
    return render_template('play_game.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# This is the correct way to configure the app for Railway
if __name__ == '__main__':
    # Get port from environment variable or default to 5000
    port = int(os.environ.get('PORT', 5000))
    # Bind to 0.0.0.0 to listen on all interfaces
    app.run(host='0.0.0.0', port=port)
    print(f"App is running on port: {port}")