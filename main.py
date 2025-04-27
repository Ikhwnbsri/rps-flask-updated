from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import hashlib
import os
import random
import logging
from datetime import datetime
from collections import defaultdict

failed_login_attempts = defaultdict(int)

def log_failed_login(username, ip_address):
    failed_login_attempts[ip_address] += 1
    print(f"[SECURITY ALERT] Failed login attempt from {username} @ {ip_address} | Attempt #{failed_login_attempts[ip_address]}")

def log_security_alert(alert_type, message):
    with open("security.log", "a") as f:
        f.write(f"[{datetime.now()}] {alert_type}: {message}\n")


# Set up logging for security events
logging.basicConfig(filename='security_logs.txt', level=logging.INFO)

# For brute force detection: Keep track of failed login attempts
failed_login_attempts = {}

# Function to log failed login attempts
def log_failed_login(username, ip):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"Failed login attempt by {username} from IP {ip} at {timestamp}")
    if ip not in failed_login_attempts:
        failed_login_attempts[ip] = 1
    else:
        failed_login_attempts[ip] += 1

# Function to detect possible SQL injection
def log_sql_injection_attempt(query, ip):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"Possible SQL injection detected: {query} from IP {ip} at {timestamp}")

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database setup function (same as your code)
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

# Security functions (same as your code)
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
    
    return render_template('dashboard.html', wins=wins, losses=losses, draws=draws, win_rate=win_rate)

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
    sql_injection_attempts = []
    brute_force_warnings = []
    suspicious_ips = []

    try:
        with open('security.log', 'r') as f:
            for line in f:
                if 'SQL Injection' in line:
                    sql_injection_attempts.append(line.strip())
                elif 'Brute Force' in line:
                    brute_force_warnings.append(line.strip())
                elif 'Suspicious activity from IP' in line:
                    suspicious_ips.append(line.strip())
    except FileNotFoundError:
        pass  # No log file yet

    return render_template(
        'security_alerts.html',
        sql_injection_attempts=sql_injection_attempts,
        brute_force_warnings=brute_force_warnings,
        suspicious_ips=suspicious_ips
    )


# Login route
from flask import request, session, redirect, url_for, render_template
import re
from datetime import datetime

# Dictionary to count failed logins per IP
failed_login_attempts = {}

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
                log_security_alert("SQL Injection", f"Attempt by IP {ip_address} with username: {username}")
                return "SQL injection attempt detected."

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


# Register route
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

# Play game route
@app.route('/play_game', methods=['GET', 'POST'])
def play_game():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user_choice = request.form['user_choice']
        computer_choice = random.choice(['rock', 'paper', 'scissors'])
        
        # Determine winner logic from your original code
        if user_choice == computer_choice:
            result = 'draw'
        elif (user_choice == 'rock' and computer_choice == 'scissors') or \
             (user_choice == 'scissors' and computer_choice == 'paper') or \
             (user_choice == 'paper' and computer_choice == 'rock'):
            result = 'user'
        else:
            result = 'computer'
        
        # Update stats and return result
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
        
        return render_template('game_result.html', result=result, user_choice=user_choice, computer_choice=computer_choice)
    
    return render_template('play_game.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False)
