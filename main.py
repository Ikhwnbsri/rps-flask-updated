from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
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

# Load config
def get_config():
    try:
        with open("config.json") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load config: {e}")
        return {}

config = get_config()

# ✅ SQLite config (reverted)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rps.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Init DB
db = SQLAlchemy(app)

# IDS
def get_ids_url():
    return config.get("ids_server_url", "")

def send_ids_alert(alert_msg, ip):
    try:
        ids_url = get_ids_url() + "/log_alert"
        requests.post(ids_url, json={"alert": alert_msg, "ip": ip})
    except Exception as e:
        print(f"[!] Could not send alert to IDS: {e}")

def is_ip_blocked(ip):
    try:
        ids_url = get_ids_url() + "/check_ip"
        response = requests.post(ids_url, json={"ip": ip})
        if response.status_code == 200:
            return response.json().get("status") == "BLOCK"
    except Exception as e:
        print(f"[!] Could not contact IDS: {e}")
    return False

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    wins = db.Column(db.Integer, default=0)
    losses = db.Column(db.Integer, default=0)
    draws = db.Column(db.Integer, default=0)

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

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if user:
        total = user.wins + user.losses + user.draws
        win_rate = (user.wins / total * 100) if total > 0 else 0
    else:
        user = User(username='Unknown', wins=0, losses=0, draws=0)
        win_rate = 0

    return render_template('dashboard.html', username=user.username, wins=user.wins, losses=user.losses, draws=user.draws, win_rate=win_rate)

@app.route('/stats')
def view_stats():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    wins, losses, draws = user.wins, user.losses, user.draws
    total = wins + losses + draws
    win_rate = (wins / total * 100) if total > 0 else 0
    return render_template('stats.html', wins=wins, losses=losses, draws=draws, win_rate=win_rate)

@app.route('/leaderboard')
def leaderboard():
    top_users = User.query.order_by(User.wins.desc()).limit(10).all()
    return render_template('leaderboard.html', top_users=[(u.username, u.wins) for u in top_users])

@app.route('/security_alerts')
def security_alerts():
    return render_template('security_alerts.html', sql_injection_attempts=[], brute_force_warnings=[], suspicious_ips=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
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
            return redirect(url_for('security_blocked'))

        user = User.query.filter_by(username=username).first()
        if user and hash_password(password, user.salt) == user.password_hash:
            failed_login_attempts[ip_address] = 0
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))

        failed_login_attempts[ip_address] += 1
        log_failed_login(username, ip_address)

        if failed_login_attempts[ip_address] > 5:
            alert = f"Too many failed logins from IP {ip_address}"
            log_security_alert("Brute Force", alert)
            send_ids_alert(alert, ip_address)
            return "Too many failed login attempts. Try again later."

        if failed_login_attempts[ip_address] == 3:
            log_security_alert("Suspicious", f"Suspicious login activity from {ip_address}")

        flash("Invalid login credentials.")
        return redirect(url_for('login'))

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

        new_user = User(username=username, password_hash=hashed, salt=salt)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except:
            db.session.rollback()
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

        user = User.query.get(session['user_id'])
        if result == 'user':
            user.wins += 1
        elif result == 'computer':
            user.losses += 1
        else:
            user.draws += 1
        db.session.commit()

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

# Create tables on startup
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
