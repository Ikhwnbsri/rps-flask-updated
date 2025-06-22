# unchanged imports
import os
import json
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import random

# Load config.json
with open('config.json') as config_file:
    config = json.load(config_file)

# Flask App Setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', config['database_url'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'supersecretkey'

# Initialize DB
db = SQLAlchemy(app)

# IDS Server URL
IDS_SERVER_URL = config['ids_server_url']

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    wins = db.Column(db.Integer, default=0)
    losses = db.Column(db.Integer, default=0)
    draws = db.Column(db.Integer, default=0)

# Game Result Model
class GameResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    player_move = db.Column(db.String(10))
    computer_move = db.Column(db.String(10))
    result = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.")
            return redirect(url_for('register'))

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

    # Step 1: Check if IP is already blocked
    try:
        check_url = f"{IDS_SERVER_URL}/check_ip"
        response = requests.post(check_url, json={"ip": ip_address}, timeout=3)
        if response.status_code == 200 and response.json().get("status") == "BLOCK":
            return render_template("security_blocked.html", ip=ip_address)
    except Exception as e:
        print(f"[!] Error contacting IDS: {e}")

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Step 2: SQL Injection patterns
        sql_patterns = [
        "' OR '1'='1",
        "'--",
        "' OR 1=1",
        '" OR "1"="1',
        "' OR ''='",
        "' OR 'x'='x",
        "';--",
        '" or ""="',
        "' or 1=1--",
        "' or 'a'='a",
        "' or 1=1#",
        "admin' --",
        "' or sleep",
        "' or true--",
        "') OR ('1'='1",
        "' or '1'='1' --",
        "' or 1=1#",
        "') or ('a'='a",
        "' OR EXISTS(SELECT * FROM users) --",
        '" OR EXISTS(SELECT * FROM users) --',
        "'; DROP TABLE users --",
        "' UNION SELECT null, null, null--",
        "' UNION SELECT username, password FROM users--",
        "' AND 1=(SELECT COUNT(*) FROM tablename)--",
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "' AND ASCII(SUBSTRING(@@version,1,1))=52 --",
        "' OR '' = '",
        'admin" --',
        '" or "" = "',
        "') or ('1'='1",
        "1' ORDER BY 1--",
        "' or sleep(3) and 'a'='a",
        "' OR 1=1 LIMIT 1--"
        ]

        if any(p.lower() in username.lower() or p.lower() in password.lower() for p in sql_patterns):
            alert_msg = f"SQL Injection detected from IP {ip_address} with username: {username}"
            try:
                requests.post(f"{IDS_SERVER_URL}/log_alert", json={"alert": alert_msg, "ip": ip_address})
            except Exception as e:
                print(f"[!] Failed to send alert to IDS: {e}")
            return render_template("security_blocked.html", ip=ip_address)

        # Step 3: Login Logic
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['username'] = user.username
            return redirect(url_for('dashboard'))

        #flash("Invalid login credentials.")
        #return redirect(url_for('login'))
        return render_template('invalid_login.html', username=username)


    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()

    if user:
        total_games = user.wins + user.losses + user.draws
        win_rate = (user.wins / total_games) * 100 if total_games > 0 else 0

        return render_template('dashboard.html',
                               username=user.username,
                               wins=user.wins,
                               draws=user.draws,
                               losses=user.losses,
                               win_rate=win_rate)
    else:
        flash("User not found")
        return redirect(url_for('login'))

@app.route('/play_game', methods=['GET', 'POST'])
def play_game():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        player_move = request.form['move']

        # Custom logic to reduce draws (only 20% chance of draw)
        if random.random() < 0.2:
            # Allow a draw
            computer_move = player_move
        else:
            # Force a win or loss by picking a different move
            moves = ['rock', 'paper', 'scissors']
            moves.remove(player_move)
            computer_move = random.choice(moves)

        # Determine result
        if player_move == computer_move:
            result = 'draw'
        elif (
            (player_move == 'rock' and computer_move == 'scissors') or
            (player_move == 'scissors' and computer_move == 'paper') or
            (player_move == 'paper' and computer_move == 'rock')
        ):
            result = 'win'
        else:
            result = 'lose'

        # Update user stats
        user = User.query.filter_by(username=session['username']).first()
        if result == 'win':
            user.wins += 1
        elif result == 'lose':
            user.losses += 1
        else:
            user.draws += 1
        db.session.commit()

        # Save game result
        game_result = GameResult(
            username=session['username'],
            player_move=player_move,
            computer_move=computer_move,
            result=result
        )
        db.session.add(game_result)
        db.session.commit()

        return render_template(
            'game_result.html',
            result=result,
            player_move=player_move,
            computer_move=computer_move
        )

    return render_template('play_game.html')

@app.route('/stats')
def stats():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    return render_template('stats.html', user=user, wins=user.wins, losses=user.losses, draws=user.draws)

@app.route('/leaderboard')
def leaderboard():
    users = User.query.order_by(User.wins.desc()).all()
    return render_template('leaderboard.html', users=users)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/check_alerts')
def check_alerts():
    response = requests.get(f"{IDS_SERVER_URL}/get_logs")
    logs = response.json().get('logs', [])
    return render_template('security_alerts.html', logs=logs)

@app.route('/blocked')
def security_blocked():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    return render_template('security_blocked.html', ip=ip)

import os
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
