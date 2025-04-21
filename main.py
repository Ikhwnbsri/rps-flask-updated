import random
import sqlite3
import hashlib
import os
from getpass import getpass

# Database setup
def setup_database():
    conn = sqlite3.connect('rps_game.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        draws INTEGER DEFAULT 0
    )
    ''')
    
    # Create game_logs table for IDS monitoring
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS game_logs (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        timestamp TEXT,
        action TEXT,
        ip_address TEXT,
        details TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.commit()
    return conn

# Security functions
def generate_salt():
    return os.urandom(16).hex()

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

def log_activity(conn, user_id, action, ip="127.0.0.1", details=""):
    import datetime
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO game_logs (user_id, timestamp, action, ip_address, details) VALUES (?, ?, ?, ?, ?)",
        (user_id, timestamp, action, ip, details)
    )
    conn.commit()

# User management
def register_user(conn):
    cursor = conn.cursor()
    print("\n=== REGISTER NEW ACCOUNT ===")
    
    while True:
        username = input("Enter username: ")
        
        # Check for SQL injection in username
        if "'" in username or ";" in username or "--" in username:
            print("Invalid username characters detected.")
            log_activity(conn, None, "SECURITY_ALERT", details=f"Possible SQL injection attempt: {username}")
            continue
            
        # Check if username exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            print("Username already exists. Please choose another.")
            continue
            
        password = getpass("Enter password: ")
        if len(password) < 6:
            print("Password must be at least 6 characters.")
            continue
            
        confirm_password = getpass("Confirm password: ")
        if password != confirm_password:
            print("Passwords do not match.")
            continue
            
        salt = generate_salt()
        password_hash = hash_password(password, salt)
        
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt)
            )
            conn.commit()
            user_id = cursor.lastrowid
            log_activity(conn, user_id, "REGISTER")
            print(f"User {username} registered successfully!")
            return user_id, username
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None, None

def login_user(conn):
    cursor = conn.cursor()
    print("\n=== LOGIN ===")
    
    username = input("Username: ")
    password = getpass("Password: ")
    
    # Secure parameterized query
    cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    
    if not user_data:
        print("Invalid username or password.")
        log_activity(conn, None, "FAILED_LOGIN", details=f"Username: {username}")
        return None, None
        
    user_id, stored_hash, salt = user_data
    computed_hash = hash_password(password, salt)
    
    if computed_hash != stored_hash:
        print("Invalid username or password.")
        log_activity(conn, user_id, "FAILED_LOGIN")
        return None, None
        
    print(f"Welcome back, {username}!")
    log_activity(conn, user_id, "LOGIN")
    return user_id, username

# Game functions
def get_user_choice():
    print("\nChoose one:")
    print("1. Rock 🪨")
    print("2. Paper 📄")
    print("3. Scissors ✂️")
    print("0. Exit game")
    
    while True:
        try:
            choice = int(input("Enter your choice (0-3): "))
            if choice == 0:
                return None
            if 1 <= choice <= 3:
                return ["rock", "paper", "scissors"][choice-1]
            print("Invalid choice. Try again.")
        except ValueError:
            print("Please enter a number.")

def get_computer_choice():
    return random.choice(["rock", "paper", "scissors"])

def determine_winner(user_choice, computer_choice):
    if user_choice == computer_choice:
        return "draw"
    
    winning_combinations = {
        "rock": "scissors",
        "paper": "rock",
        "scissors": "paper"
    }
    
    if winning_combinations[user_choice] == computer_choice:
        return "user"
    return "computer"

def update_stats(conn, user_id, result):
    cursor = conn.cursor()
    if result == "user":
        cursor.execute("UPDATE users SET wins = wins + 1 WHERE id = ?", (user_id,))
    elif result == "computer":
        cursor.execute("UPDATE users SET losses = losses + 1 WHERE id = ?", (user_id,))
    else:
        cursor.execute("UPDATE users SET draws = draws + 1 WHERE id = ?", (user_id,))
    conn.commit()

def display_stats(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT wins, losses, draws FROM users WHERE id = ?", (user_id,))
    stats = cursor.fetchone()
    
    if stats:
        wins, losses, draws = stats
        total_games = wins + losses + draws
        win_rate = (wins / total_games * 100) if total_games > 0 else 0
        
        print("\n=== YOUR STATS ===")
        print(f"Wins: {wins}")
        print(f"Losses: {losses}")
        print(f"Draws: {draws}")
        print(f"Win Rate: {win_rate:.2f}%")

def display_leaderboard(conn):
    cursor = conn.cursor()
    cursor.execute("""
    SELECT username, wins, losses, draws, 
           (wins * 1.0 / (wins + losses + draws)) * 100 as win_rate
    FROM users
    WHERE wins + losses + draws > 0
    ORDER BY win_rate DESC, wins DESC
    LIMIT 5
    """)
    
    leaders = cursor.fetchall()
    
    if not leaders:
        print("\nNo game data available yet.")
        return
        
    print("\n=== LEADERBOARD ===")
    print("Rank  Username     Wins  Losses  Draws  Win Rate")
    print("------------------------------------------")
    
    for i, (username, wins, losses, draws, win_rate) in enumerate(leaders, 1):
        print(f"{i:<5} {username:<12} {wins:<5} {losses:<7} {draws:<6} {win_rate:.2f}%")

# Main game function
def play_game(conn, user_id, username):
    print(f"\n=== ROCK PAPER SCISSORS ===")
    print(f"Player: {username}")
    
    # Dictionary for choice emojis
    choice_emojis = {
        "rock": "🪨",
        "paper": "📄",
        "scissors": "✂️"
    }
    
    while True:
        user_choice = get_user_choice()
        
        if user_choice is None:
            print("Returning to main menu...")
            return
            
        computer_choice = get_computer_choice()
        
        print(f"\nYou chose: {user_choice} {choice_emojis[user_choice]}")
        print(f"Computer chose: {computer_choice} {choice_emojis[computer_choice]}")
        
        result = determine_winner(user_choice, computer_choice)
        
        if result == "user":
            print("You win! 🎉🎉🎉🎉")
        elif result == "computer":
            print("Computer wins! 💻💻💻💻")
        else:
            print("It's a draw! 🤝🤝🤝🤝")
            
        update_stats(conn, user_id, result)
        log_activity(conn, user_id, "GAME_PLAYED", details=f"User: {user_choice}, Computer: {computer_choice}, Result: {result}")

# IDS Monitoring function
def check_for_intrusions(conn):
    cursor = conn.cursor()
    
    # Check for multiple failed logins
    cursor.execute("""
    SELECT ip_address, COUNT(*) as attempts 
    FROM game_logs 
    WHERE action = 'FAILED_LOGIN' AND timestamp > datetime('now', '-30 minutes')
    GROUP BY ip_address
    HAVING attempts >= 3
    """)
    
    suspicious_ips = cursor.fetchall()
    
    for ip, attempts in suspicious_ips:
        print(f"\n⚠️ SECURITY ALERT: {ip} has {attempts} failed login attempts in the last 30 minutes.")
        # In a real system, you might implement IP blocking here

    # Check for SQL injection attempts
    cursor.execute("""
    SELECT COUNT(*) FROM game_logs 
    WHERE action = 'SECURITY_ALERT' AND timestamp > datetime('now', '-30 minutes')
    """)
    
    injection_attempts = cursor.fetchone()[0]
    
    if injection_attempts > 0:
        print(f"\n⚠️ SECURITY ALERT: {injection_attempts} potential SQL injection attempts detected in the last 30 minutes.")

# Main menu
def main_menu():
    conn = setup_database()
    user_id = None
    username = None
    
    while True:
        print("\n=== MAIN MENU ===")
        
        if user_id:
            print(f"Logged in as: {username}")
            print("1. Play Game")
            print("2. View My Stats")
            print("3. View Leaderboard")
            print("4. Logout")
            print("5. Check Security Alerts")
            print("0. Exit")
            
            try:
                choice = int(input("Enter your choice: "))
                
                if choice == 0:
                    print("Thanks for playing! Goodbye!")
                    break
                elif choice == 1:
                    play_game(conn, user_id, username)
                elif choice == 2:
                    display_stats(conn, user_id)
                elif choice == 3:
                    display_leaderboard(conn)
                elif choice == 4:
                    log_activity(conn, user_id, "LOGOUT")
                    user_id = None
                    username = None
                    print("Logged out successfully.")
                elif choice == 5:
                    check_for_intrusions(conn)
                else:
                    print("Invalid choice. Try again.")
            except ValueError:
                print("Please enter a number.")
        else:
            print("1. Login")
            print("2. Register")
            print("0. Exit")
            
            try:
                choice = int(input("Enter your choice: "))
                
                if choice == 0:
                    print("Goodbye!")
                    break
                elif choice == 1:
                    user_id, username = login_user(conn)
                elif choice == 2:
                    user_id, username = register_user(conn)
                else:
                    print("Invalid choice. Try again.")
            except ValueError:
                print("Please enter a number.")
    
    conn.close()

if __name__ == "__main__":
    main_menu()