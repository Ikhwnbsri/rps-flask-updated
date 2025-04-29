import sqlite3
import os

def check_database():
    """Check the RPS game database and display user statistics"""
    
    # Check if database file exists
    db_file = 'rps_game.db'
    if not os.path.exists(db_file):
        print(f"ERROR: Database file '{db_file}' not found!")
        print("Make sure you're running this script in the same directory as your Flask app")
        return
    
    print(f"Database file '{db_file}' found! Size: {os.path.getsize(db_file)} bytes")
    
    # Connect to the database
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Get table info
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print("\nTables in database:")
        for table in tables:
            print(f"- {table[0]}")
        
        # Get user count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        print(f"\nTotal users in database: {user_count}")
        
        # Get all users with their stats
        cursor.execute("SELECT id, username, wins, losses, draws FROM users")
        users = cursor.fetchall()
        
        if users:
            print("\nUser Statistics:")
            print("=" * 60)
            print(f"{'ID':<5} {'Username':<20} {'Wins':<8} {'Losses':<8} {'Draws':<8} {'Total':<8} {'Win %':<8}")
            print("-" * 60)
            
            for user in users:
                user_id, username, wins, losses, draws = user
                total_games = wins + losses + draws
                win_percentage = (wins / total_games * 100) if total_games > 0 else 0
                print(f"{user_id:<5} {username:<20} {wins:<8} {losses:<8} {draws:<8} {total_games:<8} {win_percentage:.1f}%")
            
            print("=" * 60)
        else:
            print("\nNo users found in the database.")
        
        # Check database writability
        try:
            cursor.execute("CREATE TABLE IF NOT EXISTS db_check_test (id INTEGER PRIMARY KEY)")
            cursor.execute("DROP TABLE db_check_test")
            print("\nDatabase is writable: YES")
        except sqlite3.Error as e:
            print(f"\nDatabase is writable: NO - {str(e)}")
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"\nERROR: Could not access database: {str(e)}")

if __name__ == "__main__":
    print("RPS Game Database Checker")
    print("-" * 30)
    check_database()
    print("\nTo run this checker again after playing games, make sure")
    print("the Flask application is stopped first (press Ctrl+C in terminal)")