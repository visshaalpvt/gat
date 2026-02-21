import sqlite3

def migrate():
    conn = sqlite3.connect('enterprise_secure_v2.db')
    cursor = conn.cursor()
    
    # Check current columns in user_activity
    cursor.execute("PRAGMA table_info(user_activity)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if "burst_count" not in columns:
        print("Adding burst_count column...")
        cursor.execute("ALTER TABLE user_activity ADD COLUMN burst_count INTEGER")
    
    if "last_burst_time" not in columns:
        print("Adding last_burst_time column...")
        cursor.execute("ALTER TABLE user_activity ADD COLUMN last_burst_time DATETIME")
        
    conn.commit()
    conn.close()
    print("Migration complete!")

if __name__ == "__main__":
    migrate()
