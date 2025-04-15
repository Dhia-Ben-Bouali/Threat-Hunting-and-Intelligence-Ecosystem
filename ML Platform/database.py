import sqlite3

def init_email_table():
    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()

    # Create table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            result TEXT DEFAULT 'not runned yet',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Check existing columns
    cursor.execute("PRAGMA table_info(email_requests)")
    columns = [col[1] for col in cursor.fetchall()]

    if 'sender' not in columns:
        cursor.execute("ALTER TABLE email_requests ADD COLUMN sender TEXT")
    if 'receiver' not in columns:
        cursor.execute("ALTER TABLE email_requests ADD COLUMN receiver TEXT")

    conn.commit()
    conn.close()


def init_intrusion_table():
    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()

    # Create the intrusion_detection table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS intrusion_detection (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol_type TEXT,
            service TEXT,
            flag TEXT,
            src_bytes INTEGER,
            dst_bytes INTEGER,
            duration INTEGER,
            land INTEGER,
            wrong_fragment INTEGER,
            urgent INTEGER,
            result TEXT DEFAULT 'not runned yet',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


def init_db():
    init_email_table()
    init_intrusion_table()
