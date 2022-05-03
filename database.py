import os
import sqlite3


# Done
# Create the main users database
def create_db(backup=False, file_path=None):
    if backup:
        backup_file = os.path.join(file_path, 'backup.db')
        conn = sqlite3.connect(backup_file)
    else:
        conn = sqlite3.connect('users.db')
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users
    (uuid INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, 
    public_key TEXT NOT NULL UNIQUE,
    vault_location TEXT NOT NULL UNIQUE, otp_key TEXT UNIQUE)
    """)
    conn.commit()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS data
    (userid INTEGER PRIMARY KEY, session_key BLOB, nonce BLOB, tag BLOB, ciphertext BLOB, FOREIGN KEY(userid) 
    REFERENCES users(uuid))""")
    conn.commit()
    conn.close()


def create_cybervault(username, vault):
    success = False

    if not username:
        return

    try:
        conn = sqlite3.connect(vault)
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS cybervault
        (vid INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, website_url TEXT,
        username TEXT, password TEXT UNIQUE)
        """)
        success = True
    except AttributeError:
        os.remove(vault)

    if success:
        return True


# Done
def add_user(username, pub_key, vault_location, key=None, backup=False, file_path=None):
    if backup:
        pkey = pub_key
    else:
        pkey = pub_key.decode('utf-8')

    if backup:
        backup_file = os.path.join(file_path, 'backup.db')
        conn = sqlite3.connect(backup_file)
    else:
        conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()

    if key is not None:
        entities = [username, pkey, vault_location, key]
        cursor.execute("""
        INSERT INTO users("username", "public_key", "vault_location", "otp_key") VALUES(?, ?, ?, ?)
        """, entities)

    else:
        entities = [username, pkey, vault_location]
        cursor.execute("""
        INSERT INTO users("username", "public_key", "vault_location") VALUES(?, ?, ?)
        """, entities)

    conn.commit()
    last_id = cursor.lastrowid
    conn.close()

    return last_id


# Done
def add_user_enc_data(userid, session_key, nonce, tag, ciphertext, backup=False, file_path=None):
    if backup:
        backup_file = os.path.join(file_path, 'backup.db')
        conn = sqlite3.connect(backup_file)
    else:
        conn = sqlite3.connect('users.db')
    cursor = conn.cursor()  
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()

    entities = [userid, session_key, nonce, tag, ciphertext]
    cursor.execute("""
    INSERT INTO data("userid", "session_key", "nonce", "tag", "ciphertext") VALUES(?, ?, ?, ?, ?)
    """, entities)

    conn.commit()
    conn.close()


# Done
def get_user_enc_data(userid, backup=False, file_path=None):
    tag = None
    nonce = None
    session = None
    ciphertext = None

    if backup:
        backup_file = os.path.join(file_path, 'backup.db')
        conn = sqlite3.connect(backup_file)
    else:
        conn = sqlite3.connect('users.db')
    cursor = conn.cursor()  
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()

    cursor.execute("SELECT * FROM data WHERE userid=?", (userid,))

    rows = cursor.fetchall()

    for row in rows:
        session = row[1]
        nonce = row[2]
        tag = row[3]
        ciphertext = row[4]

    return session, nonce, tag, ciphertext


# Done
def get_user(username, backup=False, file_path=None):
    uid = None
    uname = None
    pkey = None
    vault_location = None
    otp_key = None

    if backup:
        backup_file = os.path.join(file_path, 'backup.db')
        conn = sqlite3.connect(backup_file)
    else:
        conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))

    rows = cursor.fetchall()

    for row in rows:
        uid = row[0]
        uname = row[1]
        pkey = row[2]
        vault_location = row[3]
        otp_key = row[4]

    if uname:
        return uname, pkey, vault_location, otp_key, uid
    else:
        return


# Done
def add_entry(vault, entryname, url, user, passwd):
    conn = sqlite3.connect(vault)
    cursor = conn.cursor()

    name = entryname
    web_url = url
    username = user
    password = passwd

    entries = [name, web_url, username, password]
    cursor.execute("""
    INSERT INTO cybervault ("name", "website_url", "username", "password") VALUES(?, ?, ?, ?)
    """, entries)

    conn.commit()
    conn.close()


# Done
def check_passwd(vault, passwd):
    conn = sqlite3.connect(vault)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM cybervault WHERE password=?", (passwd,))

    if cursor.fetchone():
        return 'yes'
    else:
        return 'no'


# Done
def check_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))

    if cursor.fetchone():
        return 'yes'
    else:
        return 'no'


# Done
def check_vault(vault_location):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE vault_location=?", (vault_location,))

    if cursor.fetchall():
        return 'yes'
    else:
        return 'no'
