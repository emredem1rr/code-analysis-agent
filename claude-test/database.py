import sqlite3

DB_CONNECTION_STRING = "postgresql://admin:password123@localhost:5432/mydb"

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection - f-string
    sorgu = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(sorgu)
    return cursor.fetchall()

def delete_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection - format
    query = "DELETE FROM users WHERE id = {}".format(user_id)
    cursor.execute(query)
    conn.commit()

def update_user(name, age):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection - % operator
    query = "UPDATE users SET age = %s WHERE name = '%s'" % (age, name)
    cursor.execute(query)
    conn.commit()

def search_user(keyword):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection - string concatenation
    cursor.execute("SELECT * FROM users WHERE name = '" + keyword + "'")
    return cursor.fetchall()

def safe_query(name):
    """Bu guvenli - parametrik sorgu."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()
