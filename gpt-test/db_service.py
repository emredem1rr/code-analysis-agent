import sqlite3

def find_user(name):
    conn = sqlite3.connect("test.db")
    cur = conn.cursor()
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(sql)
    return cur.fetchall()