import sqlite3

conn = sqlite3.connect("password_manager.db")
c = conn.cursor()


c.execute("SELECT password FROM passwords WHERE id = 1")
results = c.fetchall()

print(results)