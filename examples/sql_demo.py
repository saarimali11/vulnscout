# Demo file for VS003. Five vulnerable queries, then one safe one.
import sqlite3

conn = sqlite3.connect("app.db")
cur = conn.cursor()
name = input("name: ")

# vulnerable: user input is pasted into the SQL text 
cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
cur.execute("SELECT * FROM users WHERE name = '{}'".format(name))
query = "SELECT * FROM users WHERE name = '" + name + "'"
cur.execute(query)

# safe: the database inserts the value, so it can never become SQL 
cur.execute("SELECT * FROM users WHERE name = ?", (name,))