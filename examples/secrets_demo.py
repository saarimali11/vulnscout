# Demo file for VS004. Five vulnerable lines, then safe ones.
import os

def connect(**kwargs):
    pass

# vulnerable 
password = "hunter2" # name match
API_KEY = "abc123def456" # name match (uppercase)
session_blob = "Zk3vQ9xT7pLw2RmN8cYb5HdJ4fGs6AeU" # high entropy
config = {"db_password": "letmein123"} # dict key match
connect(user="admin", password="letmein123") # keyword argument match

# --- safe ---
db_password = os.environ.get("DB_PASSWORD") # loaded at runtime
username = "saarim" # harmless name
tokenizer = "gpt2" # "tokenizer" is not "token"
password_hint = "" # empty value