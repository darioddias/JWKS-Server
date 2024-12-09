
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import datetime
import jwt
import os
import sqlite3
import uuid

app = Flask(__name__)
ph = PasswordHasher()

# Rate limiter setup
limiter = Limiter(
    get_remote_address,  # Specify key function here
    app=app,
    default_limits=["10 per second"]
)

# Path to the SQLite database
db_file = "totally_not_my_privateKeys.db"

# AES encryption functions
def encrypt_private_key(private_key: str) -> (bytes, bytes):
    key = os.getenv("NOT_MY_KEY").encode()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(private_key.encode()) + encryptor.finalize()
    return encrypted_key, iv

def decrypt_private_key(encrypted_key: bytes, iv: bytes) -> str:
    key = os.getenv("NOT_MY_KEY").encode()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()
    return decrypted_key.decode()

# Insert private key into database with AES encryption
def insert_key(pem, exp_time):
    encrypted_key, iv = encrypt_private_key(pem.decode('utf-8'))
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp, iv) VALUES (?, ?, ?)", (encrypted_key, exp_time, iv))
    conn.commit()
    conn.close()

# Initialize database
def init_db():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL,
        iv BLOB NOT NULL
    );
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data['username']
    email = data.get('email', None)
    raw_password = str(uuid.uuid4())
    password_hash = ph.hash(raw_password)

    connection = sqlite3.connect(db_file)
    cursor = connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
        connection.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 400
    finally:
        connection.close()

    return jsonify({"password": raw_password}), 201

@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")
def authenticate_user():
    data = request.json
    username = data['username']
    password = data['password']

    connection = sqlite3.connect(db_file)
    cursor = connection.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    user_id, password_hash = user
    try:
        ph.verify(password_hash, password)
        cursor.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (request.remote_addr, user_id)
        )
        connection.commit()
    except:
        return jsonify({"error": "Invalid credentials"}), 401
    finally:
        connection.close()

    return jsonify({"message": "Authentication successful"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
