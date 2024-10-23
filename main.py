from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

hostName = "localhost"
serverPort = 8080

# SQLite database file
db_file = "totally_not_my_privateKeys.db"

# Create/open SQLite database and table for keys
def init_db():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Insert private key into database
def insert_key(pem, exp_time):
    print(f"Inserting key with exp time: {exp_time}")  # Debugging output
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp_time))
    conn.commit()
    conn.close()
    print("Key inserted.")  # Debugging output
    

# Retrieve a key from the database based on expiration status
def get_key(expired=False):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    current_time = int(datetime.datetime.utcnow().timestamp())
    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp <= ?", (current_time,))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp > ?", (current_time,))
    
    row = cursor.fetchone()
    print("Fetched key:", row)  # Debugging output
    conn.close()
    return row[0] if row else None

# Convert integer to Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        print("Received POST request")
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            print("Processing /auth")
            expired = 'expired' in params
            key_pem = get_key(expired)
            print("Key retrieved:", key_pem)

            if not key_pem:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Key not found")
                print("Key not found in database")
                return

            try:
                private_key = serialization.load_pem_private_key(key_pem, password=None)
            except Exception as e:
                print("Error loading private key:", e)
                self.send_response(500)
                self.end_headers()
                return

            headers = {
                "kid": "goodKID" if not expired else "expiredKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + (datetime.timedelta(hours=1) if not expired else -datetime.timedelta(hours=1))
            }
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            print("Generated JWT:", encoded_jwt)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"jwt": encoded_jwt}).encode('utf-8'))
            return

        self.send_response(405)
        self.end_headers()
        return


    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Welcome to Dario's JWKS server! (supposedly working)")
            return
        elif self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

        # Get the first valid (non-expired) key
        key_pem = get_key(expired=False)
        if not key_pem:
            self.wfile.write(b"{}")
            return

        private_key = serialization.load_pem_private_key(key_pem, password=None)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        keys = {
            "keys": [
                {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                }
            ]
        }
        self.wfile.write(bytes(json.dumps(keys), "utf-8"))
        return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    init_db()

    # Insert an expired and valid key
    if not os.path.exists(db_file):
        # Generate an RSA private key and serialize it
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Expired key: current time minus 1 hour
        insert_key(pem, int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp()))
        print("Expired key inserted.")

        # Valid key: current time plus 1 hour
        insert_key(pem, int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()))
        print("Valid key inserted.")
    else:
        print("Database file already exists")

    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
