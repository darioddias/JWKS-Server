from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key, PrivateKey
from cryptography.hazmat.primitives import serialization
import jwt
import time
import json

app = Flask(__name__)

# Generate RSA key pairs and store them in a dictionary
keys = {}
for i in range(5):
    private_key = generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    kid = f"key{i}"
    expiry = time.time() + 3600  # 1 hour expiry

    keys[kid] = {
        "kid": kid,
        "kty": "RSA",
        "e": "AQAB",
        "n": public_key.public_numbers().n.to_bytes(256, "big").hex(),
        "exp": expiry
    }

@app.route('/jwks', methods=['GET'])
def jwks():
    return jsonify(keys)

@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired', False)

    # Mock authentication by checking if a username is provided
    username = request.json.get('username')
    if not username:
        return jsonify({"error": "Username is required"}), 400

    # Choose a key based on the expired parameter
    if expired:
        for key in keys:
            if keys[key]['exp'] < time.time():
                key_to_use = key
                break
        else:
            return jsonify({"error": "No expired keys found"}), 400
    else:
        key_to_use = list(keys.keys())[0]

    # Generate JWT using the chosen key
    payload = {"username": username}
    jwt_token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": key_to_use})

    return jsonify({"token": jwt_token})

if __name__ == '__main__':
    app.run(debug=True)