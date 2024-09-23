# JWKS-Server

Dario Dias 
dkd0102
CSCE 3550


This Python application implements a RESTful JWKS server that provides public keys for verifying JSON Web Tokens (JWTs). It includes key expiry for enhanced security and handles the issuance of JWTs with expired keys based on a query parameter.

#Installation:

Create a virtual environment:
   python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

2. **Install dependencies:**
```bash
pip install   
 Flask cryptography jwt


#Usage:

Run the server:
python jwks_server.py

Test the JWKS endpoint:
curl http://localhost:5000/jwks

Test the authentication endpoint:
curl -X POST http://localhost:5000/auth -d '{"username": "john_doe"}'


Endpoints:

/jwks: Returns a JSON Web Key Set (JWKS) containing public keys and their expiration times.

/auth: Authenticates a user (mock authentication is used for this example) and issues a JWT signed with a chosen key. The expired query parameter determines whether an expired key is used.
