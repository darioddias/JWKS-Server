# JWKS-Server
Project 1 JWKS Server


This code creates a Flask application with two endpoints:

/jwks: Returns a JSON Web Key Set (JWKS) containing public keys and their expiration times.


/auth: Authenticates a user (mock authentication is used for this example) and issues a JWT signed with a chosen key. The expired query parameter determines whether an expired key is used.


To run the server, execute the following command:
    python jwks_server.py


Dario Dias 
dkd0102
CSCE 3550
