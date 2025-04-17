# JWT Authentication Server

## Overview
This project implements a simple HTTP server that handles JWT (JSON Web Token) authentication. The server generates and serves JWTs using RSA keys stored in an SQLite database. It provides endpoints for obtaining tokens and for retrieving public keys in JWK (JSON Web Key) format.


## TEST CLIENT



## Features
- **JWT Authentication**: Generates JWTs for authenticated users.
- **Key Management**: Stores RSA private keys in an SQLite database, including both valid and expired keys.
- **JWKS Endpoint**: Exposes a well-known endpoint to retrieve the public keys in JWK format.

## Technologies Used
- Python 3.x
- HTTPServer from the `http.server` module
- `cryptography` for key management
- `sqlite3` for database operations
- `jwt` for token generation
- `base64` for encoding

## Requirements
To run this project, you need to install the following Python packages:

```plaintext
cryptography==41.0.4
pyjwt==2.8.0
