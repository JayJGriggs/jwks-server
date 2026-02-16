# JWKS Server

This project is a simple RESTful JWKS server built in Go. It generates RSA key pairs, assigns each key a unique `kid`, and exposes a JWKS endpoint so public keys can be used to verify JWTs.

The server has two main endpoints:

- GET /.well-known/jwks.json  
  Returns the public keys in proper JWKS format. Only non-expired keys are returned.

- POST /auth  
  Returns a signed JWT.  
  If `?expired=true` is added to the request, the server signs the JWT with the expired key and sets the expiration time in the past.

## What This Project Covers

- RSA key pair generation  
- Assigning a unique `kid` to each key  
- Key expiration handling  
- JWT signing using RS256  
- Filtering expired keys from JWKS  
- Basic REST API handling  
- Test suite with over 80% coverage  

## How to Run

Make sure you're inside the project folder, then run:

go run .

The server runs on:

http://localhost:8080
