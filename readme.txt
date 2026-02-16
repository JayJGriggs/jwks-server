# JWKS Server (Beginner Version)

This is a small server that:
- Publishes public RSA keys at `/.well-known/jwks.json` (JWKS format)
- Issues JWTs at `/auth` (POST)
- If `?expired` query param is present, issues an expired JWT signed with an expired key

## Requirements Covered
- RSA keypair generation
- `kid` in JWT header
- JWKS includes only unexpired keys
- `/auth` issues normal token
- `/auth?expired=true` issues expired token using expired key
- Tests + coverage

## Run the server (port 8080)
```bash
go run .
