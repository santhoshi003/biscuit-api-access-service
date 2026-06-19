# Biscuit API Access Service

A Python API service that uses Eclipse Biscuit tokens for authorization and Ethereum wallet-signed keys for root identity. The service issues, attenuates, and verifies decentralized, offline-verifiable access tokens for scoped file operations.

## Features

- `POST /auth/mint` to mint a root Biscuit token from an Ethereum wallet signature
- `POST /token/attenuate` to narrow an existing Biscuit token with resource and operation restrictions
- `GET /files/{id}` to read scoped file content using an attenuated token
- `POST /files/{id}` to validate write access using a scoped token
- Offline verification using Biscuit token signature chain and request ambient facts

## Requirements

- Docker
- Docker Compose

## Build and Run

### Using Docker Compose

```bash
docker-compose build
docker-compose up
```

The API will be available on `http://localhost:8000`.

### Environment Variables

Use `.env.example` as a template for required environment variables.

- `APP_DOMAIN` - domain for EIP-191 wallet message binding
- `TOKEN_LIFETIME_MINUTES` - root token expiry window
- `DELEGATED_TOKEN_LIFETIME_MINUTES` - attenuated token expiry window
- `HOST` - server host
- `PORT` - server port

## API Endpoints

### 1. Mint Root Token

`POST /auth/mint`

Request body:

```json
{
  "address": "0xYourWalletAddress",
  "signature": "0x..."
}
```

Response:

```json
{
  "token": "<base64_encoded_biscuit_token>",
  "publicKey": "<hex_encoded_ed25519_public_key>"
}
```

### 2. Attenuate Token

`POST /token/attenuate`

Request body:

```json
{
  "token": "<base64_encoded_biscuit_token>",
  "publicKey": "<hex_encoded_ed25519_public_key>",
  "restrictions": {
    "file_id": "file-abc-123",
    "operation": "read"
  }
}
```

Response:

```json
{
  "attenuated_token": "<base64_encoded_attenuated_biscuit_token>"
}
```

### 3. Read File

`GET /files/{file_id}`

Header:

```http
Authorization: Bearer <token>
```

Response:

```json
{
  "file_id": "file-abc-123",
  "content": "..."
}
```

### 4. Write File Simulation

`POST /files/{file_id}`

Header:

```http
Authorization: Bearer <token>
```

Response:

```json
{
  "file_id": "file-abc-123",
  "message": "Write access granted for the requested file."
}
```

## Test Cases Covered

- Valid root token access
- Attenuated token access for the correct resource
- Rejection of incorrect resource
- Rejection of incorrect operation
- Expired token rejection
- Tamper-proof verification via Biscuit signature validation

## Notes

This service stores issuer public keys in memory for demonstration purposes. In a production deployment, use a persistent store or derive the public key from a deterministic identity mapping.
