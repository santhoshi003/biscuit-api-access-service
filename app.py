import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Dict

from biscuit_auth import (
    Algorithm,
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuilder,
    BlockBuilder,
    Check,
    Fact,
    KeyPair,
    Policy,
    PrivateKey,
    PublicKey,
    UnverifiedBiscuit,
)
from dotenv import load_dotenv
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

load_dotenv()

APP_DOMAIN = os.getenv("APP_DOMAIN", "biscuit-api-access-service")
ROOT_TOKEN_LIFETIME_MINUTES = int(os.getenv("TOKEN_LIFETIME_MINUTES", "60"))
DELEGATED_TOKEN_LIFETIME_MINUTES = int(
    os.getenv("DELEGATED_TOKEN_LIFETIME_MINUTES", "5")
)

app = FastAPI(
    title="Biscuit API Access Service",
    description="Issuer, attenuator, and verifier for Eclipse Biscuit tokens backed by Ethereum wallet signatures.",
    version="0.1.0",
)

issuer_public_keys: Dict[str, str] = {}

mock_files = {
    "file-abc-123": "The content of file abc-123.",
    "file-xyz-999": "The content of file xyz-999.",
    "file-demo-001": "Demo file content for Biscuit authorization.",
}


def build_domain_message() -> str:
    return f"Biscuit issuer key for {APP_DOMAIN}"


def normalize_address(address: str) -> str:
    return address.strip().lower()


def derive_biscuit_keypair(wallet_address: str, signature_bytes: bytes) -> PrivateKey:
    message = encode_defunct(text=build_domain_message())
    recovered_address = Account.recover_message(message, signature=signature_bytes)
    if normalize_address(recovered_address) != normalize_address(wallet_address):
        raise ValueError("Signature does not match the provided Ethereum address.")

    seed = hashlib.sha256(signature_bytes).digest()
    return PrivateKey.from_bytes(seed, Algorithm.Ed25519)


def extract_wallet_address_from_token(token_b64: str) -> str | None:
    try:
        unverified = UnverifiedBiscuit.from_base64(token_b64)
        block_source = unverified.block_source(0)
        match = re.search(r'user\("([^"\\]+)"\)', block_source)
        if match:
            return normalize_address(match.group(1))
    except Exception:
        pass
    return None


def get_root_public_key_for_token(token_b64: str) -> PublicKey:
    wallet_address = extract_wallet_address_from_token(token_b64)
    if not wallet_address:
        raise HTTPException(status_code=401, detail="Unable to determine token issuer address.")

    public_key_hex = issuer_public_keys.get(wallet_address)
    if not public_key_hex:
        raise HTTPException(
            status_code=401,
            detail="Unknown issuer public key. Mint the token with /auth/mint first.",
        )

    try:
        return PublicKey(public_key_hex)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Invalid issuer public key: {exc}")


def authorize_token(token_b64: str, resource_id: str, operation: str) -> None:
    root_key = get_root_public_key_for_token(token_b64)
    try:
        token = Biscuit.from_base64(token_b64, root_key)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Token verification failed: {exc}")

    builder = AuthorizerBuilder()
    builder.add_fact(Fact("resource({resource_id})", {"resource_id": resource_id}))
    builder.add_fact(Fact("operation({operation})", {"operation": operation}))
    builder.add_fact(Fact("time({now})", {"now": datetime.now(tz=timezone.utc)}))
    builder.add_policy(Policy("allow if permission({permission})", {"permission": f"files:{operation}"}))

    try:
        authorizer = builder.build(token)
        authorizer.authorize()
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Authorization failed: {exc}")


class MintRequest(BaseModel):
    address: str
    signature: str


class MintResponse(BaseModel):
    token: str
    publicKey: str


class RestrictionPayload(BaseModel):
    file_id: str
    operation: str


class AttenuateRequest(BaseModel):
    token: str
    publicKey: str
    restrictions: RestrictionPayload


class AttenuateResponse(BaseModel):
    attenuated_token: str


@app.post("/auth/mint", response_model=MintResponse)
def mint_token(request: MintRequest) -> MintResponse:
    if not request.address or not request.signature:
        raise HTTPException(status_code=400, detail="address and signature are required")

    try:
        signature_bytes = bytes.fromhex(request.signature.replace("0x", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="signature must be hex-encoded")

    try:
        private_key = derive_biscuit_keypair(request.address, signature_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Signature verification failed: {exc}")

    expiry_time = datetime.now(tz=timezone.utc) + timedelta(minutes=ROOT_TOKEN_LIFETIME_MINUTES)
    builder = BiscuitBuilder()
    builder.add_fact(Fact("user({user})", {"user": normalize_address(request.address)}))
    builder.add_fact(Fact('role("member")'))
    builder.add_fact(Fact('permission("files:read")'))
    builder.add_fact(Fact('permission("files:write")'))
    builder.add_check(Check("check if time($time), $time < {expiration}", {"expiration": expiry_time}))

    try:
        biscuit = builder.build(private_key)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Token build failed: {exc}")

    public_key = str(KeyPair.from_private_key(private_key).public_key)
    issuer_public_keys[normalize_address(request.address)] = public_key
    return MintResponse(token=biscuit.to_base64(), publicKey=public_key)


@app.post("/token/attenuate", response_model=AttenuateResponse)
def attenuate_token(request: AttenuateRequest) -> AttenuateResponse:
    if not request.token or not request.publicKey or not request.restrictions:
        raise HTTPException(status_code=400, detail="token, publicKey, and restrictions are required")

    try:
        root_key = PublicKey(request.publicKey)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid publicKey: {exc}")

    try:
        biscuit = Biscuit.from_base64(request.token, root_key)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Token validation failed: {exc}")

    expiry_time = datetime.now(tz=timezone.utc) + timedelta(minutes=DELEGATED_TOKEN_LIFETIME_MINUTES)
    block_builder = BlockBuilder("")
    block_builder.add_check(Check("check if resource({resource_id})", {"resource_id": request.restrictions.file_id}))
    block_builder.add_check(Check("check if operation({operation})", {"operation": request.restrictions.operation}))
    block_builder.add_check(Check("check if time($time), $time < {expiration}", {"expiration": expiry_time}))

    try:
        attenuated = biscuit.append(block_builder)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Token attenuation failed: {exc}")

    return AttenuateResponse(attenuated_token=attenuated.to_base64())


@app.get("/files/{file_id}")
def get_file(file_id: str, authorization: str | None = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token_b64 = authorization.removeprefix("Bearer ").strip()
    if token_b64 == "":
        raise HTTPException(status_code=401, detail="Empty token")

    authorize_token(token_b64, file_id, "read")

    content = mock_files.get(file_id)
    if content is None:
        raise HTTPException(status_code=404, detail="File not found")

    return {"file_id": file_id, "content": content}


@app.post("/files/{file_id}")
def update_file(file_id: str, authorization: str | None = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token_b64 = authorization.removeprefix("Bearer ").strip()
    if token_b64 == "":
        raise HTTPException(status_code=401, detail="Empty token")

    authorize_token(token_b64, file_id, "write")

    if file_id not in mock_files:
        raise HTTPException(status_code=404, detail="File not found")

    return {"file_id": file_id, "message": "Write access granted for the requested file."}
