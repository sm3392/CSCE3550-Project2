from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
import db, keys
from datetime import datetime, timedelta
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import math
import base64

app = FastAPI()

@app.on_event("startup")
def startup():
    db.init_db()
    # If DB empty, create expired + valid keys
    rows = db.get_all_valid_keys()
    if not rows:
        keys.generate_and_store_keys()

def int_to_base64url(n: int) -> str:
    b = n.to_bytes((n.bit_length()+7)//8 or 1, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

@app.post("/auth")
async def auth(expired: bool = Query(False)):
    row = db.get_key_row(expired=expired)
    if not row:
        raise HTTPException(status_code=500, detail="No key available matching criteria")
    kid, pem_str, exp_ts = row
    # load private key
    private_key = serialization.load_pem_private_key(pem_str.encode(), password=None, backend=default_backend())
    # payload: mocked user
    now = datetime.utcnow()
    payload = {
        "sub": "userABC",
        "username": "userABC",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp())
    }
    # Sign JWT using RS256
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": str(kid)})
    return {"jwt": token}

@app.get("/.well-known/jwks.json")
async def jwks():
    rows = db.get_all_valid_keys()
    keys_list = []
    for kid, pem_str, exp_ts in rows:
        private_key = serialization.load_pem_private_key(pem_str.encode(), password=None, backend=default_backend())
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()
        n = numbers.n
        e = numbers.e
        keys_list.append({
            "kty": "RSA",
            "use": "sig",
            "kid": str(kid),
            "alg": "RS256",
            "n": int_to_base64url(n),
            "e": int_to_base64url(e)
        })
    return JSONResponse({"keys": keys_list})
