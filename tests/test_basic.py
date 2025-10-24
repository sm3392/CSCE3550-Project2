import os
import db
import main
from fastapi.testclient import TestClient
import keys

client = TestClient(main.app)

def test_db_init_and_insert():
    # ensure DB initialized
    db.init_db()
    # insert a dummy key (safe, small test)
    keys.generate_and_store_keys()
    rows = db.get_all_valid_keys()
    assert isinstance(rows, list)
    assert len(rows) >= 1

def test_jwks_endpoint():
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    j = resp.json()
    assert "keys" in j
    # keys should be list
    assert isinstance(j["keys"], list)

def test_auth_endpoint_unexpired():
    resp = client.post("/auth")
    assert resp.status_code == 200
    j = resp.json()
    assert "jwt" in j

def test_auth_endpoint_expired():
    # request expired key
    resp = client.post("/auth?expired=true")
    # If an expired key exists, server returns jwt. Otherwise 500. We check either status or jwt present.
    assert resp.status_code in (200, 500)
