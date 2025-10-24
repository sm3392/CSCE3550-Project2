from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import db

def generate_and_store_keys():
    # ----- Expired key (24 hours ago) -----
    expired_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_pem = expired_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    expired_ts = int((datetime.utcnow() - timedelta(hours=24)).timestamp())
    db.insert_key(expired_pem, expired_ts)

    # ----- Valid key (1 hour in the future) -----
    valid_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    valid_pem = valid_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    valid_ts = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    db.insert_key(valid_pem, valid_ts)
