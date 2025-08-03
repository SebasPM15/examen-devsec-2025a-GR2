import os
import base64
import hmac
import hashlib
import json
from datetime import datetime, timedelta

SECRET_KEY = os.environ.get('JWT_SECRET')

try:
    JWT_EXP_MINUTES = int(os.environ.get('JWT_EXP_MINUTES', 30))
except ValueError:
    JWT_EXP_MINUTES = 30

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def base64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def create_jwt(payload: dict) -> str:
    """Crea un JWT con expiración configurada por variable de entorno."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload["exp"] = int((datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES)).timestamp())

    header_enc = base64url_encode(json.dumps(header).encode())
    payload_enc = base64url_encode(json.dumps(payload).encode())

    signature = hmac.new(
        SECRET_KEY.encode(),
        msg=f"{header_enc}.{payload_enc}".encode(),
        digestmod=hashlib.sha256
    ).digest()

    signature_enc = base64url_encode(signature)
    return f"{header_enc}.{payload_enc}.{signature_enc}"

def verify_jwt(token: str) -> dict | None:
    """Verifica un JWT y retorna el payload si es válido."""
    try:
        header_enc, payload_enc, signature_enc = token.split('.')
        expected_sig = hmac.new(
            SECRET_KEY.encode(),
            msg=f"{header_enc}.{payload_enc}".encode(),
            digestmod=hashlib.sha256
        ).digest()
        if not hmac.compare_digest(base64url_encode(expected_sig), signature_enc):
            return None

        payload = json.loads(base64url_decode(payload_enc))
        if "exp" in payload and datetime.utcnow().timestamp() > payload["exp"]:
            return None

        return payload
    except Exception:
        return None
