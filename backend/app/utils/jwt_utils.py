from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

import os
import sys

SECRET_KEY = os.environ.get("JWT_SECRET")
if not SECRET_KEY:
    if os.environ.get("ENV") == "development":
        SECRET_KEY = "dev-only-insecure-secret"
    else:
        print("FATAL: JWT_SECRET environment variable is not set.", file=sys.stderr)
        sys.exit(1)

ALGORITHM  = "HS256"
TOKEN_TTL_MINUTES = 60 * 8  # 8 hours

_bearer = HTTPBearer()


def create_access_token(email: str, name: str) -> str:
    payload = {
        "sub":  email,
        "name": name,
        "exp":  datetime.utcnow() + timedelta(minutes=TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
