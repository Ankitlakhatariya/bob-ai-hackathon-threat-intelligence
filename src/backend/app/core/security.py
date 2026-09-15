import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union
import jwt
from fastapi import HTTPException, status
from app.core.config import settings
from app.core.logging import logger
from app.core.permissions import UserRole

# Secret key for local JWT signing (falls back to secure random secret if not provided)
JWT_SECRET_KEY = settings.SUPABASE_JWT_SECRET or os.getenv("JWT_SECRET_KEY", "threatlens-production-jwt-signing-secret-key-32chars")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
REFRESH_TOKEN_EXPIRE_DAYS = 7


def get_password_hash(password: str) -> str:
    """Generates a cryptographically secure salted hash using PBKDF2 with SHA-256."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 600_000)
    return f"{salt}:{key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored salt:hash."""
    try:
        if not hashed_password or ":" not in hashed_password:
            return False
        salt, key = hashed_password.split(":", 1)
        test_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 600_000)
        return secrets.compare_digest(key, test_key.hex())
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def create_access_token(
    subject: Optional[str] = None,
    role: Optional[Union[UserRole, str]] = None,
    email: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
) -> str:
    """Creates a signed JWT access token with role and subject."""
    if data:
        subject = subject or str(data.get("sub") or data.get("subject") or "")
        role = role or data.get("role") or UserRole.ANALYST
        email = email or data.get("email") or ""
        claims = {k: v for k, v in data.items() if k not in ("sub", "subject", "role", "email")}
        if extra_claims:
            claims.update(extra_claims)
        extra_claims = claims

    role_val = role.value if isinstance(role, UserRole) else str(role or "ANALYST")
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {
        "sub": subject or "",
        "email": email or "",
        "role": role_val,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    if extra_claims:
        to_encode.update(extra_claims)
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed JWT refresh token."""
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    to_encode = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    """Decodes and validates a JWT token."""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_exp": True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "TOKEN_EXPIRED", "message": "Access token has expired"}}
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"JWT validation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "INVALID_TOKEN", "message": "Invalid authentication token signature"}}
        )
