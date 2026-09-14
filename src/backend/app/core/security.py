from typing import Optional, Dict, Any
import jwt
from fastapi import HTTPException, status
from app.core.config import settings
from app.core.logging import logger


class SupabaseJWTValidator:
    def __init__(self):
        self.secret = settings.SUPABASE_JWT_SECRET
        self.audience = settings.JWT_AUDIENCE
        self.issuer = settings.JWT_ISSUER or f"{settings.SUPABASE_URL}/auth/v1"

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify Supabase JWT token.
        If SUPABASE_JWT_SECRET is configured, performs cryptographic signature verification.
        Otherwise, if running in local development mode without secret, safely extracts unverified claims.
        """
        try:
            if self.secret:
                payload = jwt.decode(
                    token,
                    self.secret,
                    algorithms=["HS256"],
                    audience=self.audience,
                    issuer=self.issuer if settings.JWT_ISSUER else None,
                    options={"verify_aud": bool(self.audience)}
                )
                return payload
            else:
                # In development mode without JWT secret configured, decode claims
                payload = jwt.decode(token, options={"verify_signature": False})
                return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": {"code": "TOKEN_EXPIRED", "message": "Access token has expired"}}
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": {"code": "INVALID_TOKEN", "message": "Invalid authentication token"}}
            )
        except Exception as e:
            logger.error(f"JWT verification failure: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": {"code": "AUTH_ERROR", "message": "Could not validate credentials"}}
            )


jwt_validator = SupabaseJWTValidator()
