import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.main import app
from app.services.intelligence.provider import ExternalThreatIntelProvider
from app.core.security import decode_token

client = TestClient(app)

def test_ssrf_protection_validation():
    """Verify SSRF validation correctly blocks internal IPs and allows public IPs."""
    # Test internal/private IPs
    assert ExternalThreatIntelProvider._is_safe_url("http://127.0.0.1") is False
    assert ExternalThreatIntelProvider._is_safe_url("http://localhost") is False
    assert ExternalThreatIntelProvider._is_safe_url("http://10.0.0.1") is False
    assert ExternalThreatIntelProvider._is_safe_url("http://172.16.0.1") is False
    assert ExternalThreatIntelProvider._is_safe_url("http://192.168.0.1") is False
    assert ExternalThreatIntelProvider._is_safe_url("http://169.254.169.254") is False
    
    # Test valid external URLs
    # We patch socket.gethostbyname so it doesn't do real DNS during tests
    with patch("socket.gethostbyname", return_value="8.8.8.8"):
        assert ExternalThreatIntelProvider._is_safe_url("http://example.com") is True
        assert ExternalThreatIntelProvider._is_safe_url("https://threat-intel.com/api") is True

@pytest.mark.asyncio
async def test_jwt_signature_verification_regression():
    """CRITICAL REGRESSION: Verify JWT decode strictly requires signature verification."""
    # If we pass a forged token with an invalid signature, it MUST raise an error and NEVER fallback to verify_signature=False
    import jwt
    from fastapi import HTTPException
    
    # Create a forged token signed with a random secret, but purporting to be valid
    forged_token = jwt.encode({"sub": "admin-id", "role": "ADMIN"}, "wrong_secret", algorithm="HS256")
    
    # decode_token should raise an HTTPException because the signature will fail against the real secret
    with pytest.raises(HTTPException) as exc:
        decode_token(forged_token)
    
    assert exc.value.status_code == 401
    assert exc.value.detail["error"]["code"] == "INVALID_TOKEN"

@pytest.mark.asyncio
async def test_security_headers_middleware(async_client: AsyncClient):
    """Verify security headers are injected into HTTP responses."""
    response = await async_client.get("/health")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert "default-src 'self'" in response.headers.get("content-security-policy", "")

@pytest.mark.asyncio
async def test_request_size_limit_middleware(async_client: AsyncClient):
    """Verify payload size limits are enforced on POST requests."""
    # 2MB is the limit. Let's send a 3MB string.
    oversized_payload = "A" * (3 * 1024 * 1024)
    response = await async_client.post("/api/v1/auth/login", content=oversized_payload, headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"

@pytest.mark.asyncio
async def test_rate_limiting_enforcement(async_client: AsyncClient):
    """Verify the rate limiter accurately returns 429 after threshold is met."""
    # The login rate limit is 5 requests per minute
    # Send 5 failed requests
    for _ in range(5):
        await async_client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "wrong"})
        
    # The 6th request should be rate limited
    response = await async_client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "wrong"})
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in response.headers
