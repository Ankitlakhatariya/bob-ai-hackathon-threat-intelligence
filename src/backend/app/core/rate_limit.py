import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from typing import Dict

class InMemoryRateLimiter:
    """
    Lightweight, single-process, in-memory rate limiter using a sliding window.
    NOTE: This is suitable ONLY for single-instance deployments (like the hackathon MVP).
    Production multi-instance deployments must use a distributed backplane (e.g., Redis).
    """
    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self.window_size = 60
        # Stores list of timestamps for each key
        self.history: Dict[str, list[float]] = defaultdict(list)

    async def __call__(self, request: Request):
        now = time.time()
        
        # Identify client (IP + Path as baseline)
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path
        
        # Try to extract user ID if authenticated
        user_id = "anonymous"
        # Since auth dependency might run after or before, we might not always have request.state.user
        # But we can check headers manually or rely on IP for anonymous routes.
        auth_header = request.headers.get("Authorization")
        if auth_header:
            # Simple hash of the token to identify the session without decoding
            user_id = str(hash(auth_header))
            
        key = f"{client_ip}:{user_id}:{path}"
        
        # Prune old timestamps
        window_start = now - self.window_size
        self.history[key] = [t for t in self.history[key] if t > window_start]
        
        if len(self.history[key]) >= self.requests_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"error": {"code": "RATE_LIMIT_EXCEEDED", "message": "Too many requests. Please try again later."}},
                headers={"Retry-After": str(self.window_size)}
            )
            
        self.history[key].append(now)


# Standard rate limits for sensitive operations
login_rate_limiter = InMemoryRateLimiter(requests_per_minute=5)     # Prevent brute forcing passwords
bulk_ingest_rate_limiter = InMemoryRateLimiter(requests_per_minute=30)  # Prevent volumetric DoS
llm_rate_limiter = InMemoryRateLimiter(requests_per_minute=10)      # Prevent expensive LLM usage
