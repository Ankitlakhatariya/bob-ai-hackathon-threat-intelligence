from starlette.types import ASGIApp, Receive, Scope, Send, Message
from fastapi import status
from fastapi.responses import JSONResponse

class RequestSizeLimitMiddleware:
    """
    Middleware to limit the size of incoming HTTP request bodies.
    Enforces the limit both by checking the Content-Length header and by tracking
    the total bytes received during streaming, preventing memory exhaustion.
    """
    def __init__(self, app: ASGIApp, max_body_size: int = 2 * 1024 * 1024): # Default 2MB limit
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        total_size = 0
        
        # 1. Early rejection via Content-Length header
        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_body_size:
                    response = JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"error": {"code": "PAYLOAD_TOO_LARGE", "message": f"Request body exceeds the {self.max_body_size} bytes limit."}}
                    )
                    await response(scope, receive, send)
                    return
            except ValueError:
                pass

        # 2. Enforce limit while receiving the request body chunks
        async def wrapped_receive() -> Message:
            nonlocal total_size
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                total_size += len(body)
                if total_size > self.max_body_size:
                    raise RuntimeError("Request body too large")
            return message

        try:
            await self.app(scope, wrapped_receive, send)
        except RuntimeError as e:
            if str(e) == "Request body too large":
                response = JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"error": {"code": "PAYLOAD_TOO_LARGE", "message": f"Request body exceeded the {self.max_body_size} bytes limit during streaming."}}
                )
                try:
                    await response(scope, receive, send)
                except Exception:
                    # If the response has already started, we can't send a 413 JSON. 
                    pass
            else:
                raise e


class SecurityHeadersMiddleware:
    """
    Injects essential security headers into all HTTP responses.
    Exempts Swagger/OpenAPI docs from strict CSP.
    """
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.get("headers", [])
                
                # Inject standard security headers
                headers.append((b"x-content-type-options", b"nosniff"))
                headers.append((b"x-frame-options", b"DENY"))
                headers.append((b"referrer-policy", b"no-referrer"))
                
                # Apply CSP conditionally to not break Swagger UI
                path = scope.get("path", "")
                if not any(path.startswith(p) for p in ["/api/docs", "/api/redoc", "/api/openapi.json"]):
                    headers.append((b"content-security-policy", b"default-src 'self'"))
                
                message["headers"] = headers
                
            await send(message)

        await self.app(scope, receive, send_wrapper)
