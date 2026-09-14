import logging
import re
import sys
from app.core.config import settings

SENSITIVE_PATTERNS = [
    re.compile(r'(password|passwd|pwd)["\s]*[:=]["\s]*([^"\s,]+)', re.IGNORECASE),
    re.compile(r'(bearer\s+)([a-zA-Z0-9_\-\.]+)', re.IGNORECASE),
    re.compile(r'(secret|api_key|token|service_role)["\s]*[:=]["\s]*([^"\s,]+)', re.IGNORECASE),
]


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        orig = super().format(record)
        for pattern in SENSITIVE_PATTERNS:
            orig = pattern.sub(r'\1 [REDACTED]', orig)
        return orig


def setup_logging():
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d) - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Suppress verbose third party loggers if needed
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


logger = logging.getLogger("threatlens")
