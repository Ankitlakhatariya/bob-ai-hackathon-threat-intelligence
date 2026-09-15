import os
import sys
from pathlib import Path

# Add src/backend to sys.path so app modules are discoverable in Vercel serverless environment
backend_path = Path(__file__).resolve().parent.parent / "src" / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.main import app
