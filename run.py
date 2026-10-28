"""
Launch the toolkit, bound to 127.0.0.1 (local only).

    python run.py

Reads host/port from .env (defaults 127.0.0.1:8000).
"""

import uvicorn

from app.core.config import settings

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)
