"""Import check app.py (validasi FastAPI routes) tanpa start server."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app  # noqa: F401

routes = sorted(r.path for r in app.app.routes if "chat" in getattr(r, "path", ""))
# /chat/history punya 2 entri (GET + DELETE); /api/chat/ai/provider GET+POST
assert routes == [
    "/api/chat/ai/provider",
    "/api/chat/ai/provider",
    "/api/scan/{scan_id}/chat",
    "/api/scan/{scan_id}/chat/agent",
    "/api/scan/{scan_id}/chat/agent/{job_id}",
    "/api/scan/{scan_id}/chat/config",
    "/api/scan/{scan_id}/chat/history",
    "/api/scan/{scan_id}/chat/history",
], routes
print("app import OK, chat routes:", routes)
