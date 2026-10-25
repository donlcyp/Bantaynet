"""Production WSGI entrypoint for BantayNet.

Deploying on Linux:
    gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app

Deploying on Windows:
    waitress-serve --listen=0.0.0.0:5000 wsgi:app
    or: python wsgi.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.app import app
from src.db import init_db

# Initialize database schema and tables upon process launch
init_db()

# Expose WSGI application callable
application = app

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))

    try:
        from waitress import serve

        print(f"[*] Starting production Waitress server on http://{host}:{port}/")
        print("[!] Security notice: For authorized operations and lab traffic only.")
        serve(app, host=host, port=port)
    except ImportError:
        print("[!] Waitress not found. Serving with standard WSGI handler...")
        from wsgiref.simple_server import make_server

        server = make_server(host, port, app)
        print(f"[*] Serving BantayNet on http://{host}:{port}/")
        server.serve_forever()
