import os
import sys
from pathlib import Path
from waitress import serve

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"============================================================")
    print(f"🚀 PhishGuard AI Production WSGI Server (Waitress)")
    print(f"👉 Local:   http://127.0.0.1:{port}")
    print(f"👉 Network: http://0.0.0.0:{port}")
    print(f"============================================================")
    serve(app, host='0.0.0.0', port=port, threads=6)
