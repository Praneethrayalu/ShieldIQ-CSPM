"""Start ShieldIQ:  python run.py   then open http://127.0.0.1:5000"""
import os

from shieldiq import create_app

app = create_app()

if __name__ == "__main__":
    host = os.getenv("SHIELDIQ_HOST", "127.0.0.1")
    port = int(os.getenv("SHIELDIQ_PORT", "5000"))
    debug = os.getenv("SHIELDIQ_DEBUG", "0") == "1"
    print(f"\n  ShieldIQ running at http://{host}:{port}\n  Demo login: demo@shieldiq.local / ShieldIQ@2026\n")
    app.run(host=host, port=port, debug=debug)
