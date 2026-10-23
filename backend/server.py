"""Clean entry point for running the AEGIS backend.

Used both for normal `python server.py` and as the PyInstaller target
(`pyinstaller ... server.py`). This avoids __name__ / uvicorn re-exec quirks
when the app is frozen into a single binary for the desktop .dmg.
"""
import argparse
import os
import secrets

import uvicorn


def main():
    parser = argparse.ArgumentParser(description="AEGIS Backend Server")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--desktop", action="store_true",
                        help="Run in desktop-app mode (127.0.0.1, no reload, quieter)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (defaults to loopback)")
    parser.add_argument("--reload", action="store_true", help="Enable source reload in development")
    parser.add_argument("--auth-token", default=os.environ.get("AEGIS_AUTH_TOKEN", ""))
    parser.add_argument("--instance-id", default=os.environ.get("AEGIS_INSTANCE_ID", ""))
    parser.add_argument("--allowed-origin", action="append", default=[])
    args = parser.parse_args()

    generated_token = not bool(args.auth_token)
    os.environ["AEGIS_AUTH_TOKEN"] = args.auth_token or secrets.token_urlsafe(32)
    os.environ["AEGIS_INSTANCE_ID"] = args.instance_id or secrets.token_urlsafe(18)
    os.environ["AEGIS_PORT"] = str(args.port)
    if args.allowed_origin:
        os.environ["AEGIS_ALLOWED_ORIGINS"] = ",".join(args.allowed_origin)

    # Import only after launch security configuration is in the environment.
    host = "127.0.0.1" if args.desktop else args.host
    log_level = "warning" if args.desktop else "info"
    reload = args.reload and not args.desktop
    if generated_token and not args.desktop:
        print(f"AEGIS_AUTH_TOKEN={os.environ['AEGIS_AUTH_TOKEN']}")

    if reload:
        application = "main:app"
    else:
        from main import app
        application = app

    uvicorn.run(
        application,
        host=host,
        port=args.port,
        reload=reload,
        log_level=log_level,
        access_log=not args.desktop,
    )


if __name__ == "__main__":
    main()
