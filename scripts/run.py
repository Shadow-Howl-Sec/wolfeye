"""Cross-platform local launcher for the WolfEye backend and dashboard."""

from __future__ import annotations

import argparse
import signal
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the WolfEye Flask API, Streamlit dashboard, or both."
    )
    parser.add_argument(
        "service",
        choices=("backend", "dashboard", "all"),
        nargs="?",
        default="all",
        help="Service to run (default: all).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address.")
    parser.add_argument("--backend-port", type=int, default=5000)
    parser.add_argument("--dashboard-port", type=int, default=8501)
    return parser


def command_for(service: str, args: argparse.Namespace) -> list[str]:
    if service == "backend":
        return [
            sys.executable,
            "-m",
            "flask",
            "--app",
            "app:create_app('development')",
            "run",
            "--host",
            args.host,
            "--port",
            str(args.backend_port),
        ]
    return [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(PROJECT_ROOT / "app.py"),
        "--server.address",
        args.host,
        "--server.port",
        str(args.dashboard_port),
        "--server.headless",
        "true",
    ]


def run(service: str, args: argparse.Namespace) -> int:
    processes: list[subprocess.Popen[bytes]] = []
    services = ("backend", "dashboard") if service == "all" else (service,)

    def stop_processes(*_: object) -> None:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            if process.poll() is None:
                process.wait()

    signal.signal(signal.SIGINT, stop_processes)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_processes)

    for name in services:
        print(f"Starting {name}...", flush=True)
        processes.append(
            subprocess.Popen(command_for(name, args), cwd=PROJECT_ROOT)
        )

    if service == "all":
        print(
            f"Backend: http://{args.host}:{args.backend_port}\n"
            f"Dashboard: http://{args.host}:{args.dashboard_port}",
            flush=True,
        )

    try:
        while True:
            for process in processes:
                return_code = process.poll()
                if return_code is not None:
                    stop_processes()
                    return return_code
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_processes()
        return 0


def main() -> int:
    args = build_parser().parse_args()
    return run(args.service, args)


if __name__ == "__main__":
    raise SystemExit(main())
