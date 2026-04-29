from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Optional


PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"
FRONTEND_INDEX = FRONTEND_DIST / "index.html"


def ensure_runtime_dependencies() -> None:
    missing = []
    for module in ("fastapi", "uvicorn", "pandas"):
        try:
            importlib.import_module(module)
        except ModuleNotFoundError:
            missing.append(module)

    if not missing:
        return

    candidates = [
        PROJECT_ROOT / "backend" / ".venv" / "bin" / "python",
        PROJECT_ROOT / ".venv" / "bin" / "python",
        PROJECT_ROOT / "venv" / "bin" / "python",
    ]
    current_python = Path(sys.executable).absolute()

    for candidate in candidates:
        if not candidate.exists() or candidate.absolute() == current_python:
            continue
        os.execv(str(candidate), [str(candidate), str(Path(__file__).resolve()), *sys.argv[1:]])

    modules = ", ".join(missing)
    raise SystemExit(
        f"Dependencias ausentes: {modules}. Rode `python -m pip install -r requirements.txt` "
        "ou use um ambiente virtual com as dependencias instaladas."
    )


ensure_runtime_dependencies()

from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from backend.app.services.analytics import (
    anomalies,
    apply_filters,
    filters as filter_options,
    firewall_ids,
    logs,
    network,
    overview,
    threats,
)
from backend.app.services.data_loader import CSV_PATH, load_data


app = FastAPI(
    title="CyberSOC Analytics API",
    description="REST API for an executive and operational SOC cybersecurity dashboard.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def query_filters(
    start_date: Optional[str] = Query(default=None),
    end_date: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    attack_type: Optional[str] = Query(default=None),
    protocol: Optional[str] = Query(default=None),
    action_taken: Optional[str] = Query(default=None),
    network_segment: Optional[str] = Query(default=None),
    min_anomaly_score: Optional[float] = Query(default=None, ge=0, le=100),
    search: Optional[str] = Query(default=None),
) -> dict[str, object]:
    return {
        "start_date": start_date,
        "end_date": end_date,
        "severity": severity,
        "attack_type": attack_type,
        "protocol": protocol,
        "action_taken": action_taken,
        "network_segment": network_segment,
        "min_anomaly_score": min_anomaly_score,
        "search": search,
    }


def filtered_data(filter_values: dict[str, object]):
    return apply_filters(load_data(), filter_values)


@app.get("/health")
async def health() -> dict[str, object]:
    df = load_data()
    return {"status": "ok", "rows": len(df), "csv_path": str(CSV_PATH)}


@app.get("/overview")
async def get_overview(filters: dict[str, object] = Depends(query_filters)) -> dict[str, object]:
    return overview(filtered_data(filters))


@app.get("/threats")
async def get_threats(filters: dict[str, object] = Depends(query_filters)) -> dict[str, object]:
    return threats(filtered_data(filters))


@app.get("/network")
async def get_network(filters: dict[str, object] = Depends(query_filters)) -> dict[str, object]:
    return network(filtered_data(filters))


@app.get("/anomalies")
async def get_anomalies(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    protocol: Optional[str] = None,
    action_taken: Optional[str] = None,
    network_segment: Optional[str] = None,
    min_anomaly_score: Optional[float] = Query(default=None, ge=0, le=100),
    threshold: float = Query(default=70, ge=0, le=100),
) -> dict[str, object]:
    data = filtered_data(
        {
            "start_date": start_date,
            "end_date": end_date,
            "severity": severity,
            "attack_type": attack_type,
            "protocol": protocol,
            "action_taken": action_taken,
            "network_segment": network_segment,
            "min_anomaly_score": min_anomaly_score,
        }
    )
    return anomalies(data, threshold)


@app.get("/firewall-ids")
async def get_firewall_ids(filters: dict[str, object] = Depends(query_filters)) -> dict[str, object]:
    return firewall_ids(filtered_data(filters))


@app.get("/logs")
async def get_logs(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    protocol: Optional[str] = None,
    action_taken: Optional[str] = None,
    network_segment: Optional[str] = None,
    min_anomaly_score: Optional[float] = Query(default=None, ge=0, le=100),
    search: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=500),
) -> dict[str, object]:
    data = filtered_data(
        {
            "start_date": start_date,
            "end_date": end_date,
            "severity": severity,
            "attack_type": attack_type,
            "protocol": protocol,
            "action_taken": action_taken,
            "network_segment": network_segment,
            "min_anomaly_score": min_anomaly_score,
            "search": search,
        }
    )
    return logs(data, page=page, page_size=page_size)


@app.get("/filters")
async def get_filters() -> dict[str, object]:
    return filter_options(load_data())


if (FRONTEND_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="frontend-assets")


def frontend_not_built_response() -> HTMLResponse:
    return HTMLResponse(
        """
        <!doctype html>
        <html lang="pt-BR">
          <head>
            <meta charset="utf-8" />
            <title>CyberSOC</title>
            <style>
              body {
                margin: 0;
                min-height: 100vh;
                display: grid;
                place-items: center;
                background: #020607;
                color: #d7f7ff;
                font-family: Inter, ui-sans-serif, system-ui, sans-serif;
              }
              main {
                max-width: 680px;
                padding: 32px;
                border: 1px solid #1c2a32;
                border-radius: 8px;
                background: #071014;
              }
              code {
                color: #00f5a0;
              }
            </style>
          </head>
          <body>
            <main>
              <h1>Frontend nao encontrado</h1>
              <p>Gere os arquivos estaticos uma vez com:</p>
              <p><code>cd frontend && npm install && npm run build</code></p>
              <p>Depois rode novamente <code>python main.py</code>.</p>
            </main>
          </body>
        </html>
        """,
        status_code=503,
    )


def serve_frontend_file(path: str = "") -> Response:
    if not FRONTEND_INDEX.exists():
        return frontend_not_built_response()

    if path:
        dist_root = FRONTEND_DIST.resolve()
        requested = (dist_root / path).resolve()
        if requested.is_file() and dist_root in requested.parents:
            return FileResponse(requested)

    return FileResponse(FRONTEND_INDEX)


@app.get("/", include_in_schema=False)
async def frontend_root() -> Response:
    return serve_frontend_file()


@app.get("/{path:path}", include_in_schema=False)
async def frontend_path(path: str) -> Response:
    return serve_frontend_file(path)


def main() -> None:
    import uvicorn

    host = os.getenv("CYBER_HOST", "127.0.0.1")
    port = int(os.getenv("CYBER_PORT", "8000"))
    print(f"CyberSOC rodando em http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
