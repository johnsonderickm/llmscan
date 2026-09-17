from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from llmscan_engine.api.routers import findings, plugins, reports, scans
from llmscan_engine.api.ws.feed import router as ws_router
from llmscan_engine.db.init_db import init_db
from llmscan_engine.plugins.registry import init_registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise database tables and plugin registry on startup."""
    await init_db()
    init_registry()
    yield


def create_app() -> FastAPI:
    """Create and configure the LLMScan FastAPI application."""
    app = FastAPI(
        title="LLMScan",
        version="0.1.0",
        description="Automated LLM penetration testing — OWASP LLM Top 10",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(scans.router, prefix="/api")
    app.include_router(findings.router, prefix="/api")
    app.include_router(plugins.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")
    app.include_router(ws_router)

    # Serve generated report files (HTML/PDF) so the dashboard can view them
    reports_dir = Path("reports/output")
    reports_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/reports", StaticFiles(directory=str(reports_dir)), name="reports")

    # Serve React dashboard in production when built
    dist = Path(__file__).parents[4] / "dashboard" / "dist"
    if dist.exists():
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="static")

    return app


app = create_app()
