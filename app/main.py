"""FastAPI application entry point for ElasticGuard AI."""
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.elasticsearch_client import check_es_health, close_es_client
from app.routes import health, search, analytics, threats

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    logger.info("Starting ElasticGuard AI...")
    es_health = await check_es_health()
    if es_health.get("status") in ("green", "yellow"):
        logger.info(f"Elasticsearch connected: {es_health}")
    else:
        logger.warning(f"Elasticsearch not healthy: {es_health}")
    yield
    logger.info("Shutting down ElasticGuard AI...")
    await close_es_client()


app = FastAPI(
    title="ElasticGuard AI",
    description="AI-powered security observability platform for IoT devices",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Include routers
app.include_router(health.router)
app.include_router(search.router)
app.include_router(analytics.router)
app.include_router(threats.router)


@app.get("/")
async def root():
    """Redirect root to dashboard."""
    dashboard = os.path.join(static_dir, "index.html")
    if os.path.exists(dashboard):
        return FileResponse(dashboard)
    return RedirectResponse(url="/api/health")


@app.get("/dashboard")
async def dashboard():
    """Serve the dashboard."""
    dashboard = os.path.join(static_dir, "index.html")
    if os.path.exists(dashboard):
        return FileResponse(dashboard)
    return {"message": "Dashboard not found"}
