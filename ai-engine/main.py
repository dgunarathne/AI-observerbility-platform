"""
AI Engine - FastAPI application entry point.
Receives log/metric/event data from K8s agents, runs ML analysis,
predicts incidents, performs RCA, and triggers alerts.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router as api_router
from app.core.config import settings
from app.core.database import init_db, close_db
from app.core.redis_client import init_redis, close_redis
from app.services.anomaly_detector import AnomalyDetector
from app.services.incident_predictor import IncidentPredictor
from app.services.rca_engine import RCAEngine
from app.services.alert_dispatcher import AlertDispatcher
from app.grpc_server import start_grpc_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("Starting AI Observability Engine v1.0.0")

    # Initialize infrastructure
    await init_db()
    await init_redis()

    # Initialize AI services
    anomaly_detector = AnomalyDetector()
    await anomaly_detector.load_models()

    incident_predictor = IncidentPredictor()
    await incident_predictor.load_models()

    rca_engine = RCAEngine()
    alert_dispatcher = AlertDispatcher()

    # Store in app state for dependency injection
    app.state.anomaly_detector = anomaly_detector
    app.state.incident_predictor = incident_predictor
    app.state.rca_engine = rca_engine
    app.state.alert_dispatcher = alert_dispatcher

    # Start gRPC server for agent communication
    grpc_task = asyncio.create_task(
        start_grpc_server(
            port=settings.GRPC_PORT,
            anomaly_detector=anomaly_detector,
            incident_predictor=incident_predictor,
            rca_engine=rca_engine,
            alert_dispatcher=alert_dispatcher,
        )
    )

    logger.info(f"gRPC server starting on port {settings.GRPC_PORT}")
    logger.info(f"HTTP API starting on port {settings.HTTP_PORT}")

    yield

    # Shutdown
    logger.info("Shutting down AI Engine...")
    grpc_task.cancel()
    await close_redis()
    await close_db()
    logger.info("AI Engine stopped")


app = FastAPI(
    title="AI Observability Platform",
    description="AI-powered Kubernetes observability with proactive incident detection and RCA",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "ai-engine"}


@app.get("/ready")
async def ready():
    return {"status": "ready"}
