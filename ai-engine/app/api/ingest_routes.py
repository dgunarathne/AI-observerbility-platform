"""
HTTP ingest shim — allows the demo runner (and external tools)
to POST data directly over HTTP instead of gRPC.
Maps to the same IngestionService used by the gRPC server.
"""

from typing import List, Any
from fastapi import APIRouter, Request, HTTPException

ingest_router = APIRouter(prefix="/ingest", tags=["ingest"])


def _get_ingestion(request: Request):
    """Retrieve the shared IngestionService from app state."""
    svc = getattr(request.app.state, "ingestion_service", None)
    if svc is None:
        raise HTTPException(503, "Ingestion service not ready")
    return svc


@ingest_router.post("/logs", status_code=204)
async def ingest_logs(request: Request, body: List[Any]):
    await _get_ingestion(request).ingest_logs(body)


@ingest_router.post("/events", status_code=204)
async def ingest_events(request: Request, body: List[Any]):
    await _get_ingestion(request).ingest_events(body)


@ingest_router.post("/app-health", status_code=204)
async def ingest_app_health(request: Request, body: List[Any]):
    await _get_ingestion(request).ingest_app_health(body)


@ingest_router.post("/cluster-health", status_code=204)
async def ingest_cluster_health(request: Request, body: Any):
    # Accept both single object and list; normalize to single
    if isinstance(body, list):
        for item in body:
            await _get_ingestion(request).ingest_cluster_health(item)
    else:
        await _get_ingestion(request).ingest_cluster_health(body)


@ingest_router.post("/security-threats", status_code=204)
async def ingest_security_threats(request: Request, body: List[Any]):
    await _get_ingestion(request).ingest_security_threats(body)


@ingest_router.get("/", include_in_schema=False)
async def ingest_root():
    return {"endpoints": ["/logs", "/events", "/app-health", "/cluster-health", "/security-threats"]}
