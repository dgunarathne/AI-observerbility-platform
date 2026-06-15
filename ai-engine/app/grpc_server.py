"""
gRPC server that receives data from K8s agents.
Uses grpc.aio for async Python support.
"""

import json
import logging
from concurrent import futures

import grpc
import grpc.aio

from app.services.alert_dispatcher import AlertDispatcher
from app.services.anomaly_detector import AnomalyDetector
from app.services.incident_predictor import IncidentPredictor
from app.services.ingestion_service import IngestionService
from app.services.rca_engine import RCAEngine

logger = logging.getLogger(__name__)

# ─── Minimal gRPC service descriptor ────────────────────────────────────────
# Until proto is compiled, we use a generic bytes servicer approach.
# The agent sends JSON-encoded payloads as raw bytes.

OBSERVABILITY_SERVICE_FULL_NAME = "ai.ObservabilityService"


class ObservabilityServicer:
    """Handles IngestLogs, IngestMetrics, IngestEvents RPCs."""

    def __init__(self, ingestion_service: IngestionService):
        self.ingestion = ingestion_service

    async def IngestLogs(self, request, context):
        try:
            entries = json.loads(request)
            await self.ingestion.ingest_logs(entries)
        except Exception as e:
            logger.error("IngestLogs error: %s", e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
        return b"{}"

    async def IngestMetrics(self, request, context):
        try:
            entries = json.loads(request)
            await self.ingestion.ingest_metrics(entries)
        except Exception as e:
            logger.error("IngestMetrics error: %s", e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
        return b"{}"

    async def IngestEvents(self, request, context):
        try:
            entries = json.loads(request)
            await self.ingestion.ingest_events(entries)
        except Exception as e:
            logger.error("IngestEvents error: %s", e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
        return b"{}"


async def start_grpc_server(
    port: int,
    anomaly_detector: AnomalyDetector,
    incident_predictor: IncidentPredictor,
    rca_engine: RCAEngine,
    alert_dispatcher: AlertDispatcher,
):
    ingestion = IngestionService(
        anomaly_detector=anomaly_detector,
        incident_predictor=incident_predictor,
        rca_engine=rca_engine,
        alert_dispatcher=alert_dispatcher,
    )

    servicer = ObservabilityServicer(ingestion)

    server = grpc.aio.server()

    # Register a generic handler for our service
    from grpc import GenericRpcHandler, unary_unary_rpc_method_handler

    handlers = {
        "IngestLogs": unary_unary_rpc_method_handler(servicer.IngestLogs),
        "IngestMetrics": unary_unary_rpc_method_handler(servicer.IngestMetrics),
        "IngestEvents": unary_unary_rpc_method_handler(servicer.IngestEvents),
    }

    from grpc import method_service_name, ServiceRpcHandlers
    server.add_generic_rpc_handlers(
        [GenericMethodHandler(OBSERVABILITY_SERVICE_FULL_NAME, handlers)]
    )

    listen_addr = f"[::]:{port}"
    server.add_insecure_port(listen_addr)
    await server.start()
    logger.info("gRPC server listening on %s", listen_addr)

    try:
        await server.wait_for_termination()
    except Exception:
        await server.stop(5)


class GenericMethodHandler(grpc.ServiceRpcHandlers):
    """Simple passthrough to named method handlers."""

    def __init__(self, service_name: str, handlers: dict):
        self._service_name = service_name
        self._handlers = handlers

    def service_name(self):
        return self._service_name

    def service(self, handler_call_details):
        method = handler_call_details.method.split("/")[-1]
        return self._handlers.get(method)
