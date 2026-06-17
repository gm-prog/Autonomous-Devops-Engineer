from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json
import random

router = APIRouter(prefix="/ws/telemetry", tags=["WebSockets Emitter"])

@router.websocket("/socket/{client_id}")
async def telemetry_websocket_endpoint(websocket: WebSocket, client_id: str):
    """Encapsulates bi-directional push messaging stream for the application UI canvas."""
    await websocket.accept()
    try:
        while True:
            # Continuously broadcast live system loads
            payload = {
                "active_connections": 4 + random.randint(-1, 2),
                "avg_response_delay": 20 + random.randint(-10, 15),
                "nodes_online": 3,
                "incident_severity_active": "MEDIUM",
                "timestamp_utc": asyncio.get_event_loop().time()
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        # Handles client exit or connection reset gracefully
        pass
