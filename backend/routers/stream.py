"""
PANOPTES — WebSocket live stream router
Broadcasts new session/alert events to all connected dashboard clients.
"""
import asyncio
import json
import logging
from typing import Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["stream"])
logger = logging.getLogger("panoptes.stream")

# Connected WebSocket clients
_clients: Set[WebSocket] = set()


async def broadcast(event: dict):
    """Send an event to all connected WebSocket clients."""
    disconnected = set()
    message = json.dumps(event)
    for ws in _clients:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.add(ws)
    _clients.difference_update(disconnected)


@router.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await websocket.accept()
    _clients.add(websocket)
    logger.info("WebSocket client connected. Total: %d", len(_clients))
    try:
        while True:
            # Keep connection alive; server pushes events via broadcast()
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        _clients.discard(websocket)
        logger.info("WebSocket client disconnected. Total: %d", len(_clients))
    except Exception:
        _clients.discard(websocket)
