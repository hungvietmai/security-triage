"""A store module loaded lazily: its root is computed when it is first imported."""

import tempfile
import uuid
from pathlib import Path

STORE = Path(tempfile.gettempdir()) / "cex-sessions"


def init():
    STORE.mkdir(parents=True, exist_ok=True)


def entry(sid):
    uuid.UUID(sid)
    return STORE / f"{sid}.json"
