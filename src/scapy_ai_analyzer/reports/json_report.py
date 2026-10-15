"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models.session import AnalysisSession


def render_json(session: AnalysisSession, indent: int = 2) -> str:
    """Serialize a session to JSON text."""
    return json.dumps(session.to_dict(), indent=indent, ensure_ascii=False, default=str)


def write_json_report(session: AnalysisSession, output_dir: str | Path) -> Path:
    """Write ``report.json`` into ``output_dir`` and return its path."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.json"
    path.write_text(render_json(session), encoding="utf-8")
    return path


def read_json_report(path: str | Path) -> AnalysisSession:
    """Load a session previously written by :func:`write_json_report`."""
    data: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
    return AnalysisSession.from_dict(data)
