"""open_fleet — Product shell for the open-fleet autonomous engineering fleet catalog.

Provides a zero-dependency (Python 3.11+ stdlib) unified CLI, MCP JSON-RPC 2.0 server,
host onboarding/setup wizard, intent-based mission router, live SQLite/event/merge-queue
state inspector, and Mission Control web dashboard on top of the verified open-fleet kernel.
"""

from pathlib import Path
import json


def find_catalog_root(start: str | Path | None = None) -> Path:
    """Locate the open-fleet catalog root (directory holding skills/, playbooks/, runtime/)."""
    import os

    candidates: list[Path] = []
    if start is not None:
        p = Path(start).expanduser().resolve()
        candidates.extend([p, *p.parents])
    for var in ("OPEN_FLEET_ROOT", "ORCA_FLEET_ROOT"):
        val = (os.environ.get(var) or "").strip()
        if val:
            candidates.append(Path(val).expanduser().resolve())
    here = Path(__file__).resolve().parent.parent
    candidates.append(here)
    cwd = Path.cwd().resolve()
    candidates.extend([cwd, *cwd.parents])
    seen: set[Path] = set()
    for cand in candidates:
        if cand in seen:
            continue
        seen.add(cand)
        if (cand / "skills").is_dir() and (cand / "playbooks").is_dir() and (cand / "runtime").is_dir():
            return cand
    return here


def catalog_version(root: Path | None = None) -> str:
    """Read the canonical catalog version from .claude-plugin/plugin.json."""
    base = root or find_catalog_root()
    plugin = base / ".claude-plugin" / "plugin.json"
    try:
        data = json.loads(plugin.read_text(encoding="utf-8"))
        ver = data.get("version")
        if isinstance(ver, str) and ver.strip():
            return ver.strip()
    except (OSError, ValueError):
        return "0.0.0"
    return "0.0.0"


__all__ = ["catalog_version", "find_catalog_root"]
