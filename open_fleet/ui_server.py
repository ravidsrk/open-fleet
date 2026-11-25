"""Zero-dependency HTTP + SSE server for open-fleet Mission Control UI."""

import json
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from open_fleet import find_catalog_root
from open_fleet.catalog import (
    catalog_overview,
    certification_summary,
    get_mission,
    list_missions,
    load_one_way_doors,
    load_retained_runs,
    route_intent,
)
from open_fleet.ci_action import render_workflow_snippet
from open_fleet.mcp_server import (
    OpenFleetMCPServer,
    run_inert_first_run,
    run_negative_control_demo,
)
from open_fleet.readiness import readiness_report, run_certification_check, run_negative_probes
from open_fleet.sessions import (
    advance_session,
    approve_gate,
    benchmark_progressive_savings,
    build_phase_packet,
    list_sessions,
    load_session,
    start_session,
)
from open_fleet.setup import HOST_PROFILES, build_mcp_config, doctor, setup_host
from open_fleet.solo_review import run_solo_review
from open_fleet.state import read_decisions, read_workspace_status

MAX_POST_BYTES = 16 * 1024


class MissionControlApp:
    """Testable application backend for the Mission Control HTTP server."""

    def __init__(self, root: Path | None = None, repo: Path | None = None) -> None:
        self.root = (root or find_catalog_root()).resolve()
        self.repo = (repo or self.root).resolve()
        self.mcp = OpenFleetMCPServer(root=self.root, repo=self.repo)
        self._demo_lock = threading.Lock()
        self._index_path = Path(__file__).resolve().parent / "ui_assets" / "index.html"

    def index_html(self) -> bytes:
        return self._index_path.read_bytes()

    def handle_get(self, path: str, query: dict[str, list[str]]) -> tuple[int, str, bytes]:
        if path in ("/", "/index.html"):
            return HTTPStatus.OK, "text/html; charset=utf-8", self.index_html()
        if path == "/api/health":
            return self._json(HTTPStatus.OK, {"ok": True, "root": str(self.root), "repo": str(self.repo)})
        if path == "/api/overview":
            return self._json(
                HTTPStatus.OK,
                {
                    "catalog": catalog_overview(self.root),
                    "doctor": doctor(self.root),
                    "workspace": read_workspace_status(self.repo),
                    "one_way_doors": load_one_way_doors(self.root),
                    "mcp_tools": [{"name": t["name"], "description": t["description"]} for t in self.mcp.tool_definitions()],
                    "mcp_resources": self.mcp.resource_definitions(),
                },
            )
        if path == "/api/doctor":
            runtime = (query.get("runtime") or [None])[0]
            return self._json(HTTPStatus.OK, doctor(self.root, runtime=runtime))
        if path == "/api/missions":
            proof = (query.get("proof") or [None])[0]
            category = (query.get("category") or [None])[0]
            return self._json(HTTPStatus.OK, {"missions": list_missions(self.root, proof=proof, category=category)})
        if path.startswith("/api/missions/"):
            name = unquote(path.removeprefix("/api/missions/")).strip()
            found = get_mission(name, self.root)
            if found is None:
                return self._json(HTTPStatus.NOT_FOUND, {"error": f"unknown mission: {name}"})
            return self._json(HTTPStatus.OK, found)
        if path == "/api/route":
            goal = (query.get("q") or [""])[0]
            top_raw = (query.get("top") or ["5"])[0]
            try:
                top_k = max(1, min(10, int(top_raw)))
            except ValueError:
                top_k = 5
            return self._json(HTTPStatus.OK, route_intent(goal, self.root, top_k=top_k))
        if path == "/api/certification":
            return self._json(HTTPStatus.OK, certification_summary(self.root))
        if path == "/api/runs":
            return self._json(HTTPStatus.OK, {"runs": load_retained_runs(self.root)})
        if path == "/api/state":
            return self._json(HTTPStatus.OK, read_workspace_status(self.repo))
        if path == "/api/decisions":
            return self._json(HTTPStatus.OK, read_decisions(self.repo, limit=100))
        if path == "/api/sessions":
            return self._json(
                HTTPStatus.OK,
                {
                    "sessions": list_sessions(repo=self.repo),
                    "benchmark": benchmark_progressive_savings(self.root),
                },
            )
        if path.startswith("/api/sessions/"):
            sid = unquote(path.removeprefix("/api/sessions/")).strip()
            try:
                st = load_session(sid, repo=self.repo)
            except (ValueError, FileNotFoundError) as exc:
                return self._json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
            return self._json(HTTPStatus.OK, {"session": st, "packet": build_phase_packet(st, self.root)})
        if path == "/api/readiness":
            return self._json(HTTPStatus.OK, readiness_report(self.root))
        if path == "/api/ci-workflow":
            base_branch = (query.get("base") or ["main"])[0]
            inc_manifest = (query.get("manifest") or ["false"])[0].lower() in ("1", "true", "yes")
            return self._json(
                HTTPStatus.OK,
                {
                    "action_path": ".github/actions/open-fleet-verify/action.yml",
                    "workflow_yaml": render_workflow_snippet(base_branch=base_branch, include_manifest=inc_manifest),
                },
            )
        if path == "/api/setup/preview":
            host = (query.get("host") or ["claude"])[0]
            runtime = (query.get("runtime") or ["auto"])[0]
            if host not in HOST_PROFILES:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": f"unknown host: {host}"})
            if runtime not in ("auto", "posix", "orca", "overstory", "t3code", "superset", "worktrunk"):
                runtime = "auto"
            mcp_cfg = build_mcp_config(host, self.root, runtime=runtime)
            try:
                preview = setup_host(
                    host,
                    root=self.root,
                    runtime=runtime,
                    wire_hooks=(host == "claude"),
                    wire_mcp=True,
                    dry_run=True,
                    force=True,
                )
            except (RuntimeError, ValueError, OSError) as exc:
                preview = {"error": str(exc), "actions": []}
            return self._json(
                HTTPStatus.OK,
                {
                    "host": host,
                    "profile": HOST_PROFILES[host],
                    "runtime": runtime,
                    "cli_command": f"open-fleet setup --host {host} --runtime {runtime}" + (" --wire-hooks" if host == "claude" else "") + " --wire-mcp",
                    "mcp": mcp_cfg,
                    "preview": preview,
                },
            )
        return self._json(HTTPStatus.NOT_FOUND, {"error": f"not found: {path}"})

    def handle_post(self, path: str, body: bytes) -> tuple[int, str, bytes]:
        if len(body) > MAX_POST_BYTES:
            return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request body too large"})
        try:
            payload = json.loads(body.decode("utf-8")) if body.strip() else {}
        except (UnicodeDecodeError, ValueError):
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"})
        if not isinstance(payload, dict):
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"})

        if path == "/api/route":
            goal = str(payload.get("goal") or "")
            top_k = int(payload.get("top_k") or 5) if isinstance(payload.get("top_k"), int) else 5
            return self._json(HTTPStatus.OK, route_intent(goal, self.root, top_k=max(1, min(10, top_k))))

        if path == "/api/demo/negative-control":
            if not self._demo_lock.acquire(blocking=False):
                return self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "a verification demo is already running"})
            try:
                res = run_negative_control_demo(self.root)
            finally:
                self._demo_lock.release()
            return self._json(HTTPStatus.OK, res)

        if path == "/api/demo/first-run":
            profile = str(payload.get("profile") or "ro")
            if profile not in ("ro", "rw"):
                return self._json(HTTPStatus.BAD_REQUEST, {"error": "profile must be 'ro' or 'rw'"})
            if not self._demo_lock.acquire(blocking=False):
                return self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "a verification demo is already running"})
            try:
                res = run_inert_first_run(self.root, profile=profile)
            finally:
                self._demo_lock.release()
            return self._json(HTTPStatus.OK, res)

        if path == "/api/preflight":
            mission = str(payload.get("mission") or "review-it").strip()
            runtime = str(payload.get("runtime") or "posix").strip()
            valid_missions = {m["name"] for m in list_missions(self.root)}
            if mission not in valid_missions:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": f"unknown mission: {mission}"})
            if runtime not in ("auto", "posix", "orca", "overstory", "t3code", "superset", "worktrunk"):
                return self._json(HTTPStatus.BAD_REQUEST, {"error": f"unsupported runtime: {runtime}"})
            tool_out = self.mcp.call_tool(
                "fleet_preflight",
                {"mission": mission, "mode": "readonly", "runtime": runtime, "repo": str(self.repo)},
            )
            return self._json(HTTPStatus.OK, tool_out["structuredContent"])

        if path == "/api/sessions":
            mission = str(payload.get("mission") or "").strip()
            goal = str(payload.get("goal") or "").strip()
            base = str(payload.get("base") or "").strip()
            runtime = str(payload.get("runtime") or "auto").strip()
            try:
                res = start_session(mission, goal, root=self.root, repo=self.repo, base_branch=base, runtime=runtime)
            except (ValueError, OSError) as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return self._json(HTTPStatus.OK, res)

        if path == "/api/sessions/approve":
            try:
                res = approve_gate(
                    str(payload.get("session_id") or ""),
                    str(payload.get("gate") or ""),
                    str(payload.get("actor") or ""),
                    str(payload.get("rationale") or ""),
                    contract_digest=str(payload.get("contract_digest") or ""),
                    root=self.root,
                    repo=self.repo,
                )
            except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return self._json(HTTPStatus.OK, res)

        if path == "/api/sessions/advance":
            receipt = payload.get("receipt") if isinstance(payload.get("receipt"), dict) else None
            try:
                res = advance_session(
                    str(payload.get("session_id") or ""),
                    receipt=receipt,
                    terminal_state=str(payload.get("terminal_state") or ""),
                    root=self.root,
                    repo=self.repo,
                )
            except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return self._json(HTTPStatus.OK, res)

        if path == "/api/solo-review":
            base_ref = str(payload.get("base") or "origin/main").strip()
            builder = str(payload.get("builder") or "").strip()
            nc_cmd = str(payload.get("nc_command") or "").strip()
            lighting = str(payload.get("lighting") or "auto").strip()
            try:
                res = run_solo_review(
                    base=base_ref,
                    root=self.root,
                    repo=self.repo,
                    builder_harness=builder,
                    nc_command=nc_cmd,
                    lighting=lighting,
                )
            except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return self._json(HTTPStatus.OK, res)

        if path == "/api/floor-check":
            base_ref = str(payload.get("base") or "origin/main").strip()
            tool_out = self.mcp.call_tool("fleet_floor_check", {"base": base_ref, "repo": str(self.repo)})
            return self._json(HTTPStatus.OK, tool_out["structuredContent"])

        if path == "/api/readiness/cert-check":
            if not self._demo_lock.acquire(blocking=False):
                return self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "a verification task is already running"})
            try:
                res = run_certification_check(self.root)
            finally:
                self._demo_lock.release()
            return self._json(HTTPStatus.OK, res)

        if path == "/api/readiness/probes":
            if not self._demo_lock.acquire(blocking=False):
                return self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "a verification task is already running"})
            try:
                res = run_negative_probes(self.root)
            finally:
                self._demo_lock.release()
            return self._json(HTTPStatus.OK, res)

        return self._json(HTTPStatus.NOT_FOUND, {"error": f"not found: {path}"})

    @staticmethod
    def _json(status: int, obj: Any) -> tuple[int, str, bytes]:
        return status, "application/json; charset=utf-8", (json.dumps(obj) + "\n").encode("utf-8")


def make_handler(app: MissionControlApp) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/events/stream":
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                try:
                    snap = {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "workspace": read_workspace_status(app.repo)["runtime_state"]["summary"],
                    }
                    self.wfile.write(f"event: snapshot\ndata: {json.dumps(snap)}\n\n".encode("utf-8"))
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                return

            status, ctype, payload = app.handle_get(parsed.path, parse_qs(parsed.query))
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                length = -1
            if length < 0 or length > MAX_POST_BYTES:
                status, ctype, payload = app._json(HTTPStatus.BAD_REQUEST, {"error": "invalid Content-Length"})
            else:
                body = self.rfile.read(length) if length > 0 else b""
                status, ctype, payload = app.handle_post(parsed.path, body)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(payload)

    return Handler


def create_server(
    *,
    root: Path | None = None,
    repo: Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> ThreadingHTTPServer:
    app = MissionControlApp(root=root, repo=repo)
    server = ThreadingHTTPServer((host, port), make_handler(app))
    server.daemon_threads = True
    return server


def serve_ui(
    *,
    root: Path | None = None,
    repo: Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> int:
    server = create_server(root=root, repo=repo, host=host, port=port)
    actual_port = server.server_address[1]
    print(f"open-fleet Mission Control listening on http://{host}:{actual_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(serve_ui())
