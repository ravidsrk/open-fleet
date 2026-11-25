#!/usr/bin/env python3
"""Build open-fleet wheel cleanly into a temp dir and smoke-test fresh-venv CLI & MCP install.

Proves end-to-end packaging without polluting the repository working tree:
1. Builds wheel from pyproject.toml in an isolated temp staging copy (zero build/ or *.egg-info/
   artifacts left in the repo).
2. Inspects the wheel archive: zero third-party Requires-Dist, ui_assets/index.html present,
   open-fleet and open-fleet-mcp console scripts registered.
3. Installs the wheel into a brand-new venv with --no-deps --no-index and runs live CLI and
   stdio JSON-RPC MCP checks from /tmp (outside the repository CWD).

Exit codes: 0 verified · 1 packaging or runtime verification failed.
"""
import sys

# W3-01: drop this script's own directory from sys.path before any other import.
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(argv, *, cwd, env=None, input_text=None, timeout=120):
    proc = subprocess.run(
        argv,
        cwd=str(cwd),
        env=env,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc


def verify_wheel(root=ROOT, *, keep_wheel_dir=None):
    """Build wheel in an isolated staging dir, validate archive contents, and test fresh-venv install."""
    root = Path(root).resolve()
    errors = []
    report = {
        "ok": False,
        "wheel": "",
        "files_in_wheel": 0,
        "requires_dist": [],
        "cli_version": "",
        "mcp_tools": 0,
        "mcp_resources": 0,
        "errors": errors,
    }

    with tempfile.TemporaryDirectory(prefix="open-fleet-wheel-check-") as tmp:
        tmp_path = Path(tmp)
        stage = tmp_path / "src"
        stage.mkdir()
        # Copy only packaging inputs so the live checkout never accumulates build/ or *.egg-info/.
        for fname in ("pyproject.toml", "README.md", "LICENSE"):
            shutil.copy2(root / fname, stage / fname)
        shutil.copytree(
            root / "open_fleet",
            stage / "open_fleet",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )

        out_dir = Path(keep_wheel_dir).resolve() if keep_wheel_dir else (tmp_path / "dist")
        out_dir.mkdir(parents=True, exist_ok=True)

        # Prefer offline setuptools wheel build via pip --no-build-isolation when available,
        # falling back to standard isolated pip wheel (for Python 3.13+ envs without bundled
        # setuptools) or uv build --wheel.
        pip_wheel = _run(
            [sys.executable, "-m", "pip", "wheel", "--no-build-isolation", "--no-deps", str(stage), "-w", str(out_dir)],
            cwd=tmp_path,
        )
        if pip_wheel.returncode != 0:
            pip_iso = _run(
                [sys.executable, "-m", "pip", "wheel", "--no-deps", str(stage), "-w", str(out_dir)],
                cwd=tmp_path,
            )
            if pip_iso.returncode != 0:
                uv_bin = shutil.which("uv")
                if uv_bin:
                    uv_res = _run([uv_bin, "build", "--wheel", "--out-dir", str(out_dir), str(stage)], cwd=tmp_path)
                    if uv_res.returncode != 0:
                        errors.append(f"wheel build failed (pip and uv): {uv_res.stderr.strip()[:400]}")
                        return report
                else:
                    errors.append(f"wheel build failed: {pip_iso.stderr.strip()[:400]}")
                    return report

        wheels = sorted(out_dir.glob("open_fleet-*.whl"))
        if len(wheels) != 1:
            errors.append(f"expected 1 wheel in {out_dir}, found {[w.name for w in wheels]}")
            return report
        wheel = wheels[0]
        report["wheel"] = wheel.name

        # 1. Inspect wheel archive contents and metadata.
        with zipfile.ZipFile(wheel, "r") as zf:
            names = zf.namelist()
            report["files_in_wheel"] = len(names)
            for required in (
                "open_fleet/__init__.py",
                "open_fleet/cli.py",
                "open_fleet/mcp_server.py",
                "open_fleet/sessions.py",
                "open_fleet/solo_review.py",
                "open_fleet/ci_action.py",
                "open_fleet/readiness.py",
                "open_fleet/ui_server.py",
                "open_fleet/ui_assets/index.html",
            ):
                if required not in names:
                    errors.append(f"missing {required} inside {wheel.name}")
            meta_files = [n for n in names if n.endswith(".dist-info/METADATA")]
            if not meta_files:
                errors.append("missing METADATA in wheel")
            else:
                meta_text = zf.read(meta_files[0]).decode("utf-8", errors="replace")
                reqs = [ln.split(":", 1)[1].strip() for ln in meta_text.splitlines() if ln.startswith("Requires-Dist:")]
                report["requires_dist"] = reqs
                if reqs:
                    errors.append(f"expected zero third-party Requires-Dist, found {reqs}")
            ep_files = [n for n in names if n.endswith(".dist-info/entry_points.txt")]
            if not ep_files:
                errors.append("missing entry_points.txt in wheel")
            else:
                ep_text = zf.read(ep_files[0]).decode("utf-8", errors="replace")
                for script_name in ("open-fleet =", "open-fleet-mcp ="):
                    if script_name not in ep_text:
                        errors.append(f"missing console script {script_name!r} in entry_points.txt")

        if errors:
            return report

        # 2. Install into a fresh isolated venv and run from tmp_path (outside repo CWD).
        venv_dir = tmp_path / "venv"
        venv.create(venv_dir, with_pip=True, clear=True)
        bin_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
        venv_py = bin_dir / "python"
        inst = _run([str(venv_py), "-m", "pip", "install", "--no-deps", "--no-index", str(wheel)], cwd=tmp_path)
        if inst.returncode != 0:
            errors.append(f"fresh-venv wheel install failed: {inst.stderr.strip()[:400]}")
            return report

        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["OPEN_FLEET_ROOT"] = str(root)
        env["OPEN_FLEET_RUNTIME"] = "auto"

        of_bin = str(bin_dir / "open-fleet")
        mcp_bin = str(bin_dir / "open-fleet-mcp")

        ver = _run([of_bin, "--version"], cwd=tmp_path, env=env)
        if ver.returncode != 0 or not ver.stdout.strip().startswith("open-fleet "):
            errors.append(f"open-fleet --version failed: rc={ver.returncode} out={ver.stdout!r} err={ver.stderr!r}")
        else:
            report["cli_version"] = ver.stdout.strip()

        for args in (
            ["route", "review PR #7", "--json"],
            ["session", "benchmark", "--json"],
            ["readiness", "--json"],
        ):
            res = _run([of_bin, *args], cwd=tmp_path, env=env)
            if res.returncode != 0:
                errors.append(f"open-fleet {' '.join(args)} failed: rc={res.returncode} err={res.stderr[:200]}")

        # 3. Live JSON-RPC 2.0 MCP stdio handshake from outside repo CWD.
        rpc_in = (
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}\n'
            '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
            '{"jsonrpc":"2.0","id":3,"method":"resources/list"}\n'
        )
        mcp_res = _run([mcp_bin], cwd=tmp_path, env=env, input_text=rpc_in)
        if mcp_res.returncode != 0:
            errors.append(f"open-fleet-mcp failed: rc={mcp_res.returncode} err={mcp_res.stderr[:200]}")
        else:
            lines = [json.loads(ln) for ln in mcp_res.stdout.splitlines() if ln.strip()]
            if len(lines) != 3:
                errors.append(f"expected 3 JSON-RPC responses from open-fleet-mcp, got {len(lines)}")
            else:
                tools = lines[1].get("result", {}).get("tools", [])
                resources = lines[2].get("result", {}).get("resources", [])
                report["mcp_tools"] = len(tools)
                report["mcp_resources"] = len(resources)
                if len(tools) < 19:
                    errors.append(f"expected >=19 MCP tools, got {len(tools)}")
                if len(resources) < 10:
                    errors.append(f"expected >=10 MCP resources, got {len(resources)}")

        # 4. Verify UI asset loads cleanly from installed wheel package.
        ui_res = _run(
            [str(venv_py), "-c",
             "from open_fleet.ui_server import MissionControlApp; "
             "html = MissionControlApp().index_html(); "
             "assert b'open-fleet Mission Control' in html and len(html) > 20000"],
            cwd=tmp_path,
            env=env,
        )
        if ui_res.returncode != 0:
            errors.append(f"wheel ui_assets load check failed: {ui_res.stderr.strip()[:200]}")

    report["ok"] = len(errors) == 0
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT), help="repository root directory")
    parser.add_argument("--out-dir", default=None, help="optional directory to keep the built wheel")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    args = parser.parse_args(argv)

    rep = verify_wheel(Path(args.root), keep_wheel_dir=args.out_dir)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        if rep["ok"]:
            print(
                f"verify-wheel: OK — {rep['wheel']} ({rep['files_in_wheel']} files, 0 deps, "
                f"{rep['cli_version']}, {rep['mcp_tools']} MCP tools, {rep['mcp_resources']} resources)"
            )
        else:
            for err in rep["errors"]:
                print(f"FAIL: {err}", file=sys.stderr)
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
