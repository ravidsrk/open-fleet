#!/usr/bin/env python3
"""orca.py — `stablyai/orca` RuntimeProvider implementation."""
from __future__ import annotations

import json
import os
import platform
import subprocess
from typing import Any

from .base import ProviderError, RuntimeProvider, env_get

LINUX_COMMAND = "orca-ide"
DEFAULT_COMMAND = "orca"
DEV_COMMAND = "orca-dev"


def resolve_orca_binary(env: dict[str, str] | None = None, system: str | None = None) -> str:
    """Resolve the Orca CLI binary name per upstream `cli-resolution.md`."""
    source = os.environ if env is None else env
    configured = env_get("ORCA_CLI_COMMAND", "OPEN_FLEET_CLI_COMMAND", source, "")
    if configured:
        return configured
    if (source.get("ORCA_DEV_REPO_ROOT") or "").strip():
        return DEV_COMMAND
    sys_name = platform.system() if system is None else system
    if sys_name == "Linux":
        return LINUX_COMMAND
    return DEFAULT_COMMAND


class OrcaProvider(RuntimeProvider):
    """RuntimeProvider backed by the `stablyai/orca` (`orca` / `orca-ide` / `orca-dev`) CLI."""

    name = "orca"

    def __init__(self, env: dict[str, str] | None = None, system: str | None = None):
        self.env = env
        self.system = system

    def binary(self) -> str:
        return resolve_orca_binary(self.env, self.system)

    def dispatch(self, argv: list[str], *, timeout: int = 120, env: dict[str, str] | None = None) -> dict[str, Any]:
        cmd = [self.binary(), *[a for a in argv if a != "--json"], "--json"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env if env is not None else self.env,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProviderError("runtime_unreachable", f"could not run orca: {exc}")
        try:
            doc = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise ProviderError("invalid_json", f"orca returned unreadable JSON (exit {proc.returncode})")
        if not isinstance(doc, dict):
            raise ProviderError("invalid_envelope", "orca returned a non-object envelope")
        result = doc.get("result") if isinstance(doc.get("result"), dict) else {}
        err = doc.get("error") or result.get("error")
        if err:
            code = err.get("code") if isinstance(err, dict) else str(err)
            msg = err.get("message", str(code)) if isinstance(err, dict) else str(code)
            data = err.get("data") if isinstance(err, dict) and isinstance(err.get("data"), dict) else {}
            raise ProviderError(str(code), msg, data)
        return result
