#!/usr/bin/env python3
"""orca.py — `stablyai/orca` RuntimeProvider implementation."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .base import ProviderError, RuntimeProvider, split_output_flag

LINUX_COMMAND = "orca-ide"
DEFAULT_COMMAND = "orca"
DEV_COMMAND = "orca-dev"


_ORCA_CLI_PATH = Path(__file__).resolve().parent.parent / "scripts" / "orca_cli.py"
_ORCA_CLI = None


def _orca_cli():
    """runtime/scripts/orca_cli.py, loaded by path once: it holds the ONE resolution (precedence
    and validation) of the CLI command, and imports nothing from this package at load time."""
    global _ORCA_CLI
    if _ORCA_CLI is None:
        spec = importlib.util.spec_from_file_location("open_fleet_orca_cli_policy", _ORCA_CLI_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _ORCA_CLI = mod
    return _ORCA_CLI


def resolve_orca_binary(env: dict[str, str] | None = None, system: str | None = None) -> str:
    """The Orca CLI binary per upstream `cli-resolution.md`, through orca_cli.resolve_orca: the
    same precedence (OPEN_FLEET_CLI_COMMAND, else ORCA_CLI_COMMAND) and the same one-executable
    rule as every other resolver (W4-15/W2-03 re-attack: this copy read ORCA_CLI_COMMAND first
    and checked nothing). A configured value that breaks the rule is ProviderError
    `invalid_cli_command`."""
    cli = _orca_cli()
    try:
        return cli.resolve_orca(os.environ if env is None else env, system)
    except cli.CliCommandError as exc:
        raise ProviderError("invalid_cli_command", str(exc)) from None


class OrcaProvider(RuntimeProvider):
    """RuntimeProvider backed by the `stablyai/orca` (`orca` / `orca-ide` / `orca-dev`) CLI."""

    name = "orca"

    def __init__(self, env: dict[str, str] | None = None, system: str | None = None):
        self.env = env
        self.system = system

    def binary(self) -> str:
        return resolve_orca_binary(self.env, self.system)

    def dispatch(self, argv: list[str], *, timeout: int = 120, env: dict[str, str] | None = None) -> dict[str, Any]:
        # Our `--json` goes where it is an option: before any bare `--`, never in place of a text
        # flag's value or an operand after `--` (W2-01, PR #720 review).
        options, tail = split_output_flag(argv)
        cmd = [self.binary(), *options, "--json", *tail]
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
