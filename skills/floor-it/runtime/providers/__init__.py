#!/usr/bin/env python3
"""__init__.py — Runtime Provider Interface (RPI) Registry for `open-fleet`."""
from __future__ import annotations

import importlib
import os
import shutil
from typing import Any

from .base import (
    PROFILE_RANK,
    SUPPORTED_HARNESSES,
    SUPPORTED_PROVIDERS,
    ProviderError,
    RuntimeProvider,
    build_harness_command,
    check_monotonic_profile,
    env_get,
)
from .local_state import LocalStateStore
from .orca import OrcaProvider, resolve_orca_binary
from .posix import PosixWorktreeProvider, install_worktree_hooks

_PROVIDER_MODULES: dict[str, tuple[str, str]] = {
    "orca": (".orca", "OrcaProvider"),
    "posix": (".posix", "PosixWorktreeProvider"),
    "local-posix": (".posix", "PosixWorktreeProvider"),
    "superset": (".superset", "SupersetProvider"),
    "gastown": (".gastown", "GastownProvider"),
    "worktrunk": (".worktrunk", "WorktrunkProvider"),
    "openhands": (".openhands", "OpenHandsProvider"),
    "overstory": (".overstory", "OverstoryProvider"),
    "t3code": (".t3code", "T3CodeProvider"),
    "ao": (".ao", "ComposioAOProvider"),
    "jcode-swarm": (".jcode_swarm", "JCodeSwarmProvider"),
    "emdash": (".emdash", "EmdashProvider"),
    "vibe-kanban": (".vibe_kanban", "VibeKanbanProvider"),
    "paperclip": (".paperclip", "PaperclipProvider"),
    "multiclaude": (".multiclaude", "MulticlaudeProvider"),
}


def active_provider_name(env: dict[str, str] | None = None, system: str | None = None) -> str:
    """Resolve the active runtime provider name from `OPEN_FLEET_RUNTIME` / `ORCA_FLEET_RUNTIME`.

    Defaults to `'orca'` when neither variable is set so existing Orca workflows and tests
    preserve 100% backward compatibility. When `'auto'` is explicitly set, uses `'orca'` if
    the Orca binary is on PATH and otherwise falls back to `'posix'`.
    """
    raw = env_get("OPEN_FLEET_RUNTIME", "ORCA_FLEET_RUNTIME", env, "").lower()
    if not raw or raw == "orca":
        return "orca"
    if raw == "local-posix":
        return "posix"
    if raw == "auto":
        orca_bin = resolve_orca_binary(env, system)
        path_env = (os.environ if env is None else env).get("PATH")
        if shutil.which(orca_bin, path=path_env):
            return "orca"
        return "posix"
    if raw not in _PROVIDER_MODULES:
        raise ProviderError(
            "unknown_provider",
            f"unknown runtime provider {raw!r} (want auto|{'|'.join(SUPPORTED_PROVIDERS)})",
        )
    return raw


def get_provider(
    name: str | None = None,
    *,
    env: dict[str, str] | None = None,
    system: str | None = None,
    **kwargs: Any,
) -> RuntimeProvider:
    """Instantiate the requested `RuntimeProvider` adapter."""
    resolved = active_provider_name(env, system) if not name or name == "auto" else name.lower()
    if resolved == "local-posix":
        resolved = "posix"
    if resolved not in _PROVIDER_MODULES:
        raise ProviderError(
            "unknown_provider",
            f"unknown runtime provider {resolved!r} (want auto|{'|'.join(SUPPORTED_PROVIDERS)})",
        )
    mod_name, cls_name = _PROVIDER_MODULES[resolved]
    mod = importlib.import_module(mod_name, package=__package__)
    cls = getattr(mod, cls_name)
    if resolved == "orca":
        return cls(env=env, system=system, **kwargs)
    return cls(env=env, **kwargs)


__all__ = [
    "LocalStateStore",
    "OrcaProvider",
    "PosixWorktreeProvider",
    "PROFILE_RANK",
    "ProviderError",
    "RuntimeProvider",
    "SUPPORTED_HARNESSES",
    "SUPPORTED_PROVIDERS",
    "active_provider_name",
    "build_harness_command",
    "check_monotonic_profile",
    "env_get",
    "get_provider",
    "install_worktree_hooks",
    "resolve_orca_binary",
]
