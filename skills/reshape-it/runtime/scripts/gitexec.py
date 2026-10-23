#!/usr/bin/env python3
"""One git resolution rule and one hardened git environment for the read-side tools.

inventory.py, evidence-run.py, floor_guard.py and preflight.py read repositories they
do not own — a worker's worktree, a target project, a run's
directory — and each used to spawn a bare ``git``: re-resolved against PATH on every
call (a later PATH entry, or a worker-planted ``./bin/git`` on it, answers instead),
under the caller's whole git environment and the graded repo's own config. A
repo-local ``core.fsmonitor`` is a command git runs on ``status``/``diff``; a
``refs/replace/`` ref silently swaps the object a blob hash is taken from.

``GIT`` is resolved ONCE, at import, to an absolute path (the run_report.py /
verify.py rule, h409 R2). ``argv(*args)`` is the argv head every call uses; with no
git on PATH it raises ``GitAbsent`` — a FileNotFoundError, so the callers' existing
``except OSError`` handlers keep their could-not-run exits, now with a message that
names the cause.

``env()`` is the caller's environment plus the floor verify.py's git_env applies
(h409 B4/B5) and replacement objects off:

- ``GIT_NO_REPLACE_OBJECTS=1`` — hash and diff the objects the commit names;
- ``GIT_CONFIG_GLOBAL=/dev/null`` + ``GIT_CONFIG_NOSYSTEM=1`` — no ~/.gitconfig or
  system file steering a read;
- ``GIT_CONFIG_COUNT`` pairs (command-line precedence, above repo-local config):
  ``core.fsmonitor=false``, ``protocol.ext.allow=never``, and ``safe.directory=*``
  in place of the one legitimate use of the dropped global file (CI ownership belts);
- ``GIT_TERMINAL_PROMPT=0``; ``GIT_EXTERNAL_DIFF`` and any inherited
  ``GIT_CONFIG_KEY_n``/``VALUE_n`` pairs are dropped so they cannot shadow these.

Unlike verify.py the rest of the environment passes: these tools are not a verifier
stating facts against a worker, and a coordinator's locale, HOME and PATH stay theirs.
diff_scope.py inlines the same floor rather than importing this module: verify.py loads
diff_scope by path, so a sibling it imported would join the signed verifier toolchain
(verify._Transcript.TOOLCHAIN and run_report.TOOLCHAIN_FILES).

Library only: no CLI, no exit codes.
"""
import os
import shutil


class GitAbsent(FileNotFoundError):
    """No git on PATH when this module was imported."""


_found = shutil.which("git")
GIT = os.path.abspath(_found) if _found else None

HARDENED = {
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_COUNT": "3",
    "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "false",
    "GIT_CONFIG_KEY_1": "protocol.ext.allow", "GIT_CONFIG_VALUE_1": "never",
    "GIT_CONFIG_KEY_2": "safe.directory", "GIT_CONFIG_VALUE_2": "*",
}


def argv(*args):
    """[absolute git, *args]; raises GitAbsent when git was not on PATH at import."""
    if GIT is None:
        raise GitAbsent("git is not on PATH (resolved once, at startup)")
    return [GIT, *args]


def env(base=None):
    """The hardened environment for one git child (see module docstring)."""
    out = {k: v for k, v in (os.environ if base is None else base).items()
           if k != "GIT_EXTERNAL_DIFF"
           and not k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))}
    out.update(HARDENED)
    return out
