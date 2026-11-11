"""Disposable repositories for the merge-queue tests (#599): a bare "remote", a worker clone that
authors unit branches, a conductor clone, and a fake GitHub (fake_gh.py) over the bare repo.

Fixture tier, stated plainly: GitHub here is fake_gh.py and nothing leaves the machine. Global and
system git config are cut off (GIT_CONFIG_GLOBAL=/dev/null), so a host's signing or hooks never
reach these repositories.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCRIPT = ROOT / "runtime" / "scripts" / "merge_queue.py"
BASE, DEFAULT = "integration", "main"
# The gh lane's repository. Its conductor clone names it by a GitHub-style URL that git rewrites
# (`url.<bare>.insteadOf`) to the bare repo, so the queue derives the same identity GitHub uses.
SLUG = "github.invalid/fleet/repo"
IDENTITY = {"GIT_AUTHOR_NAME": "Fleet Maintainer", "GIT_AUTHOR_EMAIL": "maintainer@fleet.invalid",
            "GIT_COMMITTER_NAME": "Fleet Maintainer", "GIT_COMMITTER_EMAIL": "maintainer@fleet.invalid"}


def load_module(path: Path = SCRIPT, name: str = "merge_queue_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class World:
    def __init__(self, tmp: Path, mode: str = "gh", script: Path = SCRIPT):
        self.tmp, self.mode, self.script = Path(tmp), mode, Path(script)
        self.bare = self.tmp / "remote.git"
        self.worker = self.tmp / "worker"
        self.conductor = self.tmp / "conductor"
        self.state_file = self.tmp / "gh-state.json"
        self.log_file = self.tmp / "gh-merges.jsonl"
        self.db = self.tmp / "state" / "merge-queue.db"
        self.ledger = self.tmp / "egress.jsonl"
        bindir = self.tmp / "bin"
        bindir.mkdir()
        gh = bindir / "gh"
        gh.write_text(f"#!/bin/sh\nexec {sys.executable} {HERE / 'fake_gh.py'} \"$@\"\n", encoding="utf-8")
        gh.chmod(0o755)
        self.env = {
            **{k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "OPEN_FLEET_", "ORCA_", "MQ_"))},
            **IDENTITY,
            "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(self.tmp),
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "FAKE_GH_STATE": str(self.state_file), "FAKE_GH_LOG": str(self.log_file),
            "OPEN_FLEET_MERGE_QUEUE_DB": str(self.db), "OPEN_FLEET_EGRESS_LEDGER": str(self.ledger),
        }
        # On CI runners without bubblewrap, unprivileged userns, or hidepid=2/invisible, supply an
        # explicit fixture sandbox command so QueueError('sandbox_unavailable') remains fail-closed
        # in production while disposable World gate tests still run cleanly.
        mq_mod = load_module(self.script)
        if not mq_mod.MergeQueue._has_native_gate_isolation():
            sbx = bindir / "mq-fixture-sandbox"
            sbx.write_text(
                f"#!/bin/sh\nexec {sys.executable} -I -c "
                "\"import subprocess,sys; raise SystemExit(subprocess.call(sys.argv[1:]))\" \"$@\"\n",
                encoding="utf-8",
            )
            sbx.chmod(0o755)
            self.env["MQ_GATE_SANDBOX_CMD"] = str(sbx)
        self.state_file.write_text(json.dumps({"repo": SLUG, "bare": str(self.bare), "offline": False, "prs": {},
                                               "forks": {}}), encoding="utf-8")
        self.log_file.write_text("", encoding="utf-8")
        self.git(self.tmp, "init", "--bare", "-q", "-b", DEFAULT, str(self.bare))
        self.git(self.tmp, "clone", "-q", str(self.bare), str(self.worker))
        (self.worker / "README.md").write_text("fleet\n", encoding="utf-8")
        self.git(self.worker, "add", "README.md")
        self.git(self.worker, "commit", "-q", "-m", "root")
        self.git(self.worker, "push", "-q", "origin", f"HEAD:refs/heads/{DEFAULT}")
        self.git(self.worker, "push", "-q", "origin", f"HEAD:refs/heads/{BASE}")
        self.git(self.tmp, "clone", "-q", str(self.bare), str(self.conductor))
        if mode == "gh":
            self.point(self.conductor, "origin", SLUG, self.bare)
        self.next_pr = 1

    def point(self, clone: Path, remote: str, slug: str, bare: Path) -> None:
        """Name `slug` as the remote's URL, rewritten by git to the local bare repo `bare`."""
        url = f"https://{slug}.git"
        self.git(clone, "config", f"url.{bare}.insteadOf", url)
        self.git(clone, "remote", "set-url", remote, url)

    def fork(self, slug: str = "github.invalid/fork/repo") -> Path:
        """A fork on the fake GitHub that shares every object the upstream has."""
        bare = self.tmp / f"{slug.replace('/', '-')}.git"
        self.git(self.tmp, "clone", "-q", "--bare", str(self.bare), str(bare))
        self.set_gh(lambda s: s["forks"].__setitem__(slug, {"bare": str(bare), "prs": {}}))
        return bare

    def mirror_pr(self, u: dict, slug: str, bare: Path) -> None:
        """The same reviewed head, open as the same PR number in the fork."""
        self.git(self.worker, "push", "-q", "-f", str(bare), f"{u['branch']}:refs/heads/{u['branch']}")
        self.set_gh(lambda s: s["forks"][slug]["prs"].__setitem__(str(u["pr"]), {
            "headRefName": u["branch"], "baseRefName": BASE, "state": "OPEN", "mergeCommit": None}))

    # --- git and the fake GitHub ---------------------------------------------------------
    def git(self, cwd: Path, *args: str, check: bool = True) -> str:
        proc = subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise AssertionError(f"git {args} failed: {proc.stderr}")
        return proc.stdout.strip()

    def gh_state(self) -> dict:
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def set_gh(self, mutate) -> None:
        state = self.gh_state()
        mutate(state)
        self.state_file.write_text(json.dumps(state), encoding="utf-8")

    def merge_log(self, event: str = "merged") -> list[dict]:
        lines = [json.loads(x) for x in self.log_file.read_text(encoding="utf-8").splitlines() if x.strip()]
        return [x for x in lines if x["event"] == event]

    def remote_ref(self, name: str) -> str:
        return self.git(self.tmp, "--git-dir", str(self.bare), "rev-parse", f"refs/heads/{name}")

    def merged_heads(self) -> list[str]:
        """BASE's first-parent merges, oldest first, as the second parent (the unit head) of each."""
        out = self.git(self.tmp, "--git-dir", str(self.bare), "rev-list", "--first-parent", "--parents",
                       "--reverse", BASE)
        return [line.split()[2] for line in out.splitlines() if len(line.split()) > 2]

    def tree(self, rev: str) -> str:
        return self.git(self.worker, "rev-parse", f"{rev}^{{tree}}")

    # --- unit branches ----------------------------------------------------------------------
    def unit(self, name: str, files: dict[str, str] | None = None, *, base: str = BASE) -> dict:
        """A reviewed unit: a branch off the current remote BASE, pushed, with a PR in gh mode."""
        self.git(self.worker, "fetch", "-q", "origin")
        self.git(self.worker, "checkout", "-q", "-B", name, f"origin/{base}")
        for rel, text in (files or {f"{name}.txt": f"{name}\n"}).items():
            (self.worker / rel).write_text(text, encoding="utf-8")
            self.git(self.worker, "add", rel)
        self.git(self.worker, "commit", "-q", "-m", f"unit {name}")
        self.git(self.worker, "push", "-q", "-f", "origin", f"{name}:refs/heads/{name}")
        sha = self.git(self.worker, "rev-parse", "HEAD")
        pr = None
        if self.mode == "gh":
            pr = self.next_pr
            self.next_pr += 1
            self.set_gh(lambda s: s["prs"].__setitem__(str(pr), {"headRefName": name, "baseRefName": BASE,
                                                                  "state": "OPEN", "mergeCommit": None}))
        return {"unit": name, "pr": pr, "branch": name, "reviewed_sha": sha, "reviewed_wtree": self.tree(sha), "base": BASE}

    def amend_same_tree(self, u: dict) -> str:
        """A content-identical move: a new head whose tree is the reviewed tree."""
        self.git(self.worker, "checkout", "-q", u["branch"])
        self.git(self.worker, "commit", "-q", "--amend", "-m", f"unit {u['unit']} (message reworded)")
        self.git(self.worker, "push", "-q", "-f", "origin", f"{u['branch']}:refs/heads/{u['branch']}")
        return self.git(self.worker, "rev-parse", "HEAD")

    def push_change(self, u: dict, rel: str = "late.txt") -> str:
        """A content-CHANGING move after review (a late push or a bot autofix)."""
        self.git(self.worker, "checkout", "-q", u["branch"])
        (self.worker / rel).write_text("unreviewed\n", encoding="utf-8")
        self.git(self.worker, "add", rel)
        self.git(self.worker, "commit", "-q", "-m", "late unreviewed change")
        self.git(self.worker, "push", "-q", "-f", "origin", f"{u['branch']}:refs/heads/{u['branch']}")
        return self.git(self.worker, "rev-parse", "HEAD")

    def slow_deletions(self, seconds: float) -> Path:
        """Make every branch DELETION pushed to the bare repo take `seconds`, marking start and end."""
        marker = self.tmp / "deletions.log"
        hook = self.bare / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\nwhile read old new ref; do\n  case \"$new\" in 0000000000000000000000000000000000000000)\n"
                        f"    echo start >> {marker}; sleep {seconds}; echo end >> {marker};;\n  esac\ndone\n",
                        encoding="utf-8")
        hook.chmod(0o755)
        return marker

    def recreate_first_deleted_branch(self) -> None:
        """Someone recreates the first branch deleted on the bare repo, at the commit it had."""
        once = self.tmp / "recreated.once"
        hook = self.bare / "hooks" / "post-receive"
        hook.write_text("#!/bin/sh\nwhile read old new ref; do\n  case \"$new\" in 0000000000000000000000000000000000000000)\n"
                        f"    if [ ! -f {once} ]; then touch {once}; git update-ref \"$ref\" \"$old\"; fi;;\n  esac\ndone\n",
                        encoding="utf-8")
        hook.chmod(0o755)

    def external_base_write(self, rel: str = "external.txt") -> str:
        """A non-cooperating writer moves BASE directly (not through the queue)."""
        self.git(self.worker, "fetch", "-q", "origin")
        self.git(self.worker, "checkout", "-q", "-B", "external", f"origin/{BASE}")
        (self.worker / rel).write_text("external\n", encoding="utf-8")
        self.git(self.worker, "add", rel)
        self.git(self.worker, "commit", "-q", "-m", "external write")
        self.git(self.worker, "push", "-q", "origin", f"external:refs/heads/{BASE}")
        return self.git(self.worker, "rev-parse", "HEAD")

    # --- the queue, through the real CLI or in process --------------------------------------
    def init_args(self) -> list[str]:
        return ["init", "--base", BASE, "--default", DEFAULT, "--consent", "grant:merge-to-integration",
                "--mode", self.mode, "--host", "github.invalid"]

    def cli(self, *args: str, timeout: float = 120.0, cwd: Path | None = None) -> tuple[int, dict]:
        proc = subprocess.run([sys.executable, str(self.script), "--repo-dir", str(self.conductor), *args],
                              env=self.env, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        try:
            out = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except ValueError as exc:
            raise AssertionError(f"non-JSON output ({proc.returncode}): {proc.stdout}\n{proc.stderr}") from exc
        return proc.returncode, out

    def queue(self, module=None):
        module = module or load_module(self.script)
        return module.MergeQueue(self.db, self.conductor, env=dict(self.env))

    def cleanup(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


# The drill child: a real conductor process that parks at one merge boundary (MERGE_BOUNDARIES)
# until the test writes a line to its stdin, or SIGKILLs it there (#597's crash-drill shape).
CHILD = r'''
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("mq_child", sys.argv[1])
mq_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mq_mod)
args = json.loads(sys.argv[2])
mq = mq_mod.MergeQueue(args["db"], args["repo_dir"], env=dict(os.environ))
park = {(stage, int(nth)) for stage, nth in args.get("park_at") or []}
seen = {}


def hook(stage, info):
    seen[stage] = seen.get(stage, 0) + 1
    print(json.dumps({"boundary": stage, "nth": seen[stage], "info": info, "pid": os.getpid()}), flush=True)
    if (stage, seen[stage]) in park:
        sys.stdin.readline()


mq.on_boundary = hook
try:
    res = mq.drain(repo=args["repo"], base=args["base"], holder=args["holder"], takeover=args.get("takeover", False),
                   wait=args.get("wait", 10.0), ack=args.get("ack", True))
    print(json.dumps({"result": res}), flush=True)
except mq_mod.QueueError as exc:
    print(json.dumps({"error": exc.code, "message": exc.message}), flush=True)
    sys.exit(exc.exit_code)
'''
