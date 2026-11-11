#!/usr/bin/env python3
"""Behavior of the persisted, fenced merge queue (#599; runtime/scripts/merge_queue.py).

Every test builds disposable repositories (a bare "remote", a worker clone, a conductor clone)
and a fake GitHub (tests/fixtures/merge_queue/fake_gh.py) over the bare repo. Nothing touches the
network. The process-level drills (two conductors, pause-transfer-resume, crash restarts, the
mutation controls) are tests/test_merge_queue_drills.py.
"""
from __future__ import annotations

import importlib.util
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The fixture harness sits beside its fake gh, loaded by path (it is not a package CI installs).
_spec = importlib.util.spec_from_file_location("mq_world", ROOT / "tests" / "fixtures" / "merge_queue" / "world.py")
W = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(W)

mq_mod = W.load_module()
egress = mq_mod.egress


class QueueCase(unittest.TestCase):
    mode = "gh"

    def setUp(self):
        self.w = W.World(Path(tempfile.mkdtemp(prefix="mq-test-")), mode=self.mode)
        self.addCleanup(self.w.cleanup)
        rc, out = self.w.cli(*self.w.init_args())
        self.assertEqual(rc, 0, out)
        self.repo = out["repo"]

    def acquire(self, holder="c1", *extra):
        rc, out = self.w.cli("acquire", "--base", W.BASE, "--holder", holder, *extra)
        self.assertEqual(rc, 0, out)
        return out["token"]

    def board(self, token, *units, run="r1"):
        ids = []
        for u in units:
            rc, out = self.w.cli("enqueue", "--token", token, "--payload", json.dumps(u), "--run", run)
            self.assertEqual(rc, 0, out)
            ids.append(out["entry"]["entry_id"])
        return ids

    def status(self):
        # --repo pins the queue's identity: the offline drills point origin somewhere else.
        rc, out = self.w.cli("--repo", self.repo, "status", "--base", W.BASE)
        self.assertEqual(rc, 0, out)
        return out

    def receipts(self, entry=None):
        args = ["receipts", "--base", W.BASE] + (["--entry", entry] if entry else [])
        return self.w.cli(*args)[1]["receipts"]

    def state_of(self, entry):
        return next(e["state"] for e in self.status()["all"] if e["entry_id"] == entry)


class LeaseAndFencing(QueueCase):
    def test_one_conductor_per_repository_and_base(self):
        self.acquire("c1")
        rc, out = self.w.cli("acquire", "--base", W.BASE, "--holder", "c2")
        self.assertEqual((rc, out.get("code")), (3, "lease_held"), out)
        self.assertEqual(out["data"]["holder"], "c1")
        # A second BASE in the same repository is a second queue with its own conductor.
        self.w.git(self.w.worker, "push", "-q", "origin", f"origin/{W.BASE}:refs/heads/integration-2")
        rc, out = self.w.cli("init", "--base", "integration-2", "--default", W.DEFAULT, "--consent", "grant:x",
                             "--host", "github.invalid")
        self.assertEqual(rc, 0, out)
        rc, out = self.w.cli("acquire", "--base", "integration-2", "--holder", "c2")
        self.assertEqual((rc, out["epoch"]), (0, 1), out)

    def test_a_stale_owner_cannot_board_plan_dequeue_merge_ack_resolve_or_release(self):
        old = self.acquire("c1")
        (entry,) = self.board(old, self.w.unit("alpha"))
        new = self.acquire("c2", "--takeover")
        before = self.status()["all"]
        attempts = {
            "enqueue": ["enqueue", "--token", old, "--payload", json.dumps(self.w.unit("beta"))],
            "plan": ["plan", "--token", old],
            "merge": ["merge", "--token", old],
            "ack": ["ack", "--token", old, "--entry", entry],
            "resolve": ["resolve", "--token", old, "--entry", entry, "--action", "drop", "--reason", "x"],
            "reconcile": ["reconcile", "--token", old],
            "release": ["release", "--token", old],
        }
        for name, args in attempts.items():
            with self.subTest(op=name):
                rc, out = self.w.cli(*args)
                self.assertEqual((rc, out.get("code")), (3, "fenced"), out)
                self.assertEqual(out["data"]["currentEpoch"], 2)
        self.assertEqual(self.status()["all"], before, "a fenced write changed queue state")
        self.assertEqual(self.w.merge_log("start"), [], "a fenced conductor reached GitHub")
        stale = [r for r in self.receipts() if r["epoch"] == 1 and r["kind"] not in ("lease_acquired", "boarded")]
        self.assertEqual(stale, [], "epoch 1 wrote a receipt after it was fenced")
        rc, out = self.w.cli("plan", "--token", new)
        self.assertEqual(rc, 0, out)

    def test_a_restart_under_the_same_holder_fences_the_older_process(self):
        first = self.acquire("c1")
        second = self.acquire("c1")
        rc, out = self.w.cli("plan", "--token", first)
        self.assertEqual((rc, out.get("code")), (3, "fenced"))
        self.assertEqual(self.w.cli("plan", "--token", second)[0], 0)

    def test_an_expired_lease_is_acquirable_without_takeover(self):
        mq = self.w.queue(mq_mod)
        now = [1000.0]
        mq.clock = lambda: now[0]
        mq.acquire(repo=self.repo, base=W.BASE, holder="c1", ttl=60)
        with self.assertRaises(mq_mod.QueueError) as held:
            mq.acquire(repo=self.repo, base=W.BASE, holder="c2", ttl=60)
        self.assertEqual(held.exception.code, "lease_held")
        now[0] += 61
        self.assertEqual(mq.acquire(repo=self.repo, base=W.BASE, holder="c2", ttl=60)["epoch"], 2)

    def test_every_owner_write_renews_the_lease(self):
        mq = self.w.queue(mq_mod)
        now = [1000.0]
        mq.clock = lambda: now[0]
        token = mq.acquire(repo=self.repo, base=W.BASE, holder="c1", ttl=60)["token"]
        for _ in range(3):
            now[0] += 50
            mq.enqueue(token, self.w.unit(f"u{int(now[0])}"))
        with self.assertRaises(mq_mod.QueueError) as held:
            mq.acquire(repo=self.repo, base=W.BASE, holder="c2", ttl=60)
        self.assertEqual(held.exception.code, "lease_held")

    def test_an_unknown_token_is_not_an_owner(self):
        rc, out = self.w.cli("plan", "--token", "0" * 32)
        self.assertEqual((rc, out.get("code")), (3, "unknown_token"))


class Boarding(QueueCase):
    def test_an_entry_binds_run_unit_pr_branch_reviewed_sha_tree_base_and_arrival(self):
        token = self.acquire()
        a, b = self.w.unit("alpha"), self.w.unit("beta")
        ids = self.board(token, a, b, run="run-7")
        line = self.status()["line"]
        self.assertEqual([e["entry_id"] for e in line], ids)
        self.assertEqual([e["seq"] for e in line], [1, 2])
        got = line[0]
        self.assertEqual((got["run_id"], got["unit"], got["pr"], got["branch"], got["reviewed_sha"], got["reviewed_tree"]),
                         ("run-7", "alpha", a["pr"], "alpha", a["reviewed_sha"], a["reviewed_wtree"]))
        boarded = [r for r in self.receipts(ids[0]) if r["kind"] == "boarded"][0]["body"]
        self.assertEqual((boarded["base"], boarded["seq"], boarded["reviewedSha"], boarded["reviewedTree"]),
                         (W.BASE, 1, a["reviewed_sha"], a["reviewed_wtree"]))

    def test_a_duplicate_merge_ready_delivery_is_idempotent(self):
        token = self.acquire()
        a = self.w.unit("alpha")
        rc1, first = self.w.cli("enqueue", "--token", token, "--payload", json.dumps(a), "--run", "r1", "--delivery", "d1")
        rc2, again = self.w.cli("enqueue", "--token", token, "--payload", json.dumps(a), "--run", "r1", "--delivery", "d2")
        self.assertEqual((rc1, rc2), (0, 0))
        self.assertEqual((first["duplicate"], again["duplicate"]), (False, True))
        self.assertEqual(again["entry"]["entry_id"], first["entry"]["entry_id"])
        self.assertEqual(len(self.status()["all"]), 1)
        # No arrival slot was consumed by the duplicate.
        (nxt,) = self.board(token, self.w.unit("beta"))
        self.assertEqual(next(e["seq"] for e in self.status()["all"] if e["entry_id"] == nxt), 2)
        kinds = [r["kind"] for r in self.receipts(first["entry"]["entry_id"])]
        self.assertEqual(kinds.count("boarded"), 1)
        self.assertEqual(kinds.count("duplicate_delivery"), 1)

    def test_the_same_delivery_key_with_another_payload_is_refused(self):
        token = self.acquire()
        a = self.w.unit("alpha")
        self.board(token, a)
        rc, out = self.w.cli("enqueue", "--token", token, "--payload", json.dumps({**a, "branch": "elsewhere"}), "--run", "r1")
        self.assertEqual((rc, out.get("code")), (2, "payload_mismatch"))

    def test_reboarding_a_unit_supersedes_it_and_joins_the_back(self):
        token = self.acquire()
        a, b = self.w.unit("alpha"), self.w.unit("beta")
        old_a, _ = self.board(token, a, b)
        moved = {**a, "reviewed_sha": self.w.push_change(a), }
        moved["reviewed_wtree"] = self.w.tree(moved["reviewed_sha"])
        rc, out = self.w.cli("enqueue", "--token", token, "--payload", json.dumps(moved), "--run", "r1")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out["superseded"], [old_a])
        self.assertEqual([e["unit"] for e in self.status()["line"]], ["beta", "alpha"])
        self.assertEqual(self.state_of(old_a), "superseded")

    def test_a_redelivery_after_landing_is_a_no_op(self):
        a = self.w.unit("alpha")
        token = self.acquire()
        self.board(token, a)
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual(rc, 0, out)
        token = self.acquire()
        rc, out = self.w.cli("enqueue", "--token", token, "--payload", json.dumps(a), "--run", "r1")
        self.assertEqual((rc, out["duplicate"], out["entry"]["state"]), (0, True, "landed"))
        self.assertEqual(len(self.w.merge_log()), 1)

    def test_payloads_are_validated_before_any_write(self):
        token = self.acquire()
        a = self.w.unit("alpha")
        bad = {"not json": "{", "no unit": json.dumps({**a, "unit": ""}),
               "short sha": json.dumps({**a, "reviewed_sha": "abc"}),
               "bool pr": json.dumps({**a, "pr": True}), "no pr on gh lane": json.dumps({**a, "pr": None}),
               "refspec in branch": json.dumps({**a, "branch": "alpha:refs/heads/integration"}),
               "option as branch": json.dumps({**a, "branch": "--upload-pack=x"})}
        for name, payload in bad.items():
            with self.subTest(name):
                rc, out = self.w.cli("enqueue", "--token", token, "--payload", payload)
                self.assertEqual(rc, 2, out)
        forged = {**a, "reviewed_wtree": self.w.tree(f"{W.DEFAULT}")}
        self.w.git(self.w.conductor, "fetch", "-q", "origin", "alpha")
        rc, out = self.w.cli("enqueue", "--token", token, "--payload", json.dumps(forged))
        self.assertEqual((rc, out.get("code")), (2, "reviewed_tree_mismatch"))
        self.assertEqual(self.status()["all"], [])


class FifoAndFreeze(QueueCase):
    def test_units_merge_once_each_in_arrival_order(self):
        units = [self.w.unit(n) for n in ("alpha", "beta", "gamma")]
        token = self.acquire()
        ids = self.board(token, *units)
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.w.merged_heads(), [u["reviewed_sha"] for u in units])
        self.assertEqual([x["pr"] for x in self.w.merge_log()], [u["pr"] for u in units])
        intents = [r["entry_id"] for r in self.receipts() if r["kind"] == "merge_intent"]
        self.assertEqual(intents, ids)
        self.assertEqual({self.state_of(i) for i in ids}, {"landed"})

    def test_only_the_head_of_the_train_may_merge(self):
        token = self.acquire()
        _a, b = self.board(token, self.w.unit("alpha"), self.w.unit("beta"))
        self.assertEqual(self.w.cli("plan", "--token", token)[0], 0)
        rc, out = self.w.cli("merge", "--token", token, "--entry", b)
        self.assertEqual((rc, out.get("code")), (2, "not_head"))
        self.assertEqual(self.w.merge_log("start"), [])

    def test_a_merged_entry_must_be_acknowledged_before_the_next_merge(self):
        token = self.acquire()
        a, _b = self.board(token, self.w.unit("alpha"), self.w.unit("beta"))
        self.w.cli("plan", "--token", token)
        self.assertEqual(self.w.cli("merge", "--token", token)[0], 0)
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out.get("code")), (1, "ack_owed"))
        rc, out = self.w.cli("ack", "--token", token, "--entry", a, "--note", "ledgered")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.w.cli("merge", "--token", token)[0], 0)

    def test_a_failed_gate_freezes_the_train_behind_it_until_resolved(self):
        a, b, c = (self.w.unit(n) for n in ("alpha", "beta", "gamma"))
        token = self.acquire()
        ids = self.board(token, a, b, c)
        rc, out = self.w.cli("plan", "--token", token, "--gate-cmd", "test ! -f beta.txt")
        self.assertEqual(rc, 0, out)
        self.assertEqual([p["result"] for p in out["planned"]], ["tested", "fail"])
        self.assertEqual(out["planned"][1]["reason"], "gate_failed")
        self.assertEqual(self.w.cli("merge", "--token", token)[0], 0)
        self.w.cli("ack", "--token", token, "--entry", ids[0])
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out.get("code"), out["data"]["entry"]), (1, "queue_frozen", ids[1]))
        rc, out = self.w.cli("plan", "--token", token)
        self.assertEqual((rc, out.get("code")), (1, "queue_frozen"))
        self.assertEqual(self.status()["frozen"]["entry"], ids[1])
        self.assertEqual(self.w.merged_heads(), [a["reviewed_sha"]], "a unit merged past a frozen predecessor")
        failed = [r for r in self.receipts(ids[1]) if r["kind"] == "failed"][0]["body"]
        self.assertTrue(failed["frozen"])
        self.assertEqual(failed["gate"]["exit"], 1)
        rc, out = self.w.cli("resolve", "--token", token, "--entry", ids[1], "--action", "drop", "--reason", "gate red")
        self.assertEqual(rc, 0, out)
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.w.merged_heads(), [a["reviewed_sha"], c["reviewed_sha"]])
        self.assertIn("resolved", [r["kind"] for r in self.receipts(ids[1])])

    def test_a_refused_remote_merge_freezes_the_train(self):
        a, b = self.w.unit("alpha"), self.w.unit("beta")
        token = self.acquire()
        ids = self.board(token, a, b)
        self.w.set_gh(lambda s: s["prs"][str(a["pr"])].__setitem__("refuse", "Required status check is failing"))
        self.w.cli("plan", "--token", token)
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out.get("code")), (1, "merge_refused"), out)
        self.assertEqual(self.state_of(ids[0]), "failed")
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual(out.get("code"), "queue_frozen")
        self.w.set_gh(lambda s: s["prs"][str(a["pr"])].pop("refuse"))
        self.w.cli("resolve", "--token", token, "--entry", ids[0], "--action", "requeue", "--reason", "checks fixed")
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.w.merged_heads(), [a["reviewed_sha"], b["reviewed_sha"]])

    def test_a_conflicting_unit_fails_at_plan_and_freezes(self):
        a = self.w.unit("alpha", {"shared.txt": "alpha\n"})
        b = self.w.unit("beta", {"shared.txt": "beta\n"})
        token = self.acquire()
        ids = self.board(token, a, b)
        rc, out = self.w.cli("plan", "--token", token)
        self.assertEqual([(p["result"], p.get("reason")) for p in out["planned"]], [("tested", None), ("fail", "conflict")])
        self.assertEqual(out["planned"][1]["conflicts"], ["shared.txt"])
        self.assertEqual(self.state_of(ids[1]), "failed")


class GateSelection(QueueCase):
    """A gate the conductor asks for runs on the prefix that merges, or nothing merges (PR #647)."""

    def _plan(self, *gate):
        token = self.acquire()
        (entry,) = self.board(token, self.w.unit("alpha"))
        rc, out = self.w.cli("plan", "--token", token, *gate)
        self.assertEqual(rc, 0, out)
        return token, entry

    def _frozen_on_the_gate(self, entry, out, rc):
        self.assertEqual((rc, out.get("code")), (1, "queue_frozen"), out)
        self.assertEqual(self.w.merge_log("start"), [], "the unit merged without the requested gate")
        self.assertEqual(self.state_of(entry), "failed")
        failed = [r["body"] for r in self.receipts(entry) if r["kind"] == "failed"][0]
        self.assertEqual((failed["reason"], failed["gate"]["cmd"]), ("gate_failed", "exit 1"))

    def test_drain_runs_a_requested_gate_the_saved_plan_never_ran(self):
        token, entry = self._plan()
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--gate-cmd", "exit 1", "--ack")
        self._frozen_on_the_gate(entry, out, rc)

    def test_drain_runs_the_requested_gate_when_the_saved_plan_ran_another(self):
        token, entry = self._plan("--gate-cmd", "true")
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--gate-cmd", "exit 1", "--ack")
        self._frozen_on_the_gate(entry, out, rc)

    def test_a_saved_plan_that_passed_the_same_gate_is_reused(self):
        ran = self.w.tmp / "gate.log"
        gate = f"echo ran >> {ran}"
        token, _entry = self._plan("--gate-cmd", gate)
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--gate-cmd", gate, "--ack")
        self.assertEqual(rc, 0, out)
        self.assertEqual(ran.read_text().splitlines(), ["ran"], "a passed gate ran again for the same prefix")
        self.assertEqual(len(self.w.merge_log()), 1)

    def test_a_saved_plan_whose_gate_executable_was_replaced_is_not_reused_c19(self):
        bin_dir = self.w.tmp / "gate-bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        tool = bin_dir / "gate-check"
        tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        tool.chmod(0o755)
        self.w.env["PATH"] = f"{bin_dir}:{self.w.env.get('PATH', '/usr/bin:/bin')}"

        token, entry = self._plan("--gate-cmd", "gate-check")
        # Now replace the gate executable on PATH so it exits 1
        tool.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        tool.chmod(0o755)
        rc, out = self.w.cli("merge", "--token", token, "--require-gate", "gate-check")
        self.assertEqual((rc, out.get("code")), (1, "gate_not_run"), out)
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--gate-cmd", "gate-check", "--ack")
        self.assertEqual((rc, out.get("code")), (1, "queue_frozen"), out)
        self.assertEqual(self.state_of(entry), "failed")

    def test_merge_refuses_a_plan_that_did_not_pass_the_required_gate(self):
        token, entry = self._plan()
        rc, out = self.w.cli("merge", "--token", token, "--require-gate", "true")
        self.assertEqual((rc, out.get("code")), (1, "gate_not_run"), out)
        self.assertEqual((self.w.merge_log("start"), self.state_of(entry)), ([], "queued"))
        self.assertEqual(self.w.cli("plan", "--token", token, "--gate-cmd", "true")[0], 0)
        rc, out = self.w.cli("merge", "--token", token, "--require-gate", "true")
        self.assertEqual((rc, out.get("result")), (0, "merged"), out)

    def test_drain_passes_its_gate_timeout_to_the_gate(self):
        token, entry = self._plan()
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--gate-cmd", "sleep 5",
                             "--gate-timeout", "0.5", "--ack")
        self.assertEqual((rc, out.get("code")), (1, "queue_frozen"), out)
        failed = [r["body"] for r in self.receipts(entry) if r["kind"] == "failed"][0]
        self.assertEqual(failed["gate"]["exit"], 124)
        self.assertEqual(self.w.merge_log("start"), [])

    def test_a_timed_out_gate_is_stopped_with_everything_it_started(self):
        token, entry = self._plan()
        late = self.w.tmp / "late.txt"
        rc, out = self.w.cli("plan", "--token", token, "--gate-cmd", f"sh -c 'sleep 2; echo late > {late}'; true",
                             "--gate-timeout", "0.5")
        self.assertEqual(rc, 0, out)
        self.assertEqual([(x["result"], x["gate"]["exit"]) for x in out["planned"]], [("fail", 124)])
        self.assertEqual(self.state_of(entry), "failed")
        time.sleep(3)
        self.assertFalse(late.exists(), "a timed-out gate's child kept running after the gate was failed")

class Freshness(QueueCase):
    def _planned(self, *units):
        token = self.acquire()
        ids = self.board(token, *units)
        rc, out = self.w.cli("plan", "--token", token)
        self.assertEqual(rc, 0, out)
        return token, ids

    def test_a_changed_tree_returns_to_review_and_never_merges(self):
        a, b = self.w.unit("alpha"), self.w.unit("beta")
        token, ids = self._planned(a, b)
        moved = self.w.push_change(a)
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out.get("result"), out.get("reason")), (1, "returned_to_review", "content_changed"), out)
        self.assertEqual(out["head"], moved)
        self.assertEqual(self.state_of(ids[0]), "bounced")
        self.assertEqual(self.w.merge_log("start"), [], "unreviewed content reached GitHub")
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.w.merged_heads(), [b["reviewed_sha"]])
        self.assertNotIn(moved, self.w.git(self.w.tmp, "--git-dir", str(self.w.bare), "rev-list", W.BASE).split())

    def test_a_unit_changed_before_its_first_plan_returns_to_review(self):
        # The conductor never fetched the reviewed commit, so the payload's tree is the reference.
        a, b = self.w.unit("alpha"), self.w.unit("beta")
        token = self.acquire()
        ids = self.board(token, a, b)
        self.w.push_change(a)
        rc, out = self.w.cli("plan", "--token", token)
        self.assertEqual([(p["result"], p.get("reason")) for p in out["planned"]],
                         [("bounce", "content_changed"), ("tested", None)], out)
        self.assertEqual(self.state_of(ids[0]), "bounced")

    def test_a_content_identical_move_keeps_the_review_and_pins_the_new_head(self):
        a = self.w.unit("alpha")
        token, ids = self._planned(a)
        moved = self.w.amend_same_tree(a)
        self.assertNotEqual(moved, a["reviewed_sha"])
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out["result"], out["acceptedHead"]), (0, "merged", moved), out)
        intent = [r for r in self.receipts(ids[0]) if r["kind"] == "merge_intent"][0]["body"]
        self.assertEqual(intent["how"], "content_equivalent")
        call = self.w.merge_log("start")[0]["argv"]
        self.assertIn(f"head={moved}", call)  # the merges-endpoint write pins the newly accepted head
        self.assertEqual(self.w.merged_heads(), [moved])

    def test_a_moved_base_makes_the_tested_prefix_stale(self):
        a = self.w.unit("alpha")
        token, ids = self._planned(a)
        self.w.external_base_write()
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out.get("code"), out["data"]["reason"]), (1, "retest_required", "base_moved"), out)
        self.assertEqual(self.w.merge_log("start"), [])
        self.assertIn("retest_required", [r["kind"] for r in self.receipts(ids[0])])
        self.assertEqual(self.w.cli("plan", "--token", token)[0], 0)
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out["treeMatchesTested"]), (0, True), out)


class ReviewedCommitMustBeAtHand(QueueCase):
    """2026-10-26 review: a payload naming a reviewed_sha that exists nowhere, beside the tree of the
    real (unreviewed) head, planned and merged as `content_equivalent` — the payload's tree was the
    only witness to what was reviewed. The reviewed commit is fetched on boarding, and a head is
    content-equivalent only to a tree recomputed from that commit."""

    def test_a_reviewed_sha_the_queue_cannot_see_never_rides_on_the_payloads_tree(self):
        u = self.w.unit("alpha")
        phantom = hashlib.sha1(b"never reviewed, never existed").hexdigest()
        token = self.acquire()
        (entry,) = self.board(token, {**u, "reviewed_sha": phantom})
        rc, out = self.w.cli("plan", "--token", token)
        self.assertEqual(rc, 0, out)
        self.assertEqual([(p["result"], p.get("reason")) for p in out["planned"]],
                         [("bounce", "reviewed_sha_unavailable")], out)
        self.assertEqual(self.state_of(entry), "bounced")
        self.assertEqual(self.w.merged_heads(), [], "an unreviewed head rode on a fabricated reviewed_sha")

    def test_boarding_fetches_the_reviewed_commit_so_a_later_identical_move_still_rides(self):
        a = self.w.unit("alpha")
        token = self.acquire()
        (entry,) = self.board(token, a)
        moved = self.w.amend_same_tree(a)  # the reviewed commit is now unreachable at the remote
        rc, out = self.w.cli("plan", "--token", token)
        self.assertEqual(rc, 0, out)
        self.assertEqual([(p["result"], p.get("acceptedHead"), p.get("how")) for p in out["planned"]],
                         [("tested", moved, "content_equivalent")], out)


class GateRunsIsolated(QueueCase):
    """2026-10-26 review: `--gate-cmd` ran the unit's own test code with the conductor's whole
    environment (GH_TOKEN, SSH_AUTH_SOCK) in a worktree sharing the conductor's `.git`, whose
    config and hooks it could rewrite. It now runs in its own `--shared` clone under the
    process-hygiene floor plus MQ_GATE_ENV_KEEP."""

    def _gate_tail(self, gate):
        token = self.acquire()
        self.board(token, self.w.unit("alpha"))
        rc, out = self.w.cli("plan", "--token", token, "--gate-cmd", gate)
        self.assertEqual(rc, 0, out)
        self.assertEqual(out["planned"][0]["result"], "tested", out)
        return out["planned"][0]["gate"]["tail"]

    def test_the_conductors_credentials_never_reach_the_gate(self):
        self.w.env["GH_TOKEN"] = "ghp_SENTINEL_CONDUCTOR_TOKEN"
        self.w.env["SSH_AUTH_SOCK"] = "/run/user/1000/keyring/ssh-SENTINEL"
        self.w.env["KEEP_ME"] = "kept"
        self.w.env["MQ_GATE_ENV_KEEP"] = "KEEP_ME"
        tail = self._gate_tail('echo "gh=[$GH_TOKEN] sock=[$SSH_AUTH_SOCK] keep=[$KEEP_ME] unit=[$MQ_UNIT]"')
        self.assertIn("gh=[] sock=[] keep=[kept] unit=[alpha]", tail)

    def test_the_gate_never_holds_the_conductors_git_dir(self):
        tail = self._gate_tail('echo "common=$(git rev-parse --path-format=absolute --git-common-dir)"; '
                               'echo "head=$(git rev-parse HEAD)"')
        common = [ln for ln in tail.splitlines() if ln.startswith("common=")][0][len("common="):]
        self.assertNotEqual(Path(common).resolve(), (Path(self.w.conductor) / ".git").resolve(),
                            "the gate shares the conductor's .git: its config and hooks are the gate's to rewrite")
        self.assertNotIn("worktrees", common)
        self.assertEqual(self.w.git(self.w.conductor, "worktree", "list").count("\n") + 1, 1,
                         "a gate worktree was left in the conductor's clone")

    def test_the_gate_has_no_alternates_no_origin_remote_and_isolated_home_and_tmp_c21(self):
        conductor_home = self.w.tmp / "conductor-home"
        conductor_home.mkdir(parents=True, exist_ok=True)
        (conductor_home / ".netrc").write_text("machine github.invalid login secret\n", encoding="utf-8")
        self.w.env["HOME"] = str(conductor_home)
        self.w.env["TMPDIR"] = str(self.w.tmp)
        self.w.env["GH_TOKEN"] = "ghp_SENTINEL"
        self.w.env["MQ_GATE_ENV_KEEP"] = "GH_TOKEN,HOME,TMPDIR,ORCA_MERGE_QUEUE_DB,SAFE_VAR"
        self.w.env["SAFE_VAR"] = "allowed"
        tail = self._gate_tail(
            'test ! -e .git/objects/info/alternates && echo "alt=absent"; '
            'git remote get-url origin >/dev/null 2>&1 || echo "origin=absent"; '
            'test ! -e "$HOME/.netrc" && echo "netrc=absent"; '
            'echo "home=$HOME tmp=$TMPDIR gh=[$GH_TOKEN] safe=[$SAFE_VAR]"'
        )
        self.assertIn("alt=absent", tail)
        self.assertIn("origin=absent", tail)
        self.assertIn("netrc=absent", tail)
        self.assertIn("gh=[] safe=[allowed]", tail)
        self.assertNotIn(str(conductor_home), tail)
        self.assertNotIn(str(self.w.conductor), tail)

    def test_gate_ppid_environ_and_require_sandbox_and_shell_wrapper_fingerprint_c19_c21(self):
        self.w.env["GH_TOKEN"] = "ghp_PPID_SENTINEL_SECRET"
        tail = self._gate_tail(
            'if [ -r "/proc/$PPID/environ" ]; then '
            'tr "\\0" "\\n" < "/proc/$PPID/environ" | grep -q "ghp_PPID_SENTINEL_SECRET" '
            '&& echo "ppid=LEAKED" || echo "ppid=clean"; '
            'else echo "ppid=clean"; fi'
        )
        self.assertIn("ppid=clean", tail)
        # Subshell, compound (if/then/while/case), and sh -c wrapper executables are extracted:
        exes = mq_mod.MergeQueue._extract_gate_executables(
            '(sh -c "env FOO=1 ./scripts/gate.sh && nice -n 5 pytest"); '
            'if true; then /opt/tools/compound-gate; fi; '
            'for x in /not/an/exe; do ./loop-gate "$x"; done'
        )
        self.assertIn("./scripts/gate.sh", exes)
        self.assertIn("pytest", exes)
        self.assertIn("/opt/tools/compound-gate", exes)
        self.assertIn("./loop-gate", exes)
        self.assertNotIn("/not/an/exe", exes)
        # Replacing an executable inside `if true; then <bin>; fi` after `plan` invalidates `merge --require-gate`:
        ext_bin = self.w.tmp / "bin" / "compound-gate-bin"
        ext_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        ext_bin.chmod(0o755)
        compound_cmd = f"if true; then {ext_bin}; fi"
        tok_cmp = self.acquire("c-cmp", "--takeover")
        self.board(tok_cmp, self.w.unit("cmp-unit"))
        rc_p, out_p = self.w.cli("plan", "--token", tok_cmp, "--gate-cmd", compound_cmd)
        self.assertEqual(rc_p, 0, out_p)
        ext_bin.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        ext_bin.chmod(0o755)
        rc_m, out_m = self.w.cli("merge", "--token", tok_cmp, "--require-gate", compound_cmd)
        self.assertNotEqual(rc_m, 0, out_m)
        self.assertEqual(out_m.get("code"), "gate_not_run", out_m)
        # Replacing a `sh <script>` operand after `plan` invalidates `merge --require-gate`:
        ext_sh = self.w.tmp / "bin" / "gate-operand.sh"
        ext_sh.write_text("exit 0\n", encoding="utf-8")
        sh_operand_cmd = f"sh {ext_sh}"
        tok_sh = self.acquire("c-sh-op", "--takeover")
        self.board(tok_sh, self.w.unit("sh-op-unit"))
        rc_sp, out_sp = self.w.cli("plan", "--token", tok_sh, "--gate-cmd", sh_operand_cmd)
        self.assertEqual(rc_sp, 0, out_sp)
        self.assertEqual(out_sp["planned"][0]["result"], "tested", out_sp)
        ext_sh.write_text("exit 1\n", encoding="utf-8")
        rc_sm, out_sm = self.w.cli("merge", "--token", tok_sh, "--require-gate", sh_operand_cmd)
        self.assertNotEqual(rc_sm, 0, out_sm)
        self.assertEqual(out_sm.get("code"), "gate_not_run", out_sm)
        # Replacing a `python3 <script>` operand after `plan` also invalidates `merge --require-gate`:
        ext_py = self.w.tmp / "bin" / "gate-operand.py"
        ext_py.write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
        py_operand_cmd = f"{sys.executable} -s {ext_py}"
        tok_py = self.acquire("c-py-op", "--takeover")
        self.board(tok_py, self.w.unit("py-op-unit"))
        rc_pp, out_pp = self.w.cli("plan", "--token", tok_py, "--gate-cmd", py_operand_cmd)
        self.assertEqual(rc_pp, 0, out_pp)
        self.assertEqual(out_pp["planned"][0]["result"], "tested", out_pp)
        ext_py.write_text("import sys\nsys.exit(1)\n", encoding="utf-8")
        rc_pm, out_pm = self.w.cli("merge", "--token", tok_py, "--require-gate", py_operand_cmd)
        self.assertNotEqual(rc_pm, 0, out_pm)
        self.assertEqual(out_pm.get("code"), "gate_not_run", out_pm)
        # Line continuations (`\\\n`) and `sed -e '' -f <script>` extract the real executable/script:
        self.assertIn("gate-check", mq_mod.MergeQueue._extract_gate_executables("gat\\\ne-check"))
        ext_sed = self.w.tmp / "bin" / "gate-operand.sed"
        ext_sed.write_text("q\n", encoding="utf-8")
        sed_exes, _, sed_probs = mq_mod.MergeQueue._analyze_gate_command(f"sed -e '' -f {ext_sed} /dev/null")
        self.assertFalse(sed_probs, sed_probs)
        self.assertIn(str(ext_sed), sed_exes)
        # Wrapped builtin-named binaries (`env test`, `nice echo`, `exec test`) execute via PATH and are fingerprinted:
        self.assertEqual(mq_mod.MergeQueue._extract_gate_executables("env test -f marker"), ["env", "test"])
        self.assertEqual(mq_mod.MergeQueue._extract_gate_executables("nice -n 5 echo ok"), ["nice", "echo"])
        self.assertEqual(mq_mod.MergeQueue._extract_gate_executables("exec test -f marker"), ["test"])
        ext_test = self.w.tmp / "bin" / "test"
        ext_test.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        ext_test.chmod(0o755)
        try:
            tok_et = self.acquire("c-env-test", "--takeover")
            self.board(tok_et, self.w.unit("env-test-unit"))
            rc_etp, out_etp = self.w.cli("plan", "--token", tok_et, "--gate-cmd", "env test -f anything")
            self.assertEqual(rc_etp, 0, out_etp)
            self.assertEqual(out_etp["planned"][0]["result"], "tested", out_etp)
            ext_test.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            rc_etm, out_etm = self.w.cli("merge", "--token", tok_et, "--require-gate", "env test -f anything")
            self.assertNotEqual(rc_etm, 0, out_etm)
            self.assertEqual(out_etm.get("code"), "gate_not_run", out_etm)
        finally:
            ext_test.unlink(missing_ok=True)
        # Unresolved executable names fail closed in `_gate_fingerprint`:
        unres_fp, unres_probs = self.w.queue()._gate_fingerprint("nonexistent_gate_binary_xyz")
        self.assertEqual(unres_fp, "")
        self.assertTrue(unres_probs)
        # `bwrap` argv never `--ro-bind`s `/` or conductor `$HOME` (even through a PATH symlink):
        q_bw = self.w.queue()
        fake_home = self.w.tmp / "fake-home"
        (fake_home / "bin").mkdir(parents=True, exist_ok=True)
        (fake_home / ".ssh").mkdir(parents=True, exist_ok=True)
        sym_home = fake_home / "symbin"
        sym_home.symlink_to(fake_home)
        sym_ssh = fake_home / "sshbin"
        sym_ssh.symlink_to(fake_home / ".ssh")
        q_bw.env.pop("MQ_GATE_SANDBOX_CMD", None)
        q_bw.env["HOME"] = str(fake_home)
        q_bw.env["PATH"] = f"{fake_home / 'bin'}:{sym_home}:{sym_ssh}:/usr/bin:/bin"
        with unittest.mock.patch.object(
            type(q_bw), "_bwrap_mode", return_value=("/usr/bin/bwrap", ("--unshare-all",))
        ):
            bw_argv = q_bw._gate_exec_argv("true", self.w.tmp / "co", self.w.tmp / "gh", self.w.tmp / "gt")
        ro_srcs = [bw_argv[i + 1] for i, v in enumerate(bw_argv) if v == "--ro-bind"]
        self.assertNotIn("/", ro_srcs)
        self.assertNotIn(str(fake_home), ro_srcs)
        self.assertNotIn(str(sym_home), ro_srcs)
        self.assertNotIn(str(sym_ssh), ro_srcs)
        self.assertIn(str(fake_home / "bin"), ro_srcs)
        # Dynamic command words (`eval`) and lookup-mutating forms (`PATH=`, `env PATH=`, `env -C`, `cd`, `command -p`) fail closed:
        for unsafe_gate in (
            "eval /bin/true",
            "PATH=/opt/alternate/bin gate-check",
            'PATH="/opt/alternate/bin" gate-check',
            "env PATH=/opt/alternate/bin gate-check",
            "env 'PATH=/opt/alternate/bin' gate-check",
            "env -C /tmp ./gate-check",
            "env -i gate-check",
            "env -u PATH gate-check",
            "env -S nice /opt/gate-check",
            "env --split-string='sh -c true' /opt/gate-check",
            "cd subdir && ./gate-check",
            "export PATH=/opt/alternate/bin; gate-check",
            "for PATH in /opt/alternate/bin; do gate-check; done",
            "declare -n ref=PATH; ref=/opt/alternate/bin",
            "command -p python3 -V",
            "exec -c gate-check",
            "sh bare_script.sh",
            "sh -s",
            ". bare_script.sh",
            "[g]ate-check",
        ):
            _, _, dyn_probs = mq_mod.MergeQueue._analyze_gate_command(unsafe_gate)
            self.assertTrue(dyn_probs, f"expected fail-closed problem on {unsafe_gate!r}")
        tok_path = self.acquire("c-path", "--takeover")
        self.board(tok_path, self.w.unit("path-unit"))
        rc_path, out_path = self.w.cli("plan", "--token", tok_path, "--gate-cmd", "PATH=/opt/alternate/bin true")
        self.assertEqual(rc_path, 0, out_path)
        self.assertEqual(out_path["planned"][0]["result"], "fail", out_path)
        self.assertEqual(out_path["planned"][0]["reason"], "gate_failed", out_path)
        self.assertEqual(out_path["planned"][0]["gate"]["fingerprint"], "", out_path)
        # Resolve frozen failed entry so subsequent tests in this method can plan cleanly:
        self.w.cli(
            "resolve", "--token", tok_path, "--entry", out_path["planned"][0]["entry"],
            "--action", "drop", "--reason", "lookup-test",
        )
        # When MQ_REQUIRE_GATE_SANDBOX=1 and no sandbox binary/command is usable, fail closed:
        if mq_mod.MergeQueue._bwrap_bin() is None:
            token = self.acquire("c2", "--takeover")
            self.board(token, self.w.unit("beta"))
            saved_sbx = self.w.env.pop("MQ_GATE_SANDBOX_CMD", None)
            self.w.env["MQ_REQUIRE_GATE_SANDBOX"] = "1"
            try:
                rc, out = self.w.cli("plan", "--token", token, "--gate-cmd", "true")
            finally:
                self.w.env.pop("MQ_REQUIRE_GATE_SANDBOX", None)
                if saved_sbx is not None:
                    self.w.env["MQ_GATE_SANDBOX_CMD"] = saved_sbx
            self.assertNotEqual(rc, 0, out)
            self.assertEqual(out.get("code"), "sandbox_unavailable", out)
        # Even without MQ_REQUIRE_GATE_SANDBOX, absence of all real isolation fails closed:
        q = self.w.queue()
        q.env.pop("MQ_GATE_SANDBOX_CMD", None)
        q.env.pop("MQ_REQUIRE_GATE_SANDBOX", None)
        q_cls = type(q)
        with unittest.mock.patch.object(q_cls, "_bwrap_mode", return_value=None), \
             unittest.mock.patch.object(q_cls, "_unshare_mount_proc_argv", return_value=None), \
             unittest.mock.patch.object(q_cls, "_unshare_hidepid_argv", return_value=None):
            with self.assertRaises(Exception) as ctx_sbx:
                q._gate_exec_argv("true", self.w.tmp, self.w.tmp, self.w.tmp)
            self.assertEqual(getattr(ctx_sbx.exception, "code", None), "sandbox_unavailable")

    def test_hidden_relative_gate_scripts_preserve_leading_dots(self):
        ext_hidden_bin = self.w.tmp / "bin" / "hidden-gate-check"
        ext_hidden_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        ext_hidden_bin.chmod(0o755)
        (self.w.worker / ".ci").mkdir(parents=True, exist_ok=True)
        (self.w.worker / "ci").mkdir(parents=True, exist_ok=True)
        hidden_unit = self.w.unit(
            "hidden-gate-unit",
            files={
                ".ci/gate.sh": f"{ext_hidden_bin}\n",
                "ci/gate.sh": "true\n",
                ".ci/only.sh": "true\n",
            },
        )
        tok = self.acquire("c-hidden")
        self.board(tok, hidden_unit)
        for gate_cmd in ("sh .ci/only.sh", "sh ./.ci/only.sh"):
            rc_ho, out_ho = self.w.cli("plan", "--token", tok, "--gate-cmd", gate_cmd)
            self.assertEqual(rc_ho, 0, out_ho)
            self.assertEqual(out_ho["planned"][0]["result"], "tested", out_ho)
        rc_hp, out_hp = self.w.cli("plan", "--token", tok, "--gate-cmd", "sh .ci/gate.sh")
        self.assertEqual(rc_hp, 0, out_hp)
        self.assertEqual(out_hp["planned"][0]["result"], "tested", out_hp)
        ext_hidden_bin.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        rc_hm, out_hm = self.w.cli("merge", "--token", tok, "--require-gate", "sh .ci/gate.sh")
        self.assertNotEqual(rc_hm, 0, out_hm)
        self.assertEqual(out_hm.get("code"), "gate_not_run", out_hm)

    def test_arithmetic_expansion_and_comment_quote_substitutions_fingerprint_or_fail_closed(self):
        probe = self.w.tmp / "bin" / "arith-probe"
        probe.write_text("#!/bin/sh\necho 0\n", encoding="utf-8")
        probe.chmod(0o755)
        gate_cmd = f"(exit $(( $({probe}) )))"
        exes, _, probs = mq_mod.MergeQueue._analyze_gate_command(gate_cmd)
        self.assertEqual(probs, [])
        self.assertIn(str(probe), exes)
        for sub_form in (
            f"(exit $(( `{probe}` )))",
            f"test $(( 1 + $({probe}) )) -eq 1",
            f"echo $(({probe}); true)",
            f"true # '\necho $({probe}) # '",
            f"echo $(case x in (x) {probe} ;; esac)",
        ):
            sub_exes, _, sub_probs = mq_mod.MergeQueue._analyze_gate_command(sub_form)
            self.assertEqual(sub_probs, [], sub_form)
            self.assertIn(str(probe), sub_exes, sub_form)
        for unsafe_form in (
            "runner$((1+1))",
            f"echo $'\\'' $({probe}) $'\\''",
            ': "${PYTHONPATH:=/tmp}"',
            ': "${PATH[0]:=/opt/proofs/bin}"',
            f"echo $(case x in x) {probe} ;; esac)",
            'bash -c \'printf -v "PATH[0]" /opt/proofs/bin; proof\'',
            "bash -c 'printf -vPATH[0] /opt/proofs/bin; proof'",
            "bash -c 'printf -v safe -v PATH /opt/proofs/bin; proof'",
            'bash -c \'export "PATH[0]=/opt/proofs/bin"; proof\'',
            'bash -c \'export "PATH+=/opt/proofs/bin"; proof\'',
            'bash -c \'read "PATH[0]"; proof\'',
            'bash -c \'unset "PATH[0]"; proof\'',
            "(( true , PATH = 0 )) && pytest",
            "[[ 0 -eq PATH[0]=1 ]] && pytest",
            f"bash -c 'x=a[$({probe})]; exit \"$((x))\"'",
            "bash -c 'x=\"a[\\$(/opt/tools/probe)]\"; exit \"$((x))\"'",
            "bash -c 'x=\"a[\\$(/opt/tools/probe)]\"; s=hi; echo \"${s:x}\"'",
            "bash -c 'x=\"a[\\$(/opt/tools/probe)]\"; let x'",
            "bash -c 'declare -i y; x=\"a[\\$(/opt/tools/probe)]\"; y=$x'",
            "bash -c 'x=\"a[\\$(/opt/tools/probe)]\"; [[ $x -eq 0 ]]'",
        ):
            _, _, bad_probs = mq_mod.MergeQueue._analyze_gate_command(unsafe_form)
            self.assertTrue(bad_probs, f"expected fail-closed problem on {unsafe_form!r}")
        tok = self.acquire("c-arith")
        self.board(tok, self.w.unit("arith-unit"))
        rc_p, out_p = self.w.cli("plan", "--token", tok, "--gate-cmd", gate_cmd)
        self.assertEqual(rc_p, 0, out_p)
        self.assertEqual(out_p["planned"][0]["result"], "tested", out_p)
        probe.write_text("#!/bin/sh\necho 1\n", encoding="utf-8")
        rc_m, out_m = self.w.cli("merge", "--token", tok, "--require-gate", gate_cmd)
        self.assertNotEqual(rc_m, 0, out_m)
        self.assertEqual(out_m.get("code"), "gate_not_run", out_m)


class GitLaneFreshness(Freshness):
    mode = "git"

    def test_a_content_identical_move_keeps_the_review_and_pins_the_new_head(self):
        a = self.w.unit("alpha")
        token, _ids = self._planned(a)
        moved = self.w.amend_same_tree(a)
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out["acceptedHead"], out["noGh"]), (0, moved, True), out)
        self.assertEqual(self.w.merged_heads(), [moved])


class OfflineAndPromotion(QueueCase):
    def test_offline_github_blocks_the_merge_and_loses_nothing(self):
        a = self.w.unit("alpha")
        token = self.acquire()
        (entry,) = self.board(token, a)
        self.w.cli("plan", "--token", token)
        self.w.set_gh(lambda s: s.__setitem__("offline", True))
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out.get("code")), (1, "offline"), out)
        self.assertEqual(self.state_of(entry), "queued")
        self.assertEqual([r["body"]["step"] for r in self.receipts(entry) if r["kind"] == "offline"], ["revalidate"])
        # The lease itself needs no network: a handoff with nothing in flight succeeds offline.
        token = self.acquire("c2", "--takeover")
        self.w.set_gh(lambda s: s.__setitem__("offline", False))
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.w.merge_log()), 1)

    def test_the_default_branch_is_never_a_merge_queue_base(self):
        rc, out = self.w.cli("init", "--base", W.DEFAULT, "--default", W.DEFAULT, "--consent", "grant:x")
        self.assertEqual((rc, out.get("code")), (2, "promotion_is_human"))

    def test_a_payload_aimed_at_the_default_branch_is_refused(self):
        token = self.acquire()
        rc, out = self.w.cli("enqueue", "--token", token, "--payload", json.dumps({**self.w.unit("alpha"), "base": W.DEFAULT}))
        self.assertEqual((rc, out.get("code")), (2, "promotion_is_human"))

    def test_a_pr_retargeted_at_the_default_branch_returns_to_review(self):
        a = self.w.unit("alpha")
        token = self.acquire()
        (entry,) = self.board(token, a)
        self.w.set_gh(lambda s: s["prs"][str(a["pr"])].__setitem__("baseRefName", W.DEFAULT))
        rc, out = self.w.cli("plan", "--token", token)
        self.assertEqual([(p["result"], p["reason"]) for p in out["planned"]], [("bounce", "wrong_base")])
        self.assertEqual(self.state_of(entry), "bounced")
        self.assertEqual(self.w.merge_log("start"), [])

    def test_a_drained_train_leaves_promotion_to_a_human(self):
        main_before = self.w.remote_ref(W.DEFAULT)
        token = self.acquire()
        ids = self.board(token, self.w.unit("alpha"), self.w.unit("beta"))
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out["promotion"], {"from": W.BASE, "by": "human", "automated": False})
        self.assertEqual(self.w.remote_ref(W.DEFAULT), main_before, "the queue moved the default branch")
        self.assertEqual(self.status()["promotion"]["automated"], False)
        acks = [r["body"]["promotion"] for r in self.receipts() if r["kind"] == "acknowledged"]
        self.assertEqual(len(acks), len(ids))
        self.assertTrue(all("human gate" in p for p in acks))
        sub = subprocess.run([sys.executable, str(W.SCRIPT), "--help"], capture_output=True, text=True).stdout
        self.assertNotIn("promote", sub)

    def test_an_egress_receipt_precedes_every_merge(self):
        token = self.acquire()
        self.board(token, self.w.unit("alpha"), self.w.unit("beta"))
        self.w.cli("release", "--token", token)
        self.assertEqual(self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")[0], 0)
        ok, count, _line, _why = egress.verify_ledger(self.w.ledger)
        self.assertEqual((ok, count), (True, 4))  # each merge, then its branch deletion: one receipt per send
        lines = [json.loads(x) for x in self.w.ledger.read_text().splitlines()]
        self.assertEqual([(x["sink"], x["payload_class"], x["consent"]) for x in lines],
                         [("merge-queue", kind, "grant:merge-to-integration") for kind in ("pr-merge", "branch-delete") * 2])

    def test_every_egress_receipt_id_leaves_the_ledger_so_a_close_can_bind_it(self):
        # Re-attack of 82a2d00c (W5-05): merge_queue wrote its receipts and discarded the record,
        # so no id of them ever left the ledger, and a rewrite of the newest one (host, payload
        # hash, recomputed id) verified clean against every anchor a close held. Each id is now
        # recorded in the queue's own store (and printed), where the close takes it from.
        token = self.acquire()
        self.board(token, self.w.unit("alpha"), self.w.unit("beta"))
        self.w.cli("release", "--token", token)
        self.assertEqual(self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")[0], 0)
        rc, out = self.w.cli("--repo", self.repo, "receipts", "--base", W.BASE)
        self.assertEqual(rc, 0, out)
        recorded = [r["body"] for r in out["receipts"] if r["kind"] == "egress_receipt"]
        ledger = [json.loads(x) for x in self.w.ledger.read_text().splitlines()]
        self.assertEqual([r["id"] for r in recorded], [x["id"] for x in ledger],
                         "an egress receipt the queue wrote has no id outside the ledger")
        self.assertEqual({r["ledger"] for r in recorded}, {str(self.w.ledger)})
        verify = [sys.executable, str(ROOT / "runtime" / "scripts" / "egress.py"), "--ledger", str(self.w.ledger),
                  "verify"]
        anchors = [a for r in recorded for a in ("--expect-ancestor", r["id"])]
        honest = subprocess.run([*verify, *anchors], capture_output=True, text=True)
        self.assertEqual(honest.returncode, 0, honest.stderr)
        lines = self.w.ledger.read_text().splitlines()
        rec = json.loads(lines[-1])
        rec.update(host="gitlab.example", payload_sha256="0" * 64)
        rec["id"] = egress.record_id(rec)
        lines[-1] = egress.canonical_line(rec)
        self.w.ledger.write_text("\n".join(lines) + "\n")
        forged = subprocess.run([*verify, *anchors], capture_output=True, text=True)
        self.assertEqual(forged.returncode, 3, forged.stdout + forged.stderr)

    def test_no_receipt_means_no_send(self):
        token = self.acquire()
        (entry,) = self.board(token, self.w.unit("alpha"))
        self.w.cli("plan", "--token", token)
        self.w.ledger.mkdir()  # the ledger path is a directory: the receipt cannot be written
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out.get("code")), (1, "egress_failed"), out)
        self.assertEqual(self.w.merge_log("start"), [])
        self.assertEqual(self.state_of(entry), "queued")

    def test_the_default_ledger_is_the_repository_roots_wherever_the_queue_runs(self):
        # Re-check of 4b24dfde (W5-03): with no ledger variable the queue wrote to
        # `<--repo-dir>/.orca/egress.jsonl`, and --repo-dir defaults to the working directory, so a
        # drain run from a subdirectory receipted into `<sub>/.orca` while the close verified the
        # root. It now picks the ledger egress.py's own default picks: the repository root's, and
        # none at all (the merge refused before the send) under a `.git` nested in the repository.
        del self.w.env[egress.PRIMARY_LEDGER_ENV]
        sub = self.w.conductor / "sub"
        sub.mkdir()
        token = self.acquire()
        (entry,) = self.board(token, self.w.unit("alpha"))
        self.w.cli("plan", "--token", token)
        rc, out = self.w.cli("--repo-dir", str(sub), "merge", "--token", token)
        self.assertEqual((rc, out.get("result")), (0, "merged"), out)
        self.assertFalse((sub / ".orca").exists(), "the receipt landed under the working subdirectory")
        root_ledger = self.w.conductor / egress.DEFAULT_LEDGER
        self.assertEqual([json.loads(x)["id"] for x in root_ledger.read_text().splitlines()][:1],
                         [out["egressReceipt"]])
        self.assertEqual(self.w.cli("ack", "--token", token, "--entry", entry)[0], 0)
        nested = self.w.conductor / "vendor"
        (nested / ".git").mkdir(parents=True)
        (entry2,) = self.board(token, self.w.unit("beta"))
        self.w.cli("plan", "--token", token)
        before = self.w.merge_log("start")
        rc, out = self.w.cli("--repo-dir", str(nested), "merge", "--token", token)
        self.assertEqual((rc, out.get("code")), (1, "egress_failed"), out)
        self.assertEqual(self.w.merge_log("start"), before, "a merge was sent with no receipt on the run's ledger")
        self.assertFalse((nested / ".orca").exists())
        self.assertEqual(self.state_of(entry2), "queued")


class NonCooperatingWriters(QueueCase):
    def test_a_merge_github_landed_on_a_moved_base_needs_an_explicit_ack(self):
        # GitHub, not the queue, picks the base commit it merges onto: a write that bypasses the
        # queue between revalidation and the merge cannot be fenced, only surfaced.
        token = self.acquire()
        (entry,) = self.board(token, self.w.unit("alpha"))
        self.w.cli("plan", "--token", token)
        self.w.set_gh(lambda s: s.__setitem__("race_base_write", True))
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out["result"], out["treeMatchesTested"]), (0, "merged", False), out)
        rc, out = self.w.cli("ack", "--token", token, "--entry", entry)
        self.assertEqual((rc, out.get("code")), (1, "untested_tree_merged"), out)
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual(out.get("code"), "ack_owed")
        rc, out = self.w.cli("ack", "--token", token, "--entry", entry, "--accept-untested-tree", "--note", "re-gated")
        self.assertEqual((rc, out["acceptedUntestedTree"]), (0, True), out)


class RepositoryBinding(QueueCase):
    """Every GitHub and git call acts on the repository the queue and its lease name (PR #647)."""

    FORK = "github.invalid/fork/repo"

    def _boarded(self):
        token = self.acquire()
        u = self.w.unit("alpha")
        self.board(token, u)
        self.w.cli("release", "--token", token)
        return u

    def _drain(self):
        return self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")

    def test_github_calls_name_the_bound_repository_whatever_gh_would_default_to(self):
        u = self._boarded()
        fork = self.w.fork(self.FORK)
        self.w.mirror_pr(u, self.FORK, fork)
        fork_base = self.w.git(self.w.tmp, "--git-dir", str(fork), "rev-parse", W.BASE)
        self.w.env["GH_REPO"] = self.FORK  # gh's own default would now be the fork
        rc, out = self._drain()
        self.assertEqual(rc, 0, out)
        self.assertEqual({m["repo"] for m in self.w.merge_log("start")}, {W.SLUG}, "a merge reached another repository")
        self.assertEqual(self.w.git(self.w.tmp, "--git-dir", str(fork), "rev-parse", W.BASE), fork_base)
        self.assertEqual(self.w.merged_heads(), [u["reviewed_sha"]])
        call = self.w.merge_log("start")[0]["argv"]
        host, owner_name = W.SLUG.split("/", 1)  # the merges-endpoint write names the bound repository
        self.assertEqual((call[call.index("--hostname") + 1], f"repos/{owner_name}/merges" in call), (host, True))

    def test_a_queue_whose_identity_is_not_its_remote_is_refused(self):
        rc, out = self.w.cli("--repo", "github.invalid/other/repo", *self.w.init_args())
        self.assertEqual((rc, out.get("code")), (2, "repo_mismatch"), out)

    def test_a_remote_repointed_after_init_is_refused_before_any_remote_call(self):
        u = self._boarded()
        fork = self.w.fork(self.FORK)
        self.w.mirror_pr(u, self.FORK, fork)
        self.w.point(self.w.conductor, "origin", self.FORK, fork)
        rc, out = self.w.cli("--repo", self.repo, "drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual((rc, out.get("code")), (1, "repo_mismatch"), out)
        self.assertEqual(self.w.merge_log("start"), [])
        self.assertEqual(self.w.merged_heads(), [])

    def test_a_pull_request_github_reports_for_another_repository_is_refused(self):
        u = self._boarded()
        self.w.set_gh(lambda s: s["prs"][str(u["pr"])].__setitem__("urlRepo", self.FORK))
        rc, out = self._drain()
        self.assertEqual((rc, out.get("code")), (1, "repo_mismatch"), out)
        self.assertEqual(self.w.merge_log("start"), [])

    def test_the_gh_lane_needs_a_github_repository_identity(self):
        self.w.git(self.w.conductor, "remote", "add", "local", str(self.w.bare))
        rc, out = self.w.cli("--repo", str(self.w.bare.resolve()), "init", "--base", "integration-2", "--default",
                             W.DEFAULT, "--consent", "grant:x", "--remote", "local")
        self.assertEqual((rc, out.get("code")), (2, "repo_mismatch"), out)

    def test_a_payload_that_names_another_repository_is_refused(self):
        token = self.acquire()
        u = {**self.w.unit("alpha"), "repo": self.FORK}
        rc, out = self.w.cli("enqueue", "--token", token, "--payload", json.dumps(u))
        self.assertEqual((rc, out.get("code")), (2, "repo_mismatch"), out)
        self.assertEqual(self.status()["all"], [])
        rc, out = self.w.cli("enqueue", "--token", token, "--payload", json.dumps({**u, "repo": W.SLUG}))
        self.assertEqual(rc, 0, out)

    def test_a_pr_number_whose_head_is_another_branch_returns_to_review(self):
        token = self.acquire()
        a, b = self.w.unit("alpha"), self.w.unit("beta")
        (entry,) = self.board(token, {**a, "pr": b["pr"]})
        rc, out = self.w.cli("plan", "--token", token)
        self.assertEqual([(x["result"], x["reason"]) for x in out["planned"]], [("bounce", "pr_branch_mismatch")], out)
        self.assertEqual(self.state_of(entry), "bounced")


class MergeTargetBinding(QueueCase):
    """The remote write names the queue's BASE; nothing about the PR can redirect it (PR #647)."""

    def test_a_pr_retargeted_after_the_last_check_cannot_redirect_the_merge(self):
        main_before = self.w.remote_ref(W.DEFAULT)
        base_before = self.w.remote_ref(W.BASE)
        token = self.acquire()
        u = self.w.unit("alpha")
        (entry,) = self.board(token, u)
        self.assertEqual(self.w.cli("plan", "--token", token)[0], 0)
        # Retargeted at the default branch after every read the conductor makes, as GitHub gets the merge.
        self.w.set_gh(lambda s: s.__setitem__("retarget_before_merge", {"pr": u["pr"], "to": W.DEFAULT}))
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual(self.w.remote_ref(W.DEFAULT), main_before, "the merge reached the default branch")
        self.assertEqual((rc, out.get("result")), (0, "merged"), out)
        self.assertEqual(self.w.merged_heads(), [u["reviewed_sha"]])
        merge_sha = self.w.remote_ref(W.BASE)
        parents = self.w.git(self.w.tmp, "--git-dir", str(self.w.bare), "rev-list", "--parents", "-n", "1", merge_sha)
        self.assertEqual(parents.split()[1:], [base_before, u["reviewed_sha"]])
        pr = self.w.gh_state()["prs"][str(u["pr"])]
        self.assertEqual((pr["baseRefName"], pr["state"]), (W.DEFAULT, "OPEN"), "a PR aimed at the default was merged")
        rc, out = self.w.cli("ack", "--token", token, "--entry", entry)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.w.git(self.w.tmp, "--git-dir", str(self.w.bare), "branch", "--list", u["branch"]),
                         u["branch"], "the head branch of a PR not merged on GitHub was deleted")

    def test_the_github_write_names_the_base_and_the_accepted_commit(self):
        token = self.acquire()
        u = self.w.unit("alpha")
        self.board(token, u)
        self.w.cli("plan", "--token", token)
        self.assertEqual(self.w.cli("merge", "--token", token)[0], 0)
        call = self.w.merge_log("start")[0]["argv"]
        self.assertIn(f"base={W.BASE}", call)
        self.assertIn(f"head={u['reviewed_sha']}", call)
        self.assertEqual(self.w.gh_state()["prs"][str(u["pr"])]["state"], "MERGED")

    def test_a_base_that_is_not_a_plain_branch_name_is_refused_at_init(self):
        for bad in ("integration:refs/heads/main", "refs/heads/main", "-main", "a..b"):
            with self.subTest(bad=bad):
                rc, out = self.w.cli("init", f"--base={bad}", "--default", W.DEFAULT, "--consent", "grant:x",
                                     "--host", "github.invalid")
                self.assertEqual((rc, out.get("code")), (2, "usage"), out)

    def test_an_in_flight_merge_github_landed_elsewhere_is_never_adopted(self):
        token = self.acquire()
        u = self.w.unit("alpha")
        (entry,) = self.board(token, u)
        self.w.cli("plan", "--token", token)
        mq = self.w.queue(mq_mod)
        mq._send = lambda *a, **k: (_ for _ in ()).throw(SystemExit("conductor died before the send"))
        with self.assertRaises(SystemExit):
            mq.merge(token)
        self.assertEqual(self.state_of(entry), "merging")
        # Meanwhile the PR is retargeted at the default branch and merged there, outside the fleet.
        self.w.set_gh(lambda s: s["prs"][str(u["pr"])].__setitem__("baseRefName", W.DEFAULT))
        subprocess.run([str(self.w.tmp / "bin" / "gh"), "pr", "merge", str(u["pr"]), "--merge"], env=self.w.env,
                       capture_output=True, check=True)
        rc, out = self.w.cli("acquire", "--base", W.BASE, "--holder", "c2", "--takeover")
        self.assertEqual(rc, 0, out)
        decision = out["reconciled"][0]
        self.assertEqual((decision["resolution"], decision["reason"]), ("failed", "merged_not_on_base"), decision)
        self.assertEqual(self.state_of(entry), "failed")
        self.assertEqual(self.w.merged_heads(), [])


class BranchTeardown(QueueCase):
    """The merged head branch is deleted from the right repository, once, even across a restart (PR #647)."""

    FORK = "github.invalid/fork/repo"

    def _branch_exists(self, bare, branch):
        return self.w.git(self.w.tmp, "--git-dir", str(bare), "branch", "--list", branch) == branch

    def _teardowns(self, entry):
        return [r["body"] for r in self.receipts(entry) if r["kind"] == "branch_teardown"]

    def _boarded(self):
        token = self.acquire()
        u = self.w.unit("alpha")
        (entry,) = self.board(token, u)
        return token, u, entry

    def _crash_at(self, token, stage, **merge):
        """A conductor that dies at one merge boundary (no finally, no teardown of its own)."""
        self.assertEqual(self.w.cli("plan", "--token", token)[0], 0)
        mq = self.w.queue(mq_mod)

        def die(at, _info):
            if at == stage:
                raise SystemExit(f"conductor died at {at}")
        mq.on_boundary = die
        with self.assertRaises(SystemExit):
            mq.merge(token, **merge)

    def test_a_fork_head_branch_is_never_deleted_from_the_queues_repository(self):
        token, u, entry = self._boarded()
        fork = self.w.fork(self.FORK)  # the fork carries `alpha` at the same commit as upstream does
        self.w.set_gh(lambda s: s["prs"][str(u["pr"])].__setitem__("headRepo", self.FORK))
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual(rc, 0, out)
        self.assertTrue(self._branch_exists(self.w.bare, "alpha"), "an upstream branch was deleted for a fork's PR")
        self.assertTrue(self._branch_exists(fork, "alpha"), "a fork's branch was touched")
        (teardown,) = self._teardowns(entry)
        self.assertEqual((teardown["outcome"], teardown["headRepository"]), ("retained: head branch in a fork", self.FORK))

    def test_a_same_repository_head_branch_is_deleted_once_with_a_receipt(self):
        token, u, entry = self._boarded()
        self.w.cli("release", "--token", token)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual(rc, 0, out)
        self.assertFalse(self._branch_exists(self.w.bare, "alpha"))
        self.assertEqual([t["outcome"] for t in self._teardowns(entry)], ["deleted"])
        sends = [json.loads(x) for x in self.w.ledger.read_text().splitlines()]
        self.assertEqual([x["payload_class"] for x in sends], ["pr-merge", "branch-delete"],
                         "the branch deletion left the machine without an egress receipt")


    def test_a_restart_after_the_remote_merge_still_tears_the_branch_down(self):
        token, _u, entry = self._boarded()
        self._crash_at(token, "remote_merged")
        self.assertTrue(self._branch_exists(self.w.bare, "alpha"))
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.state_of(entry), "landed")
        self.assertFalse(self._branch_exists(self.w.bare, "alpha"), "the restart left the merged branch behind")
        self.assertEqual([t["outcome"] for t in self._teardowns(entry)], ["deleted"])

    def test_a_restart_before_the_ack_still_tears_the_branch_down(self):
        token, _u, entry = self._boarded()
        self._crash_at(token, "merged_recorded")
        self.assertEqual(self.state_of(entry), "merged")
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual(rc, 0, out)
        self.assertFalse(self._branch_exists(self.w.bare, "alpha"), "the restart left the merged branch behind")
        self.assertEqual([t["outcome"] for t in self._teardowns(entry)], ["deleted"])

    def test_keep_branch_is_honoured_across_a_restart(self):
        token, _u, entry = self._boarded()
        self._crash_at(token, "remote_merged", delete_branch=False)
        rc, out = self.w.cli("drain", "--base", W.BASE, "--holder", "c1", "--ack")  # no --keep-branch this time
        self.assertEqual(rc, 0, out)
        self.assertTrue(self._branch_exists(self.w.bare, "alpha"), "--keep-branch was forgotten on restart")
        self.assertEqual([t["outcome"] for t in self._teardowns(entry)], ["kept: --keep-branch"])

    def test_a_teardown_github_has_not_caught_up_with_is_retried_later(self):
        token, u, entry = self._boarded()
        self.w.set_gh(lambda s: s.__setitem__("defer_merged_mark", True))
        self.w.cli("plan", "--token", token)
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out.get("branch")), (0, "pending: GitHub has not marked the PR merged yet"), out)
        self.assertTrue(self._branch_exists(self.w.bare, "alpha"))
        self.w.set_gh(lambda s: (s.pop("defer_merged_mark"), s["prs"][str(u["pr"])].__setitem__("state", "MERGED")))
        rc, out = self.w.cli("reconcile", "--token", token)
        self.assertEqual(rc, 0, out)
        self.assertFalse(self._branch_exists(self.w.bare, "alpha"))
        self.assertEqual([t["outcome"] for t in self._teardowns(entry)], ["deleted"])
        rc, out = self.w.cli("reconcile", "--token", token)  # idempotent: nothing left to tear down
        self.assertEqual([t["outcome"] for t in self._teardowns(entry)], ["deleted"])

    def test_a_deletion_whose_outcome_is_unknown_is_never_sent_twice(self):
        token, u, entry = self._boarded()
        self.w.set_gh(lambda s: s.__setitem__("defer_merged_mark", True))
        self.w.cli("plan", "--token", token)
        self.assertEqual(self.w.cli("merge", "--token", token)[0], 0)
        self.w.set_gh(lambda s: (s.pop("defer_merged_mark"), s["prs"][str(u["pr"])].__setitem__("state", "MERGED")))
        mq = self.w.queue(mq_mod)
        real_run = mq.git.run

        def die_at_the_deletion(*args, **kw):
            if args[:1] == ("push",) and any(a.startswith(":refs/heads/") for a in args):
                raise SystemExit("conductor died as it sent the deletion")
            return real_run(*args, **kw)
        mq.git.run = die_at_the_deletion
        with self.assertRaises(SystemExit):
            mq.settle_in_flight(token)
        # Whether that deletion left is unknown, and the branch is there (it never did, or was
        # recreated at the same commit): a restart must not send a second one.
        rc, out = self.w.cli("reconcile", "--token", token)
        self.assertEqual(rc, 0, out)
        self.assertTrue(self._branch_exists(self.w.bare, "alpha"), "a deletion of unknown outcome was sent again")
        self.assertEqual([t["outcome"] for t in self._teardowns(entry)],
                         ["retained: an earlier deletion's outcome is unknown and the branch exists"])

    def test_a_stale_conductor_never_tears_a_branch_down(self):
        token, u, entry = self._boarded()
        self.w.set_gh(lambda s: s.__setitem__("defer_merged_mark", True))
        self.w.cli("plan", "--token", token)
        self.assertEqual(self.w.cli("merge", "--token", token)[0], 0)
        self.w.set_gh(lambda s: (s.pop("defer_merged_mark"), s["prs"][str(u["pr"])].__setitem__("state", "MERGED")))
        self.acquire("c2", "--takeover")
        rc, out = self.w.cli("reconcile", "--token", token)
        self.assertEqual((rc, out.get("code")), (3, "fenced"), out)
        self.assertTrue(self._branch_exists(self.w.bare, "alpha"), "a fenced conductor deleted a branch")

class RepositoryIdentity(QueueCase):
    """One remote is one queue, whatever directory a conductor starts from (PR #647)."""

    mode = "git"

    def test_conductors_started_from_two_directories_share_one_identity_and_one_lease(self):
        # The clone names its remote relative to its own toplevel, which is where git resolves it.
        self.w.git(self.w.conductor, "remote", "set-url", "origin", "../remote.git")
        here = self.w.conductor
        elsewhere = self.w.tmp / "elsewhere" / "deeper"
        elsewhere.mkdir(parents=True)
        sub = self.w.conductor / "sub"
        sub.mkdir()
        rc1, first = self.w.cli(*self.w.init_args(), cwd=here)
        rc2, second = self.w.cli(*self.w.init_args(), cwd=elsewhere)
        rc3, third = self.w.cli("--repo-dir", str(sub), *self.w.init_args(), cwd=elsewhere)
        self.assertEqual((rc1, rc2, rc3), (0, 0, 0), (first, second, third))
        self.assertEqual({first["repo"], second["repo"], third["repo"]}, {str(self.w.bare.resolve())},
                         "one remote was given more than one queue identity")
        self.assertEqual((second["created"], third["created"]), (False, False))
        rc, one = self.w.cli("acquire", "--base", W.BASE, "--holder", "c1", cwd=here)
        self.assertEqual(rc, 0, one)
        rc, two = self.w.cli("acquire", "--base", W.BASE, "--holder", "c2", cwd=elsewhere)
        self.assertEqual((rc, two.get("code")), (3, "lease_held"), "a second conductor got its own lease")
        rc, two = self.w.cli("acquire", "--base", W.BASE, "--holder", "c2", "--takeover", cwd=elsewhere)
        self.assertEqual((rc, two.get("epoch")), (0, one["epoch"] + 1), two)
        rc, stale = self.w.cli("plan", "--token", one["token"], cwd=here)
        self.assertEqual((rc, stale.get("code")), (3, "fenced"), stale)

    def test_identity_follows_gits_own_url_rules(self):
        base = self.w.tmp / "clone-top"
        home = str(self.w.tmp / "home")
        cases = {
            "host:repo.git": "host/repo",  # scp-style, no user@: git uses ssh
            "user@Host.example:team/repo.git": "host.example/team/repo",
            "./host:repo.git": str((base / "host:repo.git").resolve()),  # a slash first: a local path
            "dir/with:colon": str((base / "dir/with:colon").resolve()),
            "../remote.git": str((base / "../remote.git").resolve()),
            "~/r.git": str(Path(home, "r.git").resolve()),  # git expands ~ for a local remote
            "https://github.com/Owner/Repo.git": "github.com/owner/repo",  # GitHub names fold case
        }
        for url, want in cases.items():
            with self.subTest(url=url):
                self.assertEqual(mq_mod.repo_identity(url, base, home=home), want)


class IdentityNormalisation(QueueCase):
    """Two spellings of one GitHub repository are one queue (PR #647: casing split the queue)."""

    mode = "git"

    def test_github_identities_are_normalised(self):
        same = ["https://github.com/Team/Repo.git", "https://github.com/team/repo", "https://GitHub.com/team/repo/",
                "https://www.github.com/Team/Repo.git/", "git@GitHub.com:Team/Repo.git", "ssh://git@github.com/team/REPO.git",
                "github.com:team/repo.git/"]
        self.assertEqual({mq_mod.repo_identity(u) for u in same}, {"github.com/team/repo"})
        # A GitHub Enterprise host folds case only once it is configured as GitHub.
        self.assertEqual(mq_mod.repo_identity("https://GHE.example/Team/Repo.git"), "ghe.example/Team/Repo")
        self.assertEqual(mq_mod.repo_identity("https://GHE.example/Team/Repo.git", github_hosts={"ghe.example"}),
                         "ghe.example/team/repo")
        # Another forge keeps its casing; only the host is lowercased.
        self.assertEqual(mq_mod.repo_identity("https://Forge.example/Team/Repo.git"), "forge.example/Team/Repo")

    def test_local_paths_keep_their_bytes_or_their_on_disk_case(self):
        real = self.w.tmp / "CaseDir.git"
        real.mkdir()
        spelled = self.w.tmp / "casedir.GIT"
        folded = mq_mod.repo_identity(str(spelled))
        if spelled.exists():  # a case-insensitive filesystem: the on-disk spelling is the identity
            self.assertEqual(folded, str(real.resolve()))
        else:  # case-sensitive: byte-exact, never lowercased
            self.assertEqual(folded, str(spelled.resolve()))
        self.assertEqual(mq_mod.repo_identity(str(real)), str(real.resolve()))

    def test_two_clones_spelling_one_github_repository_differently_share_one_queue(self):
        other = self.w.tmp / "other-clone"
        self.w.git(self.w.tmp, "clone", "-q", str(self.w.bare), str(other))
        self.w.point(self.w.conductor, "origin", "github.com/Team/Repo", self.w.bare)
        self.w.point(other, "origin", "github.com/team/repo", self.w.bare)
        rc1, first = self.w.cli(*self.w.init_args())
        rc2, second = self.w.cli("--repo-dir", str(other), *self.w.init_args())
        self.assertEqual((rc1, rc2), (0, 0), (first, second))
        self.assertEqual((first["repo"], second["repo"], second["created"]), ("github.com/team/repo",) * 2 + (False,))
        rc, one = self.w.cli("acquire", "--base", W.BASE, "--holder", "c1")
        self.assertEqual(rc, 0, one)
        rc, two = self.w.cli("--repo-dir", str(other), "acquire", "--base", W.BASE, "--holder", "c2")
        self.assertEqual((rc, two.get("code")), (3, "lease_held"), "a differently cased clone got its own lease")
        rc, two = self.w.cli("--repo", "github.com/TEAM/Repo", "status", "--base", W.BASE)
        self.assertEqual((rc, two.get("repo")), (0, "github.com/team/repo"), two)

    def test_a_store_holding_an_older_cased_identity_is_migrated_in_place(self):
        db = self.w.tmp / "old.db"
        conn = sqlite3.connect(db)
        conn.executescript(mq_mod.Store.SCHEMA)
        conn.execute("INSERT INTO mq_queues VALUES ('github.com/Team/Repo', 'integration', 'main', 'git', 'origin', "
                     "'github.com', 'grant:x', 3, 0)")
        conn.execute("INSERT INTO mq_leases VALUES ('github.com/Team/Repo', 'integration', 'c1', 'tok', 4, 1, 'h', 60, 0, "
                     "9e12, NULL)")
        conn.execute("INSERT INTO mq_tokens VALUES ('tok', 'github.com/Team/Repo', 'integration', 4, 'c1', 0)")
        conn.commit()
        conn.close()
        mq_mod.Store(db)
        conn = sqlite3.connect(db)
        rows = {t: conn.execute(f"SELECT repo FROM {t}").fetchall() for t in ("mq_queues", "mq_leases", "mq_tokens")}
        conn.close()
        self.assertEqual(rows, {t: [("github.com/team/repo",)] for t in rows}, "the lease would split from its queue")

    def test_a_migration_waits_for_a_writer_holding_the_old_spellings_lock(self):
        db = self.w.tmp / "held.db"
        conn = sqlite3.connect(db)
        conn.executescript(mq_mod.Store.SCHEMA)
        conn.execute("INSERT INTO mq_queues VALUES ('github.com/Team/Repo', 'integration', 'main', 'git', 'origin', "
                     "'github.com', 'grant:x', 1, 0)")
        conn.execute("INSERT INTO mq_leases VALUES ('github.com/Team/Repo', 'integration', 'c1', 'tok', 1, 1, 'h', 900, 0, "
                     "9e12, NULL)")
        conn.execute("INSERT INTO mq_tokens VALUES ('tok', 'github.com/Team/Repo', 'integration', 1, 'c1', 0)")
        conn.commit()
        conn.close()
        # The lock an earlier conductor (or its still-running merge child) holds: the old spelling's.
        name = hashlib.sha256("github.com/Team/Repo\0integration".encode()).hexdigest()[:24]
        held = db.parent / "merge-queue-locks" / f"{name}.lock"
        held.parent.mkdir(parents=True, exist_ok=True)
        holder = subprocess.Popen(
            [sys.executable, "-c", "import fcntl,os,sys;fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600);"
             "fcntl.flock(fd,fcntl.LOCK_EX);print('held',flush=True);sys.stdin.readline()", str(held)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: holder.poll() is None and holder.kill())
        self.assertEqual(holder.stdout.readline().strip(), "held")
        self.w.point(self.w.conductor, "origin", "github.com/team/repo", self.w.bare)
        rc, out = self.w.cli("--db", str(db), "acquire", "--base", W.BASE, "--holder", "c2", "--takeover")
        self.assertEqual((rc, out.get("code")), (1, "migration_blocked"), out)
        conn = sqlite3.connect(db)
        lease = conn.execute("SELECT repo, holder, epoch FROM mq_leases").fetchall()
        conn.close()
        self.assertEqual(lease, [("github.com/Team/Repo", "c1", 1)], "ownership moved under a held lock")
        holder.stdin.write("\n")
        holder.stdin.flush()
        holder.wait(timeout=30)
        holder.stdin.close()
        holder.stdout.close()
        rc, out = self.w.cli("--db", str(db), "acquire", "--base", W.BASE, "--holder", "c2", "--takeover")
        self.assertEqual((rc, out.get("repo"), out.get("epoch")), (0, "github.com/team/repo", 2), out)

    def test_every_spelling_of_one_repository_takes_one_lock(self):
        mq = self.w.queue(mq_mod)
        paths = {mq._lock(r, W.BASE).path for r in ("github.com/Team/Repo", "github.com/team/repo",
                                                      "www.github.com/team/repo.git")}
        self.assertEqual(len(paths), 1, paths)

    def _github_queue(self):
        self.w.point(self.w.conductor, "origin", "github.com/Team/Repo", self.w.bare)
        rc, out = self.w.cli(*self.w.init_args())
        self.assertEqual((rc, out.get("repo")), (0, "github.com/team/repo"), out)
        rc, out = self.w.cli("acquire", "--base", W.BASE, "--holder", "c1")
        self.assertEqual(rc, 0, out)
        return out["token"]

    def test_a_delivery_naming_another_spelling_of_the_queues_repository_is_accepted(self):
        token = self._github_queue()
        u = self.w.unit("alpha")
        for spelling in ("github.com/Team/Repo", "https://www.GitHub.com/TEAM/repo.git", "git@github.com:Team/Repo.git"):
            with self.subTest(spelling=spelling):
                rc, out = self.w.cli("enqueue", "--token", token, "--payload", json.dumps({**u, "repo": spelling}))
                self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.status_of("github.com/team/repo")["all"]), 1, "one unit boarded more than once")
        rc, out = self.w.cli("enqueue", "--token", token, "--payload", json.dumps({**u, "repo": "github.com/other/repo"}))
        self.assertEqual((rc, out.get("code")), (2, "repo_mismatch"), out)

    def test_every_entry_point_accepts_any_spelling_of_the_repository(self):
        self._github_queue()
        mq = self.w.queue(mq_mod)
        self.assertEqual(mq.status("github.com/Team/Repo", W.BASE)["repo"], "github.com/team/repo")
        self.assertEqual(mq.receipts("www.github.com/TEAM/Repo.git", W.BASE)["ok"], True)
        with self.assertRaises(mq_mod.QueueError) as held:
            mq.acquire(repo="github.com/TEAM/repo", base=W.BASE, holder="c2")
        self.assertEqual(held.exception.code, "lease_held", "another spelling got its own lease")
        rc, out = self.w.cli("--repo", "https://github.com/Team/Repo.git", "status", "--base", W.BASE)
        self.assertEqual((rc, out.get("repo")), (0, "github.com/team/repo"), out)

    def status_of(self, repo):
        rc, out = self.w.cli("--repo", repo, "status", "--base", W.BASE)
        self.assertEqual(rc, 0, out)
        return out

    def test_a_store_already_split_by_casing_is_refused_not_guessed(self):
        db = self.w.tmp / "split.db"
        conn = sqlite3.connect(db)
        conn.executescript(mq_mod.Store.SCHEMA)
        for repo in ("github.com/Team/Repo", "github.com/team/repo"):
            conn.execute("INSERT INTO mq_queues VALUES (?, 'integration', 'main', 'git', 'origin', 'github.com', "
                         "'grant:x', 1, 0)", (repo,))
        conn.commit()
        conn.close()
        rc, out = self.w.cli("--db", str(db), "--repo", "github.com/team/repo", "status", "--base", W.BASE)
        self.assertEqual((rc, out.get("code")), (2, "queue_split"), out)


class GitLaneRepositoryBinding(QueueCase):
    mode = "git"

    def _fork_and_board(self):
        fork = self.w.tmp / "fork.git"
        self.w.git(self.w.tmp, "clone", "-q", "--bare", str(self.w.bare), str(fork))
        token = self.acquire()
        self.board(token, self.w.unit("alpha"))
        self.w.cli("release", "--token", token)
        return fork, self.w.git(self.w.tmp, "--git-dir", str(fork), "rev-parse", W.BASE)

    def _refused(self, fork, fork_base):
        rc, out = self.w.cli("--repo", self.repo, "drain", "--base", W.BASE, "--holder", "c1", "--ack")
        self.assertEqual((rc, out.get("code")), (1, "repo_mismatch"), out)
        self.assertEqual(self.w.git(self.w.tmp, "--git-dir", str(fork), "rev-parse", W.BASE), fork_base,
                         "the merge was pushed to another repository")
        self.assertEqual(self.w.merged_heads(), [])

    def test_a_push_url_to_another_repository_is_refused(self):
        fork, fork_base = self._fork_and_board()
        self.w.git(self.w.conductor, "config", "remote.origin.pushurl", str(fork))
        self._refused(fork, fork_base)

    def test_a_remote_repointed_after_init_is_refused(self):
        fork, fork_base = self._fork_and_board()
        self.w.git(self.w.conductor, "remote", "set-url", "origin", str(fork))
        self._refused(fork, fork_base)


class GitLaneOffline(QueueCase):
    mode = "git"

    def test_an_unreachable_remote_blocks_the_no_gh_lane_and_loses_nothing(self):
        token = self.acquire()
        (entry,) = self.board(token, self.w.unit("alpha"))
        self.w.cli("plan", "--token", token)
        away = self.w.bare.with_name("remote.away")
        self.w.bare.rename(away)  # the same repository, unreachable (re-pointing origin is a binding refusal)
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out.get("code")), (1, "offline"), out)
        self.assertEqual(self.state_of(entry), "queued")
        away.rename(self.w.bare)
        rc, out = self.w.cli("merge", "--token", token)
        self.assertEqual((rc, out["noGh"]), (0, True), out)
        rc, out = self.w.cli("ack", "--token", token, "--entry", entry)
        self.assertEqual((rc, out["ledger"]), (0, "no-gh: local-merge"))
        merge = self.w.remote_ref(W.BASE)
        author = self.w.git(self.w.tmp, "--git-dir", str(self.w.bare), "log", "-1", "--format=%an", merge)
        self.assertEqual(author, "Fleet Maintainer")


class StoreMigration(unittest.TestCase):
    def test_an_older_store_gains_the_new_columns_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "mq.db"
            conn = sqlite3.connect(db)
            conn.executescript(mq_mod.Store.SCHEMA)
            conn.execute("INSERT INTO mq_queues VALUES ('r', 'b', 'main', 'gh', 'origin', 'h', 'c', 1, 0)")
            conn.commit()
            have = {r[1] for r in conn.execute("PRAGMA table_info(mq_entries)")}
            conn.close()
            self.assertNotIn("tested_tree", have)
            mq_mod.Store(db)
            mq_mod.Store(db)  # idempotent: a second open adds nothing and raises nothing
            conn = sqlite3.connect(db)
            have = {r[1] for r in conn.execute("PRAGMA table_info(mq_entries)")}
            kept = conn.execute("SELECT base FROM mq_queues").fetchall()
            conn.close()
            self.assertTrue(set(mq_mod.Store.COLUMNS["mq_entries"]) <= have)
            self.assertEqual(kept, [("b",)])

    def test_concurrent_openers_both_succeed(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "mq.db"
            code = ("import importlib.util,sys;s=importlib.util.spec_from_file_location('m',sys.argv[1]);"
                    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.Store(sys.argv[2]);print('ok')")
            procs = [subprocess.Popen([sys.executable, "-c", code, str(W.SCRIPT), str(db)], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True) for _ in range(4)]
            results = [p.communicate(timeout=60) for p in procs]
            self.assertEqual([p.returncode for p in procs], [0] * 4, results)

    OPENER = ("import importlib.util,sys;s=importlib.util.spec_from_file_location('m',sys.argv[1]);"
              "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.Store(sys.argv[2]);print('ok')")

    def _open_together(self, db: Path, count: int) -> None:
        procs = [subprocess.Popen([sys.executable, "-c", self.OPENER, str(W.SCRIPT), str(db)], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) for _ in range(count)]
        errors = [p.communicate(timeout=120)[1] for p in procs]
        self.assertEqual([p.returncode for p in procs], [0] * count, [e for e in errors if e])

    def test_many_openers_of_a_fresh_store_all_succeed_round_after_round(self):
        # The CI race (PR #647): switching a fresh store to WAL refused a concurrent opener with
        # `database is locked` instead of waiting. One round of four rarely shows it; eight
        # openers over several rounds made it reproducible.
        for _round in range(6):
            with tempfile.TemporaryDirectory() as tmp:
                self._open_together(Path(tmp) / "mq.db", 8)

    def test_openers_racing_a_migration_all_succeed(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "mq.db"
            conn = sqlite3.connect(db)
            conn.executescript(mq_mod.Store.SCHEMA)  # an older store: rollback journal, no new columns
            conn.close()
            self._open_together(db, 8)
            conn = sqlite3.connect(db)
            names = [r[1] for r in conn.execute("PRAGMA table_info(mq_entries)")]
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            conn.close()
            self.assertTrue(set(mq_mod.Store.COLUMNS["mq_entries"]) <= set(names))
            self.assertEqual(mode, "wal")


class _ScriptedConnection:
    """A connection whose journal-mode switch is scripted: `locked` refusals, then `answer`."""

    def __init__(self, answer, locked=0, max_calls=40):
        self.mode, self.answer, self.locked, self.max_calls = "delete", answer, locked, max_calls
        self.calls = self.switches = 0

    def execute(self, sql):
        self.calls += 1
        if self.calls > self.max_calls:
            raise RuntimeError(f"the WAL switch is spinning ({self.calls} statements)")
        if sql.strip() == "PRAGMA journal_mode=WAL;":
            self.switches += 1
            if self.locked:
                self.locked -= 1
                raise sqlite3.OperationalError("database is locked")
            self.mode = self.answer
        return self

    def fetchone(self):
        return (self.mode,)


class WalSwitch(unittest.TestCase):
    """The WAL switch retries a lock only, and ends on any mode SQLite answers (PR #647 follow-up)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = mq_mod.Store(Path(self.tmp.name) / "mq.db")

    def test_a_store_sqlite_keeps_out_of_wal_opens_promptly(self):
        code = ("import importlib.util,sys;s=importlib.util.spec_from_file_location('m',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.Store(':memory:');print('ok')")
        try:
            proc = subprocess.run([sys.executable, "-c", code, str(W.SCRIPT)], capture_output=True, text=True,
                                  timeout=20, cwd=self.tmp.name)
        except subprocess.TimeoutExpired:
            self.fail("opening an in-memory store spun in the WAL switch instead of returning")
        self.assertEqual((proc.returncode, proc.stdout.strip()), (0, "ok"), proc.stderr)

    def test_a_mode_sqlite_answers_without_error_ends_the_switch(self):
        conn = _ScriptedConnection(answer="delete")
        self.store._wal(conn)
        self.assertEqual(conn.switches, 1, "a mode SQLite settled on was asked for again")

    def test_a_locked_switch_is_still_retried(self):
        conn = _ScriptedConnection(answer="wal", locked=3)
        self.store._wal(conn)
        self.assertEqual((conn.switches, conn.mode), (4, "wal"))

    def test_a_switch_locked_past_the_deadline_gives_up_clearly(self):
        self.store.BUSY_SECONDS = 0.3
        conn = _ScriptedConnection(answer="wal", locked=10**6, max_calls=10**6)
        started = time.monotonic()
        with self.assertRaises(mq_mod.QueueError) as refused:
            self.store._wal(conn)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(refused.exception.code, "store_locked")
        self.assertIn("WAL", refused.exception.message)

    def test_a_schema_comment_holding_a_semicolon_is_not_a_statement_break(self):
        class Commented(mq_mod.Store):
            SCHEMA = "-- a note; with a semicolon in it\n" + mq_mod.Store.SCHEMA
        Commented(Path(self.tmp.name) / "commented.db")


class DoctrineWiring(unittest.TestCase):
    def test_the_policy_names_the_mechanism_that_enforces_it(self):
        text = (ROOT / "runtime" / "merge-serialization.md").read_text(encoding="utf-8")
        self.assertIn("merge_queue.py", text, "merge serialization is doctrine with no mechanism named")

    def test_the_reference_page_documents_the_script(self):
        text = (ROOT / "docs" / "runtime-scripts.md").read_text(encoding="utf-8")
        self.assertIn("## `merge_queue.py`", text)
        self.assertIn("tests/test_merge_queue_drills.py", text)


if __name__ == "__main__":
    unittest.main()
