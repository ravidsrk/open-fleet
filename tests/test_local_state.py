#!/usr/bin/env python3
"""LocalStateStore acceptance tests (#579, PR #591 re-review): DAG closure, mailbox scoping,
coordinator fencing under concurrency, real HITL gates, atomic synthetic worker_died."""
from __future__ import annotations

import importlib
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _ls():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module("runtime.providers.local_state")


def _claim(db, run, handle, q):
    mod = _ls()
    try:
        mod.LocalStateStore(db, env={}).check_messages(terminal=handle, run=run)
        q.put(("ok", handle))
    except mod.ProviderError as exc:
        q.put((exc.code, handle))
    except Exception as exc:  # a raw sqlite IntegrityError is a failure of the fence
        q.put((type(exc).__name__, handle))


class Base(unittest.TestCase):
    def setUp(self):
        self.mod = _ls()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "s.db")
        self.store = self.mod.LocalStateStore(self.db, env={})


class TestDag(Base):
    def _t(self, deps=None):
        return self.store.task_create(spec="s", deps=deps)["task"]["id"]

    def test_failure_blocks_whole_downstream_closure_and_retry_unblocks(self):
        a = self._t()
        b = self._t([a])
        c = self._t([b])
        d = self._t([c])
        self.store.task_update(task_id=a, status="failed")
        st = {t["id"]: t["status"] for t in self.store.task_list()["tasks"]}
        self.assertEqual((st[b], st[c], st[d]), ("blocked", "blocked", "blocked"))
        self.store.task_update(task_id=a, status="completed")
        st = {t["id"]: t["status"] for t in self.store.task_list()["tasks"]}
        self.assertEqual((st[b], st[c], st[d]), ("ready", "pending", "pending"))
        self.store.task_update(task_id=b, status="completed")
        self.store.task_update(task_id=c, status="completed")
        st = {t["id"]: t["status"] for t in self.store.task_list()["tasks"]}
        self.assertEqual(st[d], "ready")

    def test_unknown_dependency_is_refused(self):
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.task_create(spec="s", deps=["task_nope"])
        self.assertEqual(ctx.exception.code, "task_not_found")

    def test_invalid_status_is_refused(self):
        a = self._t()
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.task_update(task_id=a, status="banana")
        self.assertEqual(ctx.exception.code, "invalid_status")

    def test_dag_gate_blocks_until_resolved(self):
        a = self._t()
        b = self._t([a])
        g = self.store.gate_create(task_id=a, question="ship?", options='["yes","no"]')["gate"]
        self.assertEqual({t["id"]: t["status"] for t in self.store.task_list()["tasks"]}[a], "blocked")
        self.store.task_update(task_id=a, status="blocked")
        self.assertEqual({t["id"]: t["status"] for t in self.store.task_list()["tasks"]}[b], "blocked")
        self.store.gate_resolve(gate_id=g["id"], resolution="yes")
        st = {t["id"]: t["status"] for t in self.store.task_list()["tasks"]}
        self.assertEqual(st[a], "ready")
        self.assertEqual(self.store.gate_list(task_id=a)["gates"][0]["status"], "resolved")

    def test_gate_resolved_after_deps_finish_makes_task_ready(self):
        a = self._t()
        b = self._t([a])
        g = self.store.gate_create(task_id=b, question="ok?")["gate"]  # gated while pending
        self.store.task_update(task_id=a, status="completed")
        self.store.gate_resolve(gate_id=g["id"], resolution="ok", sender="coordinator")
        self.assertEqual({t["id"]: t["status"] for t in self.store.task_list()["tasks"]}[b], "ready")

    def test_gate_create_needs_json_options(self):
        a = self._t()
        with self.assertRaises(self.mod.ProviderError):
            self.store.gate_create(task_id=a, question="q", options="yes,no")


class TestMailboxScoping(Base):
    def _register_worker(self, handle):
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES (?, 't', 'run1', '/w', 'claude', ?, 'ready', 0, 0)",
                (f"disp_{handle}", handle),
            )

    def test_worker_cannot_read_or_ack_coordinator_mail(self):
        self._register_worker("term_w1")
        sent = self.store.send_message(subject="done", msg_type="worker_done", to="coordinator", sender="term_w2", run="run1")
        mine = self.store.check_messages(terminal="term_w1", run="run1")
        self.assertEqual(mine["count"], 0)
        self.store.check_messages(terminal="term_w1", run="run1", ack=sent["deliveryId"])
        coord = self.store.check_messages(terminal="term_coord", run="run1")
        self.assertEqual(coord["count"], 1, "worker ack must not drain the coordinator inbox")

    def test_env_terminal_scopes_unflagged_check(self):
        self._register_worker("term_w1")
        self.store.send_message(subject="x", msg_type="info", to="coordinator", run="run1")
        worker_store = self.mod.LocalStateStore(self.db, env={"OPEN_FLEET_TERMINAL_HANDLE": "term_w1"})
        self.assertEqual(worker_store.check_messages(run="run1")["count"], 0)

    def test_fenced_run_refuses_second_coordinator_and_anonymous_reader(self):
        self.store.check_messages(terminal="term_a", run="run9")
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.check_messages(terminal="term_b", run="run9")
        self.assertEqual(ctx.exception.code, "consumer_fenced")
        with self.assertRaises(self.mod.ProviderError):
            self.store.check_messages(run="run9")

    def test_concurrent_claimers_get_one_owner_and_typed_fences(self):
        q = multiprocessing.get_context("spawn").Queue()
        procs = [
            multiprocessing.get_context("spawn").Process(target=_claim, args=(self.db, "runR", f"term_c{i}", q))
            for i in range(10)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(60)
        results = [q.get(timeout=10) for _ in procs]
        codes = sorted(r[0] for r in results)
        self.assertEqual(codes.count("ok"), 1, results)
        self.assertEqual(codes.count("consumer_fenced"), 9, results)

    def test_launched_worker_is_pinned_to_its_own_mailbox(self):
        self.store.send_message(subject="for coord", msg_type="worker_done", to="coordinator", run="default")
        self.store.send_message(subject="for me", msg_type="info", to="term_me", run="default")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp_me', 't_me', 'default', '/w', 'claude', 'term_me', 'running', 0, 0)"
            )
        worker = self.mod.LocalStateStore(self.db, env={"OPEN_FLEET_DISPATCH_ID": "disp_me", "OPEN_FLEET_TERMINAL_HANDLE": "term_me"})
        got = worker.check_messages(terminal="coordinator")
        self.assertEqual([m["subject"] for m in got["messages"]], ["for me"])

    def test_send_receipt_has_relay_message_id(self):
        r = self.store.send_message(subject="s", msg_type="info")
        self.assertEqual(r["relay"]["messageId"], r["messageId"])


class TestHitlGates(Base):
    def test_ask_reply_resume_round_trip(self):
        res = self.store.ask_human(question="deploy?", options="yes,no", sender="term_w", run="r1")
        self.assertTrue(res["timedOut"])
        self.assertTrue(res["messageId"].startswith("msg_"), "reply targets the question MESSAGE id")
        self.store.reply_message(msg_id=res["messageId"], body="yes")
        resumed = self.store.ask_human(resume=res["messageId"])
        self.assertEqual(resumed["answer"], "yes")
        self.assertFalse(resumed["timedOut"])

    def test_blocking_ask_wakes_on_reply(self):
        holder = {}

        def ask():
            holder["res"] = self.store.ask_human(question="go?", sender="term_w", timeout_ms=10000, retry_request="gate_fixed")

        t = threading.Thread(target=ask)
        t.start()
        mid = None
        for _ in range(100):
            gates = self.store.gate_list()["gates"]
            if gates:
                mid = gates[0]["messageId"]
                break
            time.sleep(0.05)
        self.assertIsNotNone(mid)
        self.store.reply_message(msg_id=mid, body="go")
        t.join(10)
        self.assertEqual(holder["res"]["answer"], "go")

    def test_retry_never_wipes_an_answer_or_duplicates_question(self):
        res = self.store.ask_human(question="q?", retry_request="gate_same")
        self.store.reply_message(msg_id=res["messageId"], body="A")
        again = self.store.ask_human(question="q?", retry_request="gate_same")
        self.assertEqual(again["answer"], "A")
        qs = [m for m in self.store.check_messages(terminal="coordinator", mode="all")["messages"] if m["type"] == "question"]
        self.assertEqual(len(qs), 1)

    def test_workers_cannot_answer_a_gate(self):
        res = self.store.ask_human(question="ship?", sender="term_w", run="r1")
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.reply_message(msg_id=res["messageId"], body="yes", sender="term_w")
        self.assertEqual(ctx.exception.code, "gate_answer_refused")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp_x', 't_x', 'r1', '/w', 'claude', 'term_x', 'running', 0, 0)"
            )
        worker = self.mod.LocalStateStore(self.db, env={"OPEN_FLEET_DISPATCH_ID": "disp_x", "OPEN_FLEET_TERMINAL_HANDLE": "term_x"})
        with self.assertRaises(self.mod.ProviderError):
            worker.reply_message(msg_id=res["messageId"], body="yes", sender="coordinator")
        self.assertTrue(self.store.ask_human(resume=res["messageId"])["timedOut"], "still unanswered")

    def test_gate_resolve_route_refuses_workers_too(self):
        res = self.store.ask_human(question="deploy?", sender="term_w", run="r1")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp_w', 't_w', 'r1', '/w', 'claude', 'term_w', 'running', 0, 0)"
            )
        worker = self.mod.LocalStateStore(self.db, env={"OPEN_FLEET_DISPATCH_ID": "disp_w", "OPEN_FLEET_TERMINAL_HANDLE": "term_w"})
        with self.assertRaises(self.mod.ProviderError) as ctx:
            worker.gate_resolve(gate_id=res["gateId"], resolution="yes")
        self.assertEqual(ctx.exception.code, "gate_answer_refused")
        with self.assertRaises(self.mod.ProviderError):
            self.store.gate_resolve(gate_id=res["gateId"], resolution="yes", sender="term_w")
        self.assertTrue(self.store.ask_human(resume=res["gateId"])["timedOut"], "still unanswered")
        self.store.gate_resolve(gate_id=res["gateId"], resolution="yes", sender="coordinator")
        self.assertEqual(self.store.ask_human(resume=res["gateId"])["answer"], "yes")

    def test_answering_acks_the_question_so_it_stops_reading_as_waiting(self):
        res = self.store.ask_human(question="go?", sender="term_w", run="r1")
        self.assertTrue(self.store.has_pending_question("term_w", run_id="r1"))
        self.store.reply_message(msg_id=res["messageId"], body="go")
        self.assertFalse(self.store.has_pending_question("term_w", run_id="r1"))

    def test_no_preset_answer_env_is_honoured(self):
        store = self.mod.LocalStateStore(self.db, env={"OPEN_FLEET_ASK_ANSWER": "yes"})
        res = store.ask_human(question="really?")
        self.assertIsNone(res["answer"], "a fleet never fakes a human answer")


class TestWorkerDied(Base):
    def _dispatch(self, did, state="ready"):
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES (?, 't', 'default', '/w', 'claude', ?, ?, 0, 0)",
                (did, f"term_{did}", state),
            )

    def test_concurrent_callers_emit_exactly_one(self):
        self._dispatch("d1")
        out = []
        ts = [
            threading.Thread(target=lambda: out.append(self.store.ensure_terminal_or_died(dispatch_id="d1", worktree_head_sha="a" * 40)))
            for _ in range(8)
        ]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(sum(1 for r in out if r["syntheticDied"]), 1)
        msgs = self.store.check_messages(terminal="coordinator")["messages"]
        self.assertEqual(len(msgs), 1)
        self.assertEqual(json.loads(msgs[0]["payload"])["headSha"], "a" * 40)

    def test_fenced_dispatch_is_left_alone(self):
        self._dispatch("d2", state="stopped")
        self.assertFalse(self.store.ensure_terminal_or_died(dispatch_id="d2")["syntheticDied"])
        self.assertEqual(self.store.dispatch_state("d2"), "stopped")


class TestDefaultDbPath(unittest.TestCase):
    def test_per_repo_and_shared_across_linked_worktrees(self):
        mod = _ls()
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a"
            b = Path(tmp) / "b"
            for r in (a, b):
                r.mkdir()
                subprocess.run(["git", "init", "-q", str(r)], check=True)
            subprocess.run(["git", "-C", str(a), "-c", "user.email=x@y", "-c", "user.name=x", "commit", "-q", "--allow-empty", "-m", "i"], check=True)
            wt = Path(tmp) / "a-wt"
            subprocess.run(["git", "-C", str(a), "worktree", "add", "-q", str(wt)], check=True)
            pa = mod.default_db_path({"OPEN_FLEET_CLI_CWD": str(a)})
            pb = mod.default_db_path({"OPEN_FLEET_CLI_CWD": str(b)})
            pw = mod.default_db_path({"OPEN_FLEET_CLI_CWD": str(wt)})
            self.assertNotEqual(pa, pb)
            self.assertEqual(pa, pw)
            self.assertEqual(pa.name, "runtime.db")
            self.assertTrue(str(pa).startswith(str(Path.home() / ".open-fleet" / "state")))
        self.assertTrue(os.path.isabs(str(mod.default_db_path({"OPEN_FLEET_STATE_DB": "rel.db"}))))


class TestDeadClaimerIsReclaimed(Base):
    """2026-10-26 review: a claim left by a caller that died held the request id for
    PENDING_STALE_S; one whose recorded claimer is gone from this host is reclaimed at once."""

    def claim_row(self, pid):
        import socket
        with self.store._connect() as conn:
            conn.execute("INSERT INTO requests(request_id, method, state, response_json, created_at, claim_pid, claim_host) "
                         "VALUES ('req-1', 'task-create', 'pending', NULL, ?, ?, ?)",
                         (time.time(), pid, socket.gethostname()))

    def test_a_claim_whose_process_is_gone_is_reclaimed(self):
        proc = subprocess.Popen(["true"])
        proc.wait()
        self.claim_row(proc.pid)
        self.assertIsNone(self.store.get_or_record_request("req-1", "task-create"), "the dead claim should be reclaimed")
        row = self.store.request_row("req-1")
        self.assertEqual((row["state"], row["claim_pid"]), ("pending", os.getpid()))

    def test_a_live_claim_is_a_pending_marker(self):
        self.claim_row(os.getpid())
        self.assertEqual(self.store.get_or_record_request("req-1", "task-create"),
                         {"state": "pending", "requestId": "req-1"})

    def test_a_claim_from_another_host_waits_out_the_stale_window(self):
        with self.store._connect() as conn:
            conn.execute("INSERT INTO requests(request_id, method, state, response_json, created_at, claim_pid, claim_host) "
                         "VALUES ('req-1', 'task-create', 'pending', NULL, ?, 1, 'elsewhere')", (time.time(),))
        self.assertEqual(self.store.get_or_record_request("req-1", "task-create")["state"], "pending")


class TestSchemaVersionStamp(Base):
    """2026-10-26 review: the store carried no schema version, so a store written by a newer
    open-fleet was read with an older layout without a word. It is stamped now, an unstamped
    (older) store is migrated and stamped as before, and a newer stamp is refused."""

    def version(self):
        with self.store._connect() as conn:
            return int(conn.execute("PRAGMA user_version").fetchone()[0])

    def test_a_store_is_stamped_with_this_schema_version(self):
        self.assertGreaterEqual(self.mod.SCHEMA_VERSION, 1)
        self.assertEqual(self.version(), self.mod.SCHEMA_VERSION)

    def test_an_unstamped_older_store_opens_and_is_stamped(self):
        with self.store._connect() as conn:
            conn.execute("PRAGMA user_version = 0")
        self.mod.LocalStateStore(self.db, env={})
        self.assertEqual(self.version(), self.mod.SCHEMA_VERSION)

    def test_a_store_from_a_newer_open_fleet_is_refused_not_misread(self):
        with self.store._connect() as conn:
            conn.execute(f"PRAGMA user_version = {self.mod.SCHEMA_VERSION + 1}")
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.mod.LocalStateStore(self.db, env={})
        self.assertEqual(ctx.exception.code, "state_schema_newer")
        self.assertEqual(self.version(), self.mod.SCHEMA_VERSION + 1, "a refused open changes nothing")


class TestRunBoundaryAndTaskSettlement(Base):
    """#750 C28 & C30: Run boundaries are enforced across tasks, deps, gates, replies, and
    worker_done / ensure_terminal_or_died settles the dispatch's task and recomputes dependents."""

    def _insert_dispatch(self, dispatch_id: str, task_id: str, handle: str, run_id: str = "default"):
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES (?, ?, ?, '/w', 'claude', ?, 'running', 0, 0)",
                (dispatch_id, task_id, run_id, handle),
            )

    def _status(self, task_id: str, run: str = "default") -> str:
        return {t["id"]: t["status"] for t in self.store.task_list(run=run)["tasks"]}[task_id]

    def test_c28_run_boundaries_across_tasks_deps_gates_and_replies(self):
        self.store.run_create(run="run-a", sender="coord-a")
        self.store.run_create(run="run-b", sender="coord-b")
        ta = self.store.task_create(spec="task a", run="run-a")["task"]["id"]
        tb = self.store.task_create(spec="task b", run="run-b")["task"]["id"]

        # Foreign dep and parent in task_create are refused
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.task_create(spec="cross dep", deps=[ta], run="run-b")
        self.assertEqual(ctx.exception.code, "cross_run_access")
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.task_create(spec="cross parent", parent=ta, run="run-b")
        self.assertEqual(ctx.exception.code, "cross_run_access")

        # Cross-run task_update is refused
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.task_update(task_id=ta, status="completed", run="run-b")
        self.assertEqual(ctx.exception.code, "cross_run_access")

        # Cross-run gate_create and gate_resolve are refused
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.gate_create(task_id=ta, question="hold?", sender="coord-b", run="run-b")
        self.assertEqual(ctx.exception.code, "cross_run_access")
        gate_a = self.store.gate_create(task_id=ta, question="hold?", sender="coord-a", run="run-a")["gate"]["id"]
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.gate_resolve(gate_id=gate_a, resolution="approved", sender="coord-a", run="run-b")
        self.assertEqual(ctx.exception.code, "cross_run_access")

        # Cross-run ask_human(resume=...) and reply_message are refused
        self._insert_dispatch("d-a", ta, "w-a", run_id="run-a")
        ask_res = self.store.ask_human(question="need help?", sender="w-a", run="run-a")
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.ask_human(resume=ask_res["messageId"], run="run-b")
        self.assertEqual(ctx.exception.code, "cross_run_access")
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.reply_message(msg_id=ask_res["messageId"], body="yes", sender="coord-a", run="run-b")
        self.assertEqual(ctx.exception.code, "cross_run_access")

        # Confirm tb in run-b stayed untouched
        self.assertEqual(self._status(tb, run="run-b"), "ready")

    def test_c30_worker_done_and_died_settle_task_and_dependents(self):
        t1 = self.store.task_create(spec="first")["task"]["id"]
        t2 = self.store.task_create(spec="second", deps=[t1])["task"]["id"]
        self.assertEqual(self._status(t2), "pending")

        self.store.task_update(task_id=t1, status="dispatched")
        self._insert_dispatch("disp-1", t1, "worker-1")
        self.assertEqual(self._status(t1), "dispatched")

        # Worker sends worker_done(outcome="succeeded") -> t1 completes and t2 becomes ready
        w_store = self.mod.LocalStateStore(
            self.db,
            env={"OPEN_FLEET_TERMINAL_HANDLE": "worker-1", "OPEN_FLEET_DISPATCH_ID": "disp-1"},
        )
        w_store.send_message(subject="done", msg_type="worker_done", outcome="succeeded", payload="done")
        self.assertEqual(self._status(t1), "completed")
        self.assertEqual(self._status(t2), "ready")

        # Dispatch t2 and simulate worker_done(outcome="failed") via relay_worker_done -> t2 fails and t3 blocks
        t3 = self.store.task_create(spec="third", deps=[t2])["task"]["id"]
        self.store.task_update(task_id=t2, status="dispatched")
        self._insert_dispatch("disp-2", t2, "worker-2")
        self.store.relay_worker_done(dispatch_id="disp-2", worker_handle="worker-2", outcome="failed")
        self.assertEqual(self._status(t2), "failed")
        self.assertEqual(self._status(t3), "blocked")

        # Reset t2 to ready, dispatch, and test send_message(msg_type="worker_done", outcome="failed") + ensure_terminal_or_died
        self.store.task_update(task_id=t2, status="ready")
        self.store.task_update(task_id=t2, status="dispatched")
        self._insert_dispatch("disp-3", t2, "worker-3")
        w3_store = self.mod.LocalStateStore(
            self.db,
            env={"OPEN_FLEET_TERMINAL_HANDLE": "worker-3", "OPEN_FLEET_DISPATCH_ID": "disp-3"},
        )
        w3_store.send_message(subject="done", msg_type="worker_done", outcome="failed", payload="fail")
        self.assertEqual(self._status(t2), "failed")
        res = self.store.ensure_terminal_or_died(dispatch_id="disp-3", worker_handle="worker-3", exit_code=1)
        self.assertFalse(res["syntheticDied"])
        self.assertEqual(self._status(t2), "failed")


class TestAtomicRequestAndPayloadBinding(Base):
    """#750 C31 & C33: Request receipt is saved in the same transaction as the effect, and
    reusing a retry_request with a different payload raises request_mismatch."""

    def test_c31_and_c33_payload_bound_idempotency_across_mutations(self):
        t = self.store.task_create(spec="alpha", title="Alpha", retry_request="req-tc")["task"]
        # Exact retry returns identical receipt
        t_again = self.store.task_create(spec="alpha", title="Alpha", retry_request="req-tc")["task"]
        self.assertEqual(t["id"], t_again["id"])
        # Changed payload with same retry_request raises request_mismatch
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.task_create(spec="beta", title="Alpha", retry_request="req-tc")
        self.assertEqual(ctx.exception.code, "request_mismatch")

        # task_update
        self.store.task_update(task_id=t["id"], status="completed", retry_request="req-tu")
        self.store.task_update(task_id=t["id"], status="completed", retry_request="req-tu")
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.task_update(task_id=t["id"], status="failed", retry_request="req-tu")
        self.assertEqual(ctx.exception.code, "request_mismatch")

        # send_message
        m1 = self.store.send_message(subject="s1", msg_type="info", payload="p1", to="coordinator", retry_request="req-sm")
        m2 = self.store.send_message(subject="s1", msg_type="info", payload="p1", to="coordinator", retry_request="req-sm")
        self.assertEqual(m1["messageId"], m2["messageId"])
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.send_message(subject="s1", msg_type="info", payload="p2", to="coordinator", retry_request="req-sm")
        self.assertEqual(ctx.exception.code, "request_mismatch")

        # gate_create & gate_resolve
        t2 = self.store.task_create(spec="gated")["task"]["id"]
        g1 = self.store.gate_create(task_id=t2, question="ok?", retry_request="req-gc")["gate"]
        g2 = self.store.gate_create(task_id=t2, question="ok?", retry_request="req-gc")["gate"]
        self.assertEqual(g1["id"], g2["id"])
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.gate_create(task_id=t2, question="different?", retry_request="req-gc")
        self.assertEqual(ctx.exception.code, "request_mismatch")

        r1 = self.store.gate_resolve(gate_id=g1["id"], resolution="yes", retry_request="req-gr")["gate"]
        r2 = self.store.gate_resolve(gate_id=g1["id"], resolution="yes", retry_request="req-gr")["gate"]
        self.assertEqual(r1["id"], r2["id"])
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.gate_resolve(gate_id=g1["id"], resolution="no", retry_request="req-gr")
        self.assertEqual(ctx.exception.code, "request_mismatch")


class TestDefaultDbPathIgnoresAmbientGitSelectors(unittest.TestCase):
    """#750 C34: Ambient GIT_DIR / GIT_WORK_TREE / GIT_COMMON_DIR must not redirect default_db_path."""

    def test_c34_ambient_git_env_ignored_when_resolving_repo_state_id(self):
        mod = _ls()
        with tempfile.TemporaryDirectory() as tmp:
            repo_a = Path(tmp) / "repo-a"
            repo_b = Path(tmp) / "repo-b"
            for r in (repo_a, repo_b):
                r.mkdir()
                subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True)
            clean_a = mod.default_db_path({"OPEN_FLEET_CLI_CWD": str(repo_a)})
            poisoned_a = mod.default_db_path({
                "OPEN_FLEET_CLI_CWD": str(repo_a),
                "GIT_DIR": str(repo_b / ".git"),
                "GIT_WORK_TREE": str(repo_b),
                "GIT_COMMON_DIR": str(repo_b / ".git"),
            })
            clean_b = mod.default_db_path({"OPEN_FLEET_CLI_CWD": str(repo_b)})
            self.assertEqual(clean_a, poisoned_a)
            self.assertNotEqual(clean_a, clean_b)


class TestCoordinatorTakeoverAndWorkerBindingFence(Base):
    """#750 C35: Workers cannot claim coordinator binding, former coordinators cannot resolve gates
    after takeover, and check_messages(wait=True) re-checks coordinator fence on takeover."""

    def test_c35_worker_cannot_claim_coordinator_and_takeover_fences_former_coordinator(self):
        t = self.store.task_create(spec="work")["task"]["id"]
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-w1', ?, 'default', '/w', 'claude', 'worker-1', 'running', 0, 0)",
                (t,),
            )

        # Worker handle cannot create or take over a run as coordinator
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.run_create(run="run-x", sender="worker-1")
        self.assertEqual(ctx.exception.code, "worker_cannot_be_coordinator")

        self.store.run_create(run="run-1", sender="coord-1")
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.run_use(run="run-1", sender="worker-1", takeover=True)
        self.assertEqual(ctx.exception.code, "worker_cannot_be_coordinator")

        # Gate created in run-1; after coord-2 takes over, coord-1 is fenced from resolving the gate
        t_r1 = self.store.task_create(spec="in run 1", run="run-1")["task"]["id"]
        gate = self.store.gate_create(task_id=t_r1, question="ship?", sender="coord-1", run="run-1")["gate"]["id"]
        self.store.run_use(run="run-1", sender="coord-2", takeover=True)
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.gate_resolve(gate_id=gate, resolution="yes", sender="coord-1", run="run-1")
        self.assertEqual(ctx.exception.code, "consumer_fenced")
        # Active coordinator coord-2 can resolve the gate
        resolved = self.store.gate_resolve(gate_id=gate, resolution="yes", sender="coord-2", run="run-1")["gate"]
        self.assertEqual(resolved["status"], "resolved")

        # A waiting check_messages(wait=True) loop by coord-1 is fenced if takeover happens mid-wait
        self.store.run_create(run="run-wait", sender="coord-1")
        err_holder: list[str] = []

        def waiter():
            try:
                self.store.check_messages(terminal="coord-1", run="run-wait", wait=True, timeout_ms=1500)
            except self.mod.ProviderError as exc:
                err_holder.append(exc.code)

        th = threading.Thread(target=waiter)
        th.start()
        time.sleep(0.12)
        self.store.run_use(run="run-wait", sender="coord-2", takeover=True)
        th.join(timeout=2.0)
        self.assertEqual(err_holder, ["consumer_fenced"])

    def test_c28_launched_worker_implicit_and_explicit_run_isolation(self):
        t_a = self.store.task_create(spec="in a", run="run-a")["task"]["id"]
        t_b = self.store.task_create(spec="in b", run="run-b")["task"]["id"]
        msg_b = self.store.send_message(subject="b-msg", msg_type="info", run="run-b")["messageId"]
        gate_b = self.store.gate_create(task_id=t_b, question="b-q?", run="run-b")["gate"]["id"]
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-a1', ?, 'run-a', '/w', 'claude', 'worker-a1', 'running', 0, 0)",
                (t_a,),
            )
        w_a = self.mod.LocalStateStore(
            self.db,
            env={"OPEN_FLEET_DISPATCH_ID": "disp-a1", "OPEN_FLEET_TERMINAL_HANDLE": "worker-a1"},
        )
        # Implicit calls default to run-a, not 'default'
        sub = w_a.task_create(spec="child")["task"]
        self.assertEqual(sub["runId"], "run-a")
        self.assertEqual({t["id"] for t in w_a.task_list()["tasks"]}, {t_a, sub["id"]})
        sent = w_a.send_message(subject="from-a", msg_type="info")
        self.assertEqual(self.store.check_messages(run="default")["count"], 0)
        self.assertEqual(self.store.check_messages(run="run-a")["count"], 1)
        self.assertEqual(sent["sent"], True)
        # Explicit or implicit cross-run access to run-b is rejected
        for fn in (
            lambda: w_a.task_create(spec="bad", run="run-b"),
            lambda: w_a.task_list(run="run-b"),
            lambda: w_a.task_update(task_id=t_b, status="completed"),
            lambda: w_a.send_message(subject="bad", msg_type="info", run="run-b"),
            lambda: w_a.check_messages(run="run-b"),
            lambda: w_a.reply_message(msg_id=msg_b, body="no"),
            lambda: w_a.ask_human(question="bad?", run="run-b"),
            lambda: w_a.gate_resolve(gate_id=gate_b, resolution="yes"),
            lambda: self.store.task_create(spec="bad-dep-init", run="run-a", deps=[t_b], initial_status="ready"),
        ):
            with self.assertRaises(self.mod.ProviderError) as ctx:
                fn()
            self.assertEqual(ctx.exception.code, "cross_run_access")
        with self.assertRaises(self.mod.ProviderError) as ctx_missing_dep:
            self.store.task_create(spec="missing-dep-init", run="run-a", deps=["task_missing_999"], initial_status="ready")
        self.assertEqual(ctx_missing_dep.exception.code, "task_not_found")
        # Declared worker identity with no dispatches row fails closed across all routes:
        w_unknown = self.mod.LocalStateStore(
            self.db,
            env={"OPEN_FLEET_DISPATCH_ID": "disp-unregistered", "OPEN_FLEET_TERMINAL_HANDLE": "worker-unregistered"},
        )
        for u_fn in (
            lambda: w_unknown.task_list(),
            lambda: w_unknown.task_create(spec="x", run="run-b"),
            lambda: w_unknown.task_update(task_id=t_b, status="completed"),
            lambda: w_unknown.send_message(subject="x", msg_type="info"),
            lambda: w_unknown.check_messages(),
            lambda: w_unknown.reply_message(msg_id=msg_b, body="no"),
            lambda: w_unknown.ask_human(question="q?"),
            lambda: w_unknown.gate_resolve(gate_id=gate_b, resolution="yes"),
            lambda: w_unknown.request_show("any-req"),
        ):
            with self.assertRaises(self.mod.ProviderError) as ctx_unk:
                u_fn()
            self.assertEqual(ctx_unk.exception.code, "cross_run_access")

    def test_c30_died_settles_task_and_superseded_or_forged_sender_cannot_clobber(self):
        t1 = self.store.task_create(spec="die-parent", run="run-d")["task"]["id"]
        t2 = self.store.task_create(spec="die-child", deps=[t1], run="run-d")["task"]["id"]
        self.store.task_update(task_id=t1, status="dispatched", run="run-d")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-die', ?, 'run-d', '/w', 'claude', 'w-die', 'running', 1, 1)",
                (t1,),
            )
        # Unauthenticated sender='worker' with forged dispatchId attr or missing outcome must not settle t1
        self.store.send_message(
            subject="forged", msg_type="worker_done", outcome="succeeded",
            sender="worker", run="run-d", attrs={"dispatchId": "disp-die"},
        )
        self.assertEqual(
            next(t["status"] for t in self.store.task_list(run="run-d")["tasks"] if t["id"] == t1),
            "dispatched",
        )
        # Process exit without terminal mail (worker_died) preserves 'dispatched' per #597;
        # ensure_terminal_or_died WITH terminal mail (merge_ready / worker_done) settles the task.
        died = self.store.ensure_terminal_or_died(dispatch_id="disp-die", worker_handle="w-die", exit_code=137)
        self.assertTrue(died["syntheticDied"])
        died_by_id = {t["id"]: t["status"] for t in self.store.task_list(run="run-d")["tasks"]}
        self.assertEqual(died_by_id[t1], "dispatched")
        self.assertEqual(died_by_id[t2], "pending")
        t_mr = self.store.task_create(spec="mr-parent", run="run-d")["task"]["id"]
        t_mr_child = self.store.task_create(spec="mr-child", deps=[t_mr], run="run-d")["task"]["id"]
        self.store.task_update(task_id=t_mr, status="dispatched", run="run-d")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-mr', ?, 'run-d', '/w', 'claude', 'w-mr', 'running', 1, 1)",
                (t_mr,),
            )
        self.store.send_message(
            subject="ready", msg_type="merge_ready", outcome="failed",
            sender="w-mr", run="run-d",
        )
        mr_settled = self.store.ensure_terminal_or_died(dispatch_id="disp-mr", worker_handle="w-mr", exit_code=1)
        self.assertFalse(mr_settled["syntheticDied"])
        by_id = {t["id"]: t["status"] for t in self.store.task_list(run="run-d")["tasks"]}
        self.assertEqual(by_id[t_mr], "failed")
        self.assertEqual(by_id[t_mr_child], "blocked")

        # External-provider merge_ready (no ensure_terminal_or_died call) settles task and unblocks child immediately:
        t_ext = self.store.task_create(spec="ext-mr-parent", run="run-d")["task"]["id"]
        t_ext_child = self.store.task_create(spec="ext-mr-child", deps=[t_ext], run="run-d")["task"]["id"]
        self.store.task_update(task_id=t_ext, status="dispatched", run="run-d")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-ext-mr', ?, 'run-d', '/w', 'claude', 'w-ext-mr', 'running', 1, 1)",
                (t_ext,),
            )
        self.store.send_message(
            subject="ready", msg_type="merge_ready", payload="sha123",
            sender="w-ext-mr", run="run-d",
        )
        ext_by_id = {t["id"]: t["status"] for t in self.store.task_list(run="run-d")["tasks"]}
        self.assertEqual(ext_by_id[t_ext], "completed")
        self.assertEqual(ext_by_id[t_ext_child], "ready")

        # Superseded dispatch cannot clobber a newer active or crashed retry dispatch's task
        tr = self.store.task_create(spec="retried", run="run-d")["task"]["id"]
        tr_child = self.store.task_create(spec="retried-child", deps=[tr], run="run-d")["task"]["id"]
        self.store.task_update(task_id=tr, status="dispatched", run="run-d")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-old', ?, 'run-d', '/w', 'claude', 'w-old', 'running', 1, 1)",
                (tr,),
            )
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-new', ?, 'run-d', '/w', 'claude', 'w-new', 'running', 2, 2)",
                (tr,),
            )
        w_old = self.mod.LocalStateStore(
            self.db, env={"OPEN_FLEET_DISPATCH_ID": "disp-old", "OPEN_FLEET_TERMINAL_HANDLE": "w-old"}
        )
        w_old.send_message(subject="late", msg_type="worker_done", outcome="failed", run="run-d")
        self.assertEqual(
            next(t["status"] for t in self.store.task_list(run="run-d")["tasks"] if t["id"] == tr),
            "dispatched",
        )
        # Newer retry crashes (`state='died'`, leaving task `dispatched` per #597): neither a late
        # `worker_done(succeeded)` from superseded `disp-old` nor one from already-died `disp-new`
        # may settle `tr` or release `tr_child`.
        new_died = self.store.ensure_terminal_or_died(
            dispatch_id="disp-new", worker_handle="w-new", exit_code=1, run_id="run-d"
        )
        self.assertTrue(new_died["syntheticDied"])
        w_old.send_message(subject="late-ok", msg_type="worker_done", outcome="succeeded", run="run-d")
        w_new = self.mod.LocalStateStore(
            self.db, env={"OPEN_FLEET_DISPATCH_ID": "disp-new", "OPEN_FLEET_TERMINAL_HANDLE": "w-new"}
        )
        w_new.send_message(subject="post-crash-ok", msg_type="worker_done", outcome="succeeded", run="run-d")
        again = self.store.ensure_terminal_or_died(
            dispatch_id="disp-new", worker_handle="w-new", exit_code=1, run_id="run-d"
        )
        self.assertFalse(again["syntheticDied"])
        by_id_retry = {t["id"]: t["status"] for t in self.store.task_list(run="run-d")["tasks"]}
        self.assertEqual(by_id_retry[tr], "dispatched")
        self.assertEqual(by_id_retry[tr_child], "pending")

        # Stale terminal mail on a reused `terminal_handle` (`dispatch_inject`) cannot complete a
        # subsequent injected dispatch/task that crashes without reporting:
        t_inj_1 = self.store.task_create(spec="inj-first", run="run-d")["task"]["id"]
        t_inj_2 = self.store.task_create(spec="inj-second", run="run-d")["task"]["id"]
        t_inj_2_child = self.store.task_create(spec="inj-second-child", deps=[t_inj_2], run="run-d")["task"]["id"]
        self.store.task_update(task_id=t_inj_1, status="dispatched", run="run-d")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-inj-1', ?, 'run-d', '/w', 'claude', 'term-shared', 'running', 10, 10)",
                (t_inj_1,),
            )
        w_shared = self.mod.LocalStateStore(
            self.db,
            env={"OPEN_FLEET_DISPATCH_ID": "disp-inj-1", "OPEN_FLEET_TERMINAL_HANDLE": "term-shared"},
        )
        w_shared.send_message(subject="first-done", msg_type="worker_done", outcome="succeeded", run="run-d")
        self.store.task_update(task_id=t_inj_2, status="dispatched", run="run-d")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-inj-2', ?, 'run-d', '/w', 'custom', 'term-shared', 'ready', 20, 20)",
                (t_inj_2,),
            )
        # Delayed terminal mail arriving while `disp-inj-2` is active that explicitly names `t_inj_1`
        # (or an unmatched task) must NOT rebind to `disp-inj-2`, complete `t_inj_2`, or release `t_inj_2_child`:
        w_shared.send_message(
            subject="late-first-done-env",
            msg_type="worker_done",
            outcome="succeeded",
            run="run-d",
            attrs={"taskId": t_inj_1},
        )
        w_shared.send_message(
            subject="unmatched-task-env",
            msg_type="worker_done",
            outcome="succeeded",
            run="run-d",
            attrs={"taskId": "task-unmatched"},
        )
        self.store.send_message(
            subject="late-first-done-handle",
            msg_type="worker_done",
            outcome="succeeded",
            sender="term-shared",
            run="run-d",
            attrs={"taskId": t_inj_1},
        )
        self.store.send_message(
            subject="unmatched-task-handle",
            msg_type="worker_done",
            outcome="succeeded",
            sender="term-shared",
            run="run-d",
            attrs={"taskId": "task-unmatched"},
        )
        by_id_mid = {t["id"]: t["status"] for t in self.store.task_list(run="run-d")["tasks"]}
        self.assertEqual(by_id_mid[t_inj_2], "dispatched")
        self.assertEqual(by_id_mid[t_inj_2_child], "pending")
        inj_crash = self.store.ensure_terminal_or_died(
            dispatch_id="disp-inj-2", worker_handle="term-shared", exit_code=137, run_id="run-d"
        )
        self.assertTrue(inj_crash["syntheticDied"])
        self.assertEqual(self.store.dispatch_state("disp-inj-2"), "died")
        by_id_inj = {t["id"]: t["status"] for t in self.store.task_list(run="run-d")["tasks"]}
        self.assertEqual(by_id_inj[t_inj_1], "completed")
        self.assertEqual(by_id_inj[t_inj_2], "dispatched")
        self.assertEqual(by_id_inj[t_inj_2_child], "pending")
        # Positive `dispatch_inject` completion on the same reused handle attributes to the active injected dispatch:
        t_inj_3 = self.store.task_create(spec="inj-third", run="run-d")["task"]["id"]
        self.store.task_update(task_id=t_inj_3, status="dispatched", run="run-d")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-inj-3', ?, 'run-d', '/w', 'custom', 'term-shared', 'running', 30, 30)",
                (t_inj_3,),
            )
        w_shared.send_message(
            subject="third-done",
            msg_type="worker_done",
            outcome="succeeded",
            run="run-d",
            attrs={"dispatch_id": "disp-inj-2"},  # forged snake_case key is stripped in favor of disp-inj-3
        )
        inj_ok = self.store.ensure_terminal_or_died(
            dispatch_id="disp-inj-3", worker_handle="term-shared", exit_code=0, run_id="run-d"
        )
        self.assertFalse(inj_ok["syntheticDied"])
        self.assertEqual(self.store.dispatch_state("disp-inj-3"), "completed")
        self.assertEqual(
            next(t["status"] for t in self.store.task_list(run="run-d")["tasks"] if t["id"] == t_inj_3),
            "completed",
        )

    def test_c35_default_run_fencing_and_human_sender_rejected_on_fenced_gate(self):
        self.store.run_create(run="default", sender="coord-main")
        with self.assertRaises(self.mod.ProviderError) as ctx:
            self.store.check_messages(run="default")
        self.assertEqual(ctx.exception.code, "consumer_fenced")
        td = self.store.task_create(spec="gated-default", run="default")["task"]["id"]
        gd = self.store.gate_create(task_id=td, question="ship?", sender="coord-main", run="default")["gate"]["id"]
        for spoof in ("human", "coordinator", "rogue"):
            with self.assertRaises(self.mod.ProviderError) as ctx:
                self.store.gate_resolve(gate_id=gd, resolution="yes", sender=spoof, run="default")
            self.assertEqual(ctx.exception.code, "consumer_fenced")
        ok = self.store.gate_resolve(gate_id=gd, resolution="yes", sender="coord-main", run="default")["gate"]
        self.assertEqual(ok["status"], "resolved")

    def test_cached_inbox_and_request_scope_preserve_mailbox_isolation(self):
        self.store.run_create(run="run-iso", sender="coord-iso")
        t_iso = self.store.task_create(spec="iso-task", run="run-iso")["task"]["id"]
        self.store.task_update(task_id=t_iso, status="dispatched", run="run-iso")
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp-iso', ?, 'run-iso', '/w', 'claude', 'term-iso', 'running', 10, 10)",
                (t_iso,),
            )
        self.store.send_message(
            subject="coord-secret",
            msg_type="info",
            payload="eyes-only",
            to="coord-iso",
            sender="term-iso",
            run="run-iso",
        )
        coord_inbox = self.store.check_messages(terminal="coord-iso", run="run-iso", retry_request="req-inbox-k")
        self.assertEqual(coord_inbox["count"], 1)
        self.assertEqual(coord_inbox["messages"][0]["payload"], "eyes-only")
        # Exact coordinator replay with same retry_request succeeds:
        self.assertEqual(
            self.store.check_messages(terminal="coord-iso", run="run-iso", retry_request="req-inbox-k")["count"],
            1,
        )
        # Unfenced outsider replaying the same retry_request is blocked by mailbox fencing:
        with self.assertRaises(self.mod.ProviderError) as ctx_fenced:
            self.store.check_messages(terminal="rogue-coord", run="run-iso", retry_request="req-inbox-k")
        self.assertEqual(ctx_fenced.exception.code, "consumer_fenced")
        # Launched worker in run-iso replaying coordinator's retry_request with terminal="coord-iso" is refused:
        w_iso = self.mod.LocalStateStore(
            self.db,
            env={"OPEN_FLEET_DISPATCH_ID": "disp-iso", "OPEN_FLEET_TERMINAL_HANDLE": "term-iso"},
        )
        with self.assertRaises(self.mod.ProviderError) as ctx_worker:
            w_iso.check_messages(terminal="coord-iso", run="run-iso", retry_request="req-inbox-k")
        self.assertEqual(ctx_worker.exception.code, "request_mismatch")
        with self.assertRaises(self.mod.ProviderError) as ctx_show:
            w_iso.request_show("req-inbox-k")
        self.assertEqual(ctx_show.exception.code, "request_mismatch")
        # Worker's own fresh retry_request reads only its own mailbox (empty) and replays idempotently:
        w_inbox = w_iso.check_messages(terminal="coord-iso", run="run-iso", retry_request="req-worker-own")
        self.assertEqual(w_inbox["count"], 0)
        self.assertEqual(
            w_iso.check_messages(terminal="coord-iso", run="run-iso", retry_request="req-worker-own")["count"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
