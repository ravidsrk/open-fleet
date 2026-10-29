"""#510: the Orca CLI command name is resolved in one place, the way upstream documents it.

Orca's Linux executable is `orca-ide` (`src/main/cli/bundled-cli-launcher-path.ts`
LINUX_CLI_COMMAND_NAME); bare `orca` on a Linux host outside an Orca terminal is the GNOME
screen reader. Before this, eight operator tools and spawn_worker.sh spelled the executable
`orca` verbatim, so the fleet could not run on the platform most servers use. These tests pin
the resolution order, the CLI entrypoint, and — the part that keeps the bug from returning —
that no script under runtime/scripts/ names the executable itself.
"""
import contextlib
import importlib.util
import io
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "runtime" / "scripts"
RESOLVER = SCRIPTS / "orca_cli.py"

TOOLS = ["check_reply.py", "hitl_ask.py", "search_sessions.py", "send_msg.py", "task_ops.py",
         "terminal_ops.py", "worker_ops.py", "worktree_ops.py"]


def _load():
    spec = importlib.util.spec_from_file_location("orca_cli", RESOLVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ResolutionOrder(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_orca_cli_command_wins_everywhere(self):
        # Orca exports it inside the sessions it manages; tests point it at a stub.
        for system in ("Linux", "Darwin", "Windows"):
            self.assertEqual(self.m.resolve({"ORCA_CLI_COMMAND": "/opt/x/orca"}, system),
                             "/opt/x/orca")

    def test_a_blank_orca_cli_command_is_unset(self):
        self.assertEqual(self.m.resolve({"ORCA_CLI_COMMAND": "  "}, "Darwin"), "orca")

    def test_dev_checkout_uses_orca_dev(self):
        self.assertEqual(self.m.resolve({"ORCA_DEV_REPO_ROOT": "/src/orca"}, "Linux"), "orca-dev")
        self.assertEqual(self.m.resolve({"ORCA_DEV_REPO_ROOT": "/src/orca"}, "Darwin"), "orca-dev")

    def test_linux_is_orca_ide_never_bare_orca(self):
        self.assertEqual(self.m.resolve({}, "Linux"), "orca-ide")

    def test_macos_and_windows_are_orca(self):
        self.assertEqual(self.m.resolve({}, "Darwin"), "orca")
        self.assertEqual(self.m.resolve({}, "Windows"), "orca")

    def test_the_host_platform_is_consulted_when_none_is_given(self):
        import platform
        want = "orca-ide" if platform.system() == "Linux" else "orca"
        self.assertEqual(self.m.resolve({}), want)


class CommandLine(unittest.TestCase):
    """main() in this process (the D9 coverage floor sees it; a subprocess is invisible to
    the shard's tracer) under the environment a subprocess would have had, plus one real
    subprocess call that proves the entry point."""

    def setUp(self):
        self.m = _load()

    def main(self, argv, env):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.m.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_prints_the_name(self):
        code, out, _ = self.main([], {"PATH": os.environ["PATH"], "ORCA_CLI_COMMAND": "orca-stub"})
        self.assertEqual((code, out.strip()), (0, "orca-stub"))

    def test_path_mode_fails_closed_when_the_command_is_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = self.main(["--path"], {"PATH": tmp, "ORCA_CLI_COMMAND": "orca-stub"})
        self.assertEqual(code, 1, err)
        self.assertIn("not on PATH", err)
        self.assertEqual(out, "")

    def test_path_mode_prints_the_resolved_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "orca-stub"
            stub.write_text("#!/bin/sh\nexit 0\n")
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
            code, out, _ = self.main(["--path"], {"PATH": tmp, "ORCA_CLI_COMMAND": "orca-stub"})
            self.assertEqual((code, out.strip()), (0, str(stub)))

    def test_unknown_arguments_are_usage(self):
        code, out, err = self.main(["--bogus"], {"PATH": os.environ["PATH"]})
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("usage", err)

    def test_runs_as_a_program(self):
        p = subprocess.run([sys.executable, str(RESOLVER)], capture_output=True, text=True,
                           env={"PATH": os.environ["PATH"], "ORCA_CLI_COMMAND": "orca-stub"})
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "orca-stub"))


class SharedEnvelopeReader(unittest.TestCase):
    """run_json is the one copy of the reader eight tools used to paste; each keeps its own
    exit-status rule through `nonzero`."""

    class Boom(Exception):
        pass

    def setUp(self):
        self.m = _load()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_stub(self, stdout, rc, **kw):
        tmp = Path(self.tmp.name)
        (tmp / "out.json").write_text(stdout, encoding="utf-8")
        stub = tmp / "orca-stub"
        stub.write_text(f'#!/bin/sh\necho "$*" > "{tmp}/argv"\ncat "{tmp}/out.json"\nexit {rc}\n',
                        encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        with mock.patch.dict(os.environ, {"ORCA_CLI_COMMAND": str(stub)}):
            result = self.m.run_json(["orchestration", "check"], timeout=30, error=self.Boom, **kw)
        self.assertEqual((tmp / "argv").read_text().strip(), "orchestration check --json")
        return result

    def test_the_result_object_is_returned(self):
        self.assertEqual(self.run_stub('{"result": {"a": 1}}', 0), {"a": 1})
        self.assertEqual(self.run_stub('{"ok": true}', 0), {})

    def test_every_failure_raises_the_callers_class(self):
        for stdout in ("not json", "[1]", '{"error": {"code": "nope"}}',
                       '{"result": {"error": "inner"}}'):
            with self.subTest(stdout=stdout), self.assertRaises(self.Boom):
                self.run_stub(stdout, 0)

    def test_nonzero_modes_keep_each_tools_rule(self):
        with self.assertRaisesRegex(self.Boom, "no error envelope"):
            self.run_stub('{"result": {"a": 1}}', 3)
        self.assertEqual(self.run_stub('{"result": {"a": 1}}', 3, nonzero="no-receipt"), {"a": 1})
        with self.assertRaisesRegex(self.Boom, "no receipt"):
            self.run_stub('{"result": {}}', 3, nonzero="no-receipt")
        self.assertEqual(self.run_stub('{"result": {}}', 3, nonzero="ignore"), {})

    def test_an_error_code_from_the_envelope_is_reported_inert(self):
        # W4-11 class sweep: every tool prints this message to the coordinator's terminal, and
        # the code is the runtime's (untrusted) text.
        with self.assertRaises(self.Boom) as ctx:
            self.run_stub('{"error": {"code": "nope\\u001b]0;pwned\\u0007\\u202e\\nOK=1"}}', 1)
        for raw in ("\x1b", "\x07", "\u202e", "\n"):
            self.assertNotIn(raw, str(ctx.exception))
        self.assertIn("orca refused: nope", str(ctx.exception))

    def test_a_provider_error_is_reported_inert(self):
        # Codex round 3 (P2): the provider-dispatch branch (a non-Orca runtime, or `auto`
        # selecting one) interpolated ProviderError.code raw, and an exception's text too.
        hostile = "bad\nSTATE=completed\u001b[2J\u202e"
        sys.path.insert(0, str(ROOT))
        self.addCleanup(sys.path.remove, str(ROOT))
        providers = importlib.import_module("runtime.providers")
        for exc in (providers.ProviderError(hostile, "m"), RuntimeError(hostile)):
            fake = mock.Mock()
            fake.ProviderError = providers.ProviderError
            fake.get_provider.return_value.dispatch.side_effect = exc
            with self.subTest(exc=type(exc).__name__), \
                    mock.patch.dict(os.environ, {"OPEN_FLEET_RUNTIME": "posix"}), \
                    mock.patch.object(self.m, "_load_providers", return_value=fake), \
                    self.assertRaises(self.Boom) as ctx:
                self.m.run_json(["orchestration", "x"], timeout=5, error=self.Boom)
            for raw in ("\n", "\x1b", "\u202e"):
                self.assertNotIn(raw, str(ctx.exception))
            self.assertIn("STATE=completed", str(ctx.exception))

    def test_an_unrunnable_cli_raises_the_callers_class(self):
        with mock.patch.dict(os.environ, {"ORCA_CLI_COMMAND": "/nonexistent/orca"}):
            with self.assertRaisesRegex(self.Boom, "could not run orca"):
                self.m.run_json(["x"], timeout=5, error=self.Boom)


class TheConfiguredCommandIsOneExecutable(unittest.TestCase):
    """W4-15 / W2-03 (2026-10-27 audit): OPEN_FLEET_CLI_COMMAND / ORCA_CLI_COMMAND was returned
    verbatim and became argv[0] everywhere. `python3 /tmp/orca.py` died as an opaque `[Errno 2]`
    on every call, and an option-shaped or cwd-relative value was not special-cased at all.
    upstream_probe.resolve_cli already refused what is not on PATH with a named rule; now both
    resolvers apply ONE policy, with the same message."""

    RULE = "(it must name one executable, without arguments)"

    class Boom(Exception):
        pass

    def setUp(self):
        self.m = _load()

    def test_a_command_line_an_option_or_a_relative_path_is_refused_by_name(self):
        for var in ("OPEN_FLEET_CLI_COMMAND", "ORCA_CLI_COMMAND"):
            for value in ("python3 /tmp/orca.py", "orca --verbose", "-x", "--help", "bin/orca",
                          "./orca", "orca\nterminal", "orca\x1b[2J"):
                with self.subTest(var=var, value=value):
                    with self.assertRaises(self.m.CliCommandError) as ctx:
                        self.m.resolve({var: value}, "Linux")
                    self.assertIn(var, str(ctx.exception))
                    self.assertIn(self.RULE, str(ctx.exception))
                    self.assertNotIn("\n", str(ctx.exception))
                    self.assertNotIn("\x1b", str(ctx.exception))

    def test_a_bare_name_or_an_absolute_path_still_resolves_without_consulting_path(self):
        for value in ("orca-stub", "/opt/x/orca", "/Applications/Orca IDE.app/bin/orca"):
            with self.subTest(value=value):
                self.assertEqual(self.m.resolve({"ORCA_CLI_COMMAND": value}, "Linux"), value)

    def test_run_json_names_the_cause_instead_of_an_errno(self):
        for value in ("python3 /tmp/orca.py", "ghost-orca-not-on-path"):
            with self.subTest(value=value), \
                    mock.patch.dict(os.environ, {"OPEN_FLEET_CLI_COMMAND": value}):
                with self.assertRaises(self.Boom) as ctx:
                    self.m.run_json(["orchestration", "check"], timeout=5, error=self.Boom)
                self.assertIn("could not run orca", str(ctx.exception))
                self.assertIn(f"OPEN_FLEET_CLI_COMMAND={value!r}", str(ctx.exception))
                self.assertIn(self.RULE, str(ctx.exception))
                self.assertNotIn("Errno", str(ctx.exception))

    def test_the_cli_entry_point_refuses_with_usage_and_the_named_rule(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"PATH": os.environ["PATH"],
                                          "ORCA_CLI_COMMAND": "python3 /tmp/orca.py"}, clear=True), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.m.main([])
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn(self.RULE, err.getvalue())

    def test_spawn_worker_refuses_before_any_call(self):
        p = subprocess.run(["bash", str(SCRIPTS / "spawn_worker.sh"), "t1", "current", "t"],
                           env={"PATH": "/usr/bin:/bin", "SW_SELFTEST": "1",
                                "ORCA_CLI_COMMAND": "python3 /tmp/orca.py"},
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn("SPAWN=REFUSED", p.stderr)
        self.assertIn(self.RULE, p.stderr)

    def test_upstream_probe_applies_the_same_policy(self):
        spec = importlib.util.spec_from_file_location("upstream_probe_for_cli",
                                                      SCRIPTS / "upstream_probe.py")
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)
        def everything(name):
            """A which() that finds anything: only the shape can refuse."""
            return f"/bin/{name}"

        for value in ("-x", "bin/orca", "python3 /tmp/orca.py"):
            with self.subTest(value=value), self.assertRaises(probe.ProbeError) as ctx:
                probe.resolve_cli({"ORCA_CLI_COMMAND": value}, "linux", which=everything)
            self.assertIn(self.RULE, str(ctx.exception))
        self.assertEqual(probe.resolve_cli({"ORCA_CLI_COMMAND": "my-orca"}, "linux", which=everything),
                         ("my-orca", "ORCA_CLI_COMMAND"))

    def test_upstream_probe_takes_the_override_in_orca_cli_precedence(self):
        # Codex review of W4-15 (P2): upstream_probe read ORCA_CLI_COMMAND only, so with
        # OPEN_FLEET_CLI_COMMAND=/opt/pinned/orca and ORCA_CLI_COMMAND=/opt/older/orca every fleet
        # call ran the pinned binary while `capture` witnessed the older one, and with only the
        # primary set `capture` ignored it. Both now take the override the same way.
        spec = importlib.util.spec_from_file_location("upstream_probe_for_precedence",
                                                      SCRIPTS / "upstream_probe.py")
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)

        def everything(name):
            """A which() that finds anything: only precedence and shape decide."""
            return name if name.startswith("/") else f"/bin/{name}"

        cases = (
            ({"OPEN_FLEET_CLI_COMMAND": "/opt/pinned/orca", "ORCA_CLI_COMMAND": "/opt/older/orca"},
             ("/opt/pinned/orca", "OPEN_FLEET_CLI_COMMAND")),
            ({"OPEN_FLEET_CLI_COMMAND": "/opt/pinned/orca"}, ("/opt/pinned/orca", "OPEN_FLEET_CLI_COMMAND")),
            ({"ORCA_CLI_COMMAND": "/opt/older/orca"}, ("/opt/older/orca", "ORCA_CLI_COMMAND")),
            ({"OPEN_FLEET_CLI_COMMAND": "  ", "ORCA_CLI_COMMAND": "/opt/older/orca"},
             ("/opt/older/orca", "ORCA_CLI_COMMAND")),
        )
        for env, want in cases:
            with self.subTest(env=env):
                self.assertEqual(probe.resolve_cli(env, "linux", which=everything), want)
                self.assertEqual(self.m.resolve(env, "Linux"), want[0], "the fleet resolver disagrees")
        # Same validation on the winning value: a bad primary is never skipped for a good legacy.
        env = {"OPEN_FLEET_CLI_COMMAND": "-x", "ORCA_CLI_COMMAND": "/opt/older/orca"}
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.resolve_cli(env, "linux", which=everything)
        self.assertIn("OPEN_FLEET_CLI_COMMAND='-x'", str(ctx.exception))
        with self.assertRaises(self.m.CliCommandError):
            self.m.resolve(env, "Linux")


class OneResolverForTheOrcaBinary(unittest.TestCase):
    """W4-15/W2-03 re-attack: a THIRD resolver, runtime/providers/orca.py:resolve_orca_binary
    (behind `orca_cli.py <domain>` on Orca, preflight, install.sh and `auto`), had neither the
    validation nor the precedence (ORCA_CLI_COMMAND before OPEN_FLEET_CLI_COMMAND), so it reproduced
    W2-03 exactly, and under OPEN_FLEET_RUNTIME=auto the registry said posix while orca_cli.resolve()
    named an Orca binary that was not there. The shape check also let C1 and format characters
    through (`orca\\x9b`, `orca\\u202e`). One resolution now serves all of them."""

    PINNED, OLDER = "/opt/pinned/orca", "/opt/older/orca"

    def setUp(self):
        self.m = _load()
        sys.path.insert(0, str(ROOT))
        self.addCleanup(sys.path.remove, str(ROOT))
        self.providers = importlib.import_module("runtime.providers")

    def test_the_provider_resolver_takes_the_same_precedence(self):
        for env, want in (({"OPEN_FLEET_CLI_COMMAND": self.PINNED, "ORCA_CLI_COMMAND": self.OLDER}, self.PINNED),
                          ({"OPEN_FLEET_CLI_COMMAND": self.PINNED}, self.PINNED),
                          ({"ORCA_CLI_COMMAND": self.OLDER}, self.OLDER),
                          ({"ORCA_DEV_REPO_ROOT": "/src/orca"}, "orca-dev"),
                          ({}, "orca-ide")):
            with self.subTest(env=env):
                self.assertEqual(self.providers.resolve_orca_binary(env, "Linux"), want)
                self.assertEqual(self.m.resolve(env, "Linux"), want)

    def test_the_provider_resolver_applies_the_same_validation(self):
        for value in ("python3 /tmp/orca.py", "-x", "bin/orca"):
            with self.subTest(value=value):
                with self.assertRaises(self.providers.ProviderError) as ctx:
                    self.providers.resolve_orca_binary({"ORCA_CLI_COMMAND": value}, "Linux")
                self.assertEqual(ctx.exception.code, "invalid_cli_command")
                self.assertIn("(it must name one executable, without arguments)", ctx.exception.message)

    def test_c1_format_and_separator_characters_are_refused(self):
        for value in ("orca\x9b", "orca\u202e", "orca\u200bx", "/opt/orca\u2028x", "orca-real\x85",
                      "/opt/o\u202erca"):
            with self.subTest(value=value):
                self.assertIsNotNone(self.m.cli_command_problem(value, "ORCA_CLI_COMMAND"))
                with self.assertRaises(self.m.CliCommandError):
                    self.m.resolve({"ORCA_CLI_COMMAND": value}, "Linux")

    def test_auto_and_the_resolver_agree_on_which_runtime_answers(self):
        env = {"OPEN_FLEET_RUNTIME": "auto", "ORCA_CLI_COMMAND": "/nonexistent/orca", "PATH": ""}
        self.assertEqual(self.providers.active_provider_name(env), "posix")
        self.assertEqual(self.m.resolve(env, "Linux"), str(RESOLVER.resolve()),
                         "auto chose posix, so the CLI that answers must be this module's shim")
        with tempfile.TemporaryDirectory() as tmp:
            orca = Path(tmp) / "orca-real"
            orca.write_text("#!/bin/sh\nexit 0\n")
            orca.chmod(0o755)
            env = {"OPEN_FLEET_RUNTIME": "auto", "ORCA_CLI_COMMAND": str(orca), "PATH": tmp}
            self.assertEqual(self.providers.active_provider_name(env), "orca")
            self.assertEqual(self.m.resolve(env, "Linux"), str(orca))


class NoScriptNamesTheExecutable(unittest.TestCase):
    """The contract: the executable is a policy decision made once, in orca_cli.py."""

    LITERAL_ARGV = re.compile(r'subprocess\.run\(\s*\[\s*["\']orca["\']')
    SHELL_INVOCATION = re.compile(r'(^|[^\w/`.$-])orca (--version|vm |orchestration |terminal |worktree |"\$@")')

    def test_every_operator_tool_resolves_through_orca_cli(self):
        for name in TOOLS:
            text = (SCRIPTS / name).read_text(encoding="utf-8")
            with self.subTest(tool=name):
                self.assertIn("import orca_cli", text)
                # The shared envelope reader runs `orca_cli.resolve()` itself, so a tool
                # reaches the CLI through run_json and never parses the envelope again.
                self.assertIn("orca_cli.run_json(", text)
                self.assertNotIn("json.loads(proc.stdout)", text,
                                 f"{name} parses the orca envelope itself again")
                self.assertIsNone(self.LITERAL_ARGV.search(text),
                                  f"{name} still spells the executable `orca` in an argv")

    def test_no_python_script_builds_a_bare_orca_argv(self):
        for path in sorted(SCRIPTS.glob("*.py")):
            if path.name == "orca_cli.py":
                continue
            with self.subTest(script=path.name):
                self.assertIsNone(self.LITERAL_ARGV.search(path.read_text(encoding="utf-8")))

    def test_spawn_worker_runs_the_resolved_command(self):
        text = (SCRIPTS / "spawn_worker.sh").read_text(encoding="utf-8")
        self.assertIn('ORCA_BIN="$(python3 -I "$HERE/orca_cli.py")"', text)
        offenders = [line for line in text.splitlines()
                     if not line.lstrip().startswith("#") and self.SHELL_INVOCATION.search(line)]
        self.assertEqual(offenders, [], "spawn_worker.sh invokes a bare `orca`")
        self.assertNotIn("command -v orca ", text)
        self.assertNotIn("command -v orca>", text)

    def test_the_detector_sees_a_planted_bare_invocation(self):
        # A guard that cannot fail is not a guard: the two regexes must catch the shapes
        # that were actually in the tree before #510.
        self.assertIsNotNone(self.LITERAL_ARGV.search('proc = subprocess.run(["orca", *argv, "--json"],'))
        self.assertIsNotNone(self.SHELL_INVOCATION.search('  orca orchestration worker-start --task "$task"'))
        self.assertIsNotNone(self.SHELL_INVOCATION.search('  orca "$@" --json > "$out"'))
        # ...and must not cry wolf on the resolved forms.
        self.assertIsNone(self.SHELL_INVOCATION.search('  "$ORCA_BIN" orchestration worker-start'))
        self.assertIsNone(self.SHELL_INVOCATION.search('  orca_json "$tl" orchestration task-list'))


if __name__ == "__main__":
    unittest.main()


class PinnedVersionIsReadNotAssumed(unittest.TestCase):
    """2026-10-26 review: an unreadable pins.json fell back to a literal `v1.4.239`, so the drift
    NOTE in spawn_worker.sh compared the installed CLI against a stale constant. Now it reads
    "unknown", which the NOTE reports as "could not be checked"."""

    def test_the_pinned_version_comes_from_pins_json(self):
        import json
        orca_cli = _load()
        pins = json.loads((ROOT / "runtime" / "pins.json").read_text(encoding="utf-8"))
        self.assertEqual(orca_cli._pinned_version(), pins["orca"]["version"])

    def test_an_unreadable_pin_is_unknown_not_a_literal(self):
        orca_cli = _load()
        with mock.patch.object(orca_cli.Path, "read_text", side_effect=OSError("gone")):
            self.assertEqual(orca_cli._pinned_version(), "unknown")
        with mock.patch.object(orca_cli.Path, "read_text", return_value="{not json"):
            self.assertEqual(orca_cli._pinned_version(), "unknown")

    def test_no_literal_pin_remains_in_the_resolver(self):
        src = (ROOT / "runtime" / "scripts" / "orca_cli.py").read_text(encoding="utf-8")
        self.assertNotRegex(src, r"\"v1\.4\.\d+\"")
