#!/usr/bin/env python3
"""Adversarial parity oracle: drive open-fleet deny-hook against all 4 deny-hook suites."""
import sys

if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import importlib.util
import os
import subprocess
from pathlib import Path

_oracle_spec = importlib.util.spec_from_file_location(
    "_rust_oracle", Path(__file__).resolve().parent / "_rust_oracle.py")
_oracle = importlib.util.module_from_spec(_oracle_spec)
_oracle_spec.loader.exec_module(_oracle)

ROOT = _oracle.ROOT
HOOK_SCRIPT = (ROOT / "runtime" / "scripts" / "deny-hook.sh").resolve()

SKIP_DENY_HOOK = frozenset({
    "TestEverySegmentIsJudged.test_the_hook_no_longer_claims_raw_splitting_is_safe",
    "TestBashWritesAreBounded.test_a_relative_target_is_not_judged_and_says_so",
    "TestThePayloadReaderStaysRunnable.test_the_embedded_program_carries_no_apostrophe",
    "TestNoChildStringNearTheKernelLimit.test_every_child_string_stays_under_the_budget_and_the_linux_cap",
    "TestNoChildStringNearTheKernelLimit.test_no_inline_interpreter_program_nears_the_limit",
    "TestScriptShape.test_executable_and_shebanged",
    "TestScriptShape.test_posix_and_bash_syntax_both_parse",
    "TestScriptShape.test_the_advisory_boundary_is_stated_not_overclaimed",
    "TestScriptShape.test_the_hook_does_not_claim_a_registration_nothing_performs",
    "TestScriptShape.test_settings_mode_shell_quotes_a_hook_path_with_a_space",
    "TestSymlinkSnippetPrinter.test_a_hostile_clone_path_still_emits_valid_json_and_one_argv_word",
    "TestPlantedModulesCannotDisarmTheHook.test_every_python_the_hook_starts_is_isolated",
    "TestMatchersFailClosed.test_a_grep_that_errors_on_every_pattern_refuses",
    "TestMatchersFailClosed.test_a_grep_error_inside_has_refuses_instead_of_reading_no_match",
    "TestThreatModelStatesWhatTheHookDoes.test_the_hook_is_not_credited_with_refusing_never_shapes_or_with_quarantine",
    "TestBraceExpansionAndInlineAliasesCannotLaunder.test_the_reader_expands_braces_the_way_bash_does",
    "TestBraceExpansionAndInlineAliasesCannotLaunder.test_the_header_names_both_closed_holes",
    "TestVerifySettingsRunsOnlyThisHook.test_the_probes_do_not_inherit_the_coordinators_secrets",
    "TestReadOnlyTierWriteFloor.test_the_header_states_the_readonly_floor_and_its_limit",
})

SKIP_CONFORMANCE = frozenset({
    "TestGuardFamily.test_the_corpus_decoys_every_path_the_hook_guards",
    "TestEverySafeguardIsCaughtWhenSwitchedOff.test_each_mutant_disagrees_with_bash",
    "TestHookOnlySafeguardsFlipWhenSwitchedOff.test_each_safeguard_flips_a_pin",
})

SKIP_MULTI = frozenset({
    "TestFileTouchConflicts.test_a_relocated_hook_finds_the_store_through_open_fleet_root",
})


def _rewrite_call(binary, cmd, kwargs):
    if not isinstance(cmd, (list, tuple)) or not cmd:
        return cmd, kwargs
    target_idx = None
    first = Path(str(cmd[0])).name
    if first in ("sh", "bash", "dash") and len(cmd) >= 2:
        target_idx = 1
    elif first == "deny-hook.sh":
        target_idx = 0
    if target_idx is None:
        return cmd, kwargs
    try:
        resolved = Path(str(cmd[target_idx])).resolve()
    except OSError:
        return cmd, kwargs
    if resolved != HOOK_SCRIPT:
        return cmd, kwargs
    new_cmd = [str(binary), "deny-hook", *[str(x) for x in cmd[target_idx + 1:]]]
    new_kw = dict(kwargs)
    env = dict(new_kw["env"]) if new_kw.get("env") is not None else dict(os.environ)
    env.setdefault("DH_SELF", str(HOOK_SCRIPT))
    new_kw["env"] = env
    return new_cmd, new_kw


def _build_suite(binary, suite, args):
    real_run = subprocess.run

    def rust_run(cmd, *rargs, **rkwargs):
        new_cmd, new_kw = _rewrite_call(binary, cmd, rkwargs)
        return real_run(new_cmd, *rargs, **new_kw)

    subprocess.run = rust_run

    suites = [
        ("test_deny_hook_oracle", ROOT / "tests" / "test_deny_hook.py", SKIP_DENY_HOOK),
        ("test_deny_hook_multi_oracle", ROOT / "tests" / "test_deny_hook_multi_harness.py", SKIP_MULTI),
        ("test_deny_hook_conf_oracle", ROOT / "tests" / "test_deny_hook_conformance.py", SKIP_CONFORMANCE),
        ("test_trajectory_evals_oracle", ROOT / "tests" / "test_trajectory_evals.py", frozenset()),
    ]
    added = 0
    for mod_name, path, skips in suites:
        mod = _oracle.load_module(mod_name, path)
        added += _oracle.add_module_tests(
            suite, mod, skip_methods=skips, pattern=args.pattern,
        )
    return added


def main(argv=None):
    saved_run = subprocess.run
    try:
        return _oracle.run_oracle(
            "rust_deny_hook_oracle",
            "Run all 4 deny-hook & trajectory suites against native `open-fleet deny-hook`.",
            _build_suite,
            argv,
        )
    finally:
        subprocess.run = saved_run


if __name__ == "__main__":
    raise SystemExit(main())
