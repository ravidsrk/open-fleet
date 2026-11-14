#!/usr/bin/env python3
"""Control-outcome reader — the verdict behind verify.py's executed negative
control (moved here verbatim by reshape-it RV-D2; `verify.py` keeps one
re-export, `_failure_signature`). Private module: import through
`runtime/scripts/verify.py`, never directly.
"""
import re


# A control run that dies before the oracle ever executes is a STILLBORN MUTANT, not a kill: the
# non-zero exit is the module failing to load, so it would be non-zero for any command at all.
# Vera-Pérez et al. 2018 and Niedermayr et al. 2016 are explicit that only a mutant the test suite
# actually EXERCISES says anything about that suite (docs/reviews/2026-09-11 §4 A14; #280).
STILLBORN_MARKERS = (
    "importerror", "modulenotfounderror", "syntaxerror", "indentationerror",
    "cannot import name", "error collecting", "collection error", "unable to import",
    "no module named", "failed to load", "conftest.py", "attributeerror: module",
)
# What a real oracle failing looks like, across the runners the catalog's missions actually drive.
ASSERTION_MARKERS = (
    "assertionerror", "assert", "failed", "fail:", "failures=", "expected", "not ok",
    "panicked at", "✗", "test failed", "e   ", "✕",
)
# Evidence an assertion was actually EVALUATED and FAILED, as opposed to a runner summarising that
# something went wrong, or a traceback merely QUOTING a line of source. Only these override a
# stillborn marker, and each is anchored to the start of a line for that reason: a collection
# traceback echoes the source it was reading ("    assert helper() == 1") while the assertion
# never ran, so an unanchored "assert " let a stillborn mutant through (PR #308 review, round 3).
# `AssertionError` at the head of a line is an exception that was RAISED; a failed import cannot
# produce one. pytest prefixes the failing assertion with `E`, and never the source it quotes.
STRONG_ASSERTION_RE = re.compile(
    r"^[ \t]*(?:e[ \t]+)?assertionerror\b"      # AssertionError raised (pytest prefixes E)
    r"|^[ \t]*e[ \t]+assert\b"                   # pytest's failing assertion line
    r"|^[ \t]*e[ \t]+failed: did not raise\b"    # pytest.raises evaluated and was not satisfied
    r"|^[ \t]*thread .*panicked at"               # Rust
    r"|✗|✕",
    re.M,
)
# A load failure the runner actually REPORTED, as opposed to a stillborn word merely appearing.
# Each alternative is anchored to the head of a line (after pytest's `E` prefix or a runner's
# indent), or is a runner's own suite-level verdict, so an assertion MESSAGE that names
# `ModuleNotFoundError` ("AssertionError: ModuleNotFoundError not raised") does not match. These
# refuse the control even beside counted failures and even beside an assertion that DID fail:
# pytest prints `1 failed` for a SyntaxError raised by an in-test import, Jest prints `Test
# Suites: 1 failed` and Vitest `Failed Suites 1` for a suite that never loaded, and Jest marks
# the in-test-require case `✕` (2026-10-23 review, P1-1).
STILLBORN_SHAPE_RE = re.compile(
    r"^[ \t]*(?:e[ \t]+)?(?:syntaxerror|indentationerror|taberror|importerror"
    r"|modulenotfounderror)\b"                    # Python / Node raised it (pytest prefixes E)
    r"|^[ \t]*(?:e[ \t]+)?attributeerror: module\b"   # the name the oracle reached for is gone
    r"|^failed \S+ - +(?:file \"|(?:syntaxerror|importerror|modulenotfounderror)\b)"  # pytest -rf
    r"|^[ \t]*(?:error: )?cannot find module\b"   # Node / Jest resolver
    r"|●[ \t]*test suite failed to run"           # Jest: the suite never loaded
    r"|^\W*failed suites \d+"                     # Vitest: the suite never loaded
    r"|^[ \t]*(?:error: )?failed to (?:load url|resolve import)\b"   # Vite / Vitest resolver
    r"|^[_= \t]*errors? collecting\b|\berrors? during collection\b"   # pytest collection
    r"|\[(?:build|setup) failed\]"                # go test: the package never compiled
    r"|^error: could not compile\b",              # cargo: the crate never compiled
    re.M,
)
# unittest and pytest both distinguish an ERROR (an exception escaped) from a FAILURE (an assertion
# was evaluated and was false). Only the second exercises the oracle. `FAILED (errors=1)` is an
# import blowing up, and it says "FAILED" — which is why the assertion markers alone cannot be
# trusted to mean an assertion ran (PR #308 review).
_ERRORS_RE = re.compile(r"\berrors?\s*[=:]\s*(\d+)|\b(\d+)\s+errors?\b")
_FAILURES_RE = re.compile(r"\bfailures?\s*[=:]\s*(\d+)|\b(\d+)\s+failed\b")


def _counted(pattern, text):
    """Sum of every count `pattern` reports in a runner's summary line. None when it reports none."""
    total, seen = 0, False
    for match in pattern.finditer(text):
        for group in match.groups():
            if group is not None:
                total += int(group)
                seen = True
    return total if seen else None


def _failure_signature(out, err):
    """Read the control run's output. Returns (ok, reason).

    A non-zero exit is not a kill on its own — `grep` exits 1 on no-match, an unimportable module
    exits 1 before a single assertion runs, and both look identical to a gate that only reads the
    return code. The RED must LOOK like an oracle failing.

    Four layers, in this order, because two review rounds on #308 showed either one alone is
    wrong. The RUNNER'S OWN SUMMARY is the best evidence there is for an ERROR: unittest and
    pytest separate errors from failures, so `FAILED (errors=1)` is a stillborn mutant no matter
    what words surround it. A counted FAILURE is weaker evidence than it looks: pytest counts an
    exception raised inside a test (an in-test `import mod` hitting a SyntaxError) as `1 failed`,
    and Jest/Vitest count a suite that never loaded as a failed suite. So the stillborn reading
    runs whatever the summary counted (2026-10-23 review, P1-1). A load failure the runner
    REPORTED (STILLBORN_SHAPE_RE) refuses outright; a stillborn WORD alone refuses unless explicit
    assertion evidence outranks it — a test asserting that a `ModuleNotFoundError` is raised
    prints that name while its oracle runs perfectly well. That evidence is line-anchored, because
    a collection traceback QUOTES the source it was reading — an `assert` in echoed source is not
    an assertion that ran.

    A run with a genuine assertion failure in one test AND a reported load failure in another is
    REFUSED, fail-closed: the verifier cannot tell which failing test is the criterion-bound
    oracle, a guarded import (`try: import mod` … `assert mod`) turns a stillborn module into an
    AssertionError, and Jest marks a test whose require blew up `✕` like any other. The control
    must leave the code loadable; narrow the mutant or the bound command until only an assertion
    fails."""
    text = f"{out}\n{err}".lower()
    if not text.strip():
        return False, ("the control run produced NO output at all. A silent non-zero exit is not a "
                       "failing test — it is what `grep` does when it finds nothing; fail-closed "
                       "(#280)")
    errors = _counted(_ERRORS_RE, text)
    failures = _counted(_FAILURES_RE, text)
    if errors and not failures:
        return False, (f"the runner reports {errors} error(s) and no assertion failure — an error is "
                       "an exception escaping, not an oracle evaluating to false, so it does not "
                       "show the criterion-bound assertion ran at all; fail-closed (#280)")
    shape = STILLBORN_SHAPE_RE.search(text)
    if shape:
        counted = f" beside {failures} counted failure(s)" if failures else ""
        return False, (f"the control run reports a load failure ({shape.group(0).strip()!r}){counted} "
                       "— that is a STILLBORN MUTANT, not a kill. A module that fails to load, or "
                       "a suite that never ran, makes every command that touches it exit non-zero; "
                       "a failed count or an assertion failing elsewhere in the same run does not "
                       "show the criterion-bound oracle ran. The control must leave the code "
                       "loadable and fail an ASSERTION (#280; 2026-10-23 review, P1-1)")
    # Read the text whatever the summary counted. A stillborn word refuses unless the output
    # carries evidence an assertion was really evaluated.
    stillborn = [mark for mark in STILLBORN_MARKERS if mark in text]
    if stillborn and not STRONG_ASSERTION_RE.search(text):
        return False, (f"the control run did not get as far as an oracle ({stillborn[0]!r} in "
                       "its output, and nothing showing an assertion was evaluated) — that is "
                       "a STILLBORN MUTANT, not a kill. The non-zero exit is the module failing "
                       "to load, which would happen for any command; the control must leave the "
                       "code runnable and fail an ASSERTION (#280)")
    if not any(mark in text for mark in ASSERTION_MARKERS):
        return False, ("the control run exited non-zero but its output names no assertion failure, "
                       "so nothing shows the criterion-bound oracle actually ran and failed; "
                       "fail-closed (#280)")
    return True, None
