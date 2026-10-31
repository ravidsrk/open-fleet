#!/usr/bin/env python3
"""Direct unit tests for the pure helpers in gitexec.py.

The git-custody path runs every content-reading git call through helpers in
runtime/scripts/gitexec.py. The pure ones had no direct tests:

- _c_quote (C quoting for an objects/info/alternates line);
- _config_quote (git-config quoting, which refuses a newline);
- sound_lane (first set provenance variable).

They were only exercised end to end. These are small, side-effect-free
functions, so they are a gentle way into the security-critical code.

No production code changes. Floor guard stays clean.
"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "runtime" / "scripts"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gitexec = _load("gitexec", "gitexec.py")


class CQuote(unittest.TestCase):
    """_c_quote: printable ASCII passes through; specials become \\NNN octal."""

    def test_printable_ascii_passes_through(self):
        raw = b"hello world"
        self.assertEqual(gitexec._c_quote(raw), b'"hello world"')

    def test_quote_backslash_and_control_are_octal(self):
        # " and \ must be escaped; newline, DEL and high bytes too.
        raw = b'"\\\n\x7f\xff'
        quoted = gitexec._c_quote(raw)
        self.assertTrue(quoted.startswith(b'"') and quoted.endswith(b'"'))
        # Inside the quotes: \042 for ", \134 for \, \012 for \n, \177 for DEL, \377 for 0xff
        body = quoted[1:-1]
        self.assertIn(b"\\042", body)
        self.assertIn(b"\\134", body)
        self.assertIn(b"\\012", body)
        self.assertIn(b"\\177", body)
        self.assertIn(b"\\377", body)

    def test_space_and_tab_are_quoted_when_needed(self):
        # Space is 0x20 and passes; tab is control and is octal.
        self.assertEqual(gitexec._c_quote(b"a b"), b'"a b"')
        self.assertIn(b"\\011", gitexec._c_quote(b"\t"))


class ConfigQuote(unittest.TestCase):
    """_config_quote: escapes \\ and \"; refuses a newline."""

    def test_plain_value_is_double_quoted(self):
        self.assertEqual(gitexec._config_quote("hello"), '"hello"')

    def test_backslash_and_quote_are_escaped(self):
        self.assertEqual(gitexec._config_quote(r'a\b"c'), r'"a\\b\"c"')

    def test_newline_raises_git_custody_refused(self):
        with self.assertRaises(gitexec.GitCustodyRefused):
            gitexec._config_quote("line1\nline2")

    def test_empty_and_whitespace_are_accepted(self):
        self.assertEqual(gitexec._config_quote(""), '""')
        self.assertEqual(gitexec._config_quote("  "), '"  "')


class SoundLane(unittest.TestCase):
    """sound_lane: first set provenance variable in PROVENANCE_VARS order, or None."""

    def test_empty_environment_returns_none(self):
        self.assertIsNone(gitexec.sound_lane({}))

    def test_whitespace_only_is_treated_as_unset(self):
        env = {"OPEN_FLEET_PROVENANCE": "   ", "ORCA_PROVENANCE": "\t"}
        self.assertIsNone(gitexec.sound_lane(env))

    def test_first_set_variable_wins(self):
        env = {"OPEN_FLEET_PROVENANCE": "trusted", "ORCA_PROVENANCE": "also"}
        self.assertEqual(gitexec.sound_lane(env), "OPEN_FLEET_PROVENANCE=trusted")

    def test_second_variable_used_when_first_unset(self):
        env = {"ORCA_PROVENANCE": "ok"}
        self.assertEqual(gitexec.sound_lane(env), "ORCA_PROVENANCE=ok")

    def test_order_is_provenence_vars(self):
        # Explicitly check the documented order.
        self.assertEqual(gitexec.PROVENANCE_VARS[0], "OPEN_FLEET_PROVENANCE")
        env = {
            "OPEN_FLEET_PROVENANCE": "first",
            "ORCA_PROVENANCE": "second",
        }
        self.assertTrue(gitexec.sound_lane(env).startswith("OPEN_FLEET_PROVENANCE="))


if __name__ == "__main__":
    unittest.main()
