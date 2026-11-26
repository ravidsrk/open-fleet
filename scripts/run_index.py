#!/usr/bin/env python3
"""The run-archive index as one row file per run, rendered into docs/runs/README.md at the cut.

docs/runs/README.md's table took one hand-written row per run, and its "N reports read yes"
summary was retyped with each one, so two PRs that each filed a run edited the same lines and
conflicted (and the hand-kept counts drifted: the "no" breakdown named three pin-it rows when the
table held ten). A run's row is now docs/runs/index/<run>.json, which only the PR filing that run
touches. This script renders the table and the yes-summary from those files into the generated
block of docs/runs/README.md. The release cut runs it (docs/ops.md, Release cut), so between
releases the block is a dated snapshot that says so, and a run filed since then is listed by its
row file until the next cut.

  python3 scripts/run_index.py check             every row file well formed, one per dated report,
                                                 and the README block consistent with itself
  python3 scripts/run_index.py check --current   ... and the README block is today's rendering
  python3 scripts/run_index.py print             the rendering, to read the index between cuts
  python3 scripts/run_index.py write --as-of DATE    rewrite the README block (the release cut)

Row file docs/runs/index/<key>.json, where <key> is the report's file stem or directory name:
  {"date": "2026-10-24", "report": "2026-10-24-<mission>-<what>.md" (or "<dir>/"),
   "mission": "[<mission>](<report>)", "target": "...", "ran_as": "self-run",
   "binds": "yes — ..." | "no — ...", "outcome": "...",
   "summary": "<the yes-list line>"   (a "yes" row needs one; a "no" row has none),
   "order": 2                          (optional: ties within a date, ascending)}
Cells are the Markdown the table shows, relative to docs/runs/; no cell holds a `|` or a newline.

Exit: 0 every check holds, 1 a check failed, 2 the input could not be read.
"""
import sys

# W3-01: drop this script's own directory from sys.path before any other import, so a sibling
# named like a stdlib module can never be the module imported here (tests/test_entrypoint_guard.py).
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import bisect
import html
import importlib.util
import json
import re
import urllib.parse
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CELLS = ("mission", "target", "ran_as", "binds", "outcome")
REQUIRED = ("date", "report") + CELLS
OPTIONAL = ("summary", "order")
_LINK_RE = re.compile(r"\]\((?!https?:|mailto:|#)([^)\s]+)\)")  # relative Markdown links
# Raw HTML read as CommonMark reads it: a COMPLETE open tag, quote-aware, carrying an attribute
# named exactly href or src (Codex at 54fe725bee: `data-href` and an unclosed `x<a` were refused).
_TAG_NAME_RE = re.compile(r"<[a-z][a-z0-9-]*", re.IGNORECASE)
_TAG_ATTR_RE = re.compile(r"""[ \t\n\x0b\f\r]+([a-z_:][a-z0-9_.:-]*)(?:[ \t\n\x0b\f\r]*=[ \t\n\x0b\f\r]*"""
                          r"""([^ \t\n\x0b\f\r"'=<>`]+|'[^']*'|"[^"]*"))?""", re.IGNORECASE)
_TAG_END_RE = re.compile(r"[ \t\n\x0b\f\r]*/?>")
# Raw HTML blocks (CommonMark 0.31 and GFM, "HTML blocks"): inside one, tags are real, and a
# backtick or a backslash is text. A line may open one when, past any block-quote or list-item
# marks, it starts a type 1-5 block (<script, <pre, <style, <textarea, <!--, <?, <!X, <![CDATA[),
# names a type 6 block tag, or holds one complete tag alone (type 7).
_HTML_OPENER_RE = re.compile(r"<(?:script|pre|style|textarea)(?:[\s>]|$)|<!--|<\?|<![a-z]|<!\[CDATA\[",
                             re.IGNORECASE)
_HTML_BLOCK6_RE = re.compile(
    r"</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|"
    r"div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|"
    r"link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|source|summary|table|tbody|td|"
    r"tfoot|th|thead|title|tr|track|ul)(?:[\s/>]|$)", re.IGNORECASE)
_HTML_BLOCK7_RE = re.compile(
    r"(?:<[a-z][a-z0-9-]*(?:[ \t\n\x0b\f\r]+[a-z_:][a-z0-9_.:-]*(?:[ \t\n\x0b\f\r]*=[ \t\n\x0b\f\r]*"
    r"(?:[^ \t\n\x0b\f\r\"'=<>`]+|'[^']*'|\"[^\"]*\"))?)*[ \t\n\x0b\f\r]*/?>"
    r"|</[a-z][a-z0-9-]*[ \t\n\x0b\f\r]*>)[ \t]*$", re.IGNORECASE)
_CONTAINER_RE = re.compile(r"[ \t]*(?:>|[-*+](?=[ \t]|$)|\d{1,9}[.)](?=[ \t]|$))")
# A line, ending at a CommonMark line ending only (\n, \r\n or \r): str.splitlines would also
# split at U+2028 and friends, inventing lines a renderer never sees (Codex at dde9cbedf9).
_LINE_RE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+")
_CLOSE_TAG_RE = re.compile(r"</[a-z][a-z0-9-]*[ \t\n\x0b\f\r]*>", re.IGNORECASE)
# A "<" a renderer may read as the start of raw HTML or an autolink: a tag, closing tag, comment,
# declaration, processing instruction, CDATA, URI or e-mail autolink. Renderers disagree on
# where each ends (Pandoc renders <!X <a href=...> as a link; CommonMark 0.31 calls it one
# declaration), so the scanner never guesses: past such a "<", backticks and escapes are text.
_MAY_OPEN_RE = re.compile(r"<[a-z0-9.!#$%&'*+/=?^_`{|}~-]", re.IGNORECASE)
# What makes a complete tag unsafe to skip whole: a backtick or a "<" inside it, or a line end.
_UNCLEAR_RE = re.compile(r"[`<\r\n]")
# A bare URL GFM turns into a link (an extended autolink): its path may hold a backtick, so no
# code span opens there (fuzzed against Pandoc's GFM reader, #673).
_BARE_URL_RE = re.compile(r"://|www\.", re.IGNORECASE)
# A tag as an HTML5 tokenizer reads raw HTML, for _loose_link: a name, then attributes whose
# names are anything but whitespace, "/", ">" and "=" (a quote included), each with an optional
# value, quoted or not. Whitespace is HTML's five characters exactly; Python's \s also matches a
# no-break space, which let a quote swallow the href (Codex at a276405fe8).
_LOOSE_NAME_RE = re.compile(r"<[a-z][^ \t\n\f\r/>]*", re.IGNORECASE)
_LOOSE_ATTR_RE = re.compile(r"""[ \t\n\f\r/]*([^ \t\n\f\r/>][^ \t\n\f\r/>=]*)"""
                            r"""([ \t\n\f\r]*=[ \t\n\f\r]*(?:"[^"]*"|'[^']*'|[^ \t\n\f\r>]*))?""")
# Raw HTML that is no tag (CommonMark 0.31, "Raw HTML"): a comment, a processing instruction, a
# declaration or CDATA. And an autolink (URI or e-mail), which CommonMark reads before raw HTML,
# so raw_html() steps over it rather than reading it as a tag (2026-10-27 security audit, W6-14).
# A scheme a browser follows to run or read something rather than to open a page (PR #718
# re-attack, W6-14). Reading link constructs missed one (a reference definition inside a list
# item, review round 3), so the scheme is refused as a token, wherever it stands: a word that
# runs into it (`metadata:`) is no scheme, anything else is.
_DANGEROUS_SCHEME_RE = re.compile(r"(?<![a-z0-9+.\-])(?:javascript|vbscript|data|file) *:")
_RAW_OTHER_RE = re.compile(r"<!--|<\?|<![A-Za-z]|<!\[CDATA\[")
# A line that may be a GFM table's delimiter row (`--- | ---`, `|:-:|`), past quote and list
# marks. GFM splits a row into cells, before it reads a code span, only inside a table, and a
# table needs one: without such a line a "|" is plain text and a code span holding one is code.
_DELIMITER_ROW_RE = re.compile(r"(?m)^[ \t>]*(?:[-*+][ \t]+|\d{1,9}[.)][ \t]+)?"
                               r"(?=[^\n]*\|)(?=[^\n]*-)[|:\- \t]+$")
_AUTOLINK_RE = re.compile(r"<[A-Za-z][A-Za-z0-9.+-]{1,31}:[^\x00-\x20<>]*>"
                          r"|<[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
                          r"[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*>")


def _opens_html(line):
    """Whether `line`, past any block-quote and list-item marks, may open a raw HTML block."""
    rest = line.rstrip("\r\n")
    while mark := _CONTAINER_RE.match(rest):
        rest = rest[mark.end():]
    rest = rest.lstrip(" \t")
    return bool(_HTML_OPENER_RE.match(rest) or _HTML_BLOCK6_RE.match(rest) or _HTML_BLOCK7_RE.match(rest))


# One block quote's mark at a line's start: a renderer strips a quote's marks before reading what
# it holds, so a tag split across quoted lines is whole once they go (Codex at b12df9e457). Only
# as many as the quote's depth go: a ">" after them is the content's own, perhaps a tag's end
# (Codex at 52ef451db4), so each depth is read as its own view.
_QUOTE_MARK_RE = re.compile(r"[ \t]*>[ \t]?")


def _quote_views(text):
    """`text` with up to 1, 2, ... leading block-quote marks removed from each line, one view per
    depth, to the deepest any line has."""
    lines = [m.group() for m in _LINE_RE.finditer(text)]

    def depth(line):
        n = 0
        while mark := _QUOTE_MARK_RE.match(line):  # every mark consumes a ">": no cap (Codex at b0a54260f9)
            line, n = line[mark.end():], n + 1
        return n

    def strip(line, k):
        for _ in range(k):
            if not (mark := _QUOTE_MARK_RE.match(line)):
                break
            line = line[mark.end():]
        return line
    return ["".join(strip(line, k) for line in lines) for k in range(1, max(map(depth, lines), default=0) + 1)]


def _loose_link(text, i, open_ok, any_tag=False):
    """The tag at text[i] when a browser reading it as raw HTML finds an href or src attribute
    with a value in it, else None; with `open_ok` (inside a raw HTML block) closed or not. Past a point where renderers may disagree, text may reach the
    page as raw HTML, so link tags there are read this loosely."""
    if not (name := _LOOSE_NAME_RE.match(text, i)):
        return None
    pos, link = name.end(), any_tag  # any_tag: every tag counts, a link attribute or not
    while attr := _LOOSE_ATTR_RE.match(text, pos):
        link = link or (attr.group(1).lower() in ("href", "src") and attr.group(2) is not None)
        pos = attr.end()
    end = re.compile(r"[ \t\n\f\r/]*>").match(text, pos)
    # In a raw HTML block an unterminated tag counts too: whatever the renderer writes next (a
    # </li>) can close it (Codex at 075baf07c5). In a paragraph it is text a renderer escapes.
    return text[i:end.end() if end else pos] if link and (end or open_ok) else None


def _tag(text, i):
    """(end, links) for a complete open or closing tag at text[i], read quote-aware and across
    lines; None when there is none."""
    if close := _CLOSE_TAG_RE.match(text, i):
        return close.end(), False
    if not (name := _TAG_NAME_RE.match(text, i)):
        return None
    pos, link = name.end(), False
    while attr := _TAG_ATTR_RE.match(text, pos):
        link = link or (attr.group(1).lower() in ("href", "src") and attr.group(2) is not None)
        pos = attr.end()
    end = _TAG_END_RE.match(text, pos)
    return (end.end(), link) if end else None
BEGIN = "<!-- BEGIN GENERATED: run-index — scripts/run_index.py -->"
END = "<!-- END GENERATED: run-index -->"
BLOCK_RE = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
STAMP_RE = re.compile(r"as of (\d{4}-\d{2}-\d{2})\b")
HEADER = ("| Date       | Mission     | Target                        | Ran as       | Binds? | Outcome |\n"
          "|------------|-------------|-------------------------------|--------------|--------|---------|")


def html_link(text):
    """The first HTML tag in Markdown `text` that carries an href or src attribute, or None: read
    in one pass (and again at each depth of block-quote marks removed), skipping a tag only inside an escape or a one-line code span before any raw HTML
    line, unclear "<", "[", bare URL, "|", "$" or open backtick run, and loosely after one. An identical copy of scripts/changelog.py's html_link
    (this script is loaded alone; tests/test_changelog.py holds the two equal)."""
    return next((found for view in (text, *_quote_views(text)) if (found := _first_link(view))), None)


def dangerous_scheme(text):
    """The first javascript:, vbscript:, data: or file: scheme in `text`, wherever it stands and
    whatever Markdown is around it (a list item, a blockquote, a nested list, `<...>`), or None.

    Read as a renderer and then a browser read a link destination, and more: the text as written,
    then decoded up to three times over, each time with every backslash dropped (CommonMark turns
    `javascript\\:` into `javascript:` in the href; found sweeping PR #718 review round 3),
    percent escapes and then HTML entities decoded (a browser decodes no percent escape in a
    scheme, so that only refuses more). Each view is read with case ignored and ASCII control
    characters (a tab or a line break inside the scheme) dropped, and again with them as spaces,
    so neither joining nor splitting hides one. Over-decoding costs a rewording; a missed scheme
    is a script in a published page. Identical in scripts/changelog.py and scripts/run_index.py."""
    views = [text]
    for _ in range(3):
        views.append(html.unescape(urllib.parse.unquote(views[-1].replace("\\", ""))))
    for view in views:
        lowered = view.lower()
        for folded in (re.sub(r"[\x00-\x1f\x7f]", "", lowered),
                       re.sub(r"[\x00-\x1f\x7f]", " ", lowered)):
            if match := _DANGEROUS_SCHEME_RE.search(folded):
                return match.group()
    return None


def raw_html(text):
    """The first raw HTML in Markdown `text`, or None: any tag, open or closing, with or without
    an href or src, a comment, a processing instruction, a declaration or CDATA, read the way
    html_link reads a link tag (skipped only inside an escape or a one-line code span before any
    point where renderers may disagree). Both writers emit a cell or a fragment verbatim into a
    published page, so a tag with no link in it (`<script>`) reaches it too (2026-10-27 security
    audit, W6-14). Identical in scripts/changelog.py and scripts/run_index.py."""
    return next((found for view in (text, *_quote_views(text))
                 if (found := _first_link(view, any_tag=True))), None)


def _first_link(text, any_tag=False):
    """html_link's one pass over one view of `text` (raw_html's, with `any_tag`)."""
    lines = [m.span() for m in _LINE_RE.finditer(text)]
    starts = [start for start, _end in lines]
    # Backticks and escapes are text from the first line that may open raw HTML, from the first
    # "<" that may begin raw HTML or an autolink and is not a plain one-line tag, from the first
    # "[" (a link or image, whose text, destination or title may hold a backtick), from the first
    # bare URL (GFM links it), the first "|" (GFM splits a table row into cells before reading a
    # span), the first "$" (Pandoc's GFM math, $x$ or $`x`$), and from the first backtick run
    # left open on its line: past any of
    # these, where a span or construct ends depends on the renderer, and a link tag is read as a
    # browser reads raw HTML (_loose_link).
    literal = html = next((start for start, end in lines if _opens_html(text[start:end])), len(text))
    # html_link reads every "|" as a table cell's edge; raw_html only where a table can exist.
    tables = not any_tag or bool(_DELIMITER_ROW_RE.search(text))
    i = 0
    while i < len(text):
        inline = i < literal
        if inline and text[i] == "\\":
            i += 2
        elif inline and text[i] == "[":
            literal, i = i, i + 1  # a link's text, destination or title may hold a backtick (Codex at d16ff6e5cc)
        elif inline and (_BARE_URL_RE.match(text, i) or text[i] == "$" or text[i] == "|" and tables):
            literal, i = i, i + 1  # a bare URL, a table cell's edge, or Pandoc's $math$ (Codex at 737bef7213, b897354b7b)
        elif inline and text[i] == "`":
            line_end = lines[bisect.bisect_right(starts, i) - 1][1]
            run = len(text[i:line_end]) - len(text[i:line_end].lstrip("`"))
            close = re.compile(f"(?<!`){'`' * run}(?!`)").search(text, i + run, line_end)
            if close and not (tables and "|" in text[i + run:close.start()]):
                i = close.end()
            else:  # left open, or holding a "|" that may split it into table cells (Codex at 0527c08900)
                literal, i = i, i + run
        elif text[i] == "<":
            if any_tag and (auto := _AUTOLINK_RE.match(text, i)):
                literal, i = min(literal, i), auto.end()  # a link, not raw HTML; past it, read loosely
                continue
            tag = _tag(text, i)
            if tag and (tag[1] or any_tag):
                return text[i:tag[0]]
            if any_tag and (other := _RAW_OTHER_RE.match(text, i)):
                return other.group()
            if not inline and (loose := _loose_link(text, i, open_ok=i >= html, any_tag=any_tag)):
                return loose
            if inline and tag and not _UNCLEAR_RE.search(text, i + 1, tag[0]):
                i = tag[0]  # a whole one-line tag holding no backtick and no "<": skipping it hides nothing
            elif inline and _MAY_OPEN_RE.match(text, i):
                literal = i  # read this same "<" again as raw HTML (Codex at 5f1eb56a73), then on
            else:
                i += 1
        else:
            i += 1
    return None


def runs_dir(root=ROOT):
    return Path(root) / "docs" / "runs"


def dated_reports(root=ROOT):
    """Every dated run report: a top-level docs/runs/2*.md, or a docs/runs/2*/ with a README.

    The same set tests/test_docs_navigation.py holds the index to (#35), named the way a row
    links it: `<file>.md` or `<dir>/`.
    """
    d = runs_dir(root)
    files = [f.name for f in sorted(d.glob("2*.md")) if f.is_file()]
    dirs = [p.name + "/" for p in sorted(d.glob("2*")) if p.is_dir() and (p / "README.md").is_file()]
    return files + dirs


def row_key(report):
    return report[:-1] if report.endswith("/") else report[:-3] if report.endswith(".md") else report


def row_errors(name, data, root=ROOT):
    """Why one row file cannot render as an honest table row ([] when it can)."""
    where = f"docs/runs/index/{name}"
    if not isinstance(data, dict):
        return [f"{where}: a row file is one JSON object"]
    errors = []
    missing = [k for k in REQUIRED if not isinstance(data.get(k), str) or not data[k].strip()]
    if missing:
        errors.append(f"{where}: missing or empty {missing}")
    unknown = sorted(set(data) - set(REQUIRED) - set(OPTIONAL))
    if unknown:
        errors.append(f"{where}: unknown keys {unknown}")
    if missing:
        return errors
    try:
        if date.fromisoformat(data["date"]).isoformat() != data["date"]:
            raise ValueError
    except ValueError:
        errors.append(f"{where}: date {data['date']!r} is not YYYY-MM-DD")
    report = data["report"]
    if name != row_key(report) + ".json":
        errors.append(f"{where}: name the file after its report, {row_key(report)}.json")
    target = runs_dir(root) / report
    if "/" in report.rstrip("/") or not (target / "README.md" if report.endswith("/")
                                         else target).is_file():
        errors.append(f"{where}: report {report!r} is not a run report under docs/runs/")
    if f"({report})" not in data["mission"]:
        errors.append(f"{where}: the mission cell does not link ({report})")
    for cell in CELLS + ("summary",):
        value = data.get(cell)
        if isinstance(value, str) and ("|" in value or "\n" in value):
            errors.append(f"{where}: {cell} holds a '|' or a newline, which breaks the table")
    for cell in CELLS + ("summary",):  # the README is not re-rendered until the cut (PR #670)
        value = data.get(cell)
        if isinstance(value, str) and html_link(value):
            errors.append(f"{where}: {cell} holds an HTML link; write it as a Markdown link "
                          "[text](path), which this check resolves")
        elif isinstance(value, str) and (raw := raw_html(value)):
            errors.append(f"{where}: {cell} holds raw HTML ({raw[:40]!r}), which docs/runs/README.md "
                          "would publish verbatim; put it in a code span or escape the '<'")
        if isinstance(value, str) and (bad := dangerous_scheme(value)):
            errors.append(f"{where}: {cell} holds {bad!r}: a javascript:, vbscript:, data: or "
                          "file: scheme is refused anywhere in a cell")
        for href in _LINK_RE.findall(value) if isinstance(value, str) else ():
            path = href.split("#", 1)[0]
            if path and not (runs_dir(root) / path).exists():
                errors.append(f"{where}: {cell} link ({href}) does not resolve from docs/runs/")
    binds = data["binds"]
    if not (binds == "yes" or binds.startswith("yes ") or binds.startswith("no ")
            or binds == "no"):
        errors.append(f"{where}: binds opens with 'yes' or 'no' — it is what moves a tier")
    summary = data.get("summary")
    if binds.startswith("yes") and not (isinstance(summary, str) and summary.strip()):
        errors.append(f"{where}: a row that binds needs the summary line the yes-list prints")
    if binds.startswith("no") and summary is not None:
        errors.append(f"{where}: only a row that binds has a summary line")
    order = data.get("order")
    if order is not None and (not isinstance(order, int) or isinstance(order, bool) or order < 0):
        errors.append(f"{where}: order is a non-negative integer")
    return errors


def load_rows(root=ROOT):
    """(rows sorted for the table, errors). Unreadable files are errors, never skipped."""
    rows, errors = [], []
    index = runs_dir(root) / "index"
    for path in sorted(index.glob("*")) if index.is_dir() else []:
        if path.suffix != ".json" or not path.is_file():
            errors.append(f"docs/runs/index/{path.name}: only <run>.json row files live here")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
            errors.append(f"docs/runs/index/{path.name}: unreadable ({err})")
            continue
        problems = row_errors(path.name, data, root)
        errors += problems
        if not problems:
            rows.append(data)
    rows.sort(key=lambda r: (r["date"], r.get("order", 0), r["report"]))
    return rows, errors


_RUN_REPORT_CACHE = {}


def _load_run_report(root):
    """Load `runtime/scripts/run_report.py` from `root`, cached by path, or None when absent
    (e.g. a bare fixture tree testing run_index.py standalone)."""
    script = Path(root) / "runtime" / "scripts" / "run_report.py"
    if not script.is_file():
        return None
    key = str(script.resolve())
    if key not in _RUN_REPORT_CACHE:
        spec = importlib.util.spec_from_file_location("_run_index_run_report", script)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _RUN_REPORT_CACHE[key] = mod
    return _RUN_REPORT_CACHE[key]


def check_bindings(root=ROOT, rows=None):
    """Verify every row whose `binds` starts with `'yes'` actually passes `run_report.check_report()`
    (#784). Returns [] when `runtime/scripts/run_report.py` is absent in `root` (standalone fixtures)."""
    rr = _load_run_report(root)
    if rr is None:
        return []
    if rows is None:
        rows, _ = load_rows(root)
    errors = []
    root_path = Path(root)
    for r in rows:
        if not r["binds"].startswith("yes"):
            continue
        report = r["report"]
        where = f"docs/runs/index/{row_key(report)}.json"
        if report.endswith("/"):
            errors.append(f"{where}: binds claims 'yes', but {report!r} is a directory rather than "
                          "a bindable run report")
            continue
        rel = f"docs/runs/{report}"
        try:
            text = (root_path / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as err:
            errors.append(f"{where}: binds claims 'yes', but {rel} is unreadable ({err})")
            continue
        fields, err = rr.parse_run_header(text)
        if err is not None:
            errors.append(f"{where}: binds claims 'yes', but {rel} fails run_report: {err}")
            continue
        tier = fields.get("tier")
        if tier not in ("doctrine-only", "self-run", "external-run"):
            errors.append(f"{where}: binds claims 'yes', but {rel} declares invalid RUN tier {tier!r}")
            continue
        label_m = re.search(rf"\[([^\]]+)\]\({re.escape(report)}\)", r["mission"])
        if not label_m or label_m.group(1) != fields["mission"]:
            got_label = label_m.group(1) if label_m else r["mission"]
            errors.append(f"{where}: binds claims 'yes', but row mission {got_label!r} disagrees with "
                          f"{rel} RUN mission {fields['mission']!r}")
            continue
        ran_as = r["ran_as"]
        if tier == "doctrine-only":
            if ran_as != "doctrine-only" and not re.search(r"\bdoctrine-only\b", r["binds"]):
                errors.append(f"{where}: binds claims 'yes', but row ran_as {ran_as!r} disagrees with "
                              f"{rel} RUN tier {tier!r}")
                continue
        elif ran_as != tier:
            errors.append(f"{where}: binds claims 'yes', but row ran_as {ran_as!r} disagrees with "
                          f"{rel} RUN tier {tier!r}")
            continue
        bind_errs = rr.check_report(rel, fields["mission"], tier, root=root_path)
        if bind_errs:
            errors.append(f"{where}: binds claims 'yes', but {rel} fails run_report: {bind_errs[0]}")
    return errors


def check_rows(root=ROOT):
    """Row-file errors plus completeness: exactly one row per dated run report, and every `'yes'`
    row verified against `run_report.check_report()` when the binder is present in `root`."""
    rows, errors = load_rows(root)
    named = {}
    for r in rows:
        named.setdefault(r["report"], 0)
        named[r["report"]] += 1
    for report in dated_reports(root):
        if report not in named:
            errors.append(f"docs/runs/{report} has no row: add docs/runs/index/{row_key(report)}.json")
    for report, n in sorted(named.items()):
        if n > 1:
            errors.append(f"docs/runs/{report} has {n} rows")
    errors += check_bindings(root, rows=rows)
    return errors


def render(rows, as_of):
    """The generated block: stamp, yes-summary, then the table."""
    yes = [r for r in rows if r["binds"].startswith("yes")]
    lines = [BEGIN,
             f"_Generated by `python3 scripts/run_index.py` from one row file per run in "
             f"[`index/`](index/), as of {as_of}. A run filed after that date has its row file "
             f"there and joins this table at the next release cut._",
             "",
             f"{len(yes)} of the {len(rows)} reports in the archive read **yes**:"]
    lines += [f"- {r['summary']}{'.' if i == len(yes) - 1 else ';'}" for i, r in enumerate(yes)]
    lines += ["",
              "Every other row reads **no**, and its `Binds?` cell says why.",
              "",
              HEADER]
    lines += [f"| {r['date']} | {r['mission']} | {r['target']} | {r['ran_as']} | {r['binds']} | "
              f"{r['outcome']} |" for r in rows]
    lines.append(END)
    return "\n".join(lines)


def readme_block(root=ROOT):
    """(README text, generated block match); (None, None) when the archive has no README."""
    path = runs_dir(root) / "README.md"
    if not path.is_file():
        return None, None
    text = path.read_text(encoding="utf-8")
    return text, BLOCK_RE.search(text)


COUNT_RE = re.compile(r"(?m)^(\d+) of the (\d+) reports in the archive read \*\*yes\*\*:$")


def check_snapshot(root=ROOT):
    """Errors when the README block contradicts itself, which only a hand edit can do.

    Between cuts the block is a dated snapshot, so it may lack rows filed since; it may never
    carry a count its own table does not show, a row twice, or a row for a report that is gone.
    """
    text, found = readme_block(root)
    if text is None:
        return ["docs/runs/README.md is missing — the run archive has no index page"]
    if not found:
        return ["docs/runs/README.md has no generated run-index block (its markers are gone)"]
    block = found.group(0)
    where = "docs/runs/README.md's run index"
    errors = []
    if not STAMP_RE.search(block):
        errors.append(f"{where} carries no 'as of' date")
    table = [ln for ln in block.split("\n") if ln.startswith("| 2")]
    cells = [[c.strip() for c in ln.strip("|").split(" | ")] for ln in table]
    yes = [c for c in cells if len(c) == 6 and c[4].startswith("yes")]
    bullets = [ln for ln in block.split("\n") if ln.startswith("- ")]
    count = COUNT_RE.search(block)
    if not count:
        errors.append(f"{where} has no 'N of the M reports ... read **yes**' line")
    elif (int(count.group(1)), int(count.group(2))) != (len(yes), len(table)) or len(bullets) != len(yes):
        errors.append(f"{where} says {count.group(1)} of {count.group(2)} read yes, but its table "
                      f"shows {len(yes)} of {len(table)} and its list {len(bullets)} — the count "
                      "is generated, never typed: run_index.py write at the cut")
    linked = [re.findall(r"\]\(([^)]+)\)", c[1])[:1] for c in cells]
    reports = [x[0] for x in linked if x]
    for report in sorted({r for r in reports if reports.count(r) > 1}):
        errors.append(f"{where} lists {report} twice")
    present = set(dated_reports(root))
    for report in sorted(set(reports) - present):
        errors.append(f"{where} lists {report}, which is not a run report under docs/runs/")
    return errors


def check_current(root=ROOT):
    """Errors unless the README block equals a fresh rendering at the block's own stamp."""
    rows, errors = load_rows(root)
    text, found = readme_block(root)
    if text is None:
        return errors + ["docs/runs/README.md is missing — the run archive has no index page"]
    if not found:
        return errors + ["docs/runs/README.md has no generated run-index block"]
    stamp = STAMP_RE.search(found.group(0))
    if not stamp:
        return errors + ["docs/runs/README.md's run-index block carries no 'as of' date"]
    if found.group(0) != render(rows, stamp.group(1)):
        errors.append("docs/runs/README.md's run index is not the rendering of docs/runs/index/ "
                      "— run python3 scripts/run_index.py write --as-of <the cut's date>")
    return errors


def write(as_of, root=ROOT):
    """Rewrite the README block from the row files. Raises ValueError on any row error."""
    errors = check_rows(root)
    if errors:
        raise ValueError("; ".join(errors))
    rows, _ = load_rows(root)
    text, found = readme_block(root)
    if not found:
        raise ValueError("docs/runs/README.md has no generated run-index block to fill")
    new = text[:found.start()] + render(rows, as_of) + text[found.end():]
    if new != text:
        (runs_dir(root) / "README.md").write_text(new, encoding="utf-8")
    return len(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="run_index.py",
                                     description="Render docs/runs/README.md's index from row files.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="row files well formed, one per dated report")
    c.add_argument("--current", action="store_true",
                   help="also require the README block to be today's rendering (the cut)")
    sub.add_parser("print", help="print the rendering without writing it")
    w = sub.add_parser("write", help="rewrite the README block (the release cut runs this)")
    w.add_argument("--as-of", required=True, help="the date the block says it was generated")
    args = parser.parse_args(argv)
    root = ROOT  # read at call time, so a test can point the CLI at a fixture in-process
    try:
        if args.cmd == "print":
            rows, errors = load_rows(root)
            for e in errors:
                print(f"FAIL {e}", file=sys.stderr)
            print(render(rows, date.today().isoformat()))
            return 1 if errors else 0
        if args.cmd == "write":
            if date.fromisoformat(args.as_of).isoformat() != args.as_of:
                raise ValueError(f"--as-of {args.as_of!r} is not YYYY-MM-DD")
            n = write(args.as_of, root)
            print(f"docs/runs/README.md: run index rendered from {n} row files, as of {args.as_of}")
            return 0
        errors = check_rows(root) + check_snapshot(root)
        if args.current:
            errors += check_current(root)
    except (OSError, ValueError) as err:
        print(f"run_index.py: {err}", file=sys.stderr)
        return 2
    for e in errors:
        print(f"FAIL {e}")
    if errors:
        return 1
    print(f"run index: {len(dated_reports(root))} reports, one row each"
          + ("; the README block is current" if args.current else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
