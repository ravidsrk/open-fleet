"""The catalog's one grammar: frontmatter and composition, read the same way by every gate.

Private module, loaded by path (no sys.path edits) the way runtime/scripts loads its siblings.
It lives under runtime/scripts/ rather than scripts/ because quarantine_check.py and
proof_status.py ship inside every bundle (scripts/bundle.py vendors runtime/scripts whole) and
must load it beside themselves; scripts/validate.py, eval.py, gen-badges.py, release_check.py
and bundle.py load it from here too.

Two things are defined once here (2026-10-23 review, P1-9 / P1-10 / P2-11 / §5):

1. ``parse_frontmatter`` — five readers had drifted apart. validate.py's nested ``metadata:``
   reader had no block-scalar branch, so ``unit: >-`` plus indented text read as the literal
   ``>-``: the identity point tokenized to nothing and the collision gate scored it 0.0 against
   every mission. A plain multi-line scalar was cut at its first line, so the description and
   compatibility caps measured a fraction of the value. gen-badges split on every ``---`` and
   crashed on one inside a description. Now each reader calls this one.

2. The composition grammar — which names a mission makes mandatory (its Composes/rides clause:
   backticked names AND bare ``name.md`` tokens), which it defers (DEFERRED READS), and which it
   can reach at all (every protocol mention, followed transitively through the protocols it
   reaches). validate.py's quarantine gate read backticks only while the CLI and preflight read
   both, so the CI gate saw a strictly smaller set than the start gate; neither followed a
   playbook into the playbooks it calls.

Stdlib-only.
"""
import os
import re

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# --- frontmatter --------------------------------------------------------------------------

# `>` / `|` with an optional chomping indicator and/or indentation digit, in either order.
BLOCK_SCALAR_RE = re.compile(r"^[|>](?:[1-9]?[+-]?|[+-]?[1-9]?)$")
# A key may open with `-` when a name character follows (`-weird:` is a key the allowlist must
# see, Greptile #224); `- item` is a sequence entry, never a key.
_KEY_RE = re.compile(r"^([A-Za-z_-][A-Za-z0-9_-]*):(?:\s+(.*?))?\s*$")
# A `#` that opens a comment in a plain scalar: start of value or after whitespace.
_PLAIN_COMMENT_RE = re.compile(r"(?:^|\s)#.*$")
# A bare `key:` at top level with nothing indented under it keeps this placeholder, so the
# "compatibility must be a string" error keeps its shape.
OBJECT = "<object>"


def _indent(line):
    return len(line) - len(line.lstrip(" \t"))


def _is_comment(line):
    return line.lstrip(" \t").startswith("#")


def _plain(value):
    """A plain scalar's text with any trailing YAML comment removed."""
    return _PLAIN_COMMENT_RE.sub("", value).strip()


def _closed(value, quote):
    return len(value) >= 2 and value.endswith(quote)


def _quoted(first, rest):
    """A quoted scalar's text; it may continue onto the indented lines under its key."""
    quote, joined = first[0], first.rstrip()
    for line in rest:
        if _closed(joined, quote):
            break
        joined = f"{joined} {line.strip()}".rstrip()
    if not _closed(joined, quote):
        return joined  # unterminated: keep the text rather than invent a value
    inner = joined[1:-1]
    if quote == "'":
        return inner.replace("''", "'")
    return inner.replace('\\"', '"').replace("\\\\", "\\")


def _value(inline, block, top):
    """One key's value from its inline text and the lines indented under it."""
    content = [line for line in block if line.strip()]
    indented = [line for line in content if _indent(line) > 0]
    if inline[:1] in ("'", '"'):
        return _quoted(inline, indented)
    head = _plain(inline)
    if BLOCK_SCALAR_RE.match(head):
        # Folded and literal scalars both read as their lines joined by one space: every
        # consumer (length caps, identity tokens, routing) wants the words, not the layout.
        return " ".join(line.strip() for line in indented)
    if head:
        tail = [_plain(line) for line in indented if not _is_comment(line)]
        return " ".join(part for part in [head, *tail] if part)
    children = [line for line in content if not _is_comment(line)]
    if not children:
        return OBJECT if top else ""
    head = children[0].strip()
    if _KEY_RE.match(head):
        width = _indent(children[0])
        return _mapping([line[min(width, _indent(line)):] for line in block], top=False)
    if head == "-" or head.startswith("- "):
        return OBJECT  # a sequence: not a string, never silently one
    return " ".join(_plain(line) for line in children)


class FrontmatterError(ValueError):
    """A frontmatter shape the reference validator (skills-ref) refuses: raised so a local
    `validate.py` pass never contradicts the CI step (2026-10-26 review)."""


def _mapping(lines, top):
    data = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip() or _is_comment(line) or _indent(line) > 0:
            continue
        m = _KEY_RE.match(line.rstrip())
        if not m:
            if top:
                raise FrontmatterError(f"unreadable top-level frontmatter line: {line.strip()[:60]!r}")
            continue
        if m.group(1) in data:
            raise FrontmatterError(f"duplicate frontmatter key {m.group(1)!r} (last-wins would hide "
                                   "the first value; skills-ref refuses it too)")
        start = i
        while i < len(lines) and (not lines[i].strip() or _indent(lines[i]) > 0
                                  or _is_comment(lines[i])):
            i += 1
        data[m.group(1)] = _value((m.group(2) or "").strip(), lines[start:i], top)
    return data


def frontmatter_lines(text):
    """(frontmatter lines, None) or (None, error). BOM- and CRLF-tolerant.

    The fences are lines that are exactly `---`: a `---` inside a value (indented, or mid-line)
    is content, never a fence.
    """
    if text.startswith("\ufeff"):
        text = text[1:]
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if not lines or lines[0].rstrip() != "---":
        return None, "missing opening ---"
    for end in range(1, len(lines)):
        if lines[end].rstrip() == "---":
            return lines[1:end], None
    return None, "missing closing ---"


def parse_frontmatter(text):
    """(data, None) or (None, error) — a YAML-frontmatter reader for the catalog's subset.

    Top-level keys map to strings; `metadata:` (the agentskills.io extension point) and any other
    key with indented `key: value` lines under it map to a dict read by the same rules. Plain,
    quoted, folded (`>`, `>-`, `>+`) and literal (`|`, `|-`, `|+`) scalars all read as their full
    value at any depth, continuation lines included. Comments are skipped.
    """
    lines, err = frontmatter_lines(text)
    if err:
        return None, err
    try:
        return _mapping(lines, top=True), None
    except FrontmatterError as exc:
        return None, str(exc)


# --- composition ----------------------------------------------------------------------------

# A mission declares what it composes in a "Composes ... rides ..." clause, captured through the
# END of its paragraph — terminating at the first sentence break let an abbreviation ("e.g. ")
# truncate the clause and smuggle dangling names past the check. RIDES (all-caps) is accepted
# alongside Rides/rides, matching COMPOSES handling.
COMPOSE_CLAUSE_RE = re.compile(
    r"\b(?:Composes|COMPOSES|composes|Rides|RIDES|rides)\b\s+(.+?)(?:\n\n|\Z)", re.DOTALL
)
# Mutator evidence-manifest must appear in a composition rides clause, not mid-prose. Accept only
# rides after `;`, after a newline, or at the start of the document.
RIDES_CLAUSE_RE = re.compile(
    r"(?:(?<=;)|(?<=\n)|(?<=\A))\s*(?:Rides|RIDES|rides)\b\s+(.+?)(?:\n\n|\Z)",
    re.DOTALL,
)
# A DEFERRED READS paragraph: protocols loaded on entering a phase, never at activation. Missions
# name them as `name.md`, as backticks, or bare ("acceptance-review at build-blind REVIEW"). It
# opens a line; prose that merely mentions "a DEFERRED READ" mid-sentence is not one.
DEFERRED_RE = re.compile(r"(?m)^[ \t*_]*DEFERRED READS\b(.+?)(?:\n\n|\Z)", re.DOTALL)
BACKTICK_RE = re.compile(r"`([a-z0-9][a-z0-9-]*)`")
ANY_BACKTICK_RE = re.compile(r"`([^`\n]+)`")
MD_TOKEN_RE = re.compile(r"[\w./-]+\.md\b")
_WORD_RE = re.compile(r"(?<![\w./-])([a-z0-9]+(?:-[a-z0-9]+)*)(?![\w/-]|\.md\b)")
# A relative markdown link that does not climb out with `../` (scripts/bundle.py rewrites these).
RELATIVE_LINK_RE = re.compile(
    r"\[([^\]]*)\]\((?!https?:|mailto:|#|/|\.\./)([A-Za-z0-9_./-]+)(#[^)]*)?\)")


def is_url_md_token(text, match):
    """True for https://…/x.md (and //…/x.md) — an external link, not a protocol ref."""
    tok = match.group(0)
    return tok.startswith("//") or text[max(0, match.start() - 1): match.start()] == ":"


def bare_md_stems(text):
    """Bare `<name>.md` tokens that look like protocol names (no URL, no path prefix)."""
    stems = []
    for m in MD_TOKEN_RE.finditer(text):
        if is_url_md_token(text, m) or "/" in m.group(0):
            continue
        stem = m.group(0)[: -len(".md")]
        if NAME_RE.match(stem):
            stems.append(stem)
    return stems


def compose_clause_backticks(text):
    """Backticked names inside every Composes/rides paragraph."""
    return [ref for clause in COMPOSE_CLAUSE_RE.findall(text) for ref in BACKTICK_RE.findall(clause)]


def clause_refs(text):
    """What the Composes/rides clause makes MANDATORY: its backticked names and its bare
    `name.md` tokens. The activation-load measure and the quarantine gate read this one set."""
    refs = set()
    for clause in COMPOSE_CLAUSE_RE.findall(text):
        refs |= set(BACKTICK_RE.findall(clause)) | set(bare_md_stems(clause))
    return refs


def deferred_declared(text):
    """Names a DEFERRED READS paragraph declares unambiguously (backticked or `name.md`)."""
    refs = set()
    for para in DEFERRED_RE.findall(text):
        refs |= set(BACKTICK_RE.findall(para)) | set(bare_md_stems(para))
    return refs


def deferred_words(text):
    """Every name-shaped bare word in a DEFERRED READS paragraph: candidates, kept only when a
    protocol by that name exists (the bare spelling is the only one the reader can resolve)."""
    return {w for para in DEFERRED_RE.findall(text) for w in _WORD_RE.findall(para)}


def explicit_protocol_refs(text):
    """Names that count as an explicit protocol reference: backticked names inside a
    Composes/rides clause, and bare `<name>.md` tokens anywhere. A Related-section backtick is not
    composition (the orphan test imports this through validate.py so the two cannot drift)."""
    return set(compose_clause_backticks(text)) | set(bare_md_stems(text))


def protocol_mentions(text):
    """Every candidate protocol name a document mentions: the explicit refs, any backticked name,
    the stem of any relative markdown link, and the bare words of a DEFERRED READS paragraph.
    Candidates only — a name counts once it resolves to a protocol document."""
    names = explicit_protocol_refs(text) | set(BACKTICK_RE.findall(text))
    names |= {os.path.splitext(os.path.basename(m.group(2)))[0]
              for m in RELATIVE_LINK_RE.finditer(text)}
    # Protocol names are lowercase: a link to README.md or ARCHITECTURE.md names a document,
    # never a protocol, even in a bundle whose references/ holds both.
    return {name for name in names | deferred_words(text) if NAME_RE.match(name)}


def protocol_closure(text, resolve, read):
    """{name: doc} — every protocol reachable from `text`, through the protocols it reaches.

    `resolve(name)` returns the document for a protocol name or None; `read(doc)` returns its
    text. A playbook that calls another (acceptance-review → risk-review) puts the callee in the
    caller's closure, so a quarantined playbook cannot be reached one hop down (P2-11).
    """
    found, pending = {}, [text]
    while pending:
        for name in sorted(protocol_mentions(pending.pop()) - found.keys()):
            doc = resolve(name)
            if doc is not None:
                found[name] = doc
                pending.append(read(doc))
    return found


def clause_token_typos(text, protocols):
    """Backticked clause tokens that are a misspelt protocol reference (P2-18).

    BACKTICK_RE reads lowercase-hyphen names only, so `Build-Change`, `build_change` and
    `playbooks/build-change` in a clause were neither resolved nor flagged while the `.md`
    spellings were. Any backticked clause token whose canonical form names a real protocol, but
    which is not spelled as that bare name, is reported.
    """
    errors = []
    for clause in COMPOSE_CLAUSE_RE.findall(text):
        for token in ANY_BACKTICK_RE.findall(clause):
            if BACKTICK_RE.fullmatch(f"`{token}`") or token.endswith(".md"):
                continue  # the bare form, or a `.md` token the md-ref check already reads
            base = token.strip().rstrip("/").rsplit("/", 1)[-1]
            canon = base.lower().replace("_", "-").strip(" .,;:")
            if canon in protocols:
                errors.append(
                    f"misspelt composition: `{token}` — the protocol is `{canon}`; reference "
                    "protocols by their bare lowercase name")
    return errors
