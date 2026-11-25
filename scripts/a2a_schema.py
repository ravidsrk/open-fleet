#!/usr/bin/env python3
"""Validate A2A AgentCards against the pinned official A2A proto, stdlib only (#607).

open-fleet's exporter emits its own offline mission descriptor. Whether a JSON object is an A2A
transport AgentCard is a question only the protocol's own schema answers, so this module answers
it from that schema and nothing else. Upstream's normative schema is `specification/a2a.proto`
(package `lf.a2a.v1`); at the pinned commit its JSON Schema is a generated build artifact that is
not committed. So this module reads the vendored proto itself -- pinned by commit and sha256 in
scripts/vendor/a2a/PIN.json, refused when the bytes drift -- and checks a ProtoJSON value:

* every key is a field of the message, by its lowerCamelCase JSON name or its proto name but not
  both; an unknown key is refused, as a ProtoJSON parser refuses it by default;
* every value has the field's JSON shape (string, bool, object, array, map,
  google.protobuf.Struct, every nested Value walked and every number a finite double), and at
  most one member of a oneof is set;
* `(google.api.field_behavior) = REQUIRED` is enforced, including the part proto3 parsing alone
  cannot see: a required string or repeated field that is empty is unset on the wire, so it is
  refused (roadmap verification note G4).

Semantic checks the proto cannot express run once the shape passes: every `url`/`*_url` field
under AgentCard (https where the proto says TLS is required), binding and protocol-version
forms, unique skill ids, media types (parameters allowed), security requirements
that name a declared scheme, API-key locations the proto lists, base64url signature parts and
unique RFC 3986 extension URIs.

The parser covers exactly the proto constructs the pinned file uses and raises on anything else,
and the validator refuses a message whose field closure holds a type it does not check. A re-pin
that brings in `reserved`, a nested type, `json_name`, an enum or a new scalar under AgentCard
therefore fails loudly instead of being validated wrongly; tests/test_a2a_schema.py pins both.

Usage:
    python3 scripts/a2a_schema.py card.json [...]   # validate ProtoJSON AgentCard files
    python3 scripts/a2a_schema.py --required        # required AgentCard fields, in proto order
    python3 scripts/a2a_schema.py --check-pin       # re-hash the vendored files against PIN.json

Exit: 0 valid · 1 invalid card or pin drift · 2 usage error.
"""
import sys
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
VENDOR_DIR = ROOT / "scripts" / "vendor" / "a2a"
PIN_PATH = VENDOR_DIR / "PIN.json"
PROTO_PATH = VENDOR_DIR / "a2a.proto"
PROTO_PIN_PATH = "scripts/vendor/a2a/a2a.proto"

# Exactly the constructs the pinned a2a.proto uses. Anything else is a ProtoSchemaError: a schema
# this parser half-understands must never validate a card.
FILE_OPTIONS = frozenset({
    "csharp_namespace", "go_package", "java_multiple_files", "java_outer_classname", "java_package",
})
RPC_OPTIONS = frozenset({"google.api.http", "google.api.method_signature"})
FIELD_BEHAVIORS = frozenset({"REQUIRED"})
PROTO_SCALARS = frozenset({
    "double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64",
    "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes",
})
WELL_KNOWN = frozenset({
    "google.protobuf.Struct", "google.protobuf.Value", "google.protobuf.Timestamp",
    "google.protobuf.Empty",
})
# What the validator checks. The AgentCard closure at the pin uses only these; a type outside the
# set under the validated message is refused rather than waved through.
VALIDATED_TYPES = frozenset({"string", "bool", "google.protobuf.Struct"})

CORE_BINDINGS = ("JSONRPC", "GRPC", "HTTP+JSON")
# a2a.proto APIKeySecurityScheme.location: 'Valid values are "query", "header", or "cookie".' (#636)
API_KEY_LOCATIONS = ("query", "header", "cookie")
# URL fields a2a.proto marks TLS-only, each with its comment quoted at the pin: an http:// value
# is refused (#636). AgentInterface.url is not here: "must be a valid absolute HTTPS URL in
# production" is a deployment rule, and a card validator cannot know the card is for production.
TLS_REQUIRED = {
    ("OAuth2SecurityScheme", "oauth2_metadata_url"): "TLS is required.",
    ("ImplicitOAuthFlow", "authorization_url"): "The OAuth2 standard requires the use of TLS",
    ("ImplicitOAuthFlow", "refresh_url"): "The OAuth2 standard requires the use of TLS.",
    ("PasswordOAuthFlow", "token_url"): "The OAuth2 standard requires the use of TLS.",
    ("PasswordOAuthFlow", "refresh_url"): "The OAuth2 standard requires the use of TLS.",
}
# Form checks use fullmatch: `$` also matches before a final "\n", and `\d` matches any Unicode
# digit, so "1.0\n" or Arabic-Indic digits passed (#636).
_PROTOCOL_VERSION = re.compile(r"[0-9]+\.[0-9]+")
# A media type (RFC 9110 section 8.3.1): RFC 6838 restricted-name type/subtype, then any number of
# `;` parameters, each token=token or token="quoted-string" (#636). Used with fullmatch.
_RESTRICTED_NAME = r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}"
_HTTP_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_QUOTED_STRING = r'"(?:[\t !#-\[\]-~]|\\[\t -~])*"'
_MEDIA_TYPE = re.compile(
    _RESTRICTED_NAME + "/" + _RESTRICTED_NAME
    + r"(?:[ \t]*;[ \t]*" + _HTTP_TOKEN + "=(?:" + _HTTP_TOKEN + "|" + _QUOTED_STRING + "))*")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")
# RFC 3986 section 3, parsed by component (#636): scheme ":" hier-part ["?" query] ["#" fragment].
# An identifier needs no network host (`tag:`, `urn:`); brackets appear only around an IP-literal
# host, and every `%` is followed by two hex digits.
_PCT = r"%[0-9A-Fa-f]{2}"
_UNRESERVED_SUB_DELIMS = r"A-Za-z0-9\-._~!$&'()*+,;="
_PCHAR = "(?:[" + _UNRESERVED_SUB_DELIMS + ":@]|" + _PCT + ")"
_URI_SPLIT = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):([^?#]*)(?:\?([^#]*))?(?:#(.*))?", re.S)
_SEGMENT = re.compile(_PCHAR + "*")
_QUERY_OR_FRAGMENT = re.compile("(?:" + _PCHAR + "|[/?])*")
_USERINFO = re.compile("(?:[" + _UNRESERVED_SUB_DELIMS + ":]|" + _PCT + ")*")
_REG_NAME = re.compile("(?:[" + _UNRESERVED_SUB_DELIMS + "]|" + _PCT + ")*")
_IPV_FUTURE = re.compile(r"v[0-9A-Fa-f]+\.[" + _UNRESERVED_SUB_DELIMS + ":]+")
# Schemes whose URI names a network authority: for these an empty host is not a URI (RFC 9110 4.2).
_HOST_SCHEMES = ("http", "https", "ws", "wss")
# gRPC `host:port`, split only: _dial_host judges the host, as it does a URL's (#636).
_HOST_PORT = re.compile(r"(\[[^\]]*\]|[^\[\]:]*):([0-9]{1,5})")
# One DNS label (RFC 1123 2.1): letters, digits and inner hyphens, 1-63 characters (#636).
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>//[^\n]*|/\*.*?\*/)
  | (?P<string>"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')
  | (?P<number>\d+)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
  | (?P<symbol>[{}\[\]()<>=;,:.-])
""", re.S | re.X)


class ProtoSchemaError(Exception):
    """The pinned schema is unreadable, drifted, or uses a construct this module does not cover."""


@dataclass
class Field:
    name: str
    number: int
    type: str
    label: str = ""  # "", "optional", "repeated" or "map"
    key_type: str = ""
    required: bool = False
    deprecated: bool = False
    oneof: str = ""

    @property
    def json_name(self):
        """protoc's lowerCamelCase JSON name: drop each `_` and upper-case the letter after it."""
        out, upper = [], False
        for ch in self.name:
            if ch == "_":
                upper = True
            else:
                out.append(ch.upper() if upper else ch)
                upper = False
        return "".join(out)


@dataclass
class Message:
    name: str
    fields: list = field(default_factory=list)
    oneofs: dict = field(default_factory=dict)

    def lookup(self, key):
        for f in self.fields:
            if key in (f.json_name, f.name):
                return f
        return None


@dataclass
class Schema:
    package: str
    imports: list
    messages: dict
    enums: dict
    services: dict
    sha256: str = ""

    @property
    def major(self):
        """The protocol major the package names (`lf.a2a.v1` -> "1")."""
        m = re.search(r"\.v([0-9]+)\Z", self.package)
        return m.group(1) if m else ""


def _tokenize(text):
    tokens, pos, line = [], 0, 1
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ProtoSchemaError(f"line {line}: unexpected character {text[pos]!r}")
        kind = m.lastgroup
        if kind not in ("ws", "comment"):
            tokens.append((kind, m.group(), line))
        line += m.group().count("\n")
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, text):
        self.toks = _tokenize(text)
        self.i = 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else ("eof", "", -1)

    def take(self, value=None, kind=None):
        tok = self.peek()
        if tok[0] == "eof" or (value is not None and tok[1] != value) or (kind and tok[0] != kind):
            want = value or kind or "a token"
            raise ProtoSchemaError(f"line {tok[2]}: expected {want!r}, found {tok[1]!r}")
        self.i += 1
        return tok

    def unsupported(self, what):
        tok = self.peek()
        raise ProtoSchemaError(f"line {tok[2]}: unsupported proto construct {what!r} "
                               "(scripts/a2a_schema.py covers only what the pinned a2a.proto uses)")

    def parse(self):
        schema = Schema(package="", imports=[], messages={}, enums={}, services={})
        while self.peek()[0] != "eof":
            word = self.peek()[1]
            if word == "syntax":
                self.take("syntax")
                self.take("=")
                if self.take(kind="string")[1].strip("\"'") != "proto3":
                    self.unsupported("syntax other than proto3")
                self.take(";")
            elif word == "package":
                self.take("package")
                schema.package = self.take(kind="ident")[1]
                self.take(";")
            elif word == "import":
                self.take("import")
                schema.imports.append(self.take(kind="string")[1].strip("\"'"))
                self.take(";")
            elif word == "option":
                self.take("option")
                name = self.take(kind="ident")[1]
                if name not in FILE_OPTIONS:
                    self.unsupported(f"option {name}")
                self.take("=")
                self._constant()
                self.take(";")
            elif word == "message":
                msg = self._message()
                schema.messages[msg.name] = msg
            elif word == "enum":
                name, values = self._enum()
                schema.enums[name] = values
            elif word == "service":
                name, rpcs = self._service()
                schema.services[name] = rpcs
            else:
                self.unsupported(word)
        _resolve(schema)
        return schema

    def _constant(self):
        tok = self.peek()
        if tok[0] in ("ident", "string", "number"):
            return self.take()[1]
        if tok[1] == "-":
            self.take("-")
            return "-" + self.take(kind="number")[1]
        return self.unsupported(f"option value {tok[1]}")

    def _message(self):
        self.take("message")
        msg = Message(name=self.take(kind="ident")[1])
        self.take("{")
        while self.peek()[1] != "}":
            word = self.peek()[1]
            if word == "oneof":
                self.take("oneof")
                oneof = self.take(kind="ident")[1]
                self.take("{")
                members = []
                while self.peek()[1] != "}":
                    f = self._field(oneof=oneof)
                    msg.fields.append(f)
                    members.append(f.name)
                self.take("}")
                msg.oneofs[oneof] = members
            elif word in ("message", "enum", "reserved", "extensions", "extend", "option", "group",
                          "required"):
                self.unsupported(f"{word} inside message {msg.name}")
            else:
                msg.fields.append(self._field())
        self.take("}")
        return msg

    def _field(self, oneof=""):
        label, key_type = "", ""
        if self.peek()[1] in ("optional", "repeated") and not oneof:
            label = self.take()[1]
        if self.peek()[1] == "map" and not oneof and not label:
            self.take("map")
            self.take("<")
            key_type = self.take(kind="ident")[1]
            self.take(",")
            ftype = self.take(kind="ident")[1]
            self.take(">")
            label = "map"
        else:
            ftype = self.take(kind="ident")[1]
            if ftype in ("message", "enum", "oneof", "map", "optional", "repeated", "group",
                         "required", "reserved", "extensions", "extend", "option", "stream"):
                self.unsupported(f"{ftype} in field position")
        f = Field(name=self.take(kind="ident")[1], number=0, type=ftype, label=label,
                  key_type=key_type, oneof=oneof)
        self.take("=")
        f.number = int(self.take(kind="number")[1])
        if self.peek()[1] == "[":
            self.take("[")
            while True:
                self._field_option(f)
                if self.peek()[1] != ",":
                    break
                self.take(",")
            self.take("]")
        self.take(";")
        return f

    def _field_option(self, f):
        if self.peek()[1] == "(":
            self.take("(")
            name = self.take(kind="ident")[1]
            self.take(")")
            self.take("=")
            value = self._constant()
            if name != "google.api.field_behavior" or value not in FIELD_BEHAVIORS:
                self.unsupported(f"field option ({name}) = {value}")
            f.required = True
            return
        name = self.take(kind="ident")[1]
        self.take("=")
        value = self._constant()
        if name != "deprecated" or value not in ("true", "false"):
            self.unsupported(f"field option {name} = {value}")
        f.deprecated = value == "true"

    def _enum(self):
        self.take("enum")
        name = self.take(kind="ident")[1]
        self.take("{")
        values = {}
        while self.peek()[1] != "}":
            word = self.peek()[1]
            if word in ("option", "reserved"):
                self.unsupported(f"{word} inside enum {name}")
            value_name = self.take(kind="ident")[1]
            self.take("=")
            sign = self.take("-")[1] if self.peek()[1] == "-" else ""
            values[value_name] = int(sign + self.take(kind="number")[1])
            if self.peek()[1] == "[":
                self.unsupported(f"enum value option on {value_name}")
            self.take(";")
        self.take("}")
        return name, values

    def _service(self):
        self.take("service")
        name = self.take(kind="ident")[1]
        self.take("{")
        rpcs = {}
        while self.peek()[1] != "}":
            if self.peek()[1] != "rpc":
                self.unsupported(f"{self.peek()[1]} inside service {name}")
            self.take("rpc")
            rpc = self.take(kind="ident")[1]
            types = []
            for i in range(2):  # (request) returns (response)
                if i:
                    self.take("returns")
                self.take("(")
                if self.peek()[1] == "stream":
                    self.take("stream")
                types.append(self.take(kind="ident")[1])
                self.take(")")
            rpcs[rpc] = tuple(types)
            if self.peek()[1] == ";":
                self.take(";")
                continue
            self.take("{")
            while self.peek()[1] != "}":
                self.take("option")
                self.take("(")
                opt = self.take(kind="ident")[1]
                self.take(")")
                if opt not in RPC_OPTIONS:
                    self.unsupported(f"rpc option ({opt})")
                self.take("=")
                if self.peek()[1] == "{":
                    self._skip_aggregate()
                else:
                    self._constant()
                self.take(";")
            self.take("}")
        self.take("}")
        return name, rpcs

    def _skip_aggregate(self):
        """An rpc option's text-format aggregate (`{ post: "/x" body: "*" }`): balanced, unread."""
        depth = 0
        while True:
            tok = self.take()
            depth += {"{": 1, "}": -1}.get(tok[1], 0) if tok[0] == "symbol" else 0
            if depth == 0:
                return


def _resolve(schema):
    """Every field and rpc type must name a scalar, a type in the file, or an imported well-known."""
    def known(t):
        return t in PROTO_SCALARS or t in schema.messages or t in schema.enums or t in WELL_KNOWN

    for msg in schema.messages.values():
        for f in msg.fields:
            if not known(f.type):
                raise ProtoSchemaError(f"{msg.name}.{f.name}: unresolved type {f.type!r}")
            if f.label == "map" and f.key_type not in PROTO_SCALARS - {"double", "float", "bytes"}:
                raise ProtoSchemaError(f"{msg.name}.{f.name}: invalid map key type {f.key_type!r}")
    for rpcs in schema.services.values():
        for rpc, types in rpcs.items():
            for t in types:
                if not known(t):
                    raise ProtoSchemaError(f"rpc {rpc}: unresolved type {t!r}")


def parse_proto(text):
    """Parse proto text into a Schema; ProtoSchemaError on any construct outside the covered set."""
    return _Parser(text).parse()


def load_pin(pin_path=PIN_PATH):
    try:
        return json.loads(Path(pin_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtoSchemaError(f"unreadable pin {pin_path}: {exc}") from exc


def pin_errors(root=ROOT, pin_path=PIN_PATH):
    """Re-hash every vendored file PIN.json names; a missing or drifted file is an error."""
    errors = []
    pin = load_pin(pin_path)
    commit = pin.get("upstream", {}).get("commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        errors.append(f"{pin_path}: upstream.commit is not a full 40-hex commit")
    for entry in pin.get("files", []):
        path = Path(root) / entry.get("path", "")
        if not path.is_file():
            errors.append(f"{entry.get('path')}: missing vendored file")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry.get("sha256"):
            errors.append(f"{entry.get('path')}: sha256 {digest} != pinned {entry.get('sha256')}")
        if commit and commit not in entry.get("source", ""):
            errors.append(f"{entry.get('path')}: source URL does not name the pinned commit")
    if not errors and not pin.get("files"):
        errors.append(f"{pin_path}: pins no files")
    return errors


def _pinned_proto_sha(pin_path=PIN_PATH):
    for entry in load_pin(pin_path).get("files", []):
        if entry.get("path") == PROTO_PIN_PATH:
            return entry.get("sha256", "")
    raise ProtoSchemaError(f"{pin_path} pins no {PROTO_PIN_PATH}")


_CACHE = {}


def load_schema(path=PROTO_PATH, expected_sha256=None):
    """Parse the vendored proto, refusing bytes that differ from the pin (fail closed)."""
    path = Path(path)
    expected = expected_sha256 if expected_sha256 is not None else _pinned_proto_sha()
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ProtoSchemaError(f"unreadable schema {path}: {exc}") from exc
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise ProtoSchemaError(f"{path}: sha256 {digest} != pinned {expected}; re-pin deliberately")
    if digest not in _CACHE:
        schema = parse_proto(data.decode("utf-8"))
        schema.sha256 = digest
        _CACHE[digest] = schema
    return _CACHE[digest]


def closure_errors(schema, root="AgentCard"):
    """Fields reachable from `root` whose type the validator does not check (empty = covered)."""
    if root not in schema.messages:
        return [f"{root}: no such message in {schema.package}"]
    problems, seen, todo = [], set(), [root]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for f in schema.messages[name].fields:
            if f.type in schema.messages:
                todo.append(f.type)
            elif f.type not in VALIDATED_TYPES:
                problems.append(f"{name}.{f.name}: type {f.type!r} is not checked by "
                                "scripts/a2a_schema.py")
            if f.label == "map" and f.key_type != "string":
                problems.append(f"{name}.{f.name}: map key {f.key_type!r} is not checked")
    return sorted(problems)


def required_fields(schema, message="AgentCard"):
    """JSON names of the message's `(google.api.field_behavior) = REQUIRED` fields, in proto order."""
    return [f.json_name for f in schema.messages[message].fields if f.required]


def _is_unset(f, value):
    """proto3 implicit presence: an empty string, false, empty list or map never reaches the wire."""
    if f.label in ("repeated", "map"):
        return len(value) == 0
    if f.label == "optional" or f.type not in ("string", "bool"):
        return False
    return value in ("", False)


def _check_struct(value, path, errors):
    """A google.protobuf.Struct with every nested google.protobuf.Value checked (#636).

    Struct carries numbers as IEEE doubles, so NaN, an infinity (Python's json reads the NaN and
    Infinity tokens, and 1e999 overflows to inf) or an integer past the double range has no
    faithful ProtoJSON form. Walked with a stack, so nesting depth cannot raise RecursionError.
    """
    if not isinstance(value, dict):
        errors.append(f"{path}: expected a JSON object (google.protobuf.Struct)")
        return
    todo = [(path, value)]
    while todo:
        where, val = todo.pop()
        if isinstance(val, dict):
            for key in [k for k in val if not isinstance(k, str)]:
                errors.append(f"{where}: key {key!r} is not a string (google.protobuf.Struct)")
            todo.extend(reversed([(f"{where}[{k!r}]", v) for k, v in val.items()
                                  if isinstance(k, str)]))
        elif isinstance(val, list):
            todo.extend(reversed([(f"{where}[{i}]", v) for i, v in enumerate(val)]))
        elif val is None or isinstance(val, (str, bool)):
            continue
        elif isinstance(val, float):
            if not math.isfinite(val):
                errors.append(f"{where}: {val!r} is not a finite number (google.protobuf.Value)")
        elif isinstance(val, int):
            try:
                float(val)
            except OverflowError:
                errors.append(f"{where}: integer overflows a double (google.protobuf.Value)")
        else:
            errors.append(f"{where}: {type(val).__name__} is not a JSON value "
                          "(google.protobuf.Value)")


def _check_single(schema, type_name, value, path, errors):
    if type_name == "string":
        if not isinstance(value, str):
            errors.append(f"{path}: expected a string")
    elif type_name == "bool":
        if not isinstance(value, bool):
            errors.append(f"{path}: expected true or false")
    elif type_name == "google.protobuf.Struct":
        _check_struct(value, path, errors)
    elif type_name in schema.messages:
        _check_message(schema, schema.messages[type_name], value, path, errors)
    else:
        raise ProtoSchemaError(f"{path}: type {type_name!r} is not checked by scripts/a2a_schema.py")


def _check_message(schema, msg, value, path, errors):
    if not isinstance(value, dict):
        errors.append(f"{path}: expected a JSON object ({schema.package}.{msg.name})")
        return
    present = {}
    for key, val in value.items():
        f = msg.lookup(key)
        if f is None:
            errors.append(f"{path}.{key}: unknown field (not in {schema.package}.{msg.name})")
        elif f.name in present:
            errors.append(f"{path}.{key}: field {f.json_name!r} given twice (JSON and proto name)")
        else:
            present[f.name] = (key, val)
    for f in msg.fields:
        key, val = present.get(f.name, (f.json_name, None))
        fpath = f"{path}.{key}"
        if val is None:  # absent, or null, which ProtoJSON reads as the field's default
            if f.required:
                errors.append(f"{fpath}: required field missing")
            continue
        if f.label in ("repeated", "map"):
            want = list if f.label == "repeated" else dict
            if not isinstance(val, want):
                errors.append(f"{fpath}: expected a JSON {'array' if want is list else 'object'}")
                continue
            items = enumerate(val) if want is list else val.items()
            for k, item in items:
                ipath = f"{fpath}[{k}]" if want is list else f"{fpath}[{k!r}]"
                if item is None:
                    errors.append(f"{ipath}: null is not allowed in a {f.label} field")
                else:
                    _check_single(schema, f.type, item, ipath, errors)
        else:
            _check_single(schema, f.type, val, fpath, errors)
        if f.required and _is_unset(f, val):
            errors.append(f"{fpath}: required field is empty (unset on the proto3 wire)")
    for oneof, members in msg.oneofs.items():
        chosen = [present[m][0] for m in members if m in present and present[m][1] is not None]
        if len(chosen) > 1:
            errors.append(f"{path}: oneof {oneof!r} has {len(chosen)} members set "
                          f"({', '.join(chosen)}); at most one")


def schema_errors(card, root="AgentCard", schema=None):
    """Shape and REQUIRED errors of a ProtoJSON value against the pinned `root` message."""
    schema = schema or load_schema()
    uncovered = closure_errors(schema, root)
    if uncovered:
        raise ProtoSchemaError("; ".join(uncovered))
    errors = []
    _check_message(schema, schema.messages[root], card, "$", errors)
    return errors


def _normalize(schema, msg, value):
    """A schema-valid ProtoJSON object with every known field keyed by its JSON name.

    A null is dropped: ProtoJSON reads it as the field's default, i.e. unset, so the semantic
    checks see an absent key and report it -- they never call a string method on None (#636).
    """
    out = {}
    for key, val in value.items():
        f = msg.lookup(key)
        if f is None or val is None:
            continue
        if f.type in schema.messages and val is not None:
            sub = schema.messages[f.type]
            if f.label == "repeated":
                val = [_normalize(schema, sub, v) for v in val]
            elif f.label == "map":
                val = {k: _normalize(schema, sub, v) for k, v in val.items()}
            else:
                val = _normalize(schema, sub, val)
        out[f.json_name] = val
    return out


def _dial_host(host):
    """A host a client can dial: an ASCII DNS name, a dotted-quad IPv4 address or a bracketed
    IPv6 literal. An IDN is written in its xn-- form; a zone id or IPvFuture literal is refused."""
    if host.startswith("[") and host.endswith("]"):
        return "%" not in host and _ipv6(host[1:-1])
    labels = (host[:-1] if host.endswith(".") else host).split(".")
    if len(host) > 254 or not all(_DNS_LABEL.fullmatch(label) for label in labels):
        return False
    if labels[-1].isdigit():  # a numeric last label makes the host an IPv4 address, or nothing
        try:
            ipaddress.IPv4Address(".".join(labels))
        except ValueError:
            return False
    return True


def split_url(text):
    """urlsplit() of `text`, raising ValueError on a URL no client can dial (#636).

    urlsplit splits; it does not validate. It reports `bad host` as a hostname, leaves a port of
    99999 or 0 to a later `.port` read, and deletes tab, CR and LF, so `https://a\\t.b/` reads as
    another host. Here the text holds no whitespace or non-printing character, an authority's
    host passes _dial_host, and an explicit port is 1-65535 in ASCII digits. The card check and
    the exporter's endpoint check both parse with this, so a URL one accepts the other accepts.
    """
    bad = next((c for c in text if c.isspace() or not c.isprintable()), None)
    if bad is not None:
        raise ValueError(f"{bad!r} is whitespace or a control character")
    parts = urlsplit(text)  # raises ValueError itself on, e.g., an unclosed IPv6 bracket
    if parts.netloc:
        hostport = parts.netloc.rpartition("@")[2]
        if hostport.startswith("["):
            host, close, port = hostport.partition("]")
            host += close
        else:
            host, colon, port = hostport.partition(":")
            port = colon + port
        if not _dial_host(host):
            raise ValueError(f"invalid host {host!r}")
        if port and not (re.fullmatch(r":[0-9]{1,5}", port) and 0 < int(port[1:]) < 65536):
            raise ValueError(f"port {port.removeprefix(':')!r} is not 1-65535")
    return parts


def _absolute_url(text):
    if not isinstance(text, str):
        return False
    try:
        parts = split_url(text)
    except ValueError:
        return False
    return bool(parts.scheme and parts.hostname)


def _uri_host(authority):
    """The host of an RFC 3986 authority (`[userinfo@]host[:port]`), or None if malformed."""
    userinfo, at, hostport = authority.rpartition("@")
    if at and not _USERINFO.fullmatch(userinfo):
        return None
    if hostport.startswith("["):
        literal, close, port = hostport[1:].partition("]")
        # An IP-literal is IPv6 or IPvFuture; RFC 3986 has no zone id, so `%` is refused.
        if not close or "%" in literal or not (_ipv6(literal) or _IPV_FUTURE.fullmatch(literal)):
            return None
        host = "[" + literal + "]"
    else:
        host, colon, port = hostport.partition(":")
        if not _REG_NAME.fullmatch(host):  # reg-name also covers the IPv4address form
            return None
        port = colon + port
    if port and not re.fullmatch(r":[0-9]*", port):  # ASCII digits only, not any Unicode \d
        return None
    return host


def _ipv6(text):
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _absolute_uri(text):
    """An RFC 3986 absolute URI such as an extension or custom-binding identifier (#636).

    Each component is parsed: the authority's userinfo, host (reg-name, IPv4 or bracketed
    IPv6/IPvFuture literal) and port for every scheme; path segments, query and fragment as
    pchar runs. The hier-part must be non-empty, and an http(s)/ws(s) URI needs a host.
    """
    m = _URI_SPLIT.fullmatch(text) if isinstance(text, str) else None
    if not m or not m.group(2):
        return False
    scheme, hier, query, fragment = m.groups()
    if any(part is not None and not _QUERY_OR_FRAGMENT.fullmatch(part)
           for part in (query, fragment)):
        return False
    host = ""
    if hier.startswith("//"):
        authority, slash, path = hier[2:].partition("/")
        host = _uri_host(authority)
        if host is None:
            return False
        hier = slash + path
    if not all(_SEGMENT.fullmatch(segment) for segment in hier.split("/")):
        return False
    return scheme.lower() not in _HOST_SCHEMES or bool(host)


def grpc_address(text):
    """(host, port) of a gRPC `host:port` address, or None (a2a.proto AgentInterface.url).

    The host is judged by _dial_host, the URL rule: a DNS name, an IPv4 address or a bracketed
    IPv6 literal (`[2606:4700::1111]:443`); an unbracketed IPv6 address is ambiguous and refused,
    and the port is 1-65535. The exporter's endpoint check uses this same parser, so an address
    it accepts the card check accepts (#636).
    """
    m = _HOST_PORT.fullmatch(text) if isinstance(text, str) else None
    if not m or not 0 < int(m.group(2)) < 65536 or not _dial_host(m.group(1)):
        return None
    return m.group(1), int(m.group(2))


def _url_fields(schema, msg, value, path):
    """(path, message name, Field, value) of every set `url`/`*_url` string under `value`.

    Found by name in the schema rather than listed by hand, so the OAuth flow, OpenID Connect and
    metadata URLs are checked and a URL field a re-pin adds is checked too (#636).
    """
    for f in msg.fields:
        val = value.get(f.json_name)
        if val is None:
            continue
        where = f"{path}.{f.json_name}"
        if f.type == "string" and f.label in ("", "optional") and (
                f.name == "url" or f.name.endswith("_url")):
            yield where, msg.name, f, val
        elif f.type in schema.messages:
            sub = schema.messages[f.type]
            if f.label == "repeated":
                items = [(f"{where}[{i}]", v) for i, v in enumerate(val)]
            elif f.label == "map":
                items = [(f"{where}[{k!r}]", v) for k, v in val.items()]
            else:
                items = [(where, val)]
            for ipath, item in items:
                yield from _url_fields(schema, sub, item, ipath)


def _security_names(requirements):
    for req in requirements or []:
        yield from (req.get("schemes") or {}).keys()


def semantic_errors(card, schema=None):
    """Checks the proto cannot express; run on a card that already passes schema_errors."""
    schema = schema or load_schema()
    card = _normalize(schema, schema.messages["AgentCard"], card)
    errors = []
    for i, iface in enumerate(card.get("supportedInterfaces") or []):
        where = f"$.supportedInterfaces[{i}]"
        binding, url = iface.get("protocolBinding", ""), iface.get("url", "")
        if binding not in CORE_BINDINGS and not _absolute_uri(binding):
            errors.append(f"{where}.protocolBinding: {binding!r} is neither a core binding "
                          f"({', '.join(CORE_BINDINGS)}) nor a custom-binding URI")
        if not _PROTOCOL_VERSION.fullmatch(iface.get("protocolVersion", "")):
            errors.append(f"{where}.protocolVersion: expected Major.Minor such as '1.0'")
        if not (binding == "GRPC" and grpc_address(url)) and not _absolute_url(url):
            errors.append(f"{where}.url: expected an absolute URL"
                          + (" or host:port" if binding == "GRPC" else ""))
    skill_ids = [s.get("id") for s in card.get("skills") or []]
    for dup in sorted({s for s in skill_ids if skill_ids.count(s) > 1}):
        errors.append(f"$.skills: duplicate skill id {dup!r}")
    modes = [("$.defaultInputModes", card.get("defaultInputModes")),
             ("$.defaultOutputModes", card.get("defaultOutputModes"))]
    for i, skill in enumerate(card.get("skills") or []):
        modes += [(f"$.skills[{i}].inputModes", skill.get("inputModes")),
                  (f"$.skills[{i}].outputModes", skill.get("outputModes"))]
    for where, values in modes:
        for mode in values or []:
            if not _MEDIA_TYPE.fullmatch(mode):
                errors.append(f"{where}: {mode!r} is not a media type (type/subtype)")
    declared = set((card.get("securitySchemes") or {}).keys())
    for name, scheme in (card.get("securitySchemes") or {}).items():
        if len([v for v in scheme.values() if v is not None]) != 1:
            errors.append(f"$.securitySchemes[{name!r}]: expected exactly one scheme variant")
        location = (scheme.get("apiKeySecurityScheme") or {}).get("location")
        if location is not None and location not in API_KEY_LOCATIONS:
            errors.append(f"$.securitySchemes[{name!r}].apiKeySecurityScheme.location: "
                          f"{location!r} is not one of {', '.join(API_KEY_LOCATIONS)}")
    requirement_sets = [("$.securityRequirements", card.get("securityRequirements"))]
    requirement_sets += [(f"$.skills[{i}].securityRequirements", s.get("securityRequirements"))
                         for i, s in enumerate(card.get("skills") or [])]
    for where, reqs in requirement_sets:
        for name in _security_names(reqs):
            if name not in declared:
                errors.append(f"{where}: names scheme {name!r} that securitySchemes does not declare")
    for i, sig in enumerate(card.get("signatures") or []):
        for part in ("protected", "signature"):
            if not _BASE64URL.fullmatch(sig.get(part, "")):
                errors.append(f"$.signatures[{i}].{part}: expected unpadded base64url")
    uris = [e.get("uri", "") for e in (card.get("capabilities") or {}).get("extensions") or []]
    for i, uri in enumerate(uris):
        if not _absolute_uri(uri):
            errors.append(f"$.capabilities.extensions[{i}].uri: expected an absolute URI")
    for dup in sorted({u for u in uris if uris.count(u) > 1}):
        errors.append(f"$.capabilities.extensions: duplicate extension uri {dup!r}")
    for where, message, f, url in _url_fields(schema, schema.messages["AgentCard"], card, "$"):
        if (message, f.name) == ("AgentInterface", "url"):
            continue  # checked above, where a gRPC interface may give host:port instead
        if url == "" and f.label != "optional":
            continue  # proto3 implicit presence: "" is the default, never on the wire
        if not _absolute_url(url):
            errors.append(f"{where}: expected an absolute URL")
        elif (message, f.name) in TLS_REQUIRED and split_url(url).scheme.lower() != "https":
            errors.append(f"{where}: expected an https URL (a2a.proto {message}.{f.name}: "
                          f"{TLS_REQUIRED[message, f.name]!r})")
    return errors


def card_errors(card, schema=None):
    """Every reason `card` is not a valid lf.a2a.v1 AgentCard at the pin (empty = valid)."""
    schema = schema or load_schema()
    errors = schema_errors(card, schema=schema)
    return errors or semantic_errors(card, schema=schema)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="a2a_schema.py",
        description="Validate ProtoJSON A2A AgentCards against the pinned lf.a2a.v1 proto.")
    parser.add_argument("cards", nargs="*", help="AgentCard JSON files to validate.")
    parser.add_argument("--required", nargs="?", const="AgentCard", metavar="MESSAGE",
                        help="Print the REQUIRED fields of MESSAGE (default AgentCard).")
    parser.add_argument("--check-pin", action="store_true",
                        help="Re-hash the vendored schema and fixtures against PIN.json.")
    ns = parser.parse_args(argv)
    if not ns.cards and not ns.required and not ns.check_pin:
        parser.error("give AgentCard files, --required or --check-pin")
    return ns


def main(argv=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if ns.check_pin:
            problems = pin_errors()
            for p in problems:
                print(f"a2a_schema: PIN DRIFT: {p}", file=sys.stderr)
            if problems:
                return 1
            print(f"A2A_SCHEMA_PIN=ok commit={load_pin()['upstream']['commit']}")
        schema = load_schema()
        if ns.required:
            if ns.required not in schema.messages:
                print(f"a2a_schema: no message {ns.required!r} in {schema.package}", file=sys.stderr)
                return 2
            print("\n".join(required_fields(schema, ns.required)))
        status = 0
        for path in ns.cards:
            try:
                card = json.loads(Path(path).read_text(encoding="utf-8"))
            # ValueError covers bad JSON, non-UTF-8 bytes and an integer past Python's digit
            # limit; RecursionError covers nesting too deep to decode (#636).
            except (OSError, ValueError, RecursionError) as exc:
                print(f"A2A_CARD=invalid {path}\n  unreadable: {exc}", file=sys.stderr)
                status = 1
                continue
            errors = card_errors(card, schema=schema)
            if errors:
                status = 1
                print(f"A2A_CARD=invalid {path}", file=sys.stderr)
                for e in errors:
                    print(f"  {e}", file=sys.stderr)
            else:
                print(f"A2A_CARD=valid {path}")
        return status
    except ProtoSchemaError as exc:
        print(f"a2a_schema: FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
