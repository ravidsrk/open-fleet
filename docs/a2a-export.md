# A2A export: offline mission descriptors and the AgentCard boundary

[`scripts/a2a_export.py`](../scripts/a2a_export.py) publishes the mission catalog as JSON for
other agents and routers. It has two outputs with two different contracts:

- **By default, an offline mission descriptor.** This is open-fleet's own format. It describes
  what each mission does and what evidence it returns. It is not an A2A AgentCard, and it
  claims no endpoint.
- **With `--standard-card`, an A2A AgentCard.** This is an `lf.a2a.v1` AgentCard for an A2A
  endpoint that you operate. It is checked against the official A2A schema, pinned at one
  upstream commit, before it is printed.

open-fleet runs no A2A server. Whether to serve one is a separate product decision
([#607](https://github.com/ravidsrk/open-fleet/issues/607)), so nothing here starts a server,
calls an endpoint or makes up a service URL.

## The offline mission descriptor

```bash
python3 scripts/a2a_export.py                     # the catalog: every mission
python3 scripts/a2a_export.py --mission ship-it   # one mission
python3 scripts/a2a_export.py --check             # build every descriptor; exit 1 on any failure
```

Each descriptor comes from one `skills/<name>/SKILL.md`. It contains the mission's name,
description, compatibility note, autonomy level and proof tier, plus the six identity points,
the composed protocols and three groups of contracts:

- **input:** the task spec and the trust-envelope helpers;
- **output:** [`evidence-manifest.md`](../runtime/evidence-manifest.md) and the verifier;
- **governance:** [`gate-classification.md`](../runtime/gate-classification.md) and the ids
  from [`one-way-doors.json`](../runtime/one-way-doors.json).

Each descriptor's id is `open-fleet:<mission>`. Its `kind` field is
`offline-mission-descriptor`, and the catalog wrapper's is `offline-mission-descriptor-catalog`.

The `schema` field holds `a2a-agent-card/v1` on a descriptor and `a2a-agent-card-catalog/v1` on
the catalog. Those names are kept so existing consumers still parse the output (see the
[compatibility policy](#migration-and-compatibility-policy)). They identify open-fleet's own
format. They are not an A2A protocol version.

A descriptor makes no transport claim. It has no `url`, `supportedInterfaces` or security key.
Every `capabilities` flag (`streaming`, `pushNotifications`, `stateTransitionHistory`) is
`false`, because no open-fleet component runs A2A tasks, streams responses or sends push
notifications. `offline_claim_errors` checks this each time a descriptor is built, so
`--check` fails if any of those claims comes back.

## The pinned official schema

The A2A protocol defines its types in `specification/a2a.proto`, package `lf.a2a.v1`. At the
pinned commit, upstream's
[`specification/json/README.md`](https://github.com/a2aproject/A2A/blob/1205f45951ca97c209634ce6046180e38c5dfb30/specification/json/README.md)
says the JSON Schema `a2a.json` is a non-normative build artifact that is not committed. So the
proto is the file that is pinned and vendored:

| | |
|---|---|
| Upstream | [a2aproject/A2A](https://github.com/a2aproject/A2A), Apache-2.0 |
| Commit | [`1205f45951ca97c209634ce6046180e38c5dfb30`](https://github.com/a2aproject/A2A/blob/1205f45951ca97c209634ce6046180e38c5dfb30/specification/a2a.proto) (2026-10-15), the revision #607 names |
| Vendored proto | [`scripts/vendor/a2a/a2a.proto`](../scripts/vendor/a2a/a2a.proto), sha256 `945df6e34001b2bfd0fd62d9484b63094dfad9d78705e41e2873441c419ae2d1` |
| Licence copy | [`scripts/vendor/a2a/LICENSE`](../scripts/vendor/a2a/LICENSE) |
| Valid fixtures | Two example cards from upstream's `docs/specification.md` at the same commit: the section 8.5 sample and the section 8.4.1 original card ([`tests/fixtures/a2a/`](../tests/fixtures/a2a/)) |
| Pin record | [`scripts/vendor/a2a/PIN.json`](../scripts/vendor/a2a/PIN.json) records the source URL, git blob and sha256 of each file |

This commit is a revision of upstream `main` that was inspected for #607. It is not a released
A2A version that open-fleet has chosen to depend on.

[`scripts/a2a_schema.py`](../scripts/a2a_schema.py) validates a ProtoJSON AgentCard against
that proto. It uses only the standard library. It refuses a proto whose sha256 differs from
the pin and never fetches anything. It checks:

- **Field names.** Every key must be a field of its message. Either the lowerCamelCase JSON
  name or the proto name is accepted, but not both. An unknown key is refused, as a ProtoJSON
  parser refuses it by default.
- **Shapes.** Each value must have the field's JSON shape, and at most one member of a `oneof`
  may be set. A `google.protobuf.Struct` is checked all the way down: every nested value is a
  JSON value and every number a finite double, so `NaN`, `Infinity` and `1e999` are refused.
- **Required fields.** A field annotated `(google.api.field_behavior) = REQUIRED` must be
  present and must not be empty. An empty required string or list is refused because proto3
  does not send it, so successful proto3 parsing alone cannot catch it.
- **Semantic rules.** Rules the proto cannot express run once the shape passes:
  - interface URL, binding and `Major.Minor` protocol-version forms;
  - every URL field under AgentCard (interface, provider, documentation, icon, OpenID Connect
    discovery, OAuth 2.0 metadata and every OAuth flow URL) has a scheme and a host a client can
    dial: no whitespace or control character anywhere, an ASCII DNS name (an IDN in its
    `xn--` form), a dotted-quad IPv4 address or a bracketed IPv6 literal, and an explicit port
    of 1-65535. A gRPC `host:port` address follows the same host and port rule, and the
    exporter's `--endpoint` check uses the same parsers. Where the proto says TLS is required
    (`oauth2MetadataUrl`, and the implicit and password flow URLs) the URL must be `https`;
  - unique skill ids;
  - `type/subtype` media types, with optional `; name=value` parameters;
  - each security requirement names a declared scheme, and each scheme sets one variant;
  - an API-key scheme's `location` is `query`, `header` or `cookie`, the values the proto allows;
  - signature parts are unpadded base64url;
  - extension URIs and custom binding identifiers are RFC 3986 absolute URIs (a scheme, not
    necessarily a host, so `tag:` and `urn:` identifiers pass), and extension URIs are unique.

The parser accepts only the constructs that the pinned proto uses. A re-pin that adds
`reserved`, a nested type, `json_name` or a new option fails to parse. A field type the
validator does not check, such as an enum, `bytes` or `int64`, is refused when it appears
anywhere under AgentCard. [`tests/test_a2a_schema.py`](../tests/test_a2a_schema.py) tests both
rules.

A valid result proves the card's shape only. The validator does not reach the endpoint,
exercise its behaviour, verify a JWS signature cryptographically, or interpret an extension's
parameters.

```bash
python3 scripts/a2a_schema.py card.json            # A2A_CARD=valid|invalid; exit 0 or 1
python3 scripts/a2a_schema.py --required           # required AgentCard fields, in proto order
python3 scripts/a2a_schema.py --check-pin          # re-hash the vendored files against PIN.json
```

## Required AgentCard fields versus the offline descriptor

Generated by `python3 scripts/a2a_export.py --compare` from the pinned proto and a mission
descriptor; every descriptor has the same keys. [`tests/test_a2a_export.py`](../tests/test_a2a_export.py)
fails if this table no longer matches either of them. A descriptor lacks five required fields. Its `capabilities`
uses the older shape, so `stateTransitionHistory` is an unknown field in `lf.a2a.v1`. Every
other descriptor key is unknown to AgentCard. That is why the validator rejects a descriptor as
a transport card.

| AgentCard field | Required | Offline descriptor | `--standard-card` source |
|---|---|---|---|
| `name` | yes | present, valid | `open-fleet`, or `open-fleet <mission>` with `--mission` |
| `description` | yes | present, valid | a fixed catalog sentence, or the mission's description |
| `supportedInterfaces` | yes | missing | one entry from `--endpoint`, `--binding`, `--protocol-version` |
| `provider` | no | missing | omitted: who operates the endpoint is not known to the exporter |
| `version` | yes | missing | `--agent-version` (default: `.claude-plugin/plugin.json` version) |
| `documentationUrl` | no | missing | omitted |
| `capabilities` | yes | present, invalid | `streaming`, `pushNotifications`, `extendedAgentCard` false; the mission extension |
| `securitySchemes` | no | missing | omitted: the exporter knows no authentication |
| `securityRequirements` | no | missing | omitted: the exporter knows no authentication |
| `defaultInputModes` | yes | missing | `text/markdown`, `application/json` |
| `defaultOutputModes` | yes | missing | `application/json`, `text/markdown` |
| `skills` | yes | missing | one per mission: `id` `open-fleet:<mission>`, name, description, tags |
| `signatures` | no | missing | omitted: the exporter does not sign |
| `iconUrl` | no | missing | omitted |

| Descriptor key | In `lf.a2a.v1.AgentCard` | `--standard-card` destination |
|---|---|---|
| `schema` | unknown field | extension `params.descriptorSchema` |
| `kind` | unknown field | dropped |
| `id` | unknown field | `skills[].id` |
| `compatibility` | unknown field | extension `params.missions[<id>].compatibility` |
| `autonomy` | unknown field | extension `params.missions[<id>].autonomy` |
| `proof` | unknown field | extension `params.missions[<id>].proof` |
| `identity` | unknown field | extension `params.missions[<id>].identity` |
| `composition` | unknown field | extension `params.missions[<id>].composition` |
| `contracts` | unknown field | extension `params.missions[<id>].contracts` |

## Project a standard AgentCard for your endpoint

Use this only when you run an A2A server for these missions. Replace `<your-host>` and the path
with the endpoint that server actually serves:

```bash
python3 scripts/a2a_export.py --standard-card \
  --endpoint https://<your-host>/a2a/v1 --binding JSONRPC [--mission ship-it] \
  [--protocol-version 1.0] [--agent-version <version>] [--out card.json]
```

`--standard-card` requires both `--endpoint` and `--binding`. Without either, it exits 2 and
prints nothing. The projection flags exit 2 if you give them without `--standard-card`.

Before printing, the exporter runs these checks. Any failure exits 1 with no output.

- **Endpoint.** HTTP bindings (`JSONRPC`, `HTTP+JSON`) need an absolute `https` URL without
  credentials. `GRPC` also accepts `host:port`, with an IPv6 host in brackets
  (`[2606:4700::1111]:443`). Reserved placeholder and loopback hosts are
  refused: `example.com`/`.net`/`.org` and their subdomains, the `.example`, `.test`,
  `.invalid` and `.localhost` TLDs, `localhost`, and loopback, unspecified or link-local
  addresses. Another agent cannot reach any of these.
- **Binding and version.** The binding must be `JSONRPC`, `GRPC` or `HTTP+JSON`. The protocol
  version must be `Major.Minor`, and its major must be `1`, the pinned package's version.
- **Pinned schema.** The card must pass the pinned-proto check and every semantic rule above.
- **Claims.** `projection_errors` refuses the card if `streaming`, `pushNotifications` or
  `extendedAgentCard` is anything but `false`. It also refuses the card if it declares
  security schemes, requirements or signatures, or if it lacks exactly one optional mission
  extension covering exactly its skills.

The card describes one interface at your endpoint, and each mission becomes one skill. The
card declares no authentication because the exporter does not know your server's. If your
server requires authentication, implements streaming or push notifications, or has a provider
or signature to publish, add those fields to the card yourself. Then re-check it with
`python3 scripts/a2a_schema.py card.json` before you serve it.

## Mission extension v1

Mission-specific proof and governance fields never replace a standard field. They go in one
data-only `AgentExtension` under `capabilities.extensions`, as upstream's
[extensions guide](https://github.com/a2aproject/A2A/blob/1205f45951ca97c209634ce6046180e38c5dfb30/docs/topics/extensions.md)
recommends for structured data:

- `uri`: `https://github.com/ravidsrk/open-fleet/blob/main/docs/a2a-export.md#mission-extension-v1`.
  This URI identifies the extension and points to this section; clients are not expected to
  fetch it.
- `required`: `false`. A client that ignores the extension loses nothing the standard fields
  carry.
- `params.descriptorSchema`: `a2a-agent-card/v1`.
- `params.missions`: maps each skill id (`open-fleet:<mission>`) to that mission's descriptor
  fields `compatibility`, `autonomy`, `proof`, `identity`, `composition` and `contracts`. The
  values are the ones the offline descriptor carries.

A change to the shape of `params` needs a new extension URI ending in `-v2`.

## Migration and compatibility policy

For consumers of the offline descriptor (the default output):

- **Format tags stay.** `schema` keeps `a2a-agent-card/v1` and `a2a-agent-card-catalog/v1`
  unchanged. Renaming them would break every consumer that dispatches on them. Read them as
  open-fleet format names, and use `kind` to tell a descriptor from a transport card.
- **Fields are added, never removed or retyped, within v1.** #607 adds `kind`. Card ids stay
  `open-fleet:<mission>`.
- **One correction in v1.** `capabilities.stateTransitionHistory` changes from `true` to
  `false`. Nothing ever served A2A tasks, so the `true` value was a claim the exporter could
  not back. Do not read any `capabilities` flag of a descriptor as a statement about a live
  agent.
- **Breaking changes need a new version.** Renaming a tag, removing a field or changing a
  field's type ships under a new version suffix (`/v2`) with a CHANGELOG entry. None is
  planned.

For consumers that need an A2A transport card:

- Do not treat a descriptor as one. Generate a card with `--standard-card` for an endpoint you
  run, and validate any card you receive with `scripts/a2a_schema.py`.

## Re-pinning the schema

A re-pin changes the pinned contract, so it is a reviewed change:

1. Fetch the new revision's files, each once, with
   `gh api repos/a2aproject/A2A/contents/<path>?ref=<commit> -H 'Accept: application/vnd.github.raw'`.
2. Replace the vendored files and update `PIN.json`: the commit, source URLs, git blobs,
   sha256 values and fixture line ranges.
3. Run `python3 -m unittest tests.test_a2a_schema tests.test_a2a_export`. If the new proto
   uses a construct the parser does not cover, extend the parser and its tests before you
   trust the result.
4. Run `python3 scripts/a2a_export.py --compare` and update the table above.
