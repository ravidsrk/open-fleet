#!/bin/sh
# Standalone zero-Python installer for the `open-fleet` Rust engine binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ravidsrk/open-fleet/main/scripts/install-engine.sh | sh
#
# Optional environment overrides:
#   OPEN_FLEET_VERSION      Pin a specific release version (default: ENGINE_VERSION at release)
#   OPEN_FLEET_INSTALL_DIR  Destination directory (default: $HOME/.local/bin)
#   OPEN_FLEET_REPO         GitHub owner/repo (default: ravidsrk/open-fleet)
set -eu

DEFAULT_VERSION="1.0.0"
VERSION="${OPEN_FLEET_VERSION:-$DEFAULT_VERSION}"
REPO="${OPEN_FLEET_REPO:-ravidsrk/open-fleet}"
INSTALL_DIR="${OPEN_FLEET_INSTALL_DIR:-${HOME:-/tmp}/.local/bin}"

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "darwin" ;;
        Linux)  echo "linux" ;;
        *)
            echo "open-fleet install: unsupported OS '$(uname -s)' (use Windows release asset open-fleet-windows-x64.exe)" >&2
            exit 2
            ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        arm64|aarch64) echo "arm64" ;;
        x86_64|amd64)  echo "x64" ;;
        *)
            echo "open-fleet install: unsupported architecture '$(uname -m)'" >&2
            exit 2
            ;;
    esac
}

download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --connect-timeout 15 -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        echo "open-fleet install: neither curl nor wget is available" >&2
        exit 2
    fi
}

compute_sha256() {
    file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file" | awk '{print $NF}'
    else
        echo "open-fleet install: no SHA-256 tool (sha256sum, shasum, or openssl) available" >&2
        exit 2
    fi
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
ASSET="open-fleet-${OS}-${ARCH}"
BASE_URL="https://github.com/${REPO}/releases/download/engine-v${VERSION}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/open-fleet-install.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

BIN_TMP="$TMP_DIR/$ASSET"
SUM_TMP="$TMP_DIR/$ASSET.sha256"

echo "Installing open-fleet v${VERSION} (${OS}-${ARCH}) from ${REPO}..."
download "${BASE_URL}/${ASSET}" "$BIN_TMP"
download "${BASE_URL}/${ASSET}.sha256" "$SUM_TMP"

EXPECTED="$(awk '{print $1}' "$SUM_TMP" | tr 'A-F' 'a-f')"
ACTUAL="$(compute_sha256 "$BIN_TMP" | tr 'A-F' 'a-f')"

if [ -z "$EXPECTED" ] || [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "open-fleet install: SHA-256 checksum mismatch for ${ASSET} (expected ${EXPECTED:-empty}, got ${ACTUAL:-empty})" >&2
    exit 3
fi

mkdir -p "$INSTALL_DIR"
TARGET="${INSTALL_DIR}/open-fleet"
chmod 755 "$BIN_TMP"
mv "$BIN_TMP" "$TARGET"

echo "Installed open-fleet v${VERSION} -> ${TARGET} (sha256 verified: ${ACTUAL})"

case ":${PATH:-}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        echo ""
        echo "Add ${INSTALL_DIR} to your PATH:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        ;;
esac

echo ""
echo "Next steps:"
echo "  open-fleet doctor"
echo "  open-fleet init --harness claude,cursor"
