#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");

const pkg = require("../package.json");
const VERSION = pkg.version;

const PLATFORM_MAP = {
  "darwin-arm64": { pkg: "@open-fleet/cli-darwin-arm64", asset: "open-fleet-darwin-arm64", bin: "open-fleet" },
  "darwin-x64": { pkg: "@open-fleet/cli-darwin-x64", asset: "open-fleet-darwin-x64", bin: "open-fleet" },
  "linux-arm64": { pkg: "@open-fleet/cli-linux-arm64", asset: "open-fleet-linux-arm64", bin: "open-fleet" },
  "linux-x64": { pkg: "@open-fleet/cli-linux-x64", asset: "open-fleet-linux-x64", bin: "open-fleet" },
  "win32-x64": { pkg: "@open-fleet/cli-windows-x64", asset: "open-fleet-windows-x64.exe", bin: "open-fleet.exe" },
};

function platformKey() {
  return `${process.platform}-${process.arch}`;
}

function isExecutable(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return fs.statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function resolveInstalledBinary(entry) {
  if (process.env.OPEN_FLEET_BIN && isExecutable(process.env.OPEN_FLEET_BIN)) {
    return process.env.OPEN_FLEET_BIN;
  }

  // 1. Optional platform npm package
  if (entry) {
    try {
      const pkgJsonPath = require.resolve(`${entry.pkg}/package.json`);
      const candidate = path.join(path.dirname(pkgJsonPath), "bin", entry.bin);
      if (isExecutable(candidate)) {
        return candidate;
      }
    } catch {
      // Optional dependency not installed; fall through to local/cache lookup.
    }
  }

  // 2. Local workspace build (useful in checkouts)
  const localName = process.platform === "win32" ? "open-fleet.exe" : "open-fleet";
  const localRelease = path.resolve(__dirname, "..", "..", "target", "release", localName);
  if (isExecutable(localRelease)) {
    return localRelease;
  }

  // 3. Cached release binary
  const cacheBase = process.env.OPEN_FLEET_CACHE_DIR || path.join(os.homedir(), ".open-fleet", "bin");
  const cached = path.join(cacheBase, VERSION, localName);
  if (isExecutable(cached)) {
    return cached;
  }

  return null;
}

function downloadBuffer(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": `open-fleet-cli/${VERSION}` } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          if (redirectsLeft <= 0) {
            reject(new Error(`too many redirects fetching ${url}`));
            return;
          }
          res.resume();
          resolve(downloadBuffer(res.headers.location, redirectsLeft - 1));
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
          return;
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

async function fetchAndCache(entry) {
  const repoSlug = process.env.OPEN_FLEET_RELEASE_REPO || "ravidsrk/open-fleet";
  const baseUrl =
    process.env.OPEN_FLEET_RELEASE_URL ||
    `https://github.com/${repoSlug}/releases/download/engine-v${VERSION}`;
  const binBuf = await downloadBuffer(`${baseUrl}/${entry.asset}`);
  const shaBuf = await downloadBuffer(`${baseUrl}/${entry.asset}.sha256`);

  const expected = shaBuf.toString("utf8").trim().split(/\s+/)[0].toLowerCase();
  const actual = crypto.createHash("sha256").update(binBuf).digest("hex").toLowerCase();
  if (!expected || expected !== actual) {
    throw new Error(
      `SHA-256 verification failed for ${entry.asset} (expected ${expected || "<empty>"}, got ${actual})`
    );
  }

  const cacheBase = process.env.OPEN_FLEET_CACHE_DIR || path.join(os.homedir(), ".open-fleet", "bin");
  const cacheDir = path.join(cacheBase, VERSION);
  fs.mkdirSync(cacheDir, { recursive: true });
  const target = path.join(cacheDir, entry.bin);
  const tmp = path.join(cacheDir, `.${entry.bin}.tmp.${process.pid}`);
  fs.writeFileSync(tmp, binBuf, { mode: 0o755 });
  fs.renameSync(tmp, target);
  return target;
}

function runBinary(binPath, args) {
  const res = spawnSync(binPath, args, { stdio: "inherit" });
  if (res.error) {
    process.stderr.write(`open-fleet: failed to exec ${binPath}: ${res.error.message}\n`);
    process.exit(2);
  }
  process.exit(res.status === null ? 1 : res.status);
}

async function main() {
  const key = platformKey();
  const entry = PLATFORM_MAP[key];
  const existing = resolveInstalledBinary(entry);
  if (existing) {
    runBinary(existing, process.argv.slice(2));
    return;
  }

  if (!entry) {
    process.stderr.write(
      `open-fleet: unsupported platform '${key}'; build from source with 'cargo build --release -p of-cli'\n`
    );
    process.exit(2);
  }

  try {
    const fetched = await fetchAndCache(entry);
    runBinary(fetched, process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`open-fleet: ${err.message}\n`);
    process.exit(2);
  }
}

main();
