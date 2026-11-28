//! Compile-time catalog embedder for standalone zero-clone `open-fleet` binaries.
//!
//! Walks the canonical Markdown catalog (`skills/`, `playbooks/`, `runtime/*.md`,
//! JSON metadata, retained run index, and Mission Control HTML asset) and generates
//! `OUT_DIR/embedded_catalog.rs` with deterministic `include_bytes!` entries and a
//! FIPS 180-4 SHA-256 content digest. Zero build-dependencies required.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_bits: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_bits: 0,
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, slot) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *slot = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn update(&mut self, data: &[u8]) {
        self.total_bits = self.total_bits.wrapping_add((data.len() as u64) * 8);
        let mut idx = 0;
        while idx < data.len() {
            let take = (64 - self.buf_len).min(data.len() - idx);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[idx..idx + take]);
            self.buf_len += take;
            idx += take;
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
    }

    fn finalize_hex(mut self) -> String {
        let total_bits = self.total_bits;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..64] {
                *b = 0;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] {
            *b = 0;
        }
        self.buf[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buf;
        self.compress(&block);

        let mut hex = String::with_capacity(64);
        for word in self.state {
            use std::fmt::Write as _;
            let _ = write!(&mut hex, "{word:08x}");
        }
        hex
    }
}

fn rel_forward(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let mut parts = Vec::new();
    for comp in rel.components() {
        let s = comp.as_os_str().to_str()?;
        parts.push(s);
    }
    Some(parts.join("/"))
}

fn collect_skills(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let Some(name_s) = name.to_str() else {
            continue;
        };
        if name_s.starts_with('.') || name_s.starts_with('_') {
            continue;
        }
        if path.is_dir() {
            println!("cargo:rerun-if-changed={}", path.display());
            collect_skills(root, &path, out);
        } else if path.is_file() {
            if let Some(rel) = rel_forward(root, &path) {
                out.insert(rel);
            }
        }
    }
}

fn collect_flat_ext(root: &Path, dir: &Path, ext: &str, out: &mut BTreeSet<String>) {
    if !dir.is_dir() {
        return;
    }
    println!("cargo:rerun-if-changed={}", dir.display());
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some(ext) {
            if let Some(rel) = rel_forward(root, &path) {
                out.insert(rel);
            }
        }
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();

    let mut files = BTreeSet::new();

    let skills_dir = workspace_root.join("skills");
    if skills_dir.is_dir() {
        println!("cargo:rerun-if-changed={}", skills_dir.display());
        collect_skills(&workspace_root, &skills_dir, &mut files);
    }

    collect_flat_ext(
        &workspace_root,
        &workspace_root.join("playbooks"),
        "md",
        &mut files,
    );
    collect_flat_ext(
        &workspace_root,
        &workspace_root.join("runtime"),
        "md",
        &mut files,
    );
    collect_flat_ext(
        &workspace_root,
        &workspace_root.join("runtime"),
        "json",
        &mut files,
    );
    collect_flat_ext(
        &workspace_root,
        &workspace_root.join("runtime/providers"),
        "json",
        &mut files,
    );
    collect_flat_ext(
        &workspace_root,
        &workspace_root.join("runtime/schemas"),
        "json",
        &mut files,
    );
    collect_flat_ext(
        &workspace_root,
        &workspace_root.join("docs/runs/index"),
        "json",
        &mut files,
    );

    for fixed in [
        "scripts/mission-load-budgets.json",
        ".claude-plugin/plugin.json",
        "ENGINE_VERSION",
        "open_fleet/ui_assets/index.html",
    ] {
        let p = workspace_root.join(fixed);
        if p.is_file() {
            files.insert(fixed.to_string());
        }
    }

    let mut hasher = Sha256::new();
    for rel in &files {
        let full = workspace_root.join(rel);
        println!("cargo:rerun-if-changed={}", full.display());
        let bytes = fs::read(&full)
            .unwrap_or_else(|e| panic!("failed to read embedded catalog file {rel}: {e}"));
        hasher.update(rel.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(&[0u8]);
        hasher.update(&bytes);
    }
    let catalog_sha256 = hasher.finalize_hex();

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out_path = out_dir.join("embedded_catalog.rs");
    let mut f = fs::File::create(&out_path).expect("create embedded_catalog.rs");
    writeln!(
        f,
        "pub const EMBEDDED_CATALOG_SHA256: &str = {catalog_sha256:?};"
    )
    .expect("write sha");
    writeln!(f, "pub const EMBEDDED_FILES: &[(&str, &[u8])] = &[").expect("write array open");
    for rel in &files {
        let rel_from_crate = format!("/../../{rel}");
        writeln!(
            f,
            "    ({rel:?}, include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), {rel_from_crate:?}))),"
        )
        .expect("write entry");
    }
    writeln!(f, "];").expect("write array close");
}
