# Armory repository contract

Status: Phase 0 contract; implemented in Phase 1.4.

## Locked source

```
https://github.com/kamalx06/tornadoc2-armory
```

Branch: `main`.

The URL is a backend constant in
`client/tornado_client/armory.py`. No bridge method accepts a URL or
repo argument. The GUI shows the source read-only. Tests inject a
transport for fixtures only; production always resolves the constant.

Derived endpoints:

- Manifest: `https://raw.githubusercontent.com/kamalx06/tornadoc2-armory/main/index.json`
- Archive: `https://codeload.github.com/kamalx06/tornadoc2-armory/tar.gz/refs/heads/main`

Redirects are followed only while the host stays in
`raw.githubusercontent.com`, `codeload.github.com`, or
`github.com`.

## Trust model

No signatures and no key ring.

1. TLS authenticates the GitHub host.
2. The host is pinned in code.
3. Every payload is SHA-256 checked against the manifest.
4. Archive members are path-checked and extension-filtered.
5. Nothing is executable at install time; the operator runs a BOF
   explicitly.

A compromised GitHub account can replace the catalogue. That is the
accepted trade-off. The digest still detects transit/cache corruption
and a mismatched manifest entry.

## Layout

```
index.json
bofs/<name>/meta.json
bofs/<name>/<file>.o
bofs/<name>/script.cna        (optional)
README.md
```

`<name>` matches `^[a-z0-9][a-z0-9._-]{0,63}$`.

`index.json`:

```json
{
  "version": 2,
  "updated": "2026-11-28T00:00:00Z",
  "extensions": [
    {
      "name": "whoami",
      "format": "coff-x64",
      "description": "Print the current identity",
      "version": "1.0.0",
      "file": "whoami.o",
      "sha256": "<64 lowercase hex>",
      "cna": "script.cna",
      "min_framework": "0.9.0"
    }
  ]
}
```

Rules:

- `version` must be `2`. A `1` index with `bofs[]` is accepted and
  normalized during the transition.
- `format` is one of `coff-x64`, `coff-x86`, `coff-arm64`.
- `sha256` is required and 64 lowercase hex characters.
- `file` is a bare filename ending in `.o`.
- `cna` is an optional bare filename ending in `.cna`.
- `description` is plain text, max 200 characters; the GUI escapes it.
- `size` is optional; if present the download must match.
- A manifest row without a corresponding archive member, or with a
  digest mismatch, fails only that row.

`meta.json` mirrors the manifest row and is the fallback when
`index.json` is missing or stale. A tree listing of `bofs/*/*.o` with
`meta.json` supplies entries not present in the index.

## Fetch and cache

- Cache: `client/.tornadoc2/armory/` (0700).
- `index.json` is refreshed on `armory update` and on first use.
- Archive fallback downloads once per refresh, max 16 MB, and is
  discarded after extraction.
- On network failure, the last good index is used and its age is
  reported. An install with no cache and no network fails cleanly.
- `User-Agent: TornadoC2-armory/<version>`.
- Timeouts: 20s manifest, 30s archive, 30s file fetch.
- Per-file cap: 4 MB; per-install cap: 200 files.

## Install / update / remove

- `install <name…>|all`: resolve manifest → fetch → digest → atomic
  write. Already-installed entries are skipped unless `--replace`.
- `update`: refresh the manifest only.
- `update <name…>|all`: reinstall entries whose `version` or `sha256`
  changed; report up-to-date rows without writing.
- `remove <name…>`: delete the entry directory and installed record.
- Installed state is `installed.json` v2: `name`, `version`, `sha256`,
  `size`, `file`, `installed_at`, `repo_commit`, `format`.
- Writes: temp file, `fsync`, `chmod 0600`, `os.replace`; directories
  `0700`. A partial install is removed on failure.

## Archive safety

- Reject absolute paths, `..` segments, and symlinks.
- Accept only `index.json`, `bofs/**/*.o`, `bofs/**/*.cna`, and
  `bofs/**/meta.json`; ignore the rest.
- Reject members whose declared size or extracted size exceeds the cap.
- Normalize names before use; never derive a destination from a member
  path without re-validating it.

## Failure surface

Capability `armory.view` lists; `armory.manage` changes state.
Bridge errors use code `armory`. The GUI shows an inline banner with
one line of text; the CLI prints the same. No error includes file
contents.

## Publishing checklist

1. Add the `.o` from a reproducible build.
2. Add `meta.json` and `index.json` row with the matching digest.
3. Run the armory fixture tests against the branch.
4. Verify install, update, remove on a clean operator state.
5. Bump `version` for any binary change.

## Migration from v1

- Drop `index.json.sig`, `armory_verify.py`, and
  `TORNADOC2_ARMORY_KEYS` reading.
- Leave existing installed directories in place; add missing v2 fields
  from their v1 metadata.
- Re-fetch the index once; a signature failure is no longer fatal.
- `scripts/armory-sign.py` moves to the armory repo as an optional
  tool and is removed here.
