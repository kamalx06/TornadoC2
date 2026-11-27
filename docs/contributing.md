# Contributing

## Layout

```
tornadoc2/agent/        Go agent, split by OS and build tag
tornadoc2/beacon/       Server-side build manager and listener manager
tornadoc2/team/         Team server, RBAC, audit, stores
client/                 Operator client, GUI, MCP server
tests_py/               Server/client Python suite
docs/                   Handbook, detection notes, ABI policy
```

## Rules

1. **Feature work is tag-gated.** A new transport, evasion method,
   sleep mask, persistence method or Jump method carries its own
   `t_*`, `ev_*`, `sleep_*`, `persist_*` or `jump_*` file tag and a
   no-op fallback for the untagged build. Add the tag to
   `all_tags` in `tornadoc2/beacon/builder.py`.
2. **Nothing Windows-only ships untested.** Add a Go test or extend
   the Windows CI job. Live-host proof beats a compile.
3. **State writes are atomic.** Temp file, `fsync`, `chmod 0600`,
   `os.replace`. Sensitive files go through `tornadoc2/team/atrest.py`.
4. **Every mutation is audited.** Use `self.audit.write(...)` and the
   `_with_cap` gate; the response carries `X-Audit-Id`.
5. **No secrets in audit detail.** Record ids and provenance, not
   password or key material.
6. **Keep the graph current.** Run `graphify update .` after code
   changes.

## Checks before a pull request

```bash
cd tests_py && python -m unittest discover
ruff check tornadoc2 client/tornado_client client/tornadoc2_mcp tests_py scripts
cd ../tornadoc2/agent && gofmt -l . && \
  GOOS=linux GOARCH=amd64 go test -race ./protocol ./transport \
    ./extensions ./evasion
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags \
  't_http jump_psexec jump_winrm jump_wmi jump_scshell wasm_host' ./windows
cd ../.. && git diff --check
```

## Commit style

`area(scope): imperative summary` — for example
`agent(windows): add fork-and-run loader`. One logical change per
commit; the changelog entry is written in the same commit.

## New armory entries

The armory index is `github.com/kamalx06/tornadoc2-armory`. A BOF
needs `manifest.json`, a `.o` and a README. Sign the index with
`scripts/armory-sign.py sign` and publish the signature next to it.
