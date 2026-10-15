# Contributing

1. Keep changes inside GOAL.md. Off-goal PRs get a polite close with a pointer here.
2. `gofmt` + `go test ./...` must pass. Add a fixture under `testdata/` for every new detector or guard case.
3. Never commit real secrets — fixtures use obviously fake values (`AKIA…TEST`, `sk-ant-api03-TEST…`).
4. Design language for `site/` is locked in `site/DESIGN.md` and `/workspace/oss-factory/design/registry.md` (hazmat absorbent pad). Do not introduce SaaS template layouts or hex/fonts already registered.
5. Commit as yourself; maintainers squash-merge after CI green.
