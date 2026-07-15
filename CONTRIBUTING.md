# Contributing to Wormhole

Thanks for considering a contribution! This guide covers everything you need to build, test, and submit changes.

## Getting Started

```bash
git clone https://github.com/lucientong/wormhole.git
cd wormhole
make deps    # go mod download + tidy
make build   # builds the web UI, then the binary, into dist/wormhole
```

Try the "[Try It Locally](README.md#try-it-locally-3-steps-no-domain-no-deploy)" section of the README to confirm your build works end-to-end before making changes.

New to the codebase? Read [`docs/architecture.md`](docs/architecture.md) first — it's written as a learning guide, not just a reference: it has a suggested reading path through the source, the reasoning behind major design decisions, a debugging/operations runbook, and a tour of the Go patterns used throughout.

## Development Workflow

```bash
make test            # go test -race ./pkg/... ./internal/... ./cmd/...
make test-coverage    # same, plus coverage.out + a printed per-func summary
make lint             # golangci-lint run ./...
make fmt              # gofmt -w
```

Before opening a PR, all four of the following should pass locally — they're exactly what CI runs:

```bash
go build ./...
go vet ./...
golangci-lint run ./...
gosec -exclude=G115 -exclude-dir=web -exclude-dir=pkg/proto/pb ./...
go test -race ./...
```

If you touched `pkg/tunnel` or `pkg/proto`'s decoders, also run the relevant fuzz target for a bit (CI runs a 20s pass on every push; run it longer locally if you're chasing something specific):

```bash
go test ./pkg/tunnel/ -run=^$ -fuzz=FuzzDecodeFrame -fuzztime=30s
go test ./pkg/proto/ -run=^$ -fuzz=FuzzDecodeControlMessage -fuzztime=30s
```

## Code Style & Conventions

- Run `gofmt`/`goimports` before committing (`make fmt` does this); CI's `golangci-lint` enforces the rest (see `.golangci.yml` for the enabled linter set).
- Prefer small, narrow, consumer-defined interfaces over large ones — see [Go Patterns Used in This Codebase](docs/architecture.md#go-patterns-used-in-this-codebase) for the conventions this project leans on (composition roots, lock-granularity-follows-ownership, `context.Context` on the control plane but not the data path, `sync.Pool` for hot-path buffers, channel-based goroutine lifecycles).
- Comments should explain *why*, not narrate *what* the code already says. Avoid restating the obvious.
- Don't reference internal planning artifacts (sprint/batch/review item IDs, etc.) in code comments or user-facing docs — describe the actual change instead. Internal planning notes live under `docs/personal/` (gitignored) precisely so they don't leak into comments or the public docs.

## Testing Guidelines

The test suite is layered — see [Testing Strategy](docs/architecture.md#testing-strategy) for the full breakdown (unit / component-integration / cluster-integration / end-to-end / fuzz / stress). A few rules of thumb:

- **Test behavior, not fields.** Drive the public API and assert on observable effects (e.g. what frames a fake peer received), rather than reaching into unexported state.
- **Every bug fix needs a regression test** at the lowest layer that can reproduce it.
- **Security-relevant code paths need explicit negative tests** — wrong HMAC, expired token, invalid cluster secret, oversized control message, and similar.
- For anything touching `pkg/client`/`pkg/server`'s control plane, the *mux-pair* pattern (a real `tunnel.Mux` on one end of a `net.Pipe`, a scripted fake peer on the other) is almost always the right tool — grep existing `_test.go` files in those packages for examples before inventing a new test harness.

## Submitting a Pull Request

1. Fork the repo and create a branch off `master`.
2. Make your change, with tests. Keep PRs focused — unrelated refactors make review slower for everyone.
3. Make sure the checklist in [Development Workflow](#development-workflow) passes locally.
4. Write a commit message and PR description that explain *why* the change is needed, not just what changed (the diff already shows that).
5. Open the PR against `master`. CI (`.github/workflows/ci.yml`) runs the same checks automatically.

## Reporting Bugs / Requesting Features

Please open a [GitHub Issue](https://github.com/lucientong/wormhole/issues) with:

- For bugs: Wormhole version (`wormhole version`), OS/arch, the command you ran, and what happened vs. what you expected. Logs with `-v` (or `--debug` for very hard-to-reproduce issues) are very helpful — see [Debugging & Operations Runbook](docs/architecture.md#debugging--operations-runbook).
- For features: the problem you're trying to solve, not just the API you imagine — it's easier to design the right solution starting from the actual use case.

## Security Issues

Please don't open a public issue for a suspected security vulnerability. Instead, use GitHub's [private vulnerability reporting](https://github.com/lucientong/wormhole/security/advisories/new) for this repository.

## License

By contributing, you agree that your contributions will be licensed under the project's [Apache License 2.0](LICENSE).
