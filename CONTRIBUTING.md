# Contributing to Operitas Collector

Thank you for your interest. The collector is the customer-facing, auditable
part of the Operitas platform, so we hold it to a high bar for correctness,
minimal footprint, and read-only behaviour.

## Before you open an issue

- Check whether the issue is already tracked.
- For security vulnerabilities, follow [SECURITY.md](SECURITY.md) — do not
  open a public issue.
- For questions about the wider Operitas platform or the ingest API, contact
  support@operitas.eu rather than filing a GitHub issue here.

## Opening an issue

Use the issue tracker for:

- Bug reports (include collector version, Go version, Kubernetes version,
  and the relevant log lines).
- Feature requests (explain the DORA or operational requirement it addresses;
  changes that expand the binary's footprint or add new external calls receive
  extra scrutiny).

## Pull requests

1. **Fork the repo and work on a feature branch.**
2. **Keep changes small and focused.** One logical change per PR.
3. **Run the test suite before pushing:**
   ```
   go test ./...
   ```
4. **Run `helm lint` before pushing Helm chart changes:**
   ```
   helm lint helm/collector/
   ```
5. **Do not add new Go module dependencies** without prior discussion in an
   issue. Every dependency is a supply-chain risk in a binary that runs inside
   customer infrastructure. We prefer the standard library.
6. **Commit message style — conventional commits:**
   ```
   <type>(<scope>): <short summary>

   <optional body — explain why, not what>
   ```
   Types: `fix`, `feat`, `refactor`, `test`, `docs`, `chore`, `ci`.
   Scopes: `transport`, `envelope`, `sources`, `redact`, `helm`, `cmd`.

   Examples:
   ```
   fix(transport): honour 429 Retry-After header from ingest API
   feat(sources): add GitHub webhook HMAC validation for X-Hub-Signature-256
   docs(helm): document egressCidr for private-link deployments
   ```

7. **No emojis** in code, commit messages, or filenames.
8. **No internal Operitas hostnames or credentials** in any committed file.
   The collector is a public repository.

## Read-only posture

The collector must never mutate the customer's infrastructure. Any PR that
introduces a write API call, a Kubernetes RBAC verb other than `get`/`list`/`watch`,
or a disk write outside `/var/lib/operitas/` will be rejected.

## Licensing

By opening a pull request you agree that your contribution is licensed under
the [MIT License](LICENSE) that covers this repository. There is no CLA.

## Code style

- Standard Go formatting (`gofmt`). CI will reject unformatted code.
- Table-driven tests where idiomatic.
- Structured JSON logs to stdout; no `log.Printf`-style free-form lines in
  production paths.
- No build tags other than `integration` (used for tests that need a live
  fake server).
