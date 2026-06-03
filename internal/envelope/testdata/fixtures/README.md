# Envelope wire-contract fixtures

These JSON files are the cross-repo source of truth for what
`infra/schemas/evidence_envelope.json` (v1.0.0) accepts and rejects.

## Layout

```
valid/         -- every file here MUST be accepted by both validators
invalid/       -- every file here MUST be rejected by both validators
  *.json       -- the fixture body
  *.expect.txt -- substring(s), one per line, that the validator's error
                  message must contain. Asserts *why* it was rejected,
                  not just that it was.
FIXTURES.lock  -- sha256 manifest of every *.json fixture above; the drift
                  guard (see below). Regenerated, never hand-edited.
```

The 1000-event "max_events" valid case and the 1001-event "too_many_events"
invalid case are generated programmatically by the contract test rather than
checked in — 1000 events of hand-written JSON in a fixture file is not practical.
See `internal/envelope/envelope_contract_test.go`.

## Lock-step rule (manifest §0)

Two independent validators consume these fixtures:

1. `services/ingest/internal/api/envelope.go` in the operitas-eu/operitas monorepo
   (BSL 1.1).
2. `internal/envelope/` in this repo (MIT).

Per manifest §0, neither side imports the other's code. The fixtures are the
contract. Therefore:

- **Any change here MUST land in lock-step with a corresponding change in the
  monorepo's `infra/schemas/fixtures/envelope/` directory.** That includes adding,
  removing, or modifying fixtures, and any change to the schema or to
  `expect.txt` substrings.
- If the two validators ever disagree on a fixture, that is a P1 wire-contract
  bug — fix the schema or the validator, not the fixture.

### Drift guard: FIXTURES.lock

`TestFixturesMatchLock` (in `internal/envelope/fixtures_lock_test.go`) hashes
every `*.json` fixture and compares the manifest to the committed `FIXTURES.lock`.
This repo cannot read the monorepo's canonical tree, so the lock is how the
collector self-checks: any add/remove/edit of a fixture fails the collector's
own CI until the lock is regenerated, which surfaces the change as a visible
`FIXTURES.lock` diff — the reminder to make the matching monorepo change.

Regenerate after an intentional fixture change:

```
UPDATE_FIXTURES_LOCK=1 go test ./internal/envelope/ -run TestFixturesMatchLock
```

The monorepo's `envelope-contract-mirror` CI job remains the hard cross-repo
gate (it diffs the real fixtures across both repos); this lock left-shifts
detection to the collector side and makes the lock-step obligation explicit.

## Future vendoring strategy

TODO(adr): These fixtures are currently checked in as a copy. The monorepo does
not yet publish `infra/schemas/` as a versioned Go module or git submodule.
When it does, replace this copy with a submodule or a `go generate` step that
fetches a pinned release. Until then, the lock-step rule above must be enforced
manually via paired PRs. See the lock-step rule in the monorepo's
`infra/schemas/fixtures/README.md` for the authoritative process.
