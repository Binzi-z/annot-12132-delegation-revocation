# Revocation-Oriented Cross-Organization Admission Protocol (Go reference)

A small, dependency-free Go reference implementation of a **two-organization /
two-node authorization revocation protocol** with a durable event log,
self-contained admission certificates, per-issuer failure isolation, and a
replayable interleaving model.

## 1. Model in one paragraph

Two organizations (`orgA`, `orgB`) run one node each. Resources live in a tenant
and are addressed by `(tenant, resourceID)`. An organization authority issues
**delegation edges**; a chain of edges rooted at a resource-owning admin grants a
subject a capability on that resource. A resource may carry **several independent
chains at once**: a subject is admitted if *any* chain is valid. Revoking a chain
(the issuer revokes an edge, a member leaves, the issuer's credential generation
rotates, a resource is transferred, or an emergency ban lands) kills only that
chain; sibling chains keep working.

Every write is appended to a **durable per-node event log** before it becomes
visible. The log is the source of truth; node state is a pure fold over the log.
Compaction replaces a log prefix with a snapshot **plus** a retained set of
revocation-evidence records, and every recovery re-applies the durable evidence
union on top of the snapshot, so no already-received emergency ban or revocation
can be undone by a stale signed snapshot, compaction, restart, or a delegation
path switch.

Each **issuer** (an organization authority) is an isolation domain. A node tracks
a per-issuer **watermark** (the highest generation + logical tick + sequence it
has ever durably observed from that issuer). Watermarks are **migratable**: they
are serialized into snapshots and carried forward across restart/compaction, so a
recovered node never regresses below evidence it already accepted. A fault in one
issuer (generation gap, origin-chain break, malformed payload) quarantines only
that issuer and never blocks decisions that do not depend on it.

## 2. Layout

```
cmd/cc-node        one node process: HTTP API + durable store (serve/author/ingest)
cmd/scenario       runs the interleaving state machine + the two-process replay
internal/event     canonical signed hash-chained records, evidence records, watermarks
internal/store     durable JSONL commit log, evidence journal, snapshots, compaction
internal/model     pure reference state machine: fold, multi-path chains, decisions
internal/proto     admission certificate + independent verifier (no node state)
internal/node      node service: authoring, ingest/isolation, watermarks, checkpoint
internal/replay    two-real-process harness + controllable queue (hold/drop/dup/order)
internal/scenario  deterministic signed-world builder used by tests and the machine
internal/interleave reference state machine enumerating action interleavings
```

## 3. Event log and evidence

- `commits.jsonl` — local acceptance chain. Each commit binds the previous commit
  hash and the accepted event hash; fsynced before the append is reported done.
- `evidence.jsonl` — append-only journal of revocation evidence (`ban`, `revoke`,
  `rotate`, `leave`, `transfer`). Compaction **rewrites but never drops** it; it
  is only deduplicated under the *minimal-evidence* rule (see below).
- `snapshot.json` — checkpoint of model state, retained evidence, per-issuer
  watermarks, and per-origin sequence marks. The state hash is computed over a
  canonical (whitespace-free) encoding so it survives re-encoding on load.

Events are canonical, issuer-signed, and hash-chained per origin. Replication is
pulled in canonical order `(tick, origin, seq)`, so both nodes fold identically.

**Minimal evidence.** Evidence records are deduplicated per *claim*:

| kind | dedup key | why |
|---|---|---|
| ban | full target tuple `(issuer, tenant, resource, subject, edge)` | different targets are different claims |
| revoke | `edgeID` | one revoke per edge |
| rotate | `(issuer, fromGen)` | one record per generation step, so the recorded generation chain is contiguous and replayable |
| leave | member identity | one departure per member |
| transfer | `(tenant, resource)` | the newest epoch fully determines owner+epoch |

Keeping each rotation *step* (rather than only the newest) is what lets a
verifier reconstruct a contiguous generation chain from evidence alone; collapsing
it would make a lone `g2→g3` record look like a false gap on a base state that only
knows `g1`.

## 4. Admission certificate

`proto.Certificate` is a portable, verifiable justification of a decision. It
carries:

- the signed **tenant** and **resource** provenance (and any transfers),
- the chosen chain, as a `StepProof` per edge: the issuer-signed delegation event
  (the per-edge proof) and the issuer-signed **grant** event proving the actor was
  entitled to delegate at that generation,
- the **evidence records** the decision relied on (bans, revocations, leaves,
  rotations, transfers), each with its full signed event,
- the node's **per-issuer watermark attestations**, including the credential
  generation used for each edge,
- the node's verdict, decision time, partition declaration, and a signature over
  the whole body.

`proto.Verify(registry, cert)` re-checks everything from public inputs only:
every signature and hash, the provenance, the chain shape (root admin, parent
links, scope nesting, subject), generation/epoch consistency, freshness, watermark
coverage of each edge's mint, and — most importantly — it **re-folds the
certificate's own signed inputs and re-derives the verdict**, so a certificate
that claims ALLOW but cannot be independently re-derived as ALLOW is rejected.

## 5. Semantics when issuers partition

Three access classes make the partition behavior explicit:

| Class | Meaning | Partition behavior |
|---|---|---|
| `LOCAL` | resource owned by the deciding node's org | decided from durable local state and evidence, including chains crossing a partitioned issuer (no live refresh is needed; the owner's durable evidence is authoritative) |
| `REMOTE_READ` | read of the other org's resource | a chain whose issuer is unreachable at decision time is refused (no stale cross-boundary read); all-reachable chains proceed |
| `REMOTE_WRITE` | mutation of the other org's resource | fail-closed while the owner org is partitioned, regardless of cached data |

A partition-induced DENY is **not** evidence of revocation and never deletes
evidence. An ALLOW from stale data is impossible because a decision only consumes
durably accepted state, and every certificate's proof is checked against an
attested watermark that must cover the edge's mint tick and generation.

## 6. Issuer failure isolation

`internal/node` treats each origin/issuer as an independent domain:

- a **replication gap** (out-of-order `seq`) isolates only that origin and refuses
  the event;
- an **origin-chain break** isolates only that origin;
- a **generation-gap rotation** (`fromGen` ahead of the issuer's current
  generation) or an **owner-mismatched transfer** quarantines only that issuer;
- quarantine is monotone and the other issuer's decisions are unaffected.

## 7. Reference state machine and the two-process replay

`internal/interleave` is a small reference state machine that enumerates action
interleavings and checks invariants on every reachable state. The action alphabet
covers reauthorization, generation rotation, ownership transfer, expiry, emergency
bans, compaction, recovery/restart, and path switching. Checked invariants:
`independent-path`, `revoked-stays-dead`, `ban-monotone`, `non-revoked-stays-live`,
`certificate-verify`. Enumeration to depth 4 explores ~1.5k states.

Harness invariants also catch the real bug this model was built to avoid: a
per-issuer rotation record was originally collapsed to the newest generation,
which made evidence replay non-contiguous and produced a false generation gap;
the per-step dedup key fixes it, and the enumerator found it.

`internal/replay` launches **two real `cc-node` subprocesses** over loopback and
routes all replication through a **controllable queue** (`hold`/`release`,
`drop`, `duplicate`, arbitrary `drain`/re-ingest). The minimal counterexample
replayed end to end is:

1. two processes share the canonical two-chain world;
2. a revoke of chain 1 is staged but **held** (partition);
3. B still admits bob from durable state (expected — it has not seen the revoke);
4. the held revoke is released and delivered, so B now **denies** bob;
5. an old, still-validly-signed delegation is delivered twice, and must **not**
   resurrect the chain;
6. carl's independent chain remains admitted throughout.

Every decision prints its explanation and its admission certificate, and the
certificate is independently verified in-process.

## 8. Running

```bash
go build ./...

# full suite: model, certificates, store durability/compaction, node semantics,
# the interleaving state machine, and the two-real-process replay
go test ./...

# the scenario command: enumerates interleavings and runs the two-process replay,
# printing per-decision certificates
go run ./cmd/scenario -v

# one node interactively
go run ./cmd/cc-node -role orgA -dir ./runtime/A -listen 127.0.0.1:18081 -bootstrap world
go run ./cmd/cc-node -role orgB -dir ./runtime/B -listen 127.0.0.1:18082
```

The replay harness builds a `cc-node` binary and caches it under the OS temp
directory (`$TMPDIR/ccrevoke-bin`); it leaves no build artifacts in the repo.
Runtime state for interactive nodes goes under the `-dir` you pass (e.g.
`./runtime/A`).

## 9. What the tests demonstrate

- **Independent paths stay usable** while a sibling chain is revoked, rotated,
  expired, or banned (`internal/scenario` model tests, `internal/node`,
  `internal/replay`).
- **Revoked paths cannot be resurrected** by stale signed snapshots, compaction,
  restart, stale event replay, or duplicate delivery (`internal/store`,
  `internal/node`, `internal/replay/counterexample_test.go`).
- **Emergency bans are monotone** across partition, compaction, restart, and path
  switch (`internal/store/TestStaleSnapshotCannotDropEvidence`,
  `internal/node/TestEmergencyBanSurvivesCompactionAndRestart`,
  `internal/replay/TestEmergencyBanMonotoneAcrossRestart`,
  `internal/scenario/TestPathSwitchKeepsBannedPathEvidence`).
- **Watermarks migrate and never regress**; a single issuer fault is isolated
  (`internal/replay/TestWatermarkMigrationAcrossRestart`,
  `internal/node/TestIssuerFaultIsolation`).
- **Partition semantics** for the three classes are exact
  (`internal/replay/TestPartitionSemanticsRealProcesses`).
- **Every decision has a checkable basis**: certificates verify independently,
  including denies, and re-derive the verdict
  (`internal/scenario/cert_test.go`, `internal/interleave` `certificate-verify`).

## 10. Notes on the reference keys

Edge and certificate proofs use HMAC-SHA256 over canonical, explicit payloads
under per-`(issuer, generation)` keys derived from a shared seed, plus a
node-authority key for certificates. Every canonical input is explicit so swapping
in real asymmetric signatures is a local change: sign/verify live in
`internal/auth`, and nothing else assumes symmetry.
