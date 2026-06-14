# Threshold Security Proxy - Development Progress

## Project Overview

Threshold is a security proxy system consisting of Client (local proxy) and Server (security gateway), deployed between user terminal devices (IDV client) and OpenStack cloud platform as a transparent middleware providing device fingerprint verification, user behavior assessment, and access control decisions.

### Core Capabilities

- Device fingerprint 6-layer Hash tree matching (whitelist)
- L0-L3 static risk classification
- Declarative decision engine (12 rules + fallback)
- Connection-level user portrait with composite risk scoring
- Cross-device correlation interface
- mTLS encrypted channel
- WAL write-ahead log for persistence consistency

### Tech Stack

| Component | Choice | Notes |
|-----------|--------|-------|
| Language | Go 1.25 | |
| Protocol | gRPC + Protobuf | Streaming support |
| Storage | bbolt | Embedded KV, interface abstracted |
| Encryption | mTLS (crypto/tls) | Prototype: one-way TLS |
| Concurrency | goroutine + channel | Go native |
| Config | YAML (gopkg.in/yaml.v3) | File-based |
| Rate Limiting | TokenBucket (hand-rolled) | API-compatible with golang.org/x/time/rate |
| Testing | go test | Standard framework |

---

## Day 1: Skeleton + Proto + gRPC Skeleton

**Status**: Complete

Project builds, proto generates code, gRPC server starts.

**Key files**: `pkg/proto/*.proto`, `pkg/types/types.go`, `pkg/config/config.go`, `cmd/server/main.go`

---

## Day 2: Storage Layer + Fingerprint Engine

**Status**: Complete

6-layer Hash tree matching, bbolt persistence, WAL crash recovery.

**Key files**: `pkg/storage/*.go`, `server/fingerprint/tree.go`

---

## Day 3: Decision Engine

**Status**: Complete

Rule engine with 10 rules (R01-R10) + R99 fallback. First-match-wins evaluation.

**Key files**: `server/decision/engine.go`, `server/decision/rules.go`

---

## Day 4: OutputBuffer + AlertQueue + Router

**Status**: Complete

Message buffering, alert queue with subscriber pattern, Router with L0-L3 classification.

**Key files**: `server/output/buffer.go`, `server/alert/queue.go`, `server/router/router.go`

---

## Day 5: DispatchManager + WorkerPool

**Status**: Complete

Elastic scaling WorkerPool, overflow to bbolt, monitor loop with reload.

**Key files**: `server/dispatch/manager.go`, `server/dispatch/worker.go`, `server/dispatch/taskstore.go`

---

## Day 6: gRPC Enhancements + Cross-device Interface

**Status**: Complete

### Ratelimit (server/grpc/ratelimit.go)
- TokenBucket: mutex-protected, refill-on-access, configurable rate + burst
- Methods: `Allow()`, `AllowN(n)`, `Tokens()`, `Rate()`, `Burst()`

### Interceptors (server/grpc/interceptor.go)
- Unary + Stream interceptors, 3 layers:
  1. Rate limiting (returns ResourceExhausted)
  2. Panic recovery (returns Internal, logs stack)
  3. Request logging (method, duration, peer address)

### Cross-device Correlator (server/crossdevice/correlator.go)
- `Correlator` interface: Correlate, Record, RiskScore
- `SimpleCorrelator`: in-memory user<->device bidirectional mapping
- RiskScore: 1 user=0.0, 2 users=0.5, 3+ users=1.0

### Integration into server.go
- TokenBucket created from `cfg.GRPC.RateLimit` + `cfg.GRPC.BucketSize`
- Interceptors wired into `grpc.NewServer()` via `grpc.UnaryInterceptor()` + `grpc.StreamInterceptor()`

**Tests**: 10 (6 ratelimit + 4 interceptor, all with -race)

---

## Day 6+: Portrait Module + Decision Engine Enhancement

**Status**: Complete

### Portrait Store (server/portrait/store.go)

**ConnectionSummary Persistence**
- On connection close, extract summary from `ConnectionContext`
- Write to bbolt with key `userID|timestamp` (lexicographic = chronological)
- Auto-trim: keep last 50 entries per user

**UserProfile Aggregation**
- Incrementally updated on each connection close
- Fields: TotalConnections, UniqueDevices, UniqueIPs, TotalWriteOps, AlertCount, OffHoursCount, KnownDevices, KnownIPs, FirstSeenAt, LastSeenAt

**Composite Risk Scoring** (`UserProfile.RiskScore()`)
- Alert frequency: 40% weight
- Write ratio: 20% weight
- Device diversity (>3 devices): 20% weight
- Off-hours ratio: 20% weight
- Output: 0.0 ~ 1.0

**Data Flow**
```
CloseConnection -> OnConnectionClose
    |
    +-> extractSummary() -> AppendSummary (bbolt)
    +-> updateProfile()  -> UpsertProfile (bbolt)

ProxyStream -> GetHistory(userID, 20)
    |
    +-> Engine.Evaluate(ctx, history, riskLevel)
         |
         +-> R04: profile.RiskScore() > 0.7 -> ALERT
         +-> R05: known user + new device -> ALERT
```

### Decision Engine Updates

| Rule | Condition | Action |
|------|-----------|--------|
| R01 | Device blacklisted | BLACKLIST_DEVICE |
| R02 | Last 3 connections all alerted | BLACKLIST_DEVICE |
| R03 | Last 5 connections cumulative delete > 10 | BLACKLIST_DEVICE |
| R04 | **Portrait risk score > 0.7** | ALERT |
| R05 | **Established user on never-seen device** | ALERT |
| R06 | 5+ login_failed in current connection | BLOCK_LOGIN |
| R07 | 3+ delete ops in single connection | BLOCK_DEVICE |
| R08 | Upload then start VM | QUARANTINE_AND_ALERT |
| R09 | Write ops during off-hours (0:00-6:00) | ALERT |
| R10 | Write ratio > 80% in current connection | ALERT |
| R99 | Fallback: static risk level | ALLOW |

**Integration**: Handler.ProxyStream now calls `portrait.GetHistory()` before evaluating engine. Handler.CloseConnection calls `portrait.OnConnectionClose()`.

**Storage**: Added `BucketProfiles` to storage constants + bbolt initialization.

---

## Day 8: End-to-End Integration Tests

**Status**: Complete

| Test | Validates |
|------|-----------|
| EstablishConnection | Fingerprint match -> connection created |
| EstablishConnection_Rejected | Unknown device -> rejected |
| ProxyStream_GET_L0 | GET -> L0 -> OutputBuffer -> OK |
| ProxyStream_DELETE_L2 | DELETE -> L2 -> decision engine -> OK |
| ProxyStream_FingerprintMismatch | Fingerprint mismatch -> BLOCKED |
| PullApproved | 3 GETs -> OutputBuffer -> pull 3 messages |
| CloseConnection | Connection closed + portrait updated |
| ConcurrentProxyStream | 20 concurrent gRPC streams -> all OK |

---

## Test Coverage Summary

| Module | Tests | Status | Notes |
|--------|-------|--------|-------|
| pkg/storage | 5 | PASS | WAL transactions / crash recovery |
| server/fingerprint | 9 | PASS | Hash tree matching / register / unregister |
| server/decision | 7 | PASS | Rule matching (R06-R10, R99, static risk) |
| server/output | 5 | PASS | OutputBuffer read/write/subscribe |
| server/alert | 5 | PASS | AlertQueue read/write/subscribe |
| server/router | 13 | PASS | Classification / multi-consumer / backpressure |
| server/dispatch | 15 | PASS | Overflow / elastic scaling / engine integration |
| server/grpc | 10 | PASS | TokenBucket + interceptors (with -race) |
| server/crossdevice | 6 | PASS | Correlator record / correlate / risk score |
| cmd/server | 8 | PASS | End-to-end gRPC integration |
| **Total** | **83** | **ALL PASS** | |

## Project File Stats

| Directory | .go Files | Test Files |
|-----------|-----------|------------|
| pkg/proto + pb | 4 (proto) + 4 (gen) | 0 |
| pkg/types | 1 | 0 |
| pkg/config | 1 | 0 |
| pkg/storage | 3 | 1 |
| server/fingerprint | 2 | 1 |
| server/portrait | 1 | 0 |
| server/decision | 3 | 1 |
| server/output | 1 | 1 |
| server/alert | 1 | 1 |
| server/router | 3 | 1 |
| server/dispatch | 4 | 1 |
| server/grpc | 4 | 2 |
| server/crossdevice | 1 | 1 |
| cmd/server | 2 | 1 |
| cmd/client | 1 | 0 |
| **Total** | **35** | **11** |

## Completion Status

| Day | Content | Status |
|-----|---------|--------|
| 1 | Skeleton + Proto + gRPC | Done |
| 2 | Storage + Fingerprint | Done |
| 3 | Decision Engine | Done |
| 4 | OutputBuffer + AlertQueue + Router | Done |
| 5 | DispatchManager + WorkerPool | Done |
| 6 | gRPC enhancements + Cross-device + Portrait | Done |
| 7 | Client implementation | Pending |
| 8 | End-to-end integration | Done |

### Future Items

- Rules YAML configuration (currently hardcoded)
- BLOCK_LOGIN auto-release timer
- QUARANTINE_AND_ALERT CICD scan integration
- REQUIRE_2FA two-factor flow
- Client-side implementation (redirect, collector, proxy)
- Cross-device correlation algorithm enhancement
- ConnectionContext WAL persistence on close
- CloseConnection notify downstream subscribers

See dispatch.md for DispatchManager module details.
