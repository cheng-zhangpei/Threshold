# Decision Engine: Modeling & Design Document

> 核心问题：怎么把"这个请求安不安全"变成一个可计算的判断？
>
> 这本质上是一个**分类问题**——给定一个请求，输出一个动作（ALLOW / ALERT / BLOCK ...）。我们用了三种模型来解决它，从简单到复杂。

## 1. Overview

The Threshold decision engine is the core security brain of the system. It sits between the Router (risk classification) and the output layer (OutputBuffer / AlertQueue), evaluating each request against a set of ordered rules and producing a final decision: ALLOW, AUDIT, ALERT, BLOCK, or more severe actions.

The engine follows a **first-match-wins** strategy: rules are evaluated in severity order, and the first matching rule determines the decision. This is equivalent to "match all, take strictest" when rules are properly ordered by severity, but with better performance (O(n) worst case) and simpler debugging.

---

## 2. Participating Modules

The decision engine does not work in isolation. Five modules feed data into it:

```
                    +-------------------+
                    |  Decision Engine  |
                    +--------+----------+
                             |
          +------------------+------------------+
          |                  |                  |
    +-----+------+   +------+------+   +------+------+
    | Connection |   |  Portrait   |   |   Router   |
    | Context    |   |  Store      |   | (Risk Lvl) |
    +-----+------+   +------+------+   +------+-----+
          |                  |                  |
    Events[]           UserProfile        RiskLevel
    EventCounts()      GetHistory()       L0/L1/L2/L3
    WriteRatio()       RiskScore()
    TriggeredFlags
          |                  |                  |
    +-----+------------------+------------------+-----+
    |                                                |
    |  +--------------+  +-------------------+      |
    |  | Fingerprint  |  | CrossDevice       |      |
    |  | Tree         |  | Correlator        |      |
    |  +--------------+  +-------------------+      |
    |  (pre-check,     (future: device               |
    |   not in rules)   sharing risk)               |
    +------------------------------------------------+
```

### 2.1 ConnectionContext (real-time per-connection)

Source: `types.ConnectionContext`

Each proxy connection maintains a live context recording every event (API call) in chronological order. The engine reads:

| Field | Usage | Rules |
|-------|-------|-------|
| Events[] | Raw event list with timestamps | R06, R08, R09, R10 |
| EventCounts() | Aggregated op counts | R07 |
| WriteRatio() | Write ops / total ops | R10 |
| TriggeredFlags | Flags set during this connection | (future use) |

This is the **real-time signal** -- it captures what is happening RIGHT NOW.

### 2.2 Portrait Store (historical)

Source: `portrait.Store`

The portrait store provides two types of historical data:

**ConnectionSummary** (per-connection snapshots):

| Field | Usage | Rules |
|-------|-------|-------|
| EventCounts | Delete counts across past connections | R03 |
| FlagsTriggered | Which rules fired in past connections | R02 |
| OffHoursWrites | Off-hours write count | (profile aggregation) |

**UserProfile** (aggregated lifetime stats):

| Field | Usage | Rules |
|-------|-------|-------|
| RiskScore() | Composite risk score (0.0-1.0) | R04 |
| TotalConnections | How experienced this user is | R05 |
| KnownDevices | Devices this user has used | R05 |
| AlertCount | How many past connections alerted | (profile aggregation) |
| UniqueDevices | Device diversity | (RiskScore component) |

This is the **historical signal** -- it captures who this user HAS BEEN.

### 2.3 Router (static risk level)

Source: `router.Classify()` -> RiskLevel

The Router assigns a static risk level based on HTTP method + path, before the engine even runs:

| Level | Trigger | Engine behavior |
|-------|---------|-----------------|
| L0 | GET operations | Engine skipped, direct ALLOW |
| L1 | POST/PUT/PATCH | Engine runs, fallback -> AUDIT |
| L2 | DELETE | Engine runs, fallback -> ALERT |
| L3 | Reserved | Engine runs, fallback -> BLOCK |

The risk level is a **coarse filter** that determines the baseline severity before behavioral analysis kicks in.

### 2.4 Fingerprint Tree (pre-check, not in rules)

The fingerprint tree runs BEFORE the decision engine in the gRPC handler. If fingerprint does not match, the request is immediately BLOCKED -- the engine never sees it. This is a hard gate, not a rule.

### 2.5 CrossDevice Correlator (future)

The `crossdevice.Correlator` interface is defined but not yet wired into rules. When integrated, it will provide:

- `Correlate(userID)` -> list of devices this user has used
- `RiskScore(deviceUUID, history)` -> cross-device risk assessment

This will enable rules like "same device used by 3+ users" or "user suddenly on a device historically associated with a different user".

---

## 3. Rule Evaluation Model

### 3.1 Evaluation Order

Rules are sorted by **severity** (most severe first). First match wins:

```
R01  BLACKLIST_DEVICE  (hard block, highest priority)
R02  BLACKLIST_DEVICE  (repeat offender)
R03  BLACKLIST_DEVICE  (historical heavy delete)
R04  ALERT            (portrait high risk score)
R05  ALERT            (new device anomaly)
R06  BLOCK_LOGIN      (brute force)
R07  BLOCK_DEVICE     (bulk delete)
R08  QUARANTINE       (upload + start)
R09  ALERT            (off-hours write)
R10  ALERT            (high write ratio)
R99  ALLOW/ALERT/BLOCK (static risk fallback)
```

### 3.2 Why First-Match-Wins

Two possible strategies:

| Strategy | Pros | Cons |
|----------|------|------|
| First-match-wins | O(n) performance, deterministic, easy to debug | Loses context of other matching rules |
| Match-all-strictest | Catches all triggers, no ordering dependency | O(n) always (must scan all), needs priority ranking anyway |

In our design, rules have a natural progression:

- If a device is blacklisted (R01), there is no need to check if it did 5 deletes (R07)
- If a user triggered alerts 3 times in a row (R02), there is no need to check write ratio (R10)

This progression structure means first-match-wins is **equivalent** to match-all-strictest, but faster. If future rules break this progression (e.g., two independent ALERT triggers), we can switch to match-all-strictest by changing only the Engine evaluation function.

### 3.3 Rule Categories

| Category | Rules | Signal Source | Action Severity |
|----------|-------|---------------|------------------|
| Identity | R01 | Fingerprint tree (blacklist) | BLACKLIST (permanent) |
| Historical Pattern | R02, R03, R04, R05 | Portrait Store | BLACKLIST / ALERT |
| Current Session | R06, R07, R08, R09, R10 | ConnectionContext | BLOCK / ALERT |
| Fallback | R99 | Router RiskLevel | Varies by level |

---

## 4. Portrait Risk Score: Weight Model

### 4.1 Scoring Formula

The `UserProfile.RiskScore()` computes a composite score from 0.0 (perfect) to 1.0 (maximum risk):

```
Score = alert_frequency  * 0.40
      + write_ratio      * 0.20
      + device_diversity * 0.20
      + off_hours_ratio  * 0.20

Clamped to [0.0, 1.0]
```

### 4.2 Weight Rationale

| Component | Weight | Why |
|-----------|--------|-----|
| Alert frequency | 40% | Strongest signal: if a user triggered alerts in many past connections, they are almost certainly a threat. This is direct evidence of malicious behavior, not circumstantial. |
| Write ratio | 20% | Moderate signal: high write ratio means the user is modifying data rather than reading it. Normal users read 80%+ of the time. Write-heavy patterns suggest data destruction or exfiltration. Weighted lower than alerts because some legitimate workflows (backups, migrations) are write-heavy. |
| Device diversity | 20% | Moderate signal: a user accessing from 4+ devices is unusual. Could indicate credential sharing, account compromise, or multi-device legitimate use. Weighted same as write ratio because the signal is ambiguous without context. |
| Off-hours ratio | 20% | Weak-to-moderate signal: working at 2AM is suspicious but not proof of malice. Different time zones, on-call rotations, and deadline crunches create legitimate off-hours activity. Weighted lowest because false positive rate is highest. |

### 4.3 Why These Weights (not equal)

The key insight is **signal reliability**:

- Alert history is a **direct** indicator of past malicious behavior (the system already decided something was wrong)
- Write ratio and device diversity are **circumstantial** indicators (could be legitimate)
- Off-hours is **contextual** (depends on timezone, role, deadlines)

If all weights were equal (25% each), a user who simply works late (off-hours=true) and uses two devices would score 0.45 -- almost triggering the 0.7 threshold -- even with zero alerts. That would produce too many false positives.

With the current weighting, the same user (no alerts, 2 devices, off-hours, normal write ratio) scores:

```
0.0 * 0.40 + 0.2 * 0.20 + 0.1 * 0.20 + 1.0 * 0.20 = 0.26
```

Well below the 0.7 threshold. Only users with actual alert history can accumulate enough score to trigger R04.

### 4.4 Threshold Selection (0.7)

The 0.7 threshold is chosen to balance:

| Threshold | False Positive Rate | False Negative Rate |
|-----------|--------------------|--------------------|
| 0.5 | High (legitimate multi-device users trigger) | Low |
| 0.7 | Moderate (only users with multiple bad signals trigger) | Moderate |
| 0.9 | Low (only extreme cases trigger) | High (misses subtle threats) |

0.7 means a user needs at least 2 out of 4 risk components to be significantly elevated. For example:

- 100% alert history (0.4) + 80% write ratio (0.16) = 0.56 -> no trigger
- 100% alert history (0.4) + 80% write (0.16) + 3 devices (0.2) = 0.76 -> ALERT
- 50% alert history (0.2) + 100% write (0.2) + 4 devices (0.2) + 100% off-hours (0.2) = 0.8 -> ALERT

This ensures the system does not panic over single anomalies but does escalate when multiple signals converge.

---

## 5. Decision Actions: Trade-off Analysis

### 5.1 Action Ladder

Actions are ordered by severity (least to most disruptive):

```
ALLOW          -> Request forwarded, no logging overhead
AUDIT          -> Request forwarded + detailed log (L1 baseline)
ALERT          -> Request forwarded + alert pushed to admin
THROTTLE       -> Request forwarded with delay
BLOCK          -> Request rejected, user notified
BLOCK_LOGIN    -> Login rejected, auto-release after 10min
BLOCK_DEVICE   -> All requests from device rejected
BLOCK_WRITE_OPS -> Only writes blocked, reads allowed
REQUIRE_2FA    -> Request held pending second factor
QUARANTINE     -> Image quarantined, CICD scan triggered
BLACKLIST_DEVICE -> Permanent block + lock account + alert
```

### 5.2 Security vs. Availability Trade-off

Every decision is a trade-off between two risks:

| Risk | Cost | Mitigated by |
|------|------|-------------|
| False Positive (block legitimate) | Business disruption, user frustration, support tickets | Higher thresholds, softer actions (AUDIT/ALERT before BLOCK) |
| False Negative (allow malicious) | Data breach, infrastructure compromise, compliance violation | Lower thresholds, harder actions, layered defense |

Thresholds strategy: **fail open for low-risk, fail closed for high-risk**

| Scenario | Strategy | Rationale |
|----------|----------|-----------|
| L0 (GET reads) | Always ALLOW | Reading public data is safe; blocking disrupts normal workflow |
| L1 (writes) | AUDIT baseline | Log for forensics, but allow business to continue |
| L2 (DELETE) | ALERT baseline | Actively notify admins, but do not block (could be legitimate cleanup) |
| Portrait high risk | ALERT | User is suspicious but not confirmed malicious; alert for human review |
| Repeat offender | BLACKLIST_DEVICE | Pattern is clear; blocking is justified to prevent further damage |
| Blacklisted device | BLACKLIST_DEVICE | Already confirmed; zero tolerance |

### 5.3 Why ALERT (not BLOCK) for R04/R05

The new portrait-based rules (R04, R05) use ALERT rather than BLOCK because:

1. **Composite scores can be wrong**: The risk score is a heuristic. A legitimate power user with 2 devices who works late could accumulate enough score to trigger. BLOCK would disrupt their work.

2. **Human-in-the-loop**: ALERT pushes a notification to the admin console. The admin can investigate and manually blacklist if needed.

3. **Escalation path**: If a user triggers ALERT multiple times, R02 (repeat offender) will eventually catch them and escalate to BLACKLIST. The system self-corrects over time.

4. **False positive cost**: For a cloud platform, blocking a legitimate user means they cannot manage their VMs/images. This can cascade into production outages. ALERT has zero operational impact on the user.

### 5.4 Why BLACKLIST for R02/R03

These rules escalate from ALERT to BLACKLIST because the signal is strong:

- R02: 3 consecutive connections ALL triggered alerts. This is not a one-time anomaly; it is a persistent pattern. The probability of 3 consecutive false positives is (FPR)^3, which is very low.

- R03: Cumulative delete count > 10 across 5 connections. This indicates sustained destructive behavior, not a single accident.

The escalation from ALERT (single incident) to BLACKLIST (repeated pattern) mirrors how SOC analysts work: first investigate, then block if confirmed.

---

## 6. Static Risk Fallback (R99)

When no behavioral rule matches, the engine falls back to the Router-assigned risk level:

| Risk Level | Fallback Action | Rationale |
|------------|-----------------|------------|
| L0 | ALLOW | GET operations are safe by definition |
| L1 | AUDIT | Write operations should be logged for forensics |
| L2 | ALERT | DELETE operations warrant admin notification |
| L3 | BLOCK | Reserved for future high-risk operations |

This ensures that even without behavioral analysis, the system has a reasonable baseline. The engine enhances this baseline with behavioral signals when available.

---

## 7. Data Flow: End-to-End Decision Path

```
Client request arrives via gRPC
    |
    v
Fingerprint Check (pre-gate)
    |-- mismatch -> BLOCKED (engine never runs)
    |-- match -> continue
    |
    v
Record event in ConnectionContext
    |
    v
Router.Classify() -> RiskLevel (L0/L1/L2/L3)
    |-- L0 -> ALLOW (engine skipped)
    |-- L1+ -> continue
    |
    v
Portrait.GetHistory(userID, 20) -> []*ConnectionSummary
    |
    v
Engine.Evaluate(ctx, history, riskLevel)
    |
    |-- R01: blacklisted? -> BLACKLIST_DEVICE
    |-- R02: 3x repeat alerts? -> BLACKLIST_DEVICE
    |-- R03: 5-conns delete>10? -> BLACKLIST_DEVICE
    |-- R04: risk_score>0.7? -> ALERT
    |-- R05: new device? -> ALERT
    |-- R06: 5x login_failed? -> BLOCK_LOGIN
    |-- R07: 3x delete? -> BLOCK_DEVICE
    |-- R08: upload+start? -> QUARANTINE
    |-- R09: off-hours write? -> ALERT
    |-- R10: write_ratio>80%? -> ALERT
    |-- R99: fallback by risk level
    |
    v
Action Router:
    |-- ALLOW/AUDIT -> OutputBuffer
    |-- ALERT/BLOCK/BLACKLIST -> AlertQueue
    |
    v
Response sent to client
    |
    v
CloseConnection -> OnConnectionClose
    |-- Extract ConnectionSummary
    |-- Append to portrait history
    |-- Update UserProfile aggregation
```

---

## 8. Limitations and Future Improvements

| Limitation | Impact | Future Solution |
|------------|--------|------------------|
| Weights are hardcoded | Cannot tune without code change | Extract to YAML config with hot-reload |
| Threshold 0.7 is static | No per-user or per-role tuning | Adaptive thresholds based on user role (admin vs. regular) |
| RiskScore is linear | Cannot capture non-linear patterns | ML model or decision tree (Phase 2) |
| No temporal decay | Old alerts count the same as recent ones | Exponential decay: recent connections weighted higher |
| No cross-user signals | Cannot detect coordinated attacks | Cross-device correlator integration |
| ConnectionContext is in-memory | Lost on server restart | WAL persistence on CloseConnection (planned) |

---

## 9. Testing Strategy

Each rule has dedicated unit tests verifying:

1. **Condition accuracy**: Correct input triggers the rule
2. **Threshold boundaries**: Just-below does not trigger, just-above does
3. **Action correctness**: Rule produces the expected action type
4. **Integration with DispatchManager**: Rules work correctly in the async Worker pipeline

The `OverflowPreservesDecision` test specifically validates that a task going through the full cold path (memory -> bbolt -> reload -> Worker) produces the same decision as the hot path (memory only).

---

See also: `dispatch.md` for DispatchManager module details, `progress.md` for current development status.
