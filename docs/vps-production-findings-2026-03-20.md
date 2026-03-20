# VPS Production Findings — 2026-03-20

Follow-up to the [2026-03-19 report](vps-production-findings-2026-03-19.md). Same VPS
(`root@vps`, 87.106.8.245), same backbone gateway config on port 4242 with
`max_connections = 128`.

Binary version: `rnsd 0.2.183-f1ab29d` (unchanged since Run 5).

Service was restarted at **2026-03-17 23:26 UTC** (clean stop/start).
Uptime at time of investigation: **~45 hours**.

---

## 1. Service state

| Service | Status | PID | Memory | Peak | CPU |
|---------|--------|-----|--------|------|-----|
| `rnsd` | running | 4137793 | **564.8 MB** | 625.0 MB | 1h 40min |
| `rns-statsd` | running | 4137867 | 30.5 MB | 37.1 MB | 12min |

System (1.8 GB RAM, no swap):
- Memory: 903 MB used, 930 MB available
- Load average: **0.08** / 0.07 / 0.02
- Disk: 11 GB / 77 GB used (15%)
- FDs in use: **121** / 65536

Outbound interface issues:
- **RNS Germany 002** was failing reconnects at ~16:30 UTC (connection refused,
  every 5 seconds). Same pattern as the Mar 19 transient disruption but more
  sustained this time.

---

## 2. Connection landscape

### 2.1 Snapshot at ~17:33 UTC (before blacklist event)

**134 TCP connections** on port 4242, 51 unique IPs.

One peer dominated the pool:

| Connections | IP | Share |
|-------------|-----|-------|
| 74 | `95.81.119.72` | **57.8%** |
| 2 | `5.227.44.203` | 1.6% |
| 2 | `46.229.97.147` | 1.6% |
| 2 | `176.15.249.74` | 1.6% |
| 2 | `136.143.158.161` | 1.6% |
| 2 | `115.186.194.233` | 1.6% |

The remaining 45 peers held 1 connection each.

### 2.2 Snapshot at ~17:50 UTC (after blacklist event)

`95.81.119.72` was blacklisted for repeated idle timeouts. Connections dropped
to **59 TCP connections**, 52 unique IPs. The blacklist mechanism worked as
designed — connection count immediately halved.

Top peers after the event:

| Connections | IP |
|-------------|-----|
| 3 | `91.197.107.180` |
| 2 | `94.252.94.198` |
| 2 | `5.180.82.160` |
| 2 | `176.15.249.74` |
| 2 | `136.143.158.161` |

No single peer holds more than 5% of the pool after the blacklist fired.

### 2.3 Connection health

| Metric | Run 5 (42h) | **Run 6 (45h)** | Change |
|--------|------------|-----------------|--------|
| TCP connections | 74 | **59–134** | Variable (see 2.1/2.2) |
| Max-conn rejections | 0 | **0** | Clean |
| EAGAIN write errors | 0 | **0** | Clean |
| Top peer slot share | 10.2% (13/128) | **57.8% → 5.1%** | Blacklist corrected |
| Blacklist events | 9,928 (~236/h) | **12,032 (~267/h)** | Comparable |

The `95.81.119.72` situation shows that a single peer can still accumulate many
connections before the idle-timeout blacklist fires. The peer first appeared on
2026-03-18 08:34 UTC and built up to 74 connections over ~33 hours before being
blacklisted. The connection-count-based blacklist (flap detection) did not
trigger because the connections were individually long-lived, not rapid
reconnects.

---

## 3. Memory analysis

### 3.1 Growth trajectory

| Time since restart | Memory (RSS) | Peak |
|--------------------|-------------|------|
| 0h (fresh start) | ~5 MB | — |
| 42h (Run 5) | 544.1 MB | 582.3 MB |
| **45h (now)** | **564.8 MB** | **625.0 MB** |

Growth since Run 5: ~20.7 MB in ~3 hours (~6.9 MB/h). The overall average
remains ~12.4 MB/h. At this rate, the process will reach ~1 GB in roughly
**~35 hours** (~80h total uptime).

The peak of 625 MB (60 MB above current RSS) suggests occasional memory spikes,
possibly from announce processing bursts or the `95.81.119.72` connection flood.

### 3.2 Root cause analysis

Code review identifies three unbounded or weakly-bounded structures responsible
for the remaining memory growth:

**1. `known_destinations`** (`BTreeMap<[u8; 16], AnnouncedIdentity>` in
`rns-net/src/driver.rs:386`)
- Has periodic cleanup with 48-hour TTL, but **no hard cap**
- Each entry is ~120+ bytes (16-byte key + 64-byte pubkey + variable `app_data:
  Option<Vec<u8>>`)
- On a busy gateway seeing the entire network, this accumulates every unique
  destination hash seen in the last 2 days
- **Likely the dominant contributor** to the ~12 MB/h growth

**2. `announce_table`** (`BTreeMap<[u8; 16], AnnounceEntry>` in
`rns-core/src/transport/mod.rs:52`)
- Entries carry three `Vec<u8>` blobs: `packet_raw`, `packet_data`, and
  indirectly `announce_raw`
- Entries are only removed when retry budget is exhausted — **no time-based
  expiry**
- If retransmit cycles stall, entries persist indefinitely

**3. `blackholed_identities`** (`BTreeMap<[u8; 16], BlackholeEntry>` in
`rns-core/src/transport/mod.rs:61`)
- Entries created with `duration_hours = None` get `expires = 0.0` (permanent)
- `cull_blackholed()` retains permanent entries forever
- Carries unbounded `reason: Option<String>` per entry
- Lower impact than the above two, but still unbounded

Already resolved in prior runs:
- **Packet dedup hashlist** — bounded FIFO (250K entries, ~12-15 MB)
- **Rate limiter** — 48h TTL cleanup (mirrors `known_destinations`)

---

## 4. Blacklist behavior

**12,032** blacklist log lines over ~45 hours (~267/hour).

Breakdown by reason:
| Count | Reason |
|-------|--------|
| 11,437 | idle timeouts |
| 350 | churn (rapid reconnect) |

Comparable to Run 5's ~236/h. The rapid-reconnector flooding remains resolved;
the idle timeout blacklist is the primary mechanism in use.

Notable: `95.81.119.72` was the most impactful blacklist event this run,
accumulating 74 connections before being caught.

---

## 5. Stats collection

### 5.1 Stats DB

Size: **82 MB** after ~45 hours (~1.8 MB/hour, ~43 MB/day).

Slightly higher rate than Run 5's ~1.6 MB/h, possibly due to the connection
churn from the dominant peer.

### 5.2 Event drops

**107,917** drop log lines over ~45 hours (~2,398/hour). Recent logs show small
bursts (1–4 events per line) rather than the large spikes (up to 438) seen in
Run 5.

| Metric | Run 4 (12h) | Run 5 (42h) | **Run 6 (45h)** |
|--------|------------|------------|-----------------|
| Drop log lines | ~19K | 91,716 | **107,917** |
| Drop rate | ~1,580/h | ~2,184/h | **~2,398/h** |

The provider bridge channel is still being overwhelmed. Per-hour rate is slowly
trending up.

---

## 6. Announce cache (disk)

| Metric | Run 5 (42h) | **Run 6 (45h)** |
|--------|------------|-----------------|
| Files | 7,406 | **3,891** |
| Size | 282 MB | **16 MB** |

The announce cache has dropped dramatically — from 282 MB to 16 MB. The batched
cleanup from commit `b446325` continues to actively prune the cache. At 3,891
files / 16 MB, the cache is well under control.

---

## 7. Comparison across all runs

| Metric | Run 1 (Mar 14, 2d) | Run 2 (Mar 15, 14h) | Run 3 (Mar 16, 17h) | Run 4 (Mar 17, 12h) | Run 5 (Mar 19, 42h) | **Run 6 (Mar 20, 45h)** |
|--------|--------------------|--------------------|---------------------|---------------------|---------------------|------------------------|
| Binary version | — | — | — | `0.1.175-f96ef5d` | `0.2.183-f1ab29d` | **`0.2.183-f1ab29d`** |
| max_connections | none | none | 128 | 128 | 128 | **128** |
| LimitNOFILE | 1024 | 1024 | 65536 | 65536 | 65536 | **65536** |
| Blacklist | none | none | none | enabled | enabled | **enabled** |
| Cache cleanup | none | none | none | none | enabled (batched) | **enabled (batched)** |
| TCP connections | 138 | 278 (fd exhaust) | 128 (capped) | 75 | 74 | **59–134** (variable) |
| Max-conn rejections | — | — | 172,538 | 0 | 0 | **0** |
| Blacklist events | — | — | — | 340,637 (28K/h) | 9,928 (236/h) | **12,032 (267/h)** |
| EAGAIN errors | — | — | 526,807 | 7 | 0 | **0** |
| Memory (at check) | 400 MB (2d) | 673 MB (14h) | 468 MB (17h) | 408 MB (12h) | 544 MB (42h) | **565 MB (45h)** |
| Memory rate | ~8 MB/h | ~48 MB/h | ~27 MB/h | ~33 MB/h | ~13 MB/h | **~12.4 MB/h** |
| FDs in use | ~150 | 1023/1024 | 271 | 109 | 126 | **121** |
| Load average | — | 4.41 | 3.50 | 0.04 | 0.19 | **0.08** |
| Announce cache files | — | — | — | 10,330 | 7,406 | **3,891** |
| Announce cache size | — | — | — | 294 MB | 282 MB | **16 MB** |
| Stats DB | — | 44 MB (17h) | 17 MB (17h) | 31 MB (12h) | 67 MB (42h) | **82 MB (45h)** |
| Stats DB rate | — | ~2.6 MB/h | ~1.0 MB/h | ~2.6 MB/h | ~1.6 MB/h | **~1.8 MB/h** |
| Statsd drop lines | — | 237,655 | 147,545 | ~19K (12h) | 91,716 (42h) | **107,917 (45h)** |

---

## 8. Issues status

### Resolved

- **FD exhaustion** — resolved by `LimitNOFILE=65536` (Run 2)
- **Unbounded connections** — resolved by `max_connections = 128` (Run 3)
- **Connection slot monopolization** — resolved by blacklist (Run 4)
- **Write-stalled peers (EAGAIN)** — resolved by idle timeout blacklist (Run 4)
- **Rapid reconnector flooding** — resolved by flap blacklist (Run 4); confirmed
  stable across Run 5 and Run 6
- **Announce cache disk bloat** — resolved by batched cleanup (Run 5); cache now
  at 16 MB / 3,891 files (Run 6), down from 294 MB peak

### Improved but still open

- **Memory growth** — stable at ~12.4 MB/h (down from ~33 MB/h in Run 4).
  Code review identifies `known_destinations` (no hard cap, 48h TTL),
  `announce_table` (no TTL at all), and `blackholed_identities` (permanent
  entries never expire) as the remaining unbounded structures. Next step: add
  a hard cap or LRU eviction to `known_destinations`; add a TTL to
  `announce_table` entries.

### New observations

- **Slow-accumulator peers** — `95.81.119.72` built up 74 connections (58% of
  the pool) over ~33 hours before the idle-timeout blacklist fired. The
  existing blacklist mechanisms (flap detection and idle timeout) do not catch
  peers that hold many long-lived but eventually idle connections. A
  per-IP connection limit or a connection-count threshold would address this
  gap.

### Still open

- **Statsd provider bridge saturation** — ~2,398 drop lines/hour, trending
  slightly up from Run 5. Channel capacity or drain speed may need tuning.

- **Stats DB retention policy** — ~43 MB/day, ~1.3 GB/month. Manageable but a
  vacuum/retention policy would be prudent.

- **Outbound peer connectivity** — RNS Germany 002 experiencing sustained
  reconnect failures (~16:30 UTC). May warrant backoff logic or alerting.
