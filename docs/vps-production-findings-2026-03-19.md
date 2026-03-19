# VPS Production Findings — 2026-03-19

Follow-up to the [2026-03-17 report](vps-production-findings-2026-03-17.md). Same VPS
(`root@vps`, 87.106.8.245), same backbone gateway config on port 4242 with
`max_connections = 128`.

Binary version: `rnsd 0.2.183-f1ab29d` (includes announce cache cleanup batching
from commit `b446325` and known_destinations/rate-limiter cleanup from `0db7805`).

Service was restarted at **2026-03-17 23:26 UTC** (clean stop/start, not a crash).
Uptime at time of investigation: **~42 hours**.

---

## 1. Service state

| Service | Status | PID | Memory | Peak | CPU |
|---------|--------|-----|--------|------|-----|
| `rnsd` | running | 4137793 | **544.1 MB** | 582.3 MB | 1h 9min |
| `rns-statsd` | running | 4137867 | 24.5 MB | 32.5 MB | 8m 21s |

System (1.8 GB RAM, no swap):
- Memory: 881 MB used, 951 MB available
- Load average: **0.19** / 0.44 / 0.44
- Disk: 11 GB / 77 GB used (14%)
- FDs in use: **126** / 65536

Two outbound interfaces failed at startup (same as Run 4):
- **Bern** (`BackboneInterface` client): connection timed out
- **Triplebit Minneapolis** (`BackboneInterface` client): connection refused (os error 111)

Additionally, both RNS Germany outbound links experienced a brief disruption on
2026-03-19 ~00:33 UTC (read timeout), with RNS Germany 002 also failing a reconnect
at ~09:55 UTC (connection refused). A total of 52 outbound connection error lines
across the full 42h run.

---

## 2. Connection landscape

### 2.1 Current connections

**74 TCP connections** on port 4242 — well below the 128 cap, with healthy headroom.

Top peers by connection count:

| Connections | IP |
|-------------|-----|
| 13 | `95.26.143.187` |
| 2 | `91.197.3.249` |
| 2 | `217.64.146.242` |
| 2 | `136.143.158.161` |
| 2 | `115.186.194.233` |

50 unique IPs currently connected. No single peer is dominating — the worst holds
13/128 slots (10.2%).

### 2.2 Connection health

| Metric | Run 4 (12h) | **Run 5 (42h)** | Change |
|--------|------------|-----------------|--------|
| TCP connections | 75 | **74** | Stable |
| Max-conn rejections | 0 | **0** | Clean |
| EAGAIN write errors | 7 | **0** | Eliminated |
| Top peer slot share | 8.6% (11/128) | **10.2%** (13/128) | Comparable |
| Blacklist events | 340,637 (28K/h) | **9,928 (~236/h)** | 99% reduction |

---

## 3. Memory analysis

### 3.1 Growth trajectory

| Time since restart | Memory (RSS) | Peak |
|--------------------|-------------|------|
| 0h (fresh start) | ~5 MB | — |
| 42h (now) | **544.1 MB** | 582.3 MB |

Growth rate: **~13 MB/hour** — a significant improvement over Run 4's ~33 MB/hour.
At this rate, the process will reach ~1 GB in another **~35 hours** (~77h total
uptime), giving roughly **3 days** between restarts on the 1.8 GB VPS.

### 3.2 Memory structures

**Resolved:**
- **Packet dedup hashlist** — rewritten in commit `78bd551` from a double-buffered
  `BTreeSet<[u8; 32]>` (1M entries, ~100-200 MB) to a bounded FIFO with custom
  hash table (250K entries, ~12-15 MB at capacity). This is likely the single
  biggest contributor to the reduced memory growth rate.

**Improved:**
- **`known_destinations`** (`HashMap<[u8; 16], AnnouncedIdentity>`) — now has periodic
  cleanup (commit `0db7805`), but still grows without a hard cap
- **Rate limiter table** (`BTreeMap<[u8; 16], RateEntry>`) — now has periodic cleanup

The combined effect of the dedup rewrite (`78bd551`) and the cleanup routines
(`0db7805`) cut memory growth from ~33 MB/h to ~13 MB/h. The remaining ~13 MB/h
growth is likely dominated by `known_destinations` and other per-peer state that
accumulates over time on a busy gateway.

### 3.3 Announce cache (disk)

| Metric | Run 4 (12h) | **Run 5 (42h)** |
|--------|------------|-----------------|
| Files | 10,330 | **7,406** |
| Size | 294 MB | **282 MB** |

The announce cache is **smaller** at 42 hours than it was at 12 hours in Run 4.
The batched cleanup introduced in commit `b446325` is working correctly — the cache
is being actively pruned without blocking the driver loop.

---

## 4. Blacklist behavior

**9,928** blacklist log lines over 42 hours (~236/hour). This is a **99% reduction**
from Run 4's ~28K/hour.

Recent blacklist activity is all idle-timeout-based, targeting a small set of peers:

| Peer | Reason |
|------|--------|
| `165.22.89.162` | repeated idle timeouts |
| `217.64.146.242` | repeated idle timeouts |
| `5.34.178.212` | repeated idle timeouts |
| `92.252.133.151` | repeated idle timeouts |

The rapid-reconnector flooding that dominated Run 4 is no longer present. The
remaining blacklist activity is low-volume and targeted.

---

## 5. Stats collection

### 5.1 Stats DB

Size: **67 MB** after 42 hours (~1.6 MB/hour, ~38 MB/day).

This is lower than Run 4's rate (~2.6 MB/hour), likely because the healthier
connection pool generates fewer events overall.

### 5.2 Event drops

**91,716** drop log lines over 42 hours (~2,184/hour). The drops remain bursty —
recent samples show bursts ranging from 2 to 438 events in a single log line.

| Metric | Run 3 (17h) | Run 4 (12h) | **Run 5 (42h)** |
|--------|------------|------------|-----------------|
| Drop log lines | — | ~19K (12h) | **91,716** (42h) |
| Drop rate | ~8,679/h | ~1,580/h | **~2,184/h** |

The per-hour rate is comparable to Run 4. The provider bridge channel is still
being overwhelmed during traffic spikes, though the baseline is much healthier
than Run 3.

---

## 6. Comparison across all runs

| Metric | Run 1 (Mar 14, 2d) | Run 2 (Mar 15, 14h) | Run 3 (Mar 16, 17h) | Run 4 (Mar 17, 12h) | **Run 5 (Mar 19, 42h)** |
|--------|--------------------|--------------------|---------------------|---------------------|------------------------|
| Binary version | — | — | — | `0.1.175-f96ef5d` | **`0.2.183-f1ab29d`** |
| max_connections | none | none | 128 | 128 | **128** |
| LimitNOFILE | 1024 | 1024 | 65536 | 65536 | **65536** |
| Blacklist | none | none | none | enabled | **enabled** |
| Cache cleanup | none | none | none | none | **enabled (batched)** |
| TCP connections | 138 | 278 (fd exhaust) | 128 (capped) | 75 | **74** (stable) |
| Max-conn rejections | — | — | 172,538 | 0 | **0** |
| Blacklist events | — | — | — | 340,637 (28K/h) | **9,928 (236/h)** |
| EAGAIN errors | — | — | 526,807 | 7 | **0** |
| Memory (at check) | 400 MB (2d) | 673 MB (14h) | 468 MB (17h) | 408 MB (12h) | **544 MB (42h)** |
| Memory rate | ~8 MB/h | ~48 MB/h | ~27 MB/h | ~33 MB/h | **~13 MB/h** |
| FDs in use | ~150 | 1023/1024 | 271 | 109 | **126** |
| Load average | — | 4.41 | 3.50 | 0.04 | **0.19** |
| Announce cache files | — | — | — | 10,330 | **7,406** |
| Announce cache size | — | — | — | 294 MB | **282 MB** |
| Stats DB | — | 44 MB (17h) | 17 MB (17h) | 31 MB (12h) | **67 MB (42h)** |
| Stats DB rate | — | ~2.6 MB/h | ~1.0 MB/h | ~2.6 MB/h | **~1.6 MB/h** |
| Statsd drop lines | — | 237,655 | 147,545 | ~19K (12h) | **91,716 (42h)** |

---

## 7. Issues status

### Resolved

- **FD exhaustion** — resolved by `LimitNOFILE=65536` (Run 2)
- **Unbounded connections** — resolved by `max_connections = 128` (Run 3)
- **Connection slot monopolization** — resolved by blacklist (Run 4)
- **Write-stalled peers (EAGAIN)** — resolved by idle timeout blacklist (Run 4)
- **Rapid reconnector flooding** — resolved by flap blacklist (Run 4); Run 5 confirms
  the problem is gone (99% reduction in blacklist events)
- **Announce cache disk bloat** — resolved by batched cleanup (Run 5); cache is
  actively shrinking

### Improved but still open

- **Memory growth** — improved from ~33 MB/h to ~13 MB/h thanks to the dedup
  hashlist rewrite (`78bd551`) and periodic cleanup of `known_destinations` and
  rate limiter (`0db7805`). Still unbounded, requiring restart every ~3 days.
  The remaining growth is likely from `known_destinations` and other per-peer
  state accumulating on a busy gateway. Next step: add a hard cap or TTL to
  `known_destinations`.

### Still open

- **Statsd provider bridge saturation** — ~2,184 drop lines/hour with bursts up to
  438 events. Channel capacity or drain speed may need tuning.

- **Stats DB retention policy** — ~38 MB/day, ~1.1 GB/month. Manageable but a
  vacuum/retention policy would be prudent.

- **Outbound peer connectivity** — Bern and Triplebit Minneapolis failed at startup.
  Both Germany links experienced a transient disruption (~00:33 UTC Mar 19).
  May warrant reconnect logic or monitoring.
