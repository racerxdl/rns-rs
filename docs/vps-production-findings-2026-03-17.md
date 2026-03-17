# VPS Production Findings — 2026-03-17

Follow-up to the [2026-03-16 report](vps-production-findings-2026-03-16.md). Same VPS
(`root@vps`, 87.106.8.245), same backbone gateway config on port 4242 with
`max_connections = 128`.

Binary version: `rnsd 0.1.175-f96ef5d` (includes blacklist feature from commit `f96ef5d`).

Service was restarted at **2026-03-16 20:28 UTC** (clean stop/start, not a crash).
Uptime at time of investigation: **~12 hours**.

---

## 1. Service state

| Service | Status | PID | Memory | Peak | CPU |
|---------|--------|-----|--------|------|-----|
| `rnsd` | running | 4107311 | **407.6 MB** | 419.7 MB | 14m 24s |
| `rns-statsd` | running | 4107327 | 12.8 MB | 17.8 MB | 1m 37s |

System (1.8 GB RAM, no swap):
- Memory: 756 MB used, 1.1 GB available
- Load average: **0.04** / 0.31 / 0.29
- Disk: 9.8 GB / 77 GB used (13%)
- FDs in use: **109** / 65536

Two outbound interfaces failed at startup:
- **Bern** (`BackboneInterface` client): connection timed out
- **Triplebit Minneapolis** (`BackboneInterface` client): connection refused (os error 111)

---

## 2. New feature: peer blacklisting

This run includes the peer blacklist feature (commit `f96ef5d`), configured as:

```toml
blacklist_duration = 900              # 15-minute ban
idle_timeout_blacklist_threshold = 3  # blacklist after 3 idle timeouts
idle_timeout_blacklist_window = 600   # within a 10-minute window
flap_blacklist_threshold = 12         # blacklist after 12 connect/disconnect flaps
flap_blacklist_window = 300           # within a 5-minute window
```

### 2.1 Impact

The blacklist is the single biggest improvement across all runs. It addresses
the connection flooding, write-stall, and slot monopolization problems
identified in previous reports — all at once.

**340,637** blacklist rejections in 12 hours (~28K/hour). The aggressive peers
that previously saturated the connection pool are now being banned before they
can cause damage.

Top blacklisted IPs (sampled from the last hour):

| Rejections | IP |
|------------|-----|
| 6,362 | `151.44.3.183` |
| 3,914 | `37.29.41.211` |
| 2,871 | `188.66.32.177` |
| 2,252 | `109.197.204.12` |
| 1,553 | `208.84.102.2` |
| 1,484 | `45.85.105.25` |
| 1,470 | `92.62.57.137` |
| 1,462 | `109.252.137.113` |
| 1,135 | `2.63.234.138` |
| 1,028 | `66.234.150.66` |

These are the same "silent leech" and "rapid reconnector" patterns from
previous reports, now being handled automatically.

### 2.2 Log noise concern

340K rejection lines in 12 hours is significant log noise. Consider
rate-limiting the blacklist rejection log messages (e.g., log once per IP per
minute with a count, rather than every rejected connection attempt).

---

## 3. Connection landscape

### 3.1 Current connections

**75 TCP connections** on port 4242 — well below the 128 cap. The blacklist is
keeping aggressive peers out, leaving ample room for legitimate clients.

Top peers by connection count:

| Connections | IP |
|-------------|-----|
| 11 | `5.142.41.204` |
| 6 | `2.63.234.138` |
| 3 | `188.66.32.177` |
| 3 | `128.71.58.198` |
| 2 | `213.87.128.255` |
| 2 | `128.71.47.58` |
| 2 | `115.186.194.233` |

54 unique IPs currently connected. No single peer is dominating — the worst
holds 11/128 slots (8.6%), down from 27% in Run 3.

### 3.2 Connection health

| Metric | Run 3 (17h) | **Run 4 (12h)** | Change |
|--------|------------|-----------------|--------|
| TCP connections | 128 (capped) | **75** | Healthy headroom |
| Max-conn rejections | 172,538 | **0** | Eliminated |
| EAGAIN write errors | 526,807 | **7** | ~99.999% reduction |
| Top peer slot share | 27% (34/128) | **8.6%** (11/128) | Much fairer |

The near-elimination of EAGAIN errors confirms that the write-stalled peers
identified in the 2026-03-16 report are being caught by the idle timeout
blacklist before their send buffers fill up.

---

## 4. Memory analysis

### 4.1 Growth trajectory

| Time since restart | Memory (RSS) | Peak |
|--------------------|-------------|------|
| 0h (fresh start) | ~5 MB | — |
| 12h (now) | **407.6 MB** | 419.7 MB |

Growth rate: **~33 MB/hour** — slightly worse than Run 3's ~27 MB/hour despite
fewer connections. This suggests the memory growth is dominated by the
unbounded data structures rather than per-connection overhead.

At 33 MB/hour, the process will reach ~1 GB in another **~18 hours** (roughly
2026-03-18 03:00 UTC), putting pressure on the 1.8 GB VPS.

### 4.2 Unbounded structures (still open)

These remain the primary memory consumers, unchanged from the 2026-03-14 report:

- **Packet dedup hashlist** (`BTreeSet<[u8; 32]>`, up to 1M entries) — estimated
  100-200 MB at capacity
- **`known_destinations`** (`HashMap<[u8; 16], AnnouncedIdentity>`) — never cleaned
- **Rate limiter table** (`BTreeMap<[u8; 16], RateEntry>`) — never cleaned

### 4.3 Announce cache (disk)

| Metric | Run 3 (17h) | Run 4 (12h) |
|--------|------------|-------------|
| Files | 6,819 | **10,330** |
| Size | 280 MB | **294 MB** |

Growing steadily. The underlying issue (no cleanup policy) remains.

---

## 5. Stats collection

### 5.1 Stats DB

Size: **31 MB** after 12 hours (~2.6 MB/hour, ~62 MB/day).

### 5.2 Event drops

**18,964** dropped events from the provider bridge over 12 hours. This is an
87% reduction from Run 3's 147,545 drops over 17 hours, likely because the
lighter and healthier connection pool generates fewer events overall.

The drops are still bursty (last logged batch showed repeated bursts of 3-6
events), indicating the channel is briefly overwhelmed during traffic spikes.

---

## 6. Comparison across all runs

| Metric | Run 1 (Mar 14, 2d) | Run 2 (Mar 15, 14h) | Run 3 (Mar 16, 17h) | **Run 4 (Mar 17, 12h)** |
|--------|--------------------|--------------------|---------------------|------------------------|
| max_connections | none | none | 128 | **128** |
| LimitNOFILE | 1024 | 1024 | 65536 | **65536** |
| Blacklist | none | none | none | **enabled** |
| TCP connections | 138 | 278 (fd exhaust) | 128 (capped) | **75** (healthy) |
| Max-conn rejections | — | — | 172,538 | **0** |
| Blacklist rejections | — | — | — | **340,637** |
| EAGAIN errors | — | — | 526,807 | **7** |
| Memory (at check) | 400 MB (2d) | 673 MB (14h) | 468 MB (17h) | **408 MB** (12h) |
| Memory rate | ~8 MB/h | ~48 MB/h | ~27 MB/h | **~33 MB/h** |
| FDs in use | ~150 | 1023/1024 | 271 | **109** |
| Load average | — | 4.41 | 3.50 | **0.04** |
| Stats DB | — | 44 MB (17h) | 17 MB (17h) | **31 MB** (12h) |
| Statsd drops | — | 237,655 | 147,545 | **18,964** |

---

## 7. Issues status

### Resolved

- **FD exhaustion** — resolved by `LimitNOFILE=65536` (Run 2)
- **Unbounded connections** — resolved by `max_connections = 128` (Run 3)
- **Connection slot monopolization** — resolved by blacklist (Run 4)
- **Write-stalled peers (EAGAIN)** — resolved by idle timeout blacklist (Run 4)
- **Rapid reconnector flooding** — resolved by flap blacklist (Run 4)

### Still open

- **Memory growth from unbounded structures** — ~33 MB/hour, will require
  restart within ~18 hours. This is the most pressing issue. Needs cleanup
  for `known_destinations`, rate limiter table, and possibly reducing dedup
  hashlist size or switching to `HashSet`.

- **Blacklist rejection log noise** — 340K lines in 12 hours. Should
  rate-limit the log messages per blacklisted IP.

- **Statsd provider bridge saturation** — 87% better but still dropping ~19K
  events in 12 hours. Channel capacity or drain speed may need tuning.

- **Stats DB retention policy** — ~62 MB/day, ~1.8 GB/month. Manageable but
  a vacuum/retention policy would be prudent.

- **Announce cache cleanup** — no cleanup policy, will grow indefinitely.
  Should be addressed alongside `known_destinations` TTL.

- **Outbound peer connectivity** — Bern (timeout) and Triplebit Minneapolis
  (connection refused) failed at startup. May be transient or may indicate
  those peers are down.
