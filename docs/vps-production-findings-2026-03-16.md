# VPS Production Findings — 2026-03-16

Follow-up to the [2026-03-15 report](vps-production-findings-2026-03-15.md). Same VPS
(`root@vps`, 87.106.8.245), same backbone gateway config on port 4242 with
`max_connections = 128`.

Uptime at time of investigation: **~17 hours** (since 2026-03-15 15:21 UTC restart).

---

## 1. Service state

| Service | Status | PID | Memory | Peak | CPU |
|---------|--------|-----|--------|------|-----|
| `rnsd` | running | 4079336 | **467.6 MB** | 517.9 MB | 21m 58s |
| `rns-statsd` | running | 4080125 | 14.3 MB | 18.8 MB | 3m 5s |

System (1.8 GB RAM, no swap):
- Memory: 838 MB used, 994 MB available (buff/cache accounts for the difference)
- Load average: **3.50** / 1.40 / 0.52
- Disk: 9.6 GB / 77 GB used (13%)

---

## 2. Connection landscape

### 2.1 Current connections

**128 TCP connections** on port 4242 — at the configured maximum. New connections
are being actively rejected.

Top peers by connection count:

| Connections | IP | Notes |
|-------------|-----|-------|
| **34** | `85.26.186.21` | New top offender — 27% of all slots |
| 12 | `85.140.1.88` | |
| 11 | `213.87.130.143` | |
| 5 | `87.249.237.46` | |
| 5 | `176.195.38.147` | Was rejected frequently on 2026-03-15, now has slots |
| 4 | `83.149.46.186` | |
| 4 | `80.13.172.26` | |
| 4 | `66.234.150.50` | |
| 4 | `151.46.68.147` | |
| 3 | `94.251.98.232` | |

The previous top offender (`79.112.78.160`, 126 connections on 2026-03-15) is no
longer present. The "silent leech" pattern continues with different IPs.

### 2.2 Connection churn

- **193 unique IPs** connected over the 17-hour period
- Interface ID counter reached **12,228** — averaging ~720 connect/disconnect
  cycles per hour
- **172,538** max-connection rejection log lines

### 2.3 Send failures

**526,807** `Resource temporarily unavailable (os error 11)` warnings — `EAGAIN`
on non-blocking TCP sends. Three interfaces are consistently failing:

- Interface `12050`
- Interface `12056`
- Interface `12058`

These are likely stalled or very slow peers whose kernel send buffers are
permanently full. The node keeps trying to forward packets to them and hitting
`EAGAIN` every time. This is a significant source of log noise and wasted CPU
(~31K failures/hour).

**New issue identified**: There is no mechanism to detect and disconnect peers
with persistently full send buffers. A "write stall timeout" would address this —
if a peer's send buffer has been full for N consecutive seconds, disconnect them
and free the slot for a healthier client.

---

## 3. Memory analysis

### 3.1 Growth trajectory

| Time since restart | Memory (RSS) | Peak |
|--------------------|-------------|------|
| 0h (fresh start) | 4.7 MB | — |
| 17h (now) | **467.6 MB** | 517.9 MB |

This is slower growth than the pre-`max_connections` run (673 MB at 14h on
2026-03-15), but still substantial. With 128 connections capped, the memory
growth is primarily from the unbounded structures identified in the 2026-03-14
report:

- **Packet dedup hashlist** (`BTreeSet<[u8; 32]>`, up to 1M entries)
- **`known_destinations`** (never cleaned)
- **Rate limiter table** (never cleaned)

At the current trajectory (~27 MB/hour), the process would reach ~1 GB in
roughly 20 more hours, putting pressure on the 1.8 GB VPS.

### 3.2 Announce cache (disk)

| Metric | 2026-03-14 | 2026-03-16 |
|--------|-----------|-----------|
| Files | 2,506,002 | **6,819** |
| Size | 9.9 GB | **280 MB** |

The dramatic reduction is because the cache was reset with the restart. At the
current rate (~400 files/hour), it will take months to reach the previous level.
The underlying issue (no cleanup policy) remains.

---

## 4. Stats collection

### 4.1 Stats DB

Size: **17 MB** after 17 hours (~1 MB/hour, ~24 MB/day).

| Table | Rows |
|-------|------|
| `seen_announces` | 132,981 |
| `process_samples` | 12,830 |
| `seen_destinations` | 8,404 |
| `seen_identities` | 5,254 |
| `packet_counters` | 2,813 |
| `seen_names` | 104 |

Growth rate is much lower than the previous run's 62 MB/day, partly because
statsd is dropping events.

### 4.2 Event drops

**147,545** dropped events from the provider bridge over 17 hours. The drops are
bursty — the last logged batch (08:40 UTC) showed drops of 2,052, 14, 4, 2, 1
events in rapid succession.

This suggests the provider channel is being overwhelmed during traffic spikes.
The stats collector is missing a significant fraction of events.

---

## 5. Comparison across runs

| Metric | Run 1 (Mar 14, 2d) | Run 2 (Mar 15, 14h) | Run 3 (Mar 16, 17h) |
|--------|--------------------|--------------------|---------------------|
| max_connections | none | none | **128** |
| LimitNOFILE | 1024 | 1024 | **65536** |
| TCP connections | 138 | 278 → fd exhaustion | **128** (capped) |
| Memory | 400 MB (2d) | 673 MB (14h) | **468 MB** (17h) |
| FDs in use | ~150 | 1023/1024 | **271** / 65536 |
| Announce cache files | 2.5M | — | 6,819 |
| Stats DB | — | 44 MB (17h) | **17 MB** (17h) |

The `max_connections = 128` cap is working well: no fd exhaustion, slower memory
growth, and the node stays responsive. However, memory growth is still
significant enough to be a concern on this VPS.

---

## 6. New issues identified

### 6.1 Write-stalled peers (NEW)

Interfaces 12050, 12056, 12058 are generating 31K `EAGAIN` failures per hour.
These peers have connected, their kernel send buffers are full, and the node
keeps trying to write to them. They occupy connection slots and waste CPU without
contributing to the network.

**Recommendation**: Add a write stall detection mechanism. Track consecutive
`EAGAIN` failures per interface. If a peer has been unwritable for e.g. 30
seconds, disconnect them. This would free slots for healthier clients and
eliminate the largest source of log noise.

### 6.2 Statsd provider bridge saturation (NEW)

147K dropped events suggests the bounded channel between rnsd and statsd is too
small, or statsd can't drain it fast enough during traffic spikes. Options:

- Increase the channel capacity
- Have statsd batch-insert to SQLite (if not already)
- Accept the drops and document the expected data loss rate

---

## 7. Remaining concerns from previous reports

### Still open

- **Per-IP connection limiting** — `85.26.186.21` holds 34/128 slots. Without
  per-IP caps, a single peer can monopolize a quarter of all capacity.
- **Memory growth from unbounded structures** — `known_destinations`, rate
  limiter table, and dedup hashlist are still the main memory consumers. No
  cleanup has been added yet.
- **Stats DB retention policy** — at ~24 MB/day, monthly growth is manageable
  (~720 MB) but a vacuum/retention policy would still be prudent.

### Resolved

- **FD exhaustion** — resolved by `LimitNOFILE=65536` (2026-03-15)
- **Unbounded connections** — resolved by `max_connections = 128` (2026-03-15)
