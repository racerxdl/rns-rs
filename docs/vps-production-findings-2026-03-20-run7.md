# VPS Production Findings — 2026-03-20 (Run 7)

Follow-up to the [2026-03-20 report](vps-production-findings-2026-03-20.md). Same VPS
(`root@vps`, 87.106.8.245), same backbone gateway config on port 4242 with
`max_connections = 128`.

Binary version: `rnsd 0.2.199-83deda9` (deployed this session, 16 commits ahead of
previous `0.2.183-f1ab29d`).

Key changes landing in this deploy:
- `74bde25` — **MEMSTATS logging** (every ~5 min: RSS + all table sizes)
- `ae4ea3f` — **Graduated IP throttling** (addresses the `95.81.119.72` situation)
- `8a20912` / `79deeb1` — Shared-client reconnect + 1-hop header injection
- `34cbd08` — Version bump (rns-core 0.1.6, rns-net 0.5.2)
- `83deda9` — CI workflow for tests and clippy

Service restarted at **2026-03-20 20:06 UTC**.

---

## 1. Deploy verification

All three binaries report `0.2.199-83deda9`:
- `rnsd`, `rns-statsd`, `rns-ctl` all match.

Isolated VPS startup probe passed — shared-instance listener (`127.0.0.1:47428`)
and RPC listener (`127.0.0.1:47429`) both started.

Post-restart services healthy:
- `rnsd` — active (running), listening on `0.0.0.0:4242` and `127.0.0.1:37429`
- `rns-statsd` — active (running), monitoring pid 56407

---

## 2. MEMSTATS time series (first 2 hours)

All samples from `journalctl -u rnsd | grep MEMSTATS`:

| Time (UTC) | Uptime | RSS (MB) | known_dest | path | hashlist | pr_tags | link | announce |
|------------|--------|----------|------------|------|----------|---------|------|----------|
| 20:11:45 | +5m | 55.7 | 370 | 370 | 1,242 | 125 | 4 | 1 |
| 20:16:45 | +10m | 58.2 | 631 | 612 | 2,469 | 270 | 9 | 4 |
| 20:21:45 | +15m | 53.4 | 856 | 837 | 3,626 | 416 | 17 | 3 |
| 20:26:45 | +20m | 56.0 | 1,035 | 1,017 | 4,793 | 559 | 26 | 3 |
| 20:31:45 | +25m | 57.8 | 1,231 | 1,176 | 6,260 | 796 | 34 | 5 |
| 20:36:45 | +30m | 59.2 | 1,406 | 1,355 | 8,182 | 1,210 | 35 | 4 |
| 20:41:45 | +35m | 60.3 | 1,579 | 1,512 | 10,202 | 1,638 | 31 | 4 |
| 20:46:45 | +40m | 61.3 | 1,696 | 1,637 | 12,228 | 2,131 | 30 | 2 |
| 20:51:45 | +45m | 61.9 | 1,815 | 1,734 | 14,161 | 2,530 | 31 | 2 |
| 20:56:45 | +50m | 64.2 | 1,943 | 1,866 | 15,943 | 2,944 | 29 | 10 |
| 21:01:45 | +55m | 65.2 | 2,059 | 1,938 | 17,803 | 3,368 | 22 | 4 |
| 21:06:45 | +1h00m | 65.5 | 2,149 | 1,996 | 19,660 | 3,800 | 17 | 4 |
| 21:11:45 | +1h05m | 66.8 | 2,236 | 2,115 | 21,529 | 4,214 | 15 | 6 |
| 21:16:45 | +1h10m | 67.6 | 2,331 | 2,192 | 23,434 | 4,649 | 13 | 5 |
| 21:21:45 | +1h15m | 68.3 | 2,438 | 2,278 | 25,330 | 5,081 | 11 | 11 |
| 21:26:45 | +1h20m | 68.5 | 2,534 | 2,360 | 27,010 | 5,453 | 11 | 8 |
| 21:31:45 | +1h25m | 68.8 | 2,614 | 2,457 | 28,821 | 5,856 | 11 | 6 |
| 21:36:45 | +1h30m | 69.1 | 2,704 | 2,517 | 30,572 | 6,264 | 12 | 2 |
| 21:41:45 | +1h35m | 69.5 | 2,798 | 2,557 | 32,518 | 6,691 | 12 | 3 |
| 21:46:45 | +1h40m | 70.2 | 2,929 | 2,679 | 34,481 | 7,124 | 14 | 3 |
| 21:51:45 | +1h45m | 70.8 | 2,999 | 2,751 | 36,159 | 7,506 | 12 | 7 |
| 21:56:46 | +1h50m | 71.3 | 3,077 | 2,845 | 37,835 | 7,883 | 15 | 3 |
| 22:01:46 | +1h55m | 71.9 | 3,147 | 2,915 | 39,593 | 8,291 | 16 | 3 |
| 22:06:46 | +2h00m | 72.3 | 3,208 | 2,892 | 41,392 | 8,687 | 17 | 4 |
| 22:11:46 | +2h05m | 72.6 | 3,280 | 2,982 | 43,041 | 9,064 | 14 | 2 |
| 22:16:46 | +2h10m | 73.3 | 3,355 | 3,071 | 44,813 | 9,429 | 14 | 6 |
| 22:21:46 | +2h15m | 74.1 | 3,417 | 3,151 | 46,498 | 9,814 | 12 | 9 |

All other tracked fields remained at 0 or near-0 throughout:
`reverse=0`, `held_ann=0-1`, `rate_lim=0`, `blackhole=0`, `tunnel=0`,
`disc_pr=0`, `sent_pkt=0`, `completed=0`, `local_dest=3`, `shared_ann=0`,
`lm_links=0`, `hp_sessions=0`, `proof_strat=1`.

---

## 3. Growth rate analysis

### 3.1 RSS

RSS grew from 55.7 MB to 74.1 MB over ~2.2 hours = **~8.4 MB/h**.

Slightly lower than the historical ~12 MB/h average from Run 6, but consistent.
The first-hour rate was steeper (~10 MB/h) as tables populated from peers;
second-hour rate dropped to ~7 MB/h.

### 3.2 Table growth rates (per hour, linear fit)

| Table | Rate/hr | Has eviction? | Cap | Notes |
|-------|---------|---------------|-----|-------|
| **hashlist** | ~20,900/hr | Yes (FIFO) | 250,000 | Pre-allocated ~24 MB at startup. **NOT a leak.** |
| **pr_tags** | ~4,470/hr | Yes (FIFO trim) | 32,000 | Will cap in ~7h. ~1 MB max. **Not the leak.** |
| **known_dest** | ~1,400/hr | Yes (48h TTL, hourly cleanup) | None | Will accumulate ~67k in 48h before eviction starts |
| **path** | ~1,300/hr | Yes (6h/24h TTL, 5s cull) | None | Will plateau within 6–24h |
| **link** | Stable ~10-35 | Yes | — | Bounded by active links |
| **announce** | Stable ~2-11 | Retransmit budget | — | Low count |

### 3.3 Estimated memory per table at steady state

| Table | Entries at steady state | Entry size (est.) | Memory (est.) |
|-------|------------------------|-------------------|---------------|
| hashlist | 250,000 (fixed) | 65 bytes | ~16 MB (pre-allocated) |
| known_dest | ~67,000 (48h) | ~120+ bytes | **~8+ MB** |
| path | ~15,000–31,000 (6–24h) | ~100 bytes | ~1.5–3 MB |
| pr_tags | 32,000 (cap) | 32 bytes | ~1 MB |

**These tracked tables account for ~27 MB max at steady state.** RSS at 2h is
already 74 MB and growing. The gap suggests either:
1. The per-entry sizes are much larger than estimated (especially `known_dest`
   with its `app_data: Option<Vec<u8>>`)
2. There are memory consumers not tracked by MEMSTATS (per-interface buffers,
   announce queue internals, ingress control state, allocator fragmentation)
3. The allocator is not returning freed memory to the OS (RSS ≠ live heap)

---

## 4. Key observations

### 4.1 hashlist is NOT the culprit

Despite being the largest counter (46k at 2h), the `PacketHashlist` pre-allocates
all memory at construction (`Vec<[u8; 32]>` of 250k entries + hash set of 512k
buckets). The counter growing just means slots are being filled, not new memory
being allocated.

### 4.2 known_destinations is the top suspect

- No hard cap, only 48h TTL
- Each entry carries `AnnouncedIdentity` which includes a public key and
  `app_data: Option<Vec<u8>>` of arbitrary size
- At ~1,400 new destinations/hr and 48h TTL, steady state is ~67k entries
- If average `app_data` is 100–200 bytes, that's 13–27 MB just for app_data
  blobs plus overhead

### 4.3 RSS growth may slow once tables reach steady state

Since all tracked tables have eviction (hashlist FIFO, pr_tags FIFO, known_dest
48h TTL, path 6–24h TTL), RSS growth should decelerate once the oldest entries
start being evicted. The earliest eviction kicks in:
- **hashlist**: fills at ~12h (but memory already allocated)
- **path**: 6h (roaming) or 24h (access point)
- **pr_tags**: ~7h
- **known_dest**: ~48h

If RSS is still growing linearly after 48h, the leak is outside these tables.

---

## 5. Next steps

1. **Continue monitoring MEMSTATS** for 24–48h to see if growth rate decelerates
   as eviction engages
2. **Measure `app_data` sizes** in `known_destinations` to estimate true
   per-entry memory cost
3. **Audit untracked allocations** — per-interface buffers, announce queue
   internals (`AnnounceQueues`), ingress control state, connection-level
   allocations in the backbone interface
4. **Consider adding a hard cap** to `known_destinations` (LRU or random eviction
   when exceeding a threshold) as a safety valve
5. **Check allocator behavior** — `jemalloc` stats or `/proc/PID/smaps` to
   distinguish live heap from retained-but-freed pages

---

## 6. Comparison across all runs

| Metric | Run 5 (42h) | Run 6 (45h) | **Run 7 (2.2h)** |
|--------|------------|------------|------------------|
| Binary version | `0.2.183-f1ab29d` | `0.2.183-f1ab29d` | **`0.2.199-83deda9`** |
| Memory (at check) | 544 MB | 565 MB | **74 MB** |
| Memory rate | ~13 MB/h | ~12.4 MB/h | **~8.4 MB/h** |
| MEMSTATS available | No | No | **Yes** |
| Graduated throttling | No | No | **Yes** |
| Top table (by count) | — | — | **hashlist (46k, pre-alloc)** |
| Top growing table | — | — | **known_dest (~1.4k/h)** |
