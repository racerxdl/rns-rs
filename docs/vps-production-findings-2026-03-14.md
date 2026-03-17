# VPS Production Findings — 2026-03-14

Investigation of `rnsd` running on the public VPS (`root@vps`, 87.106.8.245) as a
discoverable transport gateway with `interface_mode = gateway` on port 4242.

Uptime at time of investigation: **2 days** (since 2026-03-12 20:26 UTC).

---

## 1. Connection landscape

### 1.1 Configuration

4 configured interfaces:

| Interface | Type | Direction |
|-----------|------|-----------|
| Public Entrypoint (`:4242`) | BackboneInterface (server) | Inbound |
| RNS Germany 001 (`:4965`) | TCPClientInterface | Outbound |
| RNS Germany 002 (`:4965`) | TCPClientInterface | Outbound |
| Bern (`:7822`) | BackboneInterface (client) | Outbound |

The 3 outbound links each hold a single stable TCP connection. All the
action is on the Public Entrypoint.

### 1.2 Inbound connections

**138 active TCP connections** on port 4242 at time of inspection. Each becomes
a dynamic interface with its own `InterfaceId`, `InterfaceEntry`, engine
registration, ingress control state, and announce queue.

Top connecting IPs:

| IP | Connections | bytes we sent them | bytes they sent us | Notes |
|----|-------------|--------------------|--------------------|-------|
| `144.31.113.59` | 39 | ~70 MB (1.8 MB × 39) | **367 bytes** (1 conn) | NL hosting (hostoff.net) |
| `87.255.16.5` | 28 | ~12 MB | ~2 MB (1 conn) | Russian ISP (bigtelecom.ru) |
| `146.86.174.95` | 16 | unknown | ~0 | US ISP (MidSouth Fiber) |
| `83.135.241.44` | 6 | — | — | — |

### 1.3 The "silent leech" pattern

For the multi-connection IPs, **only 1 connection per IP actually sends data**.
The remaining 38/27/15 connections opened a TCP socket, sent nothing, and passively
receive all traffic we forward to them. Each connection is treated as an independent
interface, so our node duplicates all outbound packets N times to the same IP.

These are most likely machines running multiple Reticulum instances or
applications, each with its own `BackboneClientInterface` or
`TCPClientInterface` pointed at our node. This is not malicious — it's
normal behavior in the Reticulum ecosystem. The Python reference server
handles them identically (no per-IP limiting, no dedup).

### 1.4 The "rapid reconnector" pattern

Several IPs connect, stay ~5 seconds, disconnect, then immediately reconnect:

| IP | Connect events (last 24h) |
|----|--------------------------|
| `166.70.61.163` | 1,707 |
| `146.70.237.142` | 1,387 |
| `194.28.29.162` | 989 |
| `73.254.145.252` | 654 |
| `99.46.183.166` | 602 |

The Python `BackboneClientInterface` reconnects with a **fixed 5-second delay**
(`RECONNECT_WAIT = 5`, no exponential backoff, unlimited retries). These clients
are likely failing during the connection (possibly timing out on the stamp
verification given `discovery_stamp_value = 16`, or hitting a network issue) and
retrying every 5 seconds indefinitely.

Each connect/disconnect cycle allocates and deallocates an `InterfaceId`. After
2 days, the counter reached **23,000+**. The cleanup on disconnect is correct
(interface state is properly removed), so this doesn't leak memory, but it does
churn the interface ID space and produces significant log noise.

### 1.5 Consequences

- **Memory**: 138 dynamic interfaces × per-interface overhead (InterfaceEntry,
  writer, stats, engine registration, ingress control state, announce queue)
- **CPU**: Every inbound packet is forwarded to every outbound-capable interface.
  39 connections from one IP means the same announce is sent 39 times.
- **Bandwidth**: ~70 MB sent to a single IP that contributed 367 bytes.
- **Log noise**: Thousands of connect/disconnect events per day.

---

## 2. Memory analysis

**Total RSS: ~400 MB** (peak 535 MB) — suspicious for a routing daemon.

### 2.1 Packet dedup hashlist — estimated ~100-200 MB

The largest single memory consumer. `PacketHashlist` uses double-buffered
`BTreeSet<[u8; 32]>` with `HASHLIST_MAXSIZE = 1,000,000`.

- At full capacity: up to 1.5M entries × 32 bytes = 48 MB raw data
- BTreeSet node overhead roughly 2-3× → **~100-150 MB**
- On a transport node with 138 clients, the hashlist fills up fast

The Python reference uses the same 1M limit. However, `BTreeSet` has higher
per-entry overhead than Python's set (which uses a hash table). Consider:

- **Switch to `HashSet`**: lower per-entry overhead than `BTreeSet` (~50% less)
- **Reduce `HASHLIST_MAXSIZE`**: evaluate whether 1M is necessary, or if
  500K or 250K would suffice with the rotation mechanism

Location: `rns-core/src/transport/dedup.rs`, constant at
`rns-core/src/constants.rs:180`

### 2.2 `known_destinations` — unbounded, never cleaned

`HashMap<[u8; 16], AnnouncedIdentity>` in `driver.rs:272`. Every unique announced
destination is stored forever. `AnnouncedIdentity` contains:

- `dest_hash: [u8; 16]`
- `identity_hash: [u8; 16]`
- `public_key: [u8; 64]`
- `app_data: Option<Vec<u8>>` — variable size, can be significant
- `hops: u8`, `received_at: f64`, `receiving_interface: InterfaceId`

With thousands of destinations discovered on the network, this grows
indefinitely. **No cleanup, no TTL, no max size.**

Recommendation: Add TTL-based cleanup (e.g., remove entries not re-announced
in 48-72 hours). This also drives the announce cache cleanup (see §3).

Location: `rns-net/src/driver.rs:272`, struct at
`rns-net/src/common/destination.rs:183`

### 2.3 Announce rate limiter — unbounded, never cleaned

`BTreeMap<[u8; 16], RateEntry>` in `TransportEngine`. Every destination that
has ever announced creates a permanent entry (~180 bytes each). Entries are
never pruned even after the rate limiting window expires.

Recommendation: Periodically remove entries whose `last` timestamp is older
than a threshold (e.g., 1 hour).

Location: `rns-core/src/transport/rate_limit.rs`

### 2.4 `announce_raw` in PathEntry

Each `PathEntry` stores `announce_raw: Option<Vec<u8>>` — a full copy of the
original raw announce bytes (~200-500 bytes). This is used to respond to path
requests. Since paths are culled regularly, this is bounded indirectly, but it
adds significant per-destination overhead.

Location: `rns-core/src/transport/tables.rs:16`

### 2.5 Bounded structures (no issues found)

The following structures are properly bounded or cleaned:

- **Path table**: culled every 5 seconds, paths expire
- **Announce table**: culled regularly, entries have retransmit TTL
- **Reverse table**: TTL-based cleanup
- **Link table**: TTL-based cleanup, closure actions triggered
- **Discovery path requests**: 15-second expiration
- **Discovery PR tags**: capped at `MAX_PR_TAGS = 32,000`
- **Random blobs per path**: capped at `MAX_RANDOM_BLOBS = 64`
- **Announce queues**: capped at `MAX_QUEUED_ANNOUNCES`, stale entries removed
- **Ingress control**: state removed on `InterfaceDown`
- **Backbone client state**: properly cleaned on disconnect
- **`sent_packets`**: 60-second TTL via `retain()`
- **`completed_proofs`**: 120-second TTL via `retain()`

---

## 3. Disk usage — 10 GB announce cache

```
/root/.reticulum/cache/announces/  →  2,506,002 files, 9.9 GB
/root/.reticulum/storage/          →  32 MB
```

The announce cache stores every received announce as a msgpack file keyed by
packet hash. The `clean()` method syncs the cache with a set of "active" hashes,
but since `known_destinations` never prunes, neither does the cache.

2.5 million small files also cause:
- **Directory entry bloat**: the `announces/` directory entry itself is 251 MB
- **Filesystem inode pressure**
- **Slow `ls`/`find` operations** in the cache directory

Recommendation: Cache cleanup should be driven by path table expiry (paths
that have been culled should have their cache entries removed). Alternatively,
add a max-age or max-count policy to the cache itself.

Location: `rns-net/src/announce_cache.rs` (or similar)

---

## 4. Backbone server: no connection governance

The `epoll_loop` in `backbone.rs` accepts all incoming connections with:
- No max connections per IP
- No max total connections
- No handshake or bidirectional traffic requirement
- No awareness of duplicate peers

This matches the Python reference behavior (which also has none of these).
However, for a production transport node, this leads to the problems
described in §1.

### 4.1 Possible mitigations (to be evaluated)

**Per-IP connection limiting**: Cap connections per source IP (e.g., 3-5).
Simple to implement, but may break legitimate multi-instance setups behind NAT.

**Idle connection timeout**: Disconnect clients that haven't sent any data
within N seconds. Would address the silent leech pattern without hard limits.

**Reconnect backoff expectation**: Not enforceable server-side, but our own
client implementation could use exponential backoff instead of fixed 5-second
delays when connecting to other nodes.

**Outbound deduplication by IP**: Recognize that multiple connections from
the same IP likely don't need the same packet sent to all of them. Complex
to implement correctly.

---

## 5. Summary of recommended actions

### High priority (memory)

1. **Add TTL cleanup to `known_destinations`** — prune entries not re-announced
   in 48h. This will also enable proper announce cache cleanup on disk.

2. **Add cleanup to rate limiter table** — prune entries with `last` older
   than 1 hour.

3. **Evaluate `HASHLIST_MAXSIZE`** — consider reducing from 1M, and/or
   switching from `BTreeSet` to `HashSet` for lower per-entry overhead.

### Medium priority (connections)

4. **Add idle connection timeout to backbone server** — disconnect clients that
   send no data within e.g. 60 seconds. This directly addresses the silent
   leech pattern.

5. **Add max total connection limit to backbone server** — reject new
   connections when at capacity (e.g., 200). Prevents resource exhaustion.

### Low priority (operational)

6. **Implement announce cache max-age or max-count** — prevent unbounded disk
   growth independently of `known_destinations` cleanup.

7. **Consider logging rate limiting** — the rapid reconnectors generate
   thousands of log lines per day. Aggregate or throttle connect/disconnect
   logging for the same IP.
