# VPS Production Findings — 2026-03-15

Follow-up to the [2026-03-14 report](vps-production-findings-2026-03-14.md). Same VPS
(`root@vps`, 87.106.8.245), same backbone gateway config on port 4242.

---

## 1. Incident: file descriptor exhaustion

### 1.1 What happened

After ~14 hours of uptime (started 2026-03-14 22:10 UTC), `rnsd` hit the
default Linux soft fd limit of **1024** around **2026-03-15 12:21 UTC**.

Symptoms:
- Backbone accept loop spamming `Too many open files (os error 24)` — **3.7 million**
  error lines in ~3 hours
- `rns-statsd` dropping events from the provider bridge — **237,655** drop warnings
- Memory bloated to **673 MB** (peak 1.1 GB) — up from the ~400 MB seen in the
  previous day's report
- CPU usage: 1h 15min total, system load average 4.41

At inspection time:
- **1023 / 1024** file descriptors in use
- **278 TCP connections** on port 4242
- Top offending peers by connection count:
  - `79.112.78.160`: **126 connections**
  - `79.116.155.64`: **56 connections**
  - `188.243.182.89`: 20 connections

### 1.2 Root cause

The systemd unit (`/etc/systemd/system/rnsd.service`) had no `LimitNOFILE`
override, inheriting the default soft limit of 1024. With 278 inbound TCP
connections plus outbound connections, provider socket, stats db, announce cache
files, etc., 1024 fds is far too low for a public transport node.

The `max_connections` config option (added to the codebase in commit `ffc9a87`)
was not set in the production config, so there was no cap on inbound connections.

---

## 2. Mitigations applied

### 2.1 Raise file descriptor limit

Added `LimitNOFILE=65536` to the `[Service]` section of
`/etc/systemd/system/rnsd.service`:

```ini
[Service]
LimitNOFILE=65536
Type=simple
ExecStart=/usr/local/bin/rnsd
Restart=always
RestartSec=5
User=root
```

### 2.2 Set max_connections on backbone server

Added `max_connections = 128` to the `[[Public Entrypoint]]` section in
`/root/.reticulum/config`:

```toml
[[Public Entrypoint]]
  type = BackboneInterface
  enabled = yes
  listen_ip = 0.0.0.0
  listen_port = 4242
  max_connections = 128
  interface_mode = gateway
  ...
```

This uses the `max_connections` support already in `BackboneInterfaceFactory::parse_config`
(parsed as `Option<usize>`, applied in the backbone accept loop).

### 2.3 Service restarts

Both services were restarted at **~15:21 UTC**:

1. `systemctl daemon-reload && systemctl restart rnsd` — came up cleanly
2. `systemctl restart rns-statsd` — failed on first attempt (provider socket
   not yet ready), auto-restarted successfully 5 seconds later via
   `Restart=always` / `RestartSec=5`

Post-restart verification:
- `rnsd`: fd limit confirmed at 65536, memory at 4.7 MB (fresh start)
- `rns-statsd`: connected to new rnsd process (pid 4079336), 3.0 MB memory

---

## 3. Post-restart observations

Within **seconds** of restart, the backbone hit 128 connections and began
rejecting new ones:

```
[Public Entrypoint] max connections (128) reached, rejecting 79.112.78.160:56230
[Public Entrypoint] max connections (128) reached, rejecting 46.229.62.234:54278
[Public Entrypoint] max connections (128) reached, rejecting 91.78.190.87:5939
```

`79.112.78.160` is the most aggressive — it immediately saturated most of the
128 slots and kept retrying. This is the same "silent leech" / reconnect pattern
described in the 2026-03-14 report, now with a different set of top IPs.

The `max_connections` limit is working as intended: the server stays at 128-129
TCP connections and cleanly rejects excess. No fd exhaustion, no memory runaway.

---

## 4. Stats collection

- **Stats DB**: `/var/lib/rns/stats.db`, **44 MB** after ~17 hours
- `rns-statsd` was dropping events before the restart due to rnsd being
  overwhelmed. After restart, collection is clean.

---

## 5. Current state of VPS services

| Service | Status | PID | Memory | Since (UTC) |
|---------|--------|-----|--------|-------------|
| `rnsd` | running | 4079336 | 4.7 MB | 2026-03-15 15:21 |
| `rns-statsd` | running | 4079422 | 3.0 MB | 2026-03-15 15:22 |

System resources (1.8 GB RAM VPS, no swap):
- Memory: ~1.3 GB used (mostly buff/cache now that rnsd restarted fresh)
- Load average at restart: 4.41 — expected to drop significantly

---

## 6. Remaining concerns and next steps

### Connection flooding (not yet addressed)
`79.112.78.160` monopolizes most of the 128 connection slots. Without per-IP
limiting, a single aggressive peer can crowd out legitimate clients. Options:

- **Per-IP connection limit** in the backbone server (e.g., max 5 per IP)
- **Firewall rate limiting** via iptables/nftables for the worst offenders
- **Idle connection timeout** to reclaim slots from silent peers

### Memory growth (watch)
Previous run reached 673 MB / 1.1 GB peak after ~14 hours. The unbounded
`known_destinations`, rate limiter table, and packet hashlist issues identified
in the 2026-03-14 report are still present. The periodic cleanup added in commit
`0db7805` should help — monitor whether memory stays reasonable this time.

### Stats DB growth rate
44 MB in 17 hours = ~62 MB/day. At this rate the DB will reach ~1.8 GB/month.
May need a retention policy or periodic vacuum.

### max_connections tuning
128 may be too low (legitimate clients get rejected when aggressive peers fill
slots) or too high (still a lot of per-connection overhead). Needs observation
to find the right balance, ideally after per-IP limiting is in place.
