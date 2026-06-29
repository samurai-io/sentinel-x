<div align="center">

<img width="100%" src="https://capsule-render.vercel.app/api?type=venom&color=0:0a0a0f,50:0a1a0a,100:00cc44&height=200&section=header&text=SENTINEL-X&fontSize=80&fontColor=00cc44&fontAlignY=55&desc=Enterprise-Grade%20Autonomous%20Multi-Layer%20Adaptive%20Firewall%20%7C%20Written%20in%20C&descSize=15&descAlignY=75&descColor=ffffff&animation=twinkling" />

<br/>

![C17](https://img.shields.io/badge/C-17%20Standard-A8B9CC?style=for-the-badge&logo=c&logoColor=white&labelColor=0a0a0f)
![CMake](https://img.shields.io/badge/CMake-3.10+-064F8C?style=for-the-badge&logo=cmake&logoColor=white&labelColor=0a0a0f)
![pthreads](https://img.shields.io/badge/pthreads-Concurrent-00cc44?style=for-the-badge&labelColor=0a0a0f)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white&labelColor=0a0a0f)
![Zero Trust](https://img.shields.io/badge/Zero%20Trust-Engine-ff4444?style=for-the-badge&labelColor=0a0a0f)
![License](https://img.shields.io/badge/License-MIT-00cc44?style=for-the-badge&labelColor=0a0a0f)

<br/>

```
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      ██╗  ██╗
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║      ╚██╗██╔╝
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║       ╚███╔╝ 
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║       ██╔██╗ 
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ ██╔╝ ██╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
        [ Autonomous. Adaptive. Uncompromising Defense. ]
```

[![Stars](https://img.shields.io/github/stars/WHITEDECVIL/sentinel-x?style=for-the-badge&color=00cc44&labelColor=0a0a0f)](https://github.com/WHITEDECVIL/sentinel-x/stargazers)
[![Forks](https://img.shields.io/github/forks/WHITEDECVIL/sentinel-x?style=for-the-badge&color=00cc44&labelColor=0a0a0f)](https://github.com/WHITEDECVIL/sentinel-x/network)
[![Last Commit](https://img.shields.io/github/last-commit/WHITEDECVIL/sentinel-x?style=for-the-badge&color=00cc44&labelColor=0a0a0f)](https://github.com/WHITEDECVIL/sentinel-x/commits)

</div>

---

## 🔥 What is Sentinel-X?

**Sentinel-X** is an enterprise-grade, autonomous multi-layer adaptive firewall platform written in **high-performance C17**. It implements active defense mechanisms across 6 critical security layers — from stateful packet filtering at L1 to a dynamic Zero Trust scoring engine at L8.

> Think of it as a self-healing firewall that learns, scores, and quarantines threats in real time — with no runtime dependencies, no GC pauses, and no mercy for bad packets.

---

## 🏗️ Architecture

```
 ┌──────────────────────────────────────────────────────────────┐
 │                  Network Interface / Sim                      │
 └──────────────────────────┬───────────────────────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │  LAYER 1: Stateful Packet   │
              │  Filter & Rate Limiter      │
              │  (Token Bucket per src IP)  │
              └────────┬───────────┬────────┘
                       │           │
               Allowed │           │ Rate Limit / Disallowed
                       │           ▼
                       │      ┌─────────┐
                       │      │  DROP   │
                       │      │  & LOG  │
                       │      └─────────┘
              ┌────────▼───────────────────┐
              │  LAYER 2: Deep Packet       │
              │  Inspection (DPI)           │
              │  HTTP · DNS · TLS/SNI       │
              └───┬──────────┬─────────┬───┘
                  │          │         │
          HTTP    │     DNS  │    TLS  │
                  ▼          ▼         ▼
            ┌─────────┐ ┌───────┐ ┌──────────────────┐
            │ LAYER 4 │ │  L5   │ │     LAYER 8       │
            │   WAF   │ │  IDS  │ │  Zero Trust Engine│
            │SQLi·XSS │ │ Scan  │ │  Trust Score ≥ 50 │
            │CmdInj   │ │Detect │ │  → FORWARD        │
            └────┬────┘ └──┬────┘ │  Trust Score < 50 │
                 │         │      │  → DROP            │
           Malicious       │      └──────────┬─────────┘
                 └─────────┘                 │
                       │                     │
              ┌────────▼──────────┐          │
              │  LAYER 6: IPS     │          │
              │  Active Response  │          │
              │  Quarantine 60s   │          │
              └────────┬──────────┘          │
                       ▼                     ▼
                    DROP               ALLOW & FORWARD
```

---

## ✨ Features

<table>
<tr>
<td width="50%">

**🔒 Layer 1 — Stateful Packet Filter**
- TCP connection state tracking (SYN / ESTABLISHED / FIN / RST)
- UDP flow tracking + ICMP query management
- Token-bucket rate limiting per source IP
- DDoS flood mitigation at ingress

</td>
<td width="50%">

**🔬 Layer 2 — Deep Packet Inspection**
- Zero-copy HTTP parser (method, URI, Host, User-Agent)
- DNS QNAME + query type extraction
- TLS ClientHello / SNI hostname + version parsing
- Static-sized memory limits — no heap fragmentation

</td>
</tr>
<tr>
<td width="50%">

**🛡️ Layer 4 — Web Application Firewall**
- Case-insensitive regex signature matching
- SQL Injection, XSS, Command Injection, Path Traversal
- Applied to parsed HTTP metadata post-DPI
- Block reason propagation to audit log

</td>
<td width="50%">

**🚨 Layer 5 & 6 — IDS / IPS**
- Vertical + horizontal port scan heuristics
- Active quarantine: attacking IPs blocked 60s
- Automatic packet drop during quarantine window
- Recon detection before exploitation begins

</td>
</tr>
<tr>
<td width="50%">

**🔑 Layer 8 — Zero Trust Engine**
- Dynamic per-device trust scoring (0–100)
- Score starts at 80, drops on anomaly detection
- Elevates to 100 on identity provider auth (MFA)
- Trust < 50 → immediate packet drop

</td>
<td width="50%">

**⚡ Performance Core**
- Bucket-level fine-grained `pthread_mutex_t` locking
- O(1) state connection lookups via thread-safe hashmap
- O(N) rule matching with hash-accelerated state
- Zero runtime dependencies — pure C17

</td>
</tr>
</table>

---

## 🛠️ Build & Run

### Requirements

```
CMake 3.10+
GCC or Clang (C17 support)
pthread
```

### Build

```bash
cmake -B build -S .
cmake --build build
```

### Run Simulation

```bash
./build/sentinel_x
```

### Docker

```bash
# Single container
docker build -t sentinel-x -f docker/Dockerfile .

# Full stack
docker-compose -f docker/docker-compose.yml up --build
```

---

## 📡 API Reference

### `sentinel_common.h` — Utility Library

```c
// Allocate thread-safe fine-grained locked hashmap
HashMap *hashmap_create(size_t size);

// Insert key-value pair (safe)
bool hashmap_put(HashMap *map, const char *key, void *value);

// Read value by key (safe)
void *hashmap_get(HashMap *map, const char *key);

// Remove entry with optional value destructor
bool hashmap_remove(HashMap *map, const char *key, void (*free_val_fn)(void *));
```

### `sentinel_core.h` — Core Engine

```c
// Initialize firewall with rate limit and burst ceiling
FirewallEngine *sentinel_engine_create(uint32_t limit_rate, uint32_t limit_burst);

// Add IP/port rule to rules database
bool sentinel_add_rule(FirewallEngine *engine, const char *src_ip, ...);

// Core packet processing: rule match + rate limit + stateful check
bool sentinel_process_packet(FirewallEngine *engine, Packet *packet,
                             char *reason, size_t len);
```

### `sentinel_dpi.h` — DPI Engine

```c
// Parse transport payload → extract HTTP / DNS / TLS application-layer data
bool sentinel_dpi_inspect(const Packet *packet, DpiResult *result);
```

### `sentinel_waf.h` — WAF Engine

```c
// Scan parsed HTTP headers for exploit signatures
bool sentinel_waf_inspect(const HttpMeta *http, char *block_reason, size_t reason_len);
```

### `sentinel_ids_ips.h` — IDS/IPS Engine

```c
// Identify recon, drop quarantined source packets
bool sentinel_ids_ips_process(IdsIpsEngine *engine, const Packet *packet,
                              char *alert_msg, size_t msg_len);
```

### `sentinel_zero_trust.h` — Zero Trust Engine

```c
// Evaluate dynamic trust score for packet source
bool sentinel_zt_evaluate(ZeroTrustEngine *engine, const Packet *packet,
                          char *reason, size_t len);

// Penalize IP for suspicious behavior (drops trust score)
void sentinel_zt_penalize(ZeroTrustEngine *engine, const char *ip_address,
                          int points, const char *reason);
```

---

## 🎯 Threat Model

| Asset | Threat | Mitigation | Risk |
|-------|--------|-----------|------|
| Web Application Services | SQLi · XSS · Cmd Injection | Layer 4 WAF Signature Engine | 🔴 High → ✅ Mitigated |
| System Infrastructure | DDoS · SYN Flooding | Layer 1 Token-Bucket Rate Limiter | 🔴 High → ✅ Mitigated |
| Internal Server Resources | Port Scanning · Recon | Layer 5/6 IPS + Active Quarantine | 🟡 Medium → ✅ Mitigated |
| Access Privilege | Compromised Device · Credential Theft | Layer 8 Zero Trust + MFA Validation | 🔴 High → ✅ Mitigated |

---

## ⚡ Performance Design

```
┌─────────────────────────────────────────────────────────────┐
│ LOCK CONTENTION                                             │
│   Global lock  → ❌  Single bottleneck, blocks all threads  │
│   Bucket locks → ✅  Per-bucket pthread_mutex_t, concurrent │
├─────────────────────────────────────────────────────────────┤
│ DPI MEMORY                                                  │
│   Heap alloc   → ❌  Fragmentation + GC pressure            │
│   Zero-copy    → ✅  Buffer offset refs + static limits     │
├─────────────────────────────────────────────────────────────┤
│ RULE MATCHING                                               │
│   Linear scan  → O(N) for active rules                      │
│   State lookup → O(1) via thread-safe hashmap               │
└─────────────────────────────────────────────────────────────┘
```

---

## 👤 Author

<div align="center">

**Sanjay S** — *Security Engineer · Red Teamer · Systems Developer*

[![GitHub](https://img.shields.io/badge/GitHub-WHITEDECVIL-181717?style=for-the-badge&logo=github&logoColor=white&labelColor=0a0a0f)](https://github.com/WHITEDECVIL)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Sanjay_S-0077B5?style=for-the-badge&logo=linkedin&logoColor=white&labelColor=0a0a0f)](https://linkedin.com/in/sanjay-s)
[![HackerOne](https://img.shields.io/badge/HackerOne-Profile-494649?style=for-the-badge&logo=hackerone&logoColor=white&labelColor=0a0a0f)](https://hackerone.com)
[![Email](https://img.shields.io/badge/Gmail-sankicju@gmail.com-D14836?style=for-the-badge&logo=gmail&logoColor=white&labelColor=0a0a0f)](mailto:sankicju@gmail.com)

</div>

---

<div align="center">

*"The strength of a firewall is not in what it allows — it's in what it never lets through."*

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:00cc44,100:0a1a0a&height=100&section=footer" />

</div>
