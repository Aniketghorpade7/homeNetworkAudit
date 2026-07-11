# Home Network Audit

![CI](https://github.com/Aniketghorpade7/homeNetworkAudit/actions/workflows/ci.yml/badge.svg)

A command-line tool that scans your local network, identifies every device on it, and turns the raw findings into a **plain-English security report** — so a non-expert can see *what's connected* and *what to fix*.

It's written in pure Java with **no external scanner** (no `nmap`) and **no root required** — it implements its own concurrent port scanner, reads the OS ARP cache for MAC addresses, and looks vendors up against the bundled IEEE OUI registry.

---

## What it does

- **Discovers** every live host on your subnet (concurrent ping sweep).
- **Identifies** each device: MAC address → **vendor** (e.g. "TP-Link", "Samsung"), plus a device-type guess (Router, Windows host, DNS server, …).
- **Scans** common TCP ports on each host with a concurrent connect-scan.
- **Analyzes** the results against a data-driven knowledge base of security rules, producing **findings** with a severity, a plain-English explanation, and specific remediation.
- **Reports** in three formats: a colour-coded terminal summary, a shareable **Markdown** report, and a machine-readable **JSON** file.

## Example output

```
=== Home Network Audit ===
Subnet: 192.168.1.0/24    Live hosts: 3    Generated: 2026-07-12 00:24:57

192.168.1.1   [a4:2b:b0:11:22:33 · TP-Link Corporation Limited]   Router / Gateway   (risk: LOW)
   53/tcp    domain
   80/tcp    http
     [INFO] DNS service present
        fix: No action needed if this is your router or DNS server.
     [LOW] Unencrypted web service (HTTP)
        fix: Use HTTPS where possible, and ensure any admin panel has a strong password.

192.168.1.50   [00:1a:2b:cc:dd:ee · Raspberry Pi Foundation]   SSH host (Linux/Unix)   (risk: CRITICAL)
   22/tcp    ssh
   23/tcp    telnet
     [LOW] SSH remote access available
        fix: Prefer key-based authentication, disable root login, and consider fail2ban.
     [CRITICAL] Telnet exposed
        fix: Disable Telnet immediately and use SSH (port 22) for remote access.

Overall network posture: CRITICAL
```

*(Illustrative example. In a real terminal the severities are colour-coded; findings and remediation are generated only from rules that actually matched.)*

## Requirements

- **JDK 21 or newer** (developed on JDK 26; CI runs on Temurin 21).
- **Linux** for full functionality. The core scan runs anywhere with a JRE; MAC/vendor resolution currently uses Linux `ip neigh` and degrades gracefully to "unknown" on other platforms.
- Gradle is **not** required — the project ships a Gradle wrapper (`./gradlew`).

## Build & run

Scan your own network (auto-detects the subnet):

```bash
./gradlew run
```

See all options:

```bash
./gradlew run --args="--help"
```

To get the **colour-coded** output (colours are disabled under Gradle, which isn't a real terminal), build the launcher and run it directly:

```bash
./gradlew installDist
./build/install/home-net-audit/bin/home-net-audit
```

## Usage

```
home-net-audit [options]

  --subnet <cidr>        Scan this subnet (e.g. 192.168.1.0/24) instead of auto-detecting
  --output <dir>         Directory for generated reports (default: reports)
  --format <fmt>         terminal | markdown | json | all (default: all)
  --i-have-permission    Confirm you are authorized to scan a non-local subnet
  -h, --help             Show help and exit
  -v, --version          Show version and exit
```

Reports are written to `./reports/` (or `--output`) as timestamped `.md` and `.json` files.

## How it works

The scan is a pipeline over an in-memory device inventory:

1. **Subnet detection** — enumerates local interfaces (`NetworkInterface`) to find the network to scan.
2. **Host discovery** — a concurrent reachability sweep using **virtual threads** (Java 21+).
3. **Port scan** — a concurrent TCP **connect-scan** of ~20 common ports (`Socket`, no root).
4. **Identification** — reads the OS **ARP cache** for MACs, resolves the **vendor** from the bundled IEEE OUI registry, and infers a device type from the gateway + open-port signature.
5. **Analysis** — a data-driven **rules engine** (`rules.json`) turns open ports into findings with a severity, then rolls severity up per-device and to an overall network posture.
6. **Reporting** — the same inventory is rendered to terminal, Markdown, and JSON.

## Ethics & responsible use

**Only scan networks you own or are explicitly authorized to test.** By default the tool scans only your own detected subnet. If you point it at a subnet you're not connected to, it refuses unless you pass `--i-have-permission`. Port scanning networks without permission may be unwelcome or illegal.

## Limitations (v1)

Honest about what it does *not* do yet:

- **Tested on Linux (Arch).** macOS/Windows are supported for the core scan but MAC/vendor resolution is best-effort there.
- **Connect-scan**, not a SYN scan: it reliably finds *open* ports but can't distinguish "filtered" from "closed" as precisely; no service **version** detection yet.
- **Host discovery** relies on ICMP/echo reachability, so hosts that silently drop pings can be missed.
- **MAC/vendor** only resolves for devices on the same L2 segment, and modern **randomized MACs** intentionally don't map to a vendor.
- Scans a curated set of **20 common ports**, not all 65,535.

## Running the tests

```bash
./gradlew test
```

17 unit tests cover the pure, deterministic logic — the rules engine, OUI vendor lookup, subnet math, and device classification. The network/OS-dependent layers (discovery, port scan, ARP read) are verified by running the tool rather than unit-tested, since they depend on live network state.

## What I learned

Building this deepened a few things in a hands-on way:

- **Socket programming** — implementing a TCP connect-scan and understanding open vs. closed (RST) vs. filtered (timeout) from the client side.
- **Concurrency with virtual threads** — fanning out hundreds of blocking network probes, and the real lesson that *native* calls (like ICMP `isReachable`) pin virtual threads while socket I/O does not.
- **The network stack in practice** — subnets and CIDR masking with bit operations, ARP/L2 vs. IP/L3, and MAC-vendor (OUI) assignment.
- **Designing for change** — separating a data-driven knowledge base (`rules.json`) from the engine that applies it, so findings and remediation are never hardcoded.
- **Engineering discipline** — a Gradle build, JUnit tests, and CI that builds and tests on every push.

---

*Built as a portfolio project, mentored end-to-end by Claude.*
