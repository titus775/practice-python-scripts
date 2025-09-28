#!/usr/bin/env python3
"""
mass_dns_cdn_detector.py

Multithreaded DNS resolver + simple CDN detection heuristics.
This version accepts either domain names (e.g. example.com), full URLs
(e.g. https://example.com/path) or raw IP addresses (e.g. 1.2.3.4).
It writes JSON and optional CSV output.

Run:
  python3 mass_dns_cdn_detector.py --hosts host.txt -t 200 -o result.json --csv summary.csv

Use only on targets you own or are authorized to test.
"""

# ---------- imports ----------
import argparse                                # parse CLI args
import socket                                  # fallback DNS resolver and reverse DNS (PTR)
import concurrent.futures                      # ThreadPoolExecutor for concurrency
import json                                    # write JSON output
import csv                                     # write CSV summary
import time                                    # timing / elapsed measurement
import ipaddress                               # parse and manipulate IP addresses and subnets
from urllib.parse import urlparse              # parse full URLs into components

# Try to import dnspython for robust DNS queries; fall back to socket if not available
try:
    import dns.resolver                         # dnspython resolver (preferred)
    DNSPYTHON = True                            # mark availability
except Exception:
    DNSPYTHON = False                           # fallback mode

# ---------- CDN keyword list ----------
# Deduplicated list of common CDN/WAF provider tokens used for simple heuristic matching.
CDN_KEYWORDS = [
    "cloudflare", "akamai", "akamaitechnologies", "akamaiedge", "edgesuite", "edgekey",
    "fastly", "cloudfront", "amazonaws", "azureedge",
    "googleusercontent", "1e100.net", "llnw", "netdna", "maxcdn", "stackpath",
    "cdn77", "edgecast", "hwcdn", "arvancloud", "quantil", "cachefly", "cdnetworks",
    "imperva", "incapsula", "sucuri", "sitelock", "safedns", "sangfor", "sangforcdn",
    "cdn.", "cdn-"
]

# ---------- helpers ----------


def normalize_input(value: str) -> str:
    """
    Normalize a user-provided value:
      - strip whitespace
      - if it's a URL (starts with http/https), extract the hostname portion
      - return the hostname or IP string
    """
    value = value.strip()                             # remove leading/trailing whitespace
    if not value:
        return value                                  # empty stays empty
    # If the user provided a scheme (http:// or https://), parse it and extract netloc
    if value.lower().startswith(("http://", "https://")):
        parsed = urlparse(value)                      # parse the URL into components
        host = parsed.hostname                        # get only the hostname portion
        return host if host else value                # return hostname if available
    # If the user provided something like 'www.example.com/path' without scheme, try parsing
    if "/" in value and not value.count(".") == 0 and not value.replace(".", "").isdigit():
        # attempt to parse and extract hostname (best-effort)
        parsed = urlparse("http://" + value)          # add scheme to let urlparse work
        host = parsed.hostname
        return host if host else value
    return value                                      # return as-is (could be domain or IP)


def is_ip(value: str) -> bool:
    """Return True if the input value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)                   # attempt to parse as IP
        return True
    except Exception:
        return False                                   # not an IP


def resolve_host(host: str, timeout: float = 2.0) -> dict:
    """
    Resolve a hostname to A, AAAA and CNAMEs (when dnspython is available).
    If 'host' is actually an IP, this function returns empty A/AAAA/CNAME and records an explanatory error.
    Returns a dictionary with keys: host, a, aaaa, cnames, errors.
    """
    result = {"host": host, "a": [], "aaaa": [], "cnames": [], "errors": []}  # prepare output structure

    # If the input is an IP address, do not attempt A/AAAA/CNAME lookups (not meaningful).
    if is_ip(host):
        result["errors"].append("Input is an IP address; DNS A/AAAA/CNAME lookup skipped")
        return result                                  # return quickly for IPs

    # Use dnspython if present (better control and explicit record types)
    if DNSPYTHON:
        resolver = dns.resolver.Resolver()              # create resolver instance
        resolver.lifetime = timeout                     # set lifetime (total allowed time)
        resolver.timeout = timeout                      # set per-attempt timeout
        # Query A records (IPv4)
        try:
            answers = resolver.resolve(host, "A")       # attempt to resolve A
            result["a"] = [r.to_text() for r in answers]
        except Exception as e:
            result["errors"].append(f"A_error:{e}")     # log error but continue
        # Query AAAA records (IPv6)
        try:
            answers = resolver.resolve(host, "AAAA")    # attempt to resolve AAAA
            result["aaaa"] = [r.to_text() for r in answers]
        except Exception as e:
            result["errors"].append(f"AAAA_error:{e}")
        # Query CNAMEs (if present)
        try:
            answers = resolver.resolve(host, "CNAME")   # attempt to resolve CNAME
            # extract target name and strip trailing dot
            result["cnames"] = [r.target.to_text().rstrip(".") for r in answers]
        except Exception as e:
            # ignore typical 'NoAnswer' or 'NXDOMAIN' for CNAME absence; record other errors
            if "NoAnswer" not in str(e) and "NXDOMAIN" not in str(e):
                result["errors"].append(f"CNAME_error:{e}")
    else:
        # Fallback: use socket.getaddrinfo to obtain addresses (no CNAME support)
        try:
            infos = socket.getaddrinfo(host, None)      # ask OS resolver for addresses
            for fam, _, _, _, sockaddr in infos:
                if fam == socket.AF_INET:               # IPv4
                    result["a"].append(sockaddr[0])
                elif fam == socket.AF_INET6:            # IPv6
                    result["aaaa"].append(sockaddr[0])
        except Exception as e:
            result["errors"].append(f"getaddrinfo_error:{e}")
        # CNAME not available with socket fallback

    # Remove duplicates and sort for consistent output
    result["a"] = sorted(set(result["a"]))
    result["aaaa"] = sorted(set(result["aaaa"]))
    result["cnames"] = sorted(set(result["cnames"]))
    return result


def reverse_dns(ip: str) -> str:
    """
    Perform reverse DNS (PTR) lookup for an IP address.
    Returns the PTR hostname or empty string if none exists or lookup fails.
    """
    try:
        name, _, _ = socket.gethostbyaddr(ip)          # may raise if no PTR
        return name
    except Exception:
        return ""                                      # keep failures silent for main flow


def detect_cdn(cnames: list, rdns_names: list, ips: list) -> dict:
    """
    Simple heuristic-based CDN detection:
      - CNAME contains known CDN keywords -> cname_match
      - rDNS (PTR) contains known CDN keywords -> rdns_match
      - IPs spread across 3+ distinct /24 networks -> many_subnets
    Returns dict: likely_cdn (bool), flags (dict), reasons (list).
    """
    reasons = []                                      # human-readable reasons for detection
    cdn_flags = {"cname_match": False, "rdns_match": False, "many_subnets": False}

    # Check CNAME tokens for CDN keywords (case-insensitive)
    for cname in cnames:
        low = cname.lower()
        for kw in CDN_KEYWORDS:
            if kw in low:
                cdn_flags["cname_match"] = True
                reasons.append(f"cname_contains:{kw}")
                break                                 # stop at first match for this cname

    # Check rDNS (PTR) names for CDN keywords
    for r in rdns_names:
        if not r:
            continue                                # skip empty results
        low = r.lower()
        for kw in CDN_KEYWORDS:
            if kw in low:
                cdn_flags["rdns_match"] = True
                reasons.append(f"rdns_contains:{kw}")
                break

    # Calculate distinct /24 networks for IPv4 addresses as a distribution heuristic
    subnets = set()
    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)       # parse IP string
            if ip_obj.version == 4:                 # only IPv4 considered for /24 grouping
                net = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
                subnets.add(str(net.network_address))
        except Exception:
            continue                                # ignore invalid IP strings
    if len(subnets) >= 3:
        cdn_flags["many_subnets"] = True
        reasons.append(f"distinct_/24s:{len(subnets)}")

    likely = any(cdn_flags.values())                # overall boolean guess
    return {"likely_cdn": likely, "flags": cdn_flags, "reasons": reasons}


def scan_host(host_input: str, timeout: float = 2.0) -> dict:
    """
    Perform full processing for a single input item:
      - normalize input (strip URL scheme if given)
      - if input is IP: skip A/AAAA/CNAME lookups and perform reverse DNS + detection using IP
      - if input is hostname: resolve A/AAAA/CNAME, perform reverse DNS for resolved IPs, run detection
      - measure elapsed time and return structured dict
    """
    entry = {"host": host_input, "resolved": None, "rdns": {}, "detection": None, "elapsed": None}  # prepare output
    start = time.time()                              # start local timer

    host = normalize_input(host_input)               # ensure we have only hostname or IP string

    # If the normalized host is empty (bad input), record error and return
    if not host:
        entry["resolved"] = {"host": host_input, "a": [], "aaaa": [], "cnames": [], "errors": ["Invalid input"]}
        entry["detection"] = {"likely_cdn": False, "flags": {}, "reasons": ["invalid_input"]}
        entry["elapsed"] = time.time() - start
        return entry

    # If host is an IP, create a minimal resolution result and do reverse lookup
    if is_ip(host):
        # For IPs, we skip DNS A/AAAA/CNAME lookups (not applicable)
        resolved = {"host": host, "a": [], "aaaa": [], "cnames": [], "errors": ["Input is an IP; no A/AAAA/CNAME lookup"]}
        entry["resolved"] = resolved
        all_ips = [host]                              # only the single IP to inspect
        # reverse lookup for the IP
        rdns_name = reverse_dns(host)                 # may be empty
        rdns_map = {host: rdns_name}
        entry["rdns"] = rdns_map
        # run detection using the reverse name and the IP list
        entry["detection"] = detect_cdn([], [rdns_name] if rdns_name else [], all_ips)
        entry["elapsed"] = time.time() - start
        return entry

    # Otherwise, host is a domain/hostname: perform DNS resolution
    resolved = resolve_host(host, timeout=timeout)    # resolve A/AAAA/CNAME (dnspython preferred)
    entry["resolved"] = resolved

    # Compose list of all resolved IPs (IPv4 + IPv6)
    all_ips = resolved.get("a", []) + resolved.get("aaaa", [])
    rdns_map = {}
    # For each IP, attempt reverse DNS (PTR); this may be slow depending on network
    for ip in all_ips:
        rdns_name = reverse_dns(ip)                    # ptr lookup
        rdns_map[ip] = rdns_name if rdns_name else ""  # store empty string if no PTR

    entry["rdns"] = rdns_map
    # Run CDN detection using CNAMEs, rDNS names, and list of IPs
    entry["detection"] = detect_cdn(resolved.get("cnames", []), list(rdns_map.values()), all_ips)
    entry["elapsed"] = time.time() - start             # record elapsed time
    return entry


def run_bulk_scan(inputs: list, threads: int = 200, timeout: float = 2.0, cap: int = 10000) -> list:
    """
    Run scan_host concurrently for a list of inputs (domains, URLs, or IPs).
    - deduplicate inputs while preserving order
    - apply safety cap to avoid resource exhaustion
    - return list of per-host result dicts
    """
    # deduplicate preserving order
    seen = set()
    hosts = []
    for v in inputs:
        if v not in seen:
            seen.add(v)
            hosts.append(v)

    # enforce cap for safety
    if len(hosts) > cap:
        hosts = hosts[:cap]

    results = []
    # Use ThreadPoolExecutor for IO-bound parallelism
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
        # schedule all jobs and map futures back to inputs
        future_to_host = {exe.submit(scan_host, h, timeout): h for h in hosts}
        try:
            # as each future completes, collect and append results
            for fut in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[fut]
                try:
                    res = fut.result()                    # may raise if scan_host raised
                    results.append(res)                   # accumulate structured result
                    # print a compact progress line to the console
                    print(f"{host} -> CDN? {res['detection']['likely_cdn']} (reasons: {res['detection']['reasons']})")
                except Exception as e:
                    # unexpected error per-host: record as minimal error entry and continue
                    print(f"[!] Error scanning {host}: {e}")
                    results.append({"host": host, "error": str(e)})
        except KeyboardInterrupt:
            # if user interrupts (Ctrl+C), attempt to shut down the pool gracefully
            print("\n[!] Interrupted by user - shutting down executor...")
            exe.shutdown(wait=False)
    return results


def load_hosts_from_file(path: str) -> list:
    """Read host entries from a file, ignoring empty lines and comments starting with #."""
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            s = ln.strip()
            if not s or s.startswith("#"):               # skip blanks and comments
                continue
            out.append(s)                                 # preserve the raw input (we normalize later)
    return out


def generate_hosts_from_wordlist(wordlist_path: str, domain: str) -> list:
    """Generate sub.domain for each non-empty line in the wordlist file."""
    out = []
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            sub = ln.strip()
            if not sub:
                continue
            out.append(f"{sub}.{domain}")               # e.g. admin + example.com -> admin.example.com
    return out


def save_json(path: str, data: list) -> None:
    """Save structured results to a pretty-printed JSON file (UTF-8)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def save_csv(path: str, data: list) -> None:
    """
    Save a compact CSV summary:
      columns: host, resolved_ips (semicolon-separated), cnames, rdns (semicolon), likely_cdn, reasons
    """
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "resolved_ips", "cnames", "rdns", "likely_cdn", "reasons"])  # header
        for e in data:
            host = e.get("host", "")
            resolved = e.get("resolved", {}) or {}
            ips = resolved.get("a", []) + resolved.get("aaaa", [])                     # list of IP strings
            ips_str = ";".join(ips)                                                    # join with semicolon
            cnames = ";".join(resolved.get("cnames", []) or [])
            rdns_map = e.get("rdns", {}) or {}
            rdns_vals = ";".join([v for v in rdns_map.values() if v])                  # only non-empty PTRs
            detection = e.get("detection", {}) or {}
            likely = detection.get("likely_cdn", False)
            reasons = ";".join(detection.get("reasons", []))
            writer.writerow([host, ips_str, cnames, rdns_vals, str(likely), reasons])


def parse_args():
    """Parse command-line arguments and return argparse Namespace."""
    p = argparse.ArgumentParser(description="Mass DNS Resolver + CDN detection (lab/use with permission)")
    group = p.add_mutually_exclusive_group(required=True)                         # require exactly one input mode
    group.add_argument("--hosts", help="Path to file with hosts (one per line)")    # file with host entries
    group.add_argument("--domain", help="Base domain to brute subdomains against with --wordlist")
    p.add_argument("--wordlist", help="Wordlist of subdomains (one per line) - used with --domain")
    p.add_argument("-t", "--threads", type=int, default=200, help="Worker threads (default 200)")
    p.add_argument("--timeout", type=float, default=2.0, help="DNS timeout seconds (default 2.0)")
    p.add_argument("-o", "--output", help="Save JSON output to this file (optional)")
    p.add_argument("--csv", help="Also save CSV summary to this file (optional)")
    p.add_argument("--cap", type=int, default=10000, help="Max hosts to process (safety cap)")
    return p.parse_args()


def main():
    """Main entry point: parse args, build host list, run scanning, and save outputs."""
    args = parse_args()

    # Build raw inputs list: either read hosts file or generate subdomains with wordlist
    if args.hosts:
        raw_inputs = load_hosts_from_file(args.hosts)           # read each line (could be URL, domain, or IP)
    else:
        if not args.wordlist:
            print("Error: --wordlist is required with --domain")
            return
        raw_inputs = generate_hosts_from_wordlist(args.wordlist, args.domain)

    # Normalize inputs: strip URL schemes if provided (we keep the raw in 'host' field for audit)
    normalized = [normalize_input(x) for x in raw_inputs]

    print(f"[+] Targets to scan: {len(normalized)} (cap={args.cap})")  # print brief summary
    results = run_bulk_scan(normalized, threads=args.threads, timeout=args.timeout, cap=args.cap)  # run parallel scan

    # Save outputs if requested
    if args.output:
        save_json(args.output, results)
        print(f"[+] JSON saved to {args.output}")
    if args.csv:
        save_csv(args.csv, results)
        print(f"[+] CSV saved to {args.csv}")
    print("[+] Done.")


if __name__ == "__main__":
    main()
