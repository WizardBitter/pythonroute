#!/usr/bin/env python3
import pyfiglet
import argparse
import socket
import time
import sys
import os
from scapy.all import IP, ICMP, sr1 # Import necessary Scapy components
import requests
import json
from datetime import datetime
from statistics import mean, stdev

# Add color and symbols support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback: define dummy color codes if colorama is not installed
    class Dummy:
        RESET = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''
    Fore = Style = Dummy()

# Symbols
SYMBOL_SUCCESS = f"{Fore.GREEN}✔{Style.RESET_ALL}"
SYMBOL_FAIL = f"{Fore.RED}✖{Style.RESET_ALL}"
SYMBOL_WARN = f"{Fore.YELLOW}!{Style.RESET_ALL}"
SYMBOL_ARROW = f"{Fore.CYAN}➜{Style.RESET_ALL}"
SYMBOL_STAR = f"{Fore.MAGENTA}★{Style.RESET_ALL}"

# Custom hop status symbols
HOP_SYMBOL_OK = f"{Fore.GREEN}✈️ {Style.RESET_ALL}"    # Success
HOP_SYMBOL_PARTIAL = f"{Fore.YELLOW}⚠️ {Style.RESET_ALL}" # Partial loss
HOP_SYMBOL_TIMEOUT = f"{Fore.RED}🛑{Style.RESET_ALL}"     # Timeout
HOP_SYMBOL_DEST = f"{Fore.MAGENTA}🏁{Style.RESET_ALL}"    # Destination reached

ascii_banner = pyfiglet.figlet_format("Python Route")
print(f"{Fore.CYAN}{ascii_banner}{Style.RESET_ALL}")

print(f"{Fore.YELLOW}{SYMBOL_ARROW} Welcome to the Enhanced Python Route Tracer!{Style.RESET_ALL}")

print(Fore.BLUE + "_" * 50 + Style.RESET_ALL)
target = input(f"{Fore.GREEN}Enter the target address: {Style.RESET_ALL}")
print(Fore.BLUE + "_" * 50 + Style.RESET_ALL)
print(f"{Fore.CYAN}{SYMBOL_STAR} Scanning Target: {Fore.YELLOW}{target}{Style.RESET_ALL}")
print(f"{Fore.CYAN}{SYMBOL_STAR} Scanning started at: {Fore.YELLOW}{datetime.now()}{Style.RESET_ALL}")
print(Fore.BLUE + "_" * 50 + Style.RESET_ALL)


#Cache for IP info to avoid redundant API calls
ip_info_cache = {}

def get_ip_info(ip_address):
    """Fetches Geolocation, ASN, Timezone, Abuse info for an IP using ipinfo.io"""
    if ip_address in ip_info_cache:
        return ip_info_cache[ip_address]
    # Basic private IP check (expand if needed)
    if is_private_ip(ip_address):
        return {"hostname": "(Private IP)", "city": "", "region": "", "country": "", "org": "", "loc": "", "timezone": "", "abuse": ""}

    try:
        # Use a free token if you have one for higher limits, otherwise it's anonymous
        # response = requests.get(f"https://ipinfo.io/{ip_address}/json?token=YOUR_TOKEN")
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        response.raise_for_status() # Raise an exception for bad status codes
        data = response.json()
        # Extract abuse contact if available
        abuse_contact = data.get('abuse', {}).get('email', '') if isinstance(data.get('abuse'), dict) else ''
        info = {
            "hostname": data.get('hostname', '(No hostname)'),
            "city": data.get('city', ''),
            "region": data.get('region', ''),
            "country": data.get('country', ''),
            "org": data.get('org', ''),
            "loc": data.get('loc', ''), # Latitude,Longitude
            "timezone": data.get('timezone', ''),
            "abuse": abuse_contact
        }
        ip_info_cache[ip_address] = info
        return info
    except requests.exceptions.RequestException as e:
        print(f"\n{Fore.RED}{SYMBOL_WARN} API Error for {ip_address}: {e}{Style.RESET_ALL}", file=sys.stderr)
        return {"hostname": "(API Error)", "city": "", "region": "", "country": "", "org": "", "loc": "", "timezone": "", "abuse": ""}
    except json.JSONDecodeError:
        print(f"\n{Fore.RED}{SYMBOL_WARN} API Error: Could not decode JSON response for {ip_address}{Style.RESET_ALL}", file=sys.stderr)
        return {"hostname": "(API Error)", "city": "", "region": "", "country": "", "org": "", "loc": "", "timezone": "", "abuse": ""}


def resolve_hostname(ip_address):
    """Attempts to resolve hostname using system's resolver (reverse DNS)."""
    if is_private_ip(ip_address):
        return "(Private IP)"
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        # Fallback to ipinfo if system resolver fails or ipinfo has a hostname
        info = get_ip_info(ip_address)
        return info.get("hostname", ip_address) # Return ipinfo hostname or IP if unavailable


def is_private_ip(ip_address):
    """Checks if an IP address is private."""
    return (
        ip_address.startswith("192.168.") or
        ip_address.startswith("10.") or
        ip_address.startswith("172.")
    )


def get_all_hop_info(ip_address):
    """Fetches all enrichment info (geo, ASN, WHOIS) for a hop."""
    info = get_ip_info(ip_address)
    hostname = resolve_hostname(ip_address)
    return {
        "ip": ip_address,
        "hostname": hostname,
        "geo": f"{info.get('city','')}, {info.get('region','')}, {info.get('country','')}",
        "timezone": info.get('timezone',''),
        "asn": info.get('org',''),
        "abuse": info.get('abuse','')
    }


def print_hop_info(ttl, hop_ip, hop_info, rtt_str, hop_status):
    """Prints hop information in a consistent, vertical format, with status symbol."""
    print(f"{hop_status}{Fore.CYAN}{ttl:<3} {hop_ip} ({hop_info['hostname']}){Style.RESET_ALL}")
    print(f"{Fore.GREEN}    RTT: {rtt_str}{Style.RESET_ALL}")
    geo_tz = f"{hop_info['geo']} | {hop_info['timezone']}".strip(' |')
    if geo_tz and geo_tz != ', ,' and geo_tz != ', , ':
        print(f"{Fore.MAGENTA}    Geo: {geo_tz}{Style.RESET_ALL}")
    if hop_info['asn'] or hop_info['abuse']:
        print(f"{Fore.YELLOW}    ASN: {hop_info['asn']} | Abuse: {hop_info['abuse']}{Style.RESET_ALL}")
    print()


def main(target, max_hops=30, timeout=1, probes_per_hop=3):
    """Performs the enhanced traceroute."""
    try:
        dest_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{Fore.RED}{SYMBOL_WARN} Unable to resolve {target}{Style.RESET_ALL}")
        return
    print(f"{Fore.CYAN}Traceroute to {target} ({dest_ip}), {max_hops} hops max, {probes_per_hop} probes per hop{Style.RESET_ALL}")
    reached_dest = False
    for ttl in range(1, max_hops + 1):
        rtts = []
        hop_ip = None
        received_probes = 0
        for probe in range(probes_per_hop):
            pkt = IP(dst=dest_ip, ttl=ttl) / ICMP()
            start = time.time()
            reply = sr1(pkt, verbose=0, timeout=timeout)
            end = time.time()
            if reply is not None:
                hop_ip = reply.src
                rtts.append((end - start) * 1000)
                received_probes += 1
                if reply.src == dest_ip:
                    reached_dest = True
            else:
                rtts.append(None)
        if hop_ip:
            hop_info = get_all_hop_info(hop_ip)
            valid_rtts = [r for r in rtts if r is not None]
            # Choose symbol for this hop
            if valid_rtts:
                avg_rtt = mean(valid_rtts)
                rtt_str = f"{avg_rtt:.2f} ms"
                if len(valid_rtts) > 1:
                    rtt_str += f" (±{stdev(valid_rtts):.2f})"
                loss_perc = (1 - (received_probes / probes_per_hop)) * 100
                if loss_perc > 0:
                    rtt_str += f" [{loss_perc:.0f}% loss]"
                    hop_status = HOP_SYMBOL_PARTIAL
                else:
                    hop_status = HOP_SYMBOL_OK
            elif received_probes > 0:
                loss_perc = (1 - (received_probes / probes_per_hop)) * 100
                rtt_str = f"* [{loss_perc:.0f}% loss]"
                hop_status = HOP_SYMBOL_PARTIAL
            else:
                rtt_str = "* [100% loss]"
                hop_status = HOP_SYMBOL_TIMEOUT
            # Destination reached symbol
            if reached_dest:
                hop_status = HOP_SYMBOL_DEST
            print_hop_info(ttl, hop_ip, hop_info, rtt_str, hop_status)
        else:
            print(f"{HOP_SYMBOL_TIMEOUT}{Fore.RED}{SYMBOL_WARN}{ttl:<3} Request timed out.{Style.RESET_ALL}\n")
        if reached_dest:
            print(f"\n{Fore.GREEN}{SYMBOL_SUCCESS} Destination reached.{Style.RESET_ALL}")
            break
    if not reached_dest:
        print(f"\n{Fore.RED}{SYMBOL_WARN} Traceroute incomplete. Max hops ({max_hops}) reached.{Style.RESET_ALL}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Enhanced Traceroute Tool")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="Set the max number of hops (max TTL value).")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Set the time (in seconds) to wait for a response to a probe.")
    parser.add_argument("-p", "--probes", type=int, default=3, help="Number of probes to send per hop.")
    args = parser.parse_args()

    try:
        # Basic check for root/admin privileges needed for raw sockets
        if sys.platform != "win32" and os.geteuid() != 0:
            print(f"{Fore.YELLOW}{SYMBOL_WARN} Warning: This script likely requires root privileges (use sudo) to send raw packets.{Style.RESET_ALL}", file=sys.stderr)
        elif sys.platform == "win32":
            print(f"{Fore.YELLOW}{SYMBOL_WARN} Warning: This script likely requires Administrator privileges on Windows.{Style.RESET_ALL}", file=sys.stderr)

        main(target, args.max_hops, args.timeout, args.probes)
        print(f"{Fore.CYAN}{SYMBOL_STAR} Scan completed at: {datetime.now()}{Style.RESET_ALL}")
        print("_" * 50)
    except KeyboardInterrupt:
        print(f"{Fore.CYAN}{SYMBOL_STAR} Scan cancelled by user.{Style.RESET_ALL}")
        print("_" * 50)
        sys.exit()
