#!/usr/bin/env python3
"""
Telegram NetWatch — DNS-based network monitor with Telegram alerts.
Captures UDP port 53 queries and sends a notification when a device visits a tracked domain.
Requires root/sudo for packet capture.
"""
import os
import sys
import time
import socket
import threading
import re
import bisect
import requests
from datetime import datetime
from dotenv import load_dotenv
from scapy.all import sniff, DNS, DNSQR, IP, get_if_list

load_dotenv()

TELEGRAM_TOKEN   = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
BLOCKLIST_URL    = os.environ.get(
    'BLOCKLIST_URL',
    'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list',
)
REFRESH_HOURS = int(os.environ.get('REFRESH_HOURS', '24'))
COOLDOWN_SEC  = int(os.environ.get('COOLDOWN_SEC', '300'))
IFACE         = os.environ.get('IFACE', '')
DEBUG         = os.environ.get('DEBUG', '').lower() in ('1', 'true', 'yes')

# sorted list → O(log n) bisect lookup, ~2x less RAM than a hash set
blocklist: list[str] = []
device_cache: dict[str, str] = {}
cooldown_cache: dict[str, float] = {}
lock = threading.Lock()


# ── blocklist ─────────────────────────────────────────────────────────────────

def load_blocklist() -> None:
    global blocklist
    print('[*] Downloading blocklist…', flush=True)
    try:
        resp = requests.get(BLOCKLIST_URL, timeout=60)
        resp.raise_for_status()
        domains = sorted({
            line.strip().lower()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith('#')
        })
        with lock:
            blocklist = domains
        print(f'[*] Blocklist loaded: {len(blocklist):,} domains', flush=True)
    except Exception as e:
        print(f'[!] Blocklist download failed: {e}', flush=True)
        sys.exit(1)


def refresh_loop() -> None:
    while True:
        time.sleep(REFRESH_HOURS * 3600)
        load_blocklist()


def is_blocked(domain: str) -> bool:
    domain = domain.lower().rstrip('.')
    with lock:
        bl = blocklist

    def hit(d: str) -> bool:
        idx = bisect.bisect_left(bl, d)
        return idx < len(bl) and bl[idx] == d

    if hit(domain):
        return True
    # walk up: sub.example.com → example.com
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


# ── device name ───────────────────────────────────────────────────────────────

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


# ── packet handler ────────────────────────────────────────────────────────────

def packet_handler(pkt) -> None:
    try:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP)):
            return
        if pkt[DNS].qr != 0:
            return

        src_ip = pkt[IP].src
        domain = pkt[DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')

        if len(domain) < 4:
            return

        blocked = is_blocked(domain)
        if DEBUG:
            print(f'[{"TRACK" if blocked else "     "}] {src_ip} → {domain}', flush=True)

        if not blocked:
            return

        device = get_device_name(src_ip)
        cooldown_key = f'{src_ip}:{domain}'
        now = time.monotonic()

        if cooldown_cache.get(cooldown_key, 0) + COOLDOWN_SEC > now:
            return
        cooldown_cache[cooldown_key] = now

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

    except Exception as e:
        print(f'[!] packet_handler error: {e}', flush=True)


# ── cli commands ──────────────────────────────────────────────────────────────

def cmd_test(domain: str) -> None:
    """Test watchlist lookup and Telegram delivery for a given domain."""
    load_blocklist()
    domain = domain.lower().strip()
    tracked = is_blocked(domain)
    print(f'[TEST] {domain} → {"in watchlist ✅" if tracked else "not in watchlist ❌"}', flush=True)
    if not tracked:
        return
    ts = datetime.now().strftime('%H:%M:%S  %d.%m.%Y')
    send_telegram(
        f'🧪 <b>Test notification</b>\n\n'
        f'🌐 <b>Domain:</b> <code>{domain}</code>\n'
        f'🕐 <b>Time:</b> {ts}'
    )
    print('[TEST] Telegram message sent — check your chat.', flush=True)


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--test':
        cmd_test(sys.argv[2])
        sys.exit(0)

    load_blocklist()

    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        send_telegram(
            f'✅ <b>Telegram NetWatch started</b>\n'
            f'Watchlist: {len(blocklist):,} domains'
        )
        print('[*] Startup message sent to Telegram', flush=True)
    else:
        print('[WARN] TELEGRAM_TOKEN / TELEGRAM_CHAT_ID not set — notifications will print to stdout only', flush=True)

    threading.Thread(target=refresh_loop, daemon=True).start()

    if IFACE:
        ifaces = [IFACE]
    else:
        all_ifaces = get_if_list()
        # en* = physical adapters on macOS (WiFi/Ethernet); eth* on Linux
        ifaces = [i for i in all_ifaces if re.match(r'^(en|eth)\d+$', i)]
        if not ifaces:
            skip = re.compile(r'^(lo|anpi|utun|bridge|gif|stf|awdl|llw|ap)')
            ifaces = [i for i in all_ifaces if not skip.match(i)]

    print(f'[*] Sniffing on: {ifaces}', flush=True)
    print(f'[*] Cooldown: {COOLDOWN_SEC}s per device+domain', flush=True)
    print('[*] Waiting for DNS queries…', flush=True)

    sniff(filter='udp port 53', prn=packet_handler, store=False, iface=ifaces)
