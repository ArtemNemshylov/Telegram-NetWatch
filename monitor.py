#!/usr/bin/env python3
"""
Telegram NetWatch — DNS proxy with Telegram alerts.
Listens on UDP 53, forwards every query to an upstream DNS server,
and sends a Telegram notification when a device visits a tracked domain.

Setup: point your router's DNS (or each device's DNS) to this machine's IP.
Requires root/sudo — port 53 is privileged.
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
from dnslib import DNSRecord

load_dotenv()

TELEGRAM_TOKEN   = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
UPSTREAM_DNS     = os.environ.get('UPSTREAM_DNS', '8.8.8.8')
UPSTREAM_PORT    = int(os.environ.get('UPSTREAM_PORT', '53'))
LISTEN_HOST      = os.environ.get('LISTEN_HOST', '0.0.0.0')
LISTEN_PORT      = int(os.environ.get('LISTEN_PORT', '53'))
BLOCKLIST_URL    = os.environ.get(
    'BLOCKLIST_URL',
    'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list',
)
REFRESH_HOURS = int(os.environ.get('REFRESH_HOURS', '24'))
COOLDOWN_SEC  = int(os.environ.get('COOLDOWN_SEC', '300'))
DEBUG         = os.environ.get('DEBUG', '').lower() in ('1', 'true', 'yes')

# sorted list → O(log n) bisect, ~2x less RAM than a hash set
blocklist: list[str] = []
device_cache: dict[str, str] = {}
cooldown_cache: dict[str, float] = {}
lock = threading.Lock()


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
        with lock:
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


# ── notify ────────────────────────────────────────────────────────────────────

def notify(src_ip: str, domain: str) -> None:
    cooldown_key = f'{src_ip}:{domain}'
    now = time.monotonic()
    if cooldown_cache.get(cooldown_key, 0) + COOLDOWN_SEC > now:
        return
    cooldown_cache[cooldown_key] = now

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


# ── dns proxy ─────────────────────────────────────────────────────────────────

def handle_query(sock: socket.socket, data: bytes, client_addr: tuple) -> None:
    try:
        request = DNSRecord.parse(data)
        domain = str(request.q.qname).rstrip('.')
        src_ip = client_addr[0]

        if DEBUG:
            print(f'[DNS] {src_ip} → {domain}', flush=True)

        # forward raw bytes to upstream — no modification
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.settimeout(5)
        upstream.sendto(data, (UPSTREAM_DNS, UPSTREAM_PORT))
        response, _ = upstream.recvfrom(4096)
        upstream.close()

        # reply to client first, then check watchlist (keeps latency low)
        sock.sendto(response, client_addr)

        if is_tracked(domain):
            notify(src_ip, domain)

    except Exception as e:
        print(f'[!] Query error from {client_addr}: {e}', flush=True)


def start_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((LISTEN_HOST, LISTEN_PORT))
    except PermissionError:
        print(f'[!] Cannot bind to port {LISTEN_PORT} — run with sudo.', flush=True)
        sys.exit(1)
    except OSError as e:
        print(f'[!] Bind failed: {e}', flush=True)
        sys.exit(1)

    print(f'[*] DNS proxy listening on {LISTEN_HOST}:{LISTEN_PORT}', flush=True)
    print(f'[*] Upstream DNS: {UPSTREAM_DNS}:{UPSTREAM_PORT}', flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            threading.Thread(target=handle_query, args=(sock, data, addr), daemon=True).start()
        except Exception as e:
            print(f'[!] Server loop error: {e}', flush=True)


# ── cli commands ──────────────────────────────────────────────────────────────

def cmd_test(domain: str) -> None:
    """Test watchlist lookup and Telegram delivery for a given domain."""
    load_blocklist()
    domain = domain.lower().strip()
    tracked = is_tracked(domain)
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
            f'Watchlist: {len(blocklist):,} domains\n'
            f'Upstream DNS: {UPSTREAM_DNS}'
        )
        print('[*] Startup message sent to Telegram', flush=True)
    else:
        print('[WARN] TELEGRAM_TOKEN / TELEGRAM_CHAT_ID not set — notifications will print to stdout only', flush=True)

    threading.Thread(target=refresh_loop, daemon=True).start()
    print(f'[*] Cooldown: {COOLDOWN_SEC}s per device+domain', flush=True)
    start_server()
