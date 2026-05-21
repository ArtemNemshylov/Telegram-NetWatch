# Telegram NetWatch

Monitors DNS traffic on your local network and sends a Telegram notification when a device visits a domain from the watchlist (adult content, etc.).

Works in two modes:
- **MitM mode** — ARP-spoofs the LAN, intercepts DNS with Scapy. No router changes needed.
- **DNS proxy mode** — acts as a DNS server. Requires pointing your router's DNS to this machine.

---

## How it works (MitM mode)

```
 [Phone]  ──ARP spoofed──▶  [NetWatch]  ──forwards──▶  [8.8.8.8]
              thinks we                    real DNS
              are the router               response

 Every DNS query passes through NetWatch:
   domain in watchlist? → Telegram notification 👁
```

1. Sends fake ARP replies to all devices: "I am the router"
2. Sends fake ARP replies to the router: "I am each device"
3. Enables IP forwarding so non-DNS traffic passes through transparently
4. Scapy intercepts every DNS query, forwards it to upstream, checks the watchlist
5. On Ctrl+C: restores real ARP tables, disables forwarding — network returns to normal

---

## Quick start

### 1. Clone & install

```bash
git clone https://github.com/ArtemNemshylov/Telegram-NetWatch.git
cd Telegram-NetWatch
make install
```

### 2. Configure

```bash
make setup   # creates .env from .env.example
```

Open `.env` and fill in the two required values:

| Variable | How to get it |
|---|---|
| `TELEGRAM_TOKEN` | Message [@BotFather](https://t.me/BotFather) → `/newbot` |
| `TELEGRAM_CHAT_ID` | Message [@userinfobot](https://t.me/userinfobot) → `/start` |

### 3. Verify Telegram works

```bash
make test                       # tests pornhub.com (default)
make test DOMAIN=xhamster.com   # test any domain
```

### 4. Run

```bash
make run-mitm   # MitM mode — no router changes (recommended)
make run        # DNS proxy mode — requires router DNS change
```

Both require `sudo` (raw packet capture and port 53 binding).

---

## MitM mode options

```env
# Monitor specific devices only (default: all hosts on the network)
TARGET_IPS=192.168.1.42,192.168.1.55

# Override auto-detected gateway
GATEWAY_IP=192.168.1.1

# Override auto-detected network range
NETWORK=192.168.1.0/24

# Seconds between ARP bursts (default: 2)
SPOOF_INTERVAL=2
```

---

## Docker (Linux only)

```bash
make setup
make docker-up    # build + start in background
make docker-logs  # tail logs
make docker-down  # stop
```

> `network_mode: host` is required and only works on **Linux**.
> On macOS, run natively with `make run-mitm`.

---

## Configuration reference

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_TOKEN` | — | **Required.** Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | — | **Required.** Your chat or group ID |
| `UPSTREAM_DNS` | `8.8.8.8` | DNS server to forward queries to |
| `BLOCKLIST_URL` | chadmayfield's adult list | URL of a plain-text domain watchlist |
| `REFRESH_HOURS` | `24` | How often to re-download the watchlist |
| `COOLDOWN_SEC` | `300` | Seconds before re-notifying for same device+domain |
| `DEBUG` | `false` | Print every DNS query to stdout |

---

## Makefile reference

```
make setup           Copy .env.example → .env
make install         Install Python dependencies
make run             DNS proxy mode (sudo)
make run-mitm        MitM mode — no router changes (sudo)
make debug           DNS proxy with DEBUG=true (sudo)
make test            Test pornhub.com against watchlist + Telegram
make test DOMAIN=…   Test a custom domain
make docker-up       Build and start Docker container
make docker-down     Stop Docker container
make docker-logs     Tail Docker logs
make docker-rebuild  Rebuild and restart Docker container
```

---

## Limitations

### DNS-over-HTTPS (DoH)
The biggest blind spot. Chrome, Firefox, and iOS/Android can send DNS queries over HTTPS (port 443, encrypted) directly to Cloudflare or Google — completely bypassing UDP port 53. NetWatch won't see those queries.

**Workarounds:**
- Disable DoH in browser settings (Chrome: `chrome://settings/security` → Secure DNS → off)
- Block DoH providers at the router level (block `1.1.1.1`, `8.8.8.8`, `9.9.9.9` on port 443)
- Use Pi-hole as the DNS server and disable DoH on devices

### DNS caching
If a device already has a domain cached, it won't make a new DNS query until the TTL expires. NetWatch will miss the visit entirely during the cache window (typically 5 minutes to 24 hours).

### WiFi client isolation
Some routers have AP Isolation enabled, which blocks direct communication between WiFi clients. ARP spoofing won't reach other devices in this case. Usually disabled on home routers but common in public/office WiFi.

### IPv6
Only IPv4 DNS (A records) is intercepted. Devices using IPv6 DNS (`AAAA` queries over IPv6) are not monitored. Most home networks are IPv4-only, so this rarely matters.

### Local machine not monitored in MitM mode
The machine running NetWatch bypasses its own interceptor (to avoid routing loops). To monitor the local machine too, use `make run` (DNS proxy mode) and point local DNS to `127.0.0.1`.

### Requires sudo
Both modes require root privileges — MitM for raw packet capture (Scapy), DNS proxy for binding to port 53.

### macOS only for native mode
Docker's `network_mode: host` doesn't work on macOS Docker Desktop. Run natively on macOS. On a Linux server or Raspberry Pi, Docker works fine.

### ARP spoof is detectable
Any device running ARP monitoring software (e.g. XArp) can detect the spoofing. Not an issue for personal home network use.

---

> **Use only on networks you own or have permission to monitor.**
