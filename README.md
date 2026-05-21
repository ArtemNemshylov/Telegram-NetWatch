# Telegram NetWatch

DNS proxy that tracks your network traffic and sends a Telegram notification when any device visits a domain from the watchlist (e.g. adult content).

Acts as a **DNS server** — all queries pass through it, so it sees traffic from every device on the network. No packet sniffing, no promiscuous mode.

---

## How it works

```
 Router DHCP → sets DNS = this machine's IP
                          │
 iPhone  ──┐              ▼
 Android ──┼──▶  Telegram NetWatch (UDP 53)
 Laptop  ──┘       │            │
                   │            └─▶ 8.8.8.8 (upstream DNS)
                   │
                   └─▶ domain in watchlist?
                             └─▶ YES → Telegram 👁
```

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

### 3. Verify setup

```bash
make test                       # tests pornhub.com (default)
make test DOMAIN=xhamster.com   # test any domain
```

### 4. Run

```bash
make run   # requires sudo — port 53 is privileged
```

### 5. Point your network at it

In your **router settings**, set the Primary DNS to this machine's local IP (e.g. `192.168.1.100`).  
All devices that connect to the router will automatically use NetWatch as their DNS server.

> To find your machine's local IP: `ipconfig getifaddr en0` (macOS) or `hostname -I` (Linux)

---

## Docker (Linux only)

```bash
make setup
make docker-up    # build + start in background
make docker-logs  # tail logs
make docker-down  # stop
```

> Uses `network_mode: host` — works on **Linux**. On macOS Docker Desktop, host networking is not supported; run natively with `make run`.

---

## Configuration

All settings in `.env` (see `.env.example` for full list):

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_TOKEN` | — | **Required.** Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | — | **Required.** Your chat or group ID |
| `UPSTREAM_DNS` | `8.8.8.8` | DNS server to forward queries to |
| `LISTEN_PORT` | `53` | Port to listen on |
| `BLOCKLIST_URL` | chadmayfield's list | URL of a plain-text domain watchlist |
| `REFRESH_HOURS` | `24` | How often to re-download the watchlist |
| `COOLDOWN_SEC` | `300` | Seconds before re-notifying for the same device+domain |
| `DEBUG` | `false` | Print every DNS query, not just tracked ones |

---

## Makefile reference

```
make setup           Copy .env.example → .env
make install         Install Python dependencies
make run             Start DNS proxy (sudo)
make debug           Start with DEBUG=true (sudo)
make test            Test pornhub.com against watchlist + Telegram
make test DOMAIN=…   Test a custom domain
make docker-up       Build and start Docker container
make docker-down     Stop Docker container
make docker-logs     Tail Docker logs
make docker-rebuild  Rebuild and restart Docker container
```
