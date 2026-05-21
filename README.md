# Telegram NetWatch

Monitors DNS traffic on your local network and sends a Telegram notification whenever a device visits a domain from your watchlist (e.g. adult content sites).

Captures **UDP port 53** queries using Scapy. Subdomain matching included — tracking `pornhub.com` also catches `www.pornhub.com`, `cdn.pornhub.com`, etc.

> **Note on DNS-over-HTTPS (DoH):** Modern browsers (Chrome, Firefox) may bypass UDP 53 using DoH. To catch those queries too, disable DoH in the browser settings or block DoH providers at the router level.

---

## How it works

```
Device on your network
  └─▶ DNS query (UDP 53)
        └─▶ Telegram NetWatch captures it
              └─▶ domain in watchlist?
                    └─▶ YES → Telegram notification 👁
```

---

## Quick start

### 1. Clone & install

```bash
git clone <repo-url>
cd telegram-netwatch
make install
```

### 2. Configure

```bash
make setup        # creates .env from .env.example
```

Open `.env` and fill in the two required values:

| Variable | How to get it |
|---|---|
| `TELEGRAM_TOKEN` | Message [@BotFather](https://t.me/BotFather) → `/newbot` |
| `TELEGRAM_CHAT_ID` | Message [@userinfobot](https://t.me/userinfobot) → `/start` |

### 3. Verify setup

```bash
make test                        # tests pornhub.com (default)
make test DOMAIN=xhamster.com    # test any domain
```

You should see `in watchlist ✅` in the terminal and receive a Telegram notification.

### 4. Run

```bash
make run          # requires sudo (raw packet capture)
```

---

## Docker

```bash
make setup        # create .env first
make docker-up    # build + start in background
make docker-logs  # tail logs
make docker-down  # stop
```

> Docker uses `network_mode: host` to see LAN traffic.  
> This works on **Linux**. On macOS Docker Desktop, host networking is not supported — run natively with `make run` instead.

---

## Configuration

All settings live in `.env` (see `.env.example` for descriptions):

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_TOKEN` | — | **Required.** Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | — | **Required.** Your chat or group ID |
| `BLOCKLIST_URL` | chadmayfield's adult content list | URL of a plain-text domain watchlist |
| `REFRESH_HOURS` | `24` | How often to re-download the watchlist |
| `COOLDOWN_SEC` | `300` | Seconds before re-notifying for the same device+domain |
| `IFACE` | auto | Network interface to sniff (`en0`, `eth0`, …) |
| `DEBUG` | `false` | Print every DNS query, not just tracked ones |

---

## Makefile reference

```
make setup          Copy .env.example → .env
make install        Install Python dependencies
make run            Start monitor (sudo)
make debug          Start with DEBUG=true (sudo)
make test           Test pornhub.com against watchlist + Telegram
make test DOMAIN=…  Test a custom domain
make docker-up      Build and start Docker container
make docker-down    Stop Docker container
make docker-logs    Tail Docker logs
make docker-rebuild Rebuild and restart Docker container
```
