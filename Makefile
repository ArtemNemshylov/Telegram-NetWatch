.PHONY: setup install run debug test docker-up docker-down docker-logs docker-rebuild help

DOMAIN ?= pornhub.com
PYTHON  ?= python3

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  Override defaults:  make test DOMAIN=xhamster.com"

setup: ## Copy .env.example → .env (edit it before running)
	@if [ -f .env ]; then \
		echo "  .env already exists — skipping. Edit it manually if needed."; \
	else \
		cp .env.example .env; \
		echo "  .env created. Open it and fill in TELEGRAM_TOKEN and TELEGRAM_CHAT_ID."; \
	fi

# rebuilt whenever requirements.txt changes
.installed: requirements.txt
	pip install -r requirements.txt
	@touch .installed

install: .installed ## Install Python dependencies

run: .installed ## Start the monitor (requires sudo for packet capture)
	sudo $(PYTHON) monitor.py

debug: .installed ## Start in debug mode — prints every DNS query
	sudo DEBUG=true $(PYTHON) monitor.py

test: .installed ## Test watchlist lookup + Telegram for a domain (make test DOMAIN=pornhub.com)
	$(PYTHON) monitor.py --test $(DOMAIN)

docker-up: ## Build image and start container (detached)
	docker compose up -d --build

docker-down: ## Stop and remove container
	docker compose down

docker-logs: ## Tail container logs
	docker compose logs -f

docker-rebuild: docker-down docker-up ## Rebuild and restart container
