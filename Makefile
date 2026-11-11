# Local PQC demo stack. Recipes are POSIX sh; every target has a ## help line.
# Run `make` with no arguments to list the targets.

ROOT := $(CURDIR)
COMPOSE_FILE := $(ROOT)/docker-compose.pqc-local.yml
COMPOSE := docker compose -f "$(COMPOSE_FILE)"

# Keep the :3000 port: it must match the Caddy site address and published port
# in docker-compose.pqc-local.yml. Change all three together if 3000 is taken.
LOCAL_DOMAIN ?= localhost:3000
LOCAL_URL ?= https://$(LOCAL_DOMAIN)

ADMIN_USERNAME ?= pqcadmin
ADMIN_EMAIL ?= admin@example.test
ADMIN_PASSWORD ?= pqc-demo-password

DEMO_USERNAME ?= demo
DEMO_EMAIL ?= demo@example.test
DEMO_PASSWORD ?= pqc-demo-password

SERVICE ?=

.DEFAULT_GOAL := help

help: ## Show this help
	@printf 'Usage: make <target>\n\n'
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nOverride defaults like this: make up ADMIN_PASSWORD=secret\n'

up: ## Build and start the stack, seed the admin, open registrations, then check PQC support
	@set -e; \
	command -v docker >/dev/null 2>&1 || { printf '%s\n' "docker is not installed or not on PATH. Install Docker Desktop or Docker Engine first."; exit 1; }; \
	docker compose version >/dev/null 2>&1 || { printf '%s\n' "Docker Compose v2 is required (the 'docker compose' command, not 'docker-compose')."; exit 1; }; \
	printf '%s\n' "Building and starting the PQC demo stack." "The first build compiles libvips and ffmpeg and can take 10-25 minutes; later starts are seconds."; \
	$(COMPOSE) up -d --build; \
	printf '%s\n' "Waiting for web to become healthy..."; \
	i=0; \
	while :; do \
		id=$$($(COMPOSE) ps -q web 2>/dev/null | head -n 1); \
		status=$$(docker inspect -f '{{.State.Health.Status}}' "$$id" 2>/dev/null || true); \
		[ "$$status" = "healthy" ] && break; \
		i=$$((i + 1)); \
		if [ $$i -ge 120 ]; then \
			printf '%s\n' "web did not become healthy after four minutes. Recent logs:"; \
			$(COMPOSE) logs --tail=80 web || true; \
			exit 1; \
		fi; \
		sleep 2; \
	done; \
	$(MAKE) seed; \
	printf '\n'; \
	if $(COMPOSE) exec -T web ruby bin/pqc-doctor; then \
		printf '%s\n' "PQC runtime looks good." "Open $(LOCAL_URL) (accept the local certificate warning) and sign in as $(ADMIN_EMAIL) / $(ADMIN_PASSWORD)." "Run 'make demo' for the second account and the click path."; \
	else \
		printf '\n%s\n' "The stack is running, but the PQC check failed. ML-DSA-87 keys and badges will not work until it passes." "Run 'make doctor' for the full report, or read docs/QUICKSTART.md."; \
		exit 1; \
	fi

down: ## Stop the stack, keeping named volumes, accounts and ML-DSA keys
	@$(COMPOSE) down --remove-orphans
	@printf '%s\n' "Stopped. Data volumes were kept. Delete them with: docker compose -f docker-compose.pqc-local.yml down -v"

logs: ## Follow container logs (SERVICE=web narrows to one service)
	@$(COMPOSE) logs -f --tail=200 $(SERVICE)

status: ## Show PQC key and badge status via bin/rails pqc:status
	@set -e; \
	id=$$($(COMPOSE) ps -q web 2>/dev/null | head -n 1); \
	[ -n "$$id" ] || { printf '%s\n' "web is not running. Run 'make up' first."; exit 1; }; \
	if ! $(COMPOSE) exec -T web bin/rails -T pqc 2>/dev/null | grep -q 'pqc:status'; then \
		printf '%s\n' "pqc:status is not defined in this checkout yet (the PQC monitoring change adds it)." "Until then: 'make doctor' checks the runtime, and 'make logs' shows provisioning warnings."; \
		exit 0; \
	fi; \
	$(COMPOSE) exec -T web bin/rails pqc:status

seed: ## Create/confirm the admin account and set registrations_mode=open
	@set -e; \
	id=$$($(COMPOSE) ps -q web 2>/dev/null | head -n 1); \
	[ -n "$$id" ] || { printf '%s\n' "web is not running. Run 'make up' first."; exit 1; }; \
	printf '%s\n' "Seeding the admin account and opening registrations..."; \
	$(COMPOSE) exec -T \
		-e PQC_ADMIN_USERNAME="$(ADMIN_USERNAME)" \
		-e PQC_ADMIN_EMAIL="$(ADMIN_EMAIL)" \
		-e PQC_ADMIN_PASSWORD="$(ADMIN_PASSWORD)" \
		web bin/rails runner 'begin; def User.skip_mx_check?; true; end; Setting.registrations_mode = "open"; email = ENV.fetch("PQC_ADMIN_EMAIL"); username = ENV.fetch("PQC_ADMIN_USERNAME"); password = ENV.fetch("PQC_ADMIN_PASSWORD"); user = User.find_by(email: email); account = user&.account; if user.nil?; account = Account.find_local(username) || Account.new(username: username); user = User.new(email: email, password: password, password_confirmation: password, agreement: true, confirmed_at: Time.now.utc, approved: true, bypass_registration_checks: true); user.account = account; user.save!; end; user.mark_email_as_confirmed! unless user.confirmed?; user.approve! unless user.approved?; load Rails.root.join("db/seeds/03_roles.rb") if UserRole.find_by(name: "Owner").nil?; owner = UserRole.find_by(name: "Owner"); user.update!(role: owner) if owner && user.role_id != owner.id; puts "Admin: #{email} / #{password} (@#{account.username})"; puts "registrations_mode=#{Setting.registrations_mode}"; puts account.pqc_signed? ? "ML-DSA-87 key: present" : "ML-DSA-87 key: MISSING (run make doctor)"; rescue => e; abort "seed failed: #{e.class}: #{e.message}"; end'

demo: ## Create the second account and print exactly what to click
	@set -e; \
	id=$$($(COMPOSE) ps -q web 2>/dev/null | head -n 1); \
	[ -n "$$id" ] || { printf '%s\n' "web is not running. Run 'make up' first."; exit 1; }; \
	$(MAKE) seed; \
	$(COMPOSE) exec -T \
		-e PQC_DEMO_USERNAME="$(DEMO_USERNAME)" \
		-e PQC_DEMO_EMAIL="$(DEMO_EMAIL)" \
		-e PQC_DEMO_PASSWORD="$(DEMO_PASSWORD)" \
		-e PQC_ADMIN_USERNAME="$(ADMIN_USERNAME)" \
		-e PQC_LOCAL_URL="$(LOCAL_URL)" \
		web bin/rails runner 'begin; def User.skip_mx_check?; true; end; email = ENV.fetch("PQC_DEMO_EMAIL"); username = ENV.fetch("PQC_DEMO_USERNAME"); password = ENV.fetch("PQC_DEMO_PASSWORD"); admin = ENV.fetch("PQC_ADMIN_USERNAME"); url = ENV.fetch("PQC_LOCAL_URL"); user = User.find_by(email: email); account = user&.account; if user.nil?; account = Account.find_local(username) || Account.new(username: username); user = User.new(email: email, password: password, password_confirmation: password, agreement: true, confirmed_at: Time.now.utc, approved: true, bypass_registration_checks: true); user.account = account; user.save!; end; user.mark_email_as_confirmed! unless user.confirmed?; user.approve! unless user.approved?; begin; ActivityPub::GeneratePqcKeyService.new.call(account); rescue => e; warn "ML-DSA-87 provisioning failed: #{e.class}: #{e.message}"; end; puts ""; puts "Demo account: #{email} / #{password} (@#{account.username})"; puts ""; puts "What to click:"; puts "  1. Open #{url} and accept the local certificate warning (Advanced -> Proceed)."; puts "  2. Sign in as #{email} / #{password}."; puts "  3. Open #{url}/@#{admin} - the profile header should show a \"Post-quantum signed\" badge."; puts "  4. Open #{url}/@#{account.username} - your own profile carries the same badge."; puts ""; if account.pqc_signed?; puts "ML-DSA-87 key: present. Everything the badge needs is in place."; else; abort "ML-DSA-87 key: MISSING. Accounts work, but no badge will appear. Run \"make doctor\" for the reason."; end; rescue => e; abort "demo failed: #{e.class}: #{e.message}"; end'

doctor: ## Check Ruby, OpenSSL, ML-DSA-87 support, switches and database reachability
	@set -e; \
	id=$$($(COMPOSE) ps -q web 2>/dev/null | head -n 1); \
	if [ -z "$$id" ]; then \
		printf '%s\n' "web is not running. Run 'make up' first." "To inspect the built image without starting the stack:" "  docker compose -f docker-compose.pqc-local.yml run --rm --no-deps web ruby bin/pqc-doctor"; \
		exit 1; \
	fi; \
	$(COMPOSE) exec -T web ruby bin/pqc-doctor
