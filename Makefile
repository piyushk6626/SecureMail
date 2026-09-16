.PHONY: doctor sync lint test frontend-build frontend-dev dashboard-api dashboard-catalog e2e analyzer-lock zeek-image tshark-image docs-check

ifeq ($(shell uname -s),Darwin)
export DYLD_FALLBACK_LIBRARY_PATH := /opt/homebrew/lib:$(if $(DYLD_FALLBACK_LIBRARY_PATH),$(DYLD_FALLBACK_LIBRARY_PATH),)
endif

UV ?= uv
NPM ?= npm
DASHBOARD_DATA_ROOT ?= out/local-dashboard

doctor:
	$(UV) run python tools/doctor.py

sync:
	$(UV) sync --all-extras
	$(NPM) --prefix frontend ci

lint:
	$(UV) run ruff check src tests tools
	$(UV) run ruff format --check src tests tools
	$(UV) run mypy
	$(UV) run lint-imports
	$(NPM) --prefix frontend run lint
	$(NPM) --prefix frontend run typecheck

test:
	$(UV) run pytest tests/unit tests/support tests -q --ignore=tests/fixtures/generators
	$(NPM) --prefix frontend run test

frontend-build:
	$(NPM) --prefix frontend run build

frontend-dev:
	$(NPM) --prefix frontend run dev

# Default local dashboard API: uploads are writable and one worker is attached.
dashboard-api:
	SECUREMAIL_DATA_ROOT=$(DASHBOARD_DATA_ROOT) \
	SECUREMAIL_REPORT_ROOT=$(DASHBOARD_DATA_ROOT) \
	SECUREMAIL_START_WORKER=1 \
		$(UV) run uvicorn securemail.api.main:app --host 127.0.0.1 --port 8000

# Fixture browsing only. A separate port prevents replacing the upload-capable API.
dashboard-catalog:
	SECUREMAIL_REPORT_ROOT=tests/fixtures/dashboard \
	SECUREMAIL_START_WORKER=0 \
		$(UV) run uvicorn securemail.api.main:app --host 127.0.0.1 --port 8001

e2e:
	$(NPM) --prefix frontend run test:e2e

analyzer-lock:
	$(UV) run python tools/refresh_analyzer_lock.py

zeek-image:
	docker build -f docker/zeek/Dockerfile \
		--build-arg ZEEK_BUNDLE_SHA256=$$($(UV) run python tools/refresh_analyzer_lock.py --print-bundle-sha) \
		--build-arg ZEEK_BASE_DIGEST=sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3 \
		-t securemail/zeek:step0 .

tshark-image:
	docker build -f docker/tshark/Dockerfile -t securemail/tshark:step0 .

docs-check:
	$(UV) run python tools/check_docs.py
