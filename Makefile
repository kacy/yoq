ZIG ?= $(shell command -v zig)

.PHONY: build run test test-operator test-network test-integration test-contract test-sim test-gpu test-hardening test-runtime-core test-runtime-network test-runtime-cluster test-privileged clean clean-all bpf install fmt loc cache-sqlite release-patch release-minor release-cross

build:
	$(ZIG) build -Doptimize=ReleaseSafe

run:
	$(ZIG) build -Doptimize=ReleaseSafe run

test:
	$(ZIG) build -Doptimize=ReleaseSafe test

test-operator:
	$(ZIG) build -Doptimize=ReleaseSafe test-operator

test-network:
	$(ZIG) build -Doptimize=ReleaseSafe test-network

test-integration:
	$(ZIG) build -Doptimize=ReleaseSafe test-integration

test-contract:
	$(ZIG) build -Doptimize=ReleaseSafe test-contract

test-sim:
	$(ZIG) build -Doptimize=ReleaseSafe test-sim

test-gpu:
	$(ZIG) build -Doptimize=ReleaseSafe test-gpu

test-hardening:
	YOQ_SKIP_SLOW_TESTS=1 $(ZIG) build -Doptimize=ReleaseSafe test-hardening

test-runtime-core: build
	sudo env YOQ_SKIP_SLOW_TESTS=1 $(ZIG) build -Doptimize=ReleaseSafe -Drun-privileged-tests=true test-runtime-core

test-runtime-network: build
	sudo env YOQ_SKIP_SLOW_TESTS=1 $(ZIG) build -Doptimize=ReleaseSafe -Drun-privileged-tests=true test-runtime-network

test-runtime-cluster: build
	sudo env YOQ_SKIP_SLOW_TESTS=1 $(ZIG) build -Doptimize=ReleaseSafe -Drun-privileged-tests=true test-runtime-cluster

test-privileged: build
	sudo env YOQ_SKIP_SLOW_TESTS=1 $(ZIG) build -Doptimize=ReleaseSafe -Drun-privileged-tests=true test-privileged

clean:
	rm -rf zig-out .zig-cache

clean-all: clean
	rm -rf vendor/prebuilt

cache-sqlite:
	$(ZIG) build cache-sqlite

bpf:
	$(ZIG) build bpf

install: build
	cp zig-out/bin/yoq /usr/local/bin/yoq

fmt:
	zig fmt src/

loc:
	@find src -name '*.zig' | xargs wc -l | tail -1

# --- release helpers ---

CURRENT_VERSION := $(shell sed -n 's/.*\.version = "\([^"]*\)".*/\1/p' build.zig.zon)
MAJOR := $(word 1,$(subst ., ,$(CURRENT_VERSION)))
MINOR := $(word 2,$(subst ., ,$(CURRENT_VERSION)))
PATCH := $(word 3,$(subst ., ,$(CURRENT_VERSION)))

define do_release
	@echo "releasing v$(1) (was $(CURRENT_VERSION))"
	sed -i 's/\.version = "$(CURRENT_VERSION)"/.version = "$(1)"/' build.zig.zon
	sed -i 's/"version":"$(CURRENT_VERSION)"/"version":"$(1)"/g' src/api/routes.zig
	sed -i 's/"version", "$(CURRENT_VERSION)"/"version", "$(1)"/' src/lib/command_registry.zig
	sed -i 's/yoq $(CURRENT_VERSION)/yoq $(1)/' src/lib/command_registry.zig
	sed -i 's/"version":"$(CURRENT_VERSION)"/"version":"$(1)"/g' src/test_contract_http.zig
	sed -E -i 's/"software_version":"[0-9]+\.[0-9]+\.[0-9]+"/"software_version":"$(1)"/' src/api/routes/cluster_agents/cluster_routes.zig
	git add build.zig.zon src/api/routes.zig src/lib/command_registry.zig src/test_contract_http.zig src/api/routes/cluster_agents/cluster_routes.zig
	git commit -m "chore: release v$(1)"
	git tag "v$(1)"
	git push origin main "v$(1)"
endef

CROSS_TARGETS := x86_64-linux aarch64-linux riscv64-linux

release-cross:
	@for target in $(CROSS_TARGETS); do \
		echo "building $$target..."; \
		$(ZIG) build -Doptimize=ReleaseSafe -Dtarget=$$target; \
		arch=$$(echo $$target | sed 's/-linux//'); \
		mkdir -p dist; \
		cp zig-out/bin/yoq dist/yoq-linux-$$arch; \
	done
	@echo "binaries in dist/"

release-patch:
	$(call do_release,$(MAJOR).$(MINOR).$(shell echo $$(($(PATCH)+1))))

release-minor:
	$(call do_release,$(MAJOR).$(shell echo $$(($(MINOR)+1))).0)
