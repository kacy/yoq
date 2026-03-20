.PHONY: build run test test-integration test-privileged clean clean-all bpf install fmt loc cache-sqlite release-patch release-minor release-cross

build:
	zig build -Doptimize=ReleaseSafe

run:
	zig build run -Doptimize=ReleaseSafe

test:
	zig build test -Doptimize=ReleaseSafe

test-integration:
	zig build test-integration -Doptimize=ReleaseSafe

test-privileged: build
	sudo zig build test-privileged -Doptimize=ReleaseSafe

clean:
	rm -rf zig-out .zig-cache

clean-all: clean
	rm -rf vendor/prebuilt

cache-sqlite:
	zig build cache-sqlite

bpf:
	zig build bpf

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
	git add build.zig.zon src/api/routes.zig src/lib/command_registry.zig
	git commit -m "chore: release v$(1)"
	git tag "v$(1)"
	git push origin main "v$(1)"
endef

CROSS_TARGETS := x86_64-linux aarch64-linux riscv64-linux

release-cross:
	@for target in $(CROSS_TARGETS); do \
		echo "building $$target..."; \
		zig build -Doptimize=ReleaseSafe -Dtarget=$$target; \
		arch=$$(echo $$target | sed 's/-linux//'); \
		mkdir -p dist; \
		cp zig-out/bin/yoq dist/yoq-linux-$$arch; \
	done
	@echo "binaries in dist/"

release-patch:
	$(call do_release,$(MAJOR).$(MINOR).$(shell echo $$(($(PATCH)+1))))

release-minor:
	$(call do_release,$(MAJOR).$(shell echo $$(($(MINOR)+1))).0)
