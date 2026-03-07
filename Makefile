.PHONY: build run test test-integration test-privileged clean clean-all bpf install fmt loc cache-sqlite

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
