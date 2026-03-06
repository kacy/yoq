.PHONY: build run test test-integration test-privileged clean bpf install fmt loc

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

bpf:
	zig build bpf

install: build
	cp zig-out/bin/yoq /usr/local/bin/yoq

fmt:
	zig fmt src/

loc:
	@find src -name '*.zig' | xargs wc -l | tail -1
