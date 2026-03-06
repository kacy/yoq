.PHONY: build run test test-integration clean bpf install fmt loc

build:
	zig build

run:
	zig build run

test:
	zig build test

test-integration:
	zig build test-integration

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
