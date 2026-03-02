.PHONY: build run test clean

build:
	zig build

run:
	zig build run

test:
	zig build test

clean:
	rm -rf zig-out .zig-cache
