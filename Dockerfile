FROM alpine:3.20 AS builder

RUN apk add --no-cache curl tar xz
RUN curl -fsSL https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz \
    | tar -xJ -C /opt
ENV PATH="/opt/zig-x86_64-linux-0.16.0:${PATH}"
ENV ZIG_GLOBAL_CACHE_DIR="/tmp/zig-global-cache"
ENV ZIG_LOCAL_CACHE_DIR="/src/.zig-cache"

WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src/ ./src/
COPY vendor/zig-sqlite/ ./vendor/zig-sqlite/

RUN mkdir -p "$ZIG_GLOBAL_CACHE_DIR/tmp" "$ZIG_LOCAL_CACHE_DIR/tmp"
RUN zig build -Doptimize=ReleaseSafe

FROM alpine:3.20
COPY --from=builder /src/zig-out/bin/yoq /usr/local/bin/yoq
ENTRYPOINT ["yoq"]
