FROM alpine:3.20 AS builder

RUN apk add --no-cache curl tar xz
ARG ZIG_VERSION=0.17.0
ARG ZIG_TARGET=x86_64-linux
ARG ZIG_SHA256=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
RUN set -eux; \
    zig_archive="zig-${ZIG_TARGET}-${ZIG_VERSION}.tar.xz"; \
    zig_url="https://ziglang.org/download/${ZIG_VERSION}/${zig_archive}"; \
    curl --fail --location --show-error \
        --retry 5 --retry-all-errors --retry-delay 2 \
        --connect-timeout 20 --max-time 300 \
        --output "/tmp/${zig_archive}" \
        "${zig_url}"; \
    echo "${ZIG_SHA256}  /tmp/${zig_archive}" | sha256sum -c -; \
    tar -xJ -C /opt -f "/tmp/${zig_archive}"; \
    rm -f "/tmp/${zig_archive}"
ENV PATH="/opt/zig-${ZIG_TARGET}-${ZIG_VERSION}:${PATH}"
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
