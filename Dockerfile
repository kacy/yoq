FROM alpine:3.20 AS builder

RUN apk add --no-cache curl tar xz
RUN curl -fsSL https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz \
    | tar -xJ -C /opt
ENV PATH="/opt/zig-x86_64-linux-0.15.2:${PATH}"

WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src/ ./src/

RUN zig build -Doptimize=ReleaseSafe

FROM alpine:3.20
COPY --from=builder /src/zig-out/bin/yoq /usr/local/bin/yoq
ENTRYPOINT ["yoq"]
