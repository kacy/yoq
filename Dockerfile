FROM alpine:3.20 AS builder

RUN apk add --no-cache zig=0.15.2-r0

WORKDIR /src
COPY build.zig build.zig.zon src/ ./src/

RUN zig build -Doptimize=ReleaseSafe

FROM alpine:3.20
COPY --from=builder /src/zig-out/bin/yoq /usr/local/bin/yoq
ENTRYPOINT ["yoq"]
