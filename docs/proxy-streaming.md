# http proxy streaming

the http/1 listener streams fixed-length, chunked, and close-delimited upstream responses. large downloads and server-sent events do not require buffering the complete body. response headers are limited to 32 kib, and body copies use 16 kib buffers. the upstream may use plaintext or the configured service tls policy.

a slow client applies backpressure to upstream reads. disconnects and socket deadlines stop forwarding. once any response bytes have been sent, a later error closes the connection; the proxy cannot replace a partial response or retry it safely. for requests without a body, method-aware retries and configured server-error retries still apply before response output starts.

ordinary http/1.0 requests are accepted. chunked responses are decoded and delimited by closing the client connection. stacked transfer codings cannot be translated to http/1.0 and are refused before response output.

websocket requests retain their upgrade headers. after an upstream `101` response, the proxy relays bytes in both directions, including frames received with the request or response headers. the application's websocket implementation owns frame validation, ping/pong handling, and closing handshakes.

client request headers have a fixed five-second deadline. `request_timeout_ms` controls upstream headers and socket operation deadlines. body progress renews the operation deadline, allowing streams to run longer than a single timeout. an idle websocket or event stream can still time out; send application heartbeats or configure a suitable timeout for the route.

the http/1 listener reads at most 16 kib of request headers before routing. fixed-length and chunked uploads then stream with bounded buffers, up to 256 mib of body data after chunk framing is removed. conflicting content-length and transfer-encoding headers, repeated lengths, unsupported transfer codings, and malformed chunk framing are rejected. chunk lines are limited to 4 kib and trailers to 16 kib; trailers cannot change framing, routing, or authorization.

uploads share one worker with upstream response reads, so an early rejection stops forwarding even while the client is sending. slow upstream writes stop further client reads. the proxy handles `Expect: 100-continue` after sending the upstream request headers and removes that expectation from the forwarded request. body-bearing websocket and h2c upgrades are refused.

streamed request bodies are neither retried nor mirrored because their bytes are not retained for replay. requests without a body keep the existing retry and mirror policies. ordinary http/1 connections close after one response; bytes belonging to a later pipelined request are never forwarded as part of an upload. the buffered forwarding api used by internal callers retains its response limit.
