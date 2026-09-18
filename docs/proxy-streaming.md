# http response streaming

the http/1 listener streams fixed-length, chunked, and close-delimited upstream responses. large downloads and server-sent events do not require buffering the complete body. response headers are limited to 32 kib, and body copies use 16 kib buffers. the upstream may use plaintext or the configured service tls policy.

a slow client applies backpressure to upstream reads. disconnects and socket deadlines stop forwarding. once any response bytes have been sent, a later error closes the connection; the proxy cannot replace a partial response or retry it safely. method-aware retries and configured server-error retries still apply before response output starts.

ordinary http/1.0 requests are accepted. chunked responses are decoded and delimited by closing the client connection. stacked transfer codings cannot be translated to http/1.0 and are refused before response output.

websocket requests retain their upgrade headers. after an upstream `101` response, the proxy relays bytes in both directions, including frames received with the request or response headers. the application's websocket implementation owns frame validation, ping/pong handling, and closing handshakes.

`request_timeout_ms` controls header and socket operation deadlines. body progress renews the operation deadline, allowing streams to run longer than a single timeout. an idle websocket or event stream can still time out; send application heartbeats or configure a suitable timeout for the route.

request headers and bodies still share the existing 64 kib input buffer. large uploads do not stream in this implementation. the buffered forwarding api used by internal callers and mirrors retains its response limit, and http/2 follows its existing forwarding path.
