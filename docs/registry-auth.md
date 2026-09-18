# registry authentication

pulls and pushes read credentials from the docker configuration file. set `DOCKER_CONFIG` to a directory containing `config.json`, or use the default `$HOME/.docker/config.json`. yoq reads the `auth` value under `auths`; credential helpers, `credsStore`, and `identitytoken` entries are not supported.

a registry entry matches its exact hostname and port. `registry.example:5000` does not match `registry.example`. docker hub also accepts the `docker.io` and `https://index.docker.io/v1/` keys used by docker clients. a missing configuration file or matching entry uses anonymous authentication.

```json
{
  "auths": {
    "registry.example:5000": {
      "auth": "dXNlcjpwYXNz"
    }
  }
}
```

`auth` contains base64-encoded `username:password`; the example decodes to `user:pass`. base64 does not encrypt credentials. use the same file permissions you would use for a docker login configuration.

yoq probes the requested repository before fetching its manifest. a registry can accept basic authentication directly or return a bearer challenge. credentials are sent over https to the configured registry. they can also be sent to a token endpoint on that same origin, where origin means scheme, hostname, and port. docker hub's `https://auth.docker.io` token origin is trusted for `registry-1.docker.io`.

for a private registry with a separate token service, add its https origin explicitly:

```json
{
  "auths": {
    "registry.example:5000": {
      "auth": "dXNlcjpwYXNz",
      "yoq_token_origin": "https://auth.example"
    }
  }
}
```

this setting authorizes sending that registry's basic credentials to any token path on `https://auth.example:443`. a different hostname, port, or scheme does not match. use an origin without a path, query, fragment, or user information. authentication fails if a credential-bearing registry challenge names an untrusted token origin. anonymous challenges may use another https token service because no configured credentials are sent.

authentication redirects are refused. manifest requests, blob existence checks, and upload requests also refuse automatic redirects whenever they carry basic or bearer credentials, including redirects to the same origin. configure the registry endpoint directly when it redirects these requests. blob downloads may follow redirects, but drop authorization before doing so. configuration files are limited to 1 mib, authentication response headers to 8 kib, and token response bodies to 64 kib, including chunked bodies. the repository probe and token exchange share a 30-second deadline; cancellation joins outstanding work before returning an error.

# layer formats and size limits

pull results retain each layer's media type, digest, and size. extraction accepts raw tar, gzip, and zstd oci layers, including the corresponding nondistributable media types and docker gzip layers. unsupported media types fail before layer downloads. compressed blobs are verified by digest before extraction; the declared compression must match the blob even when its extracted directory is cached.

a compressed layer is limited to 512 mib by default. set `YOQ_MAX_LAYER_BYTES` to a positive decimal byte count to change the limit; `8589934592` allows layers up to 8 gib. the limit applies to both declared sizes and bytes received, including responses without a content length. callers of the zig api can supply `PullOptions` to `pullForPlatformWithOptions` instead. configuration and manifest response limits stay separate.

zstd extraction uses an 8 mib decoder window. layers requiring a larger window fail extraction even if their compressed size fits the download policy. archive extraction also retains its 10 gib per-file limit. see [image layer storage](image-layers.md) for hard-link handling and archive limits.
