# image archives

`yoq save` exports local images to an uncompressed tar archive. `yoq load` restores their blobs and image references without contacting a registry.

```sh
yoq tag myapp:latest myapp:release
yoq save -o myapp.tar myapp:latest myapp:release
yoq load -i myapp.tar
yoq run --pull never myapp:release
```

save each tag you want to transfer. Multiple tags for the same image share one copy of its blobs. Tags retain their registry and repository names. Loading replaces matching local tags; it leaves other tags intact.

without `-o` or `-i`, the commands use standard output and standard input. A path of `-` selects the same stream. Archive bytes are the only output from `save` on standard output.

```sh
yoq save myapp:release | gzip > myapp.tar.gz
gzip -dc myapp.tar.gz | yoq load
```

## format and compatibility

the archive contains an [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md): `oci-layout`, `index.json`, and content blobs under `blobs/sha256/`. The layout version is `1.0.0`. Each selected reference has an index descriptor with an `org.opencontainers.image.ref.name` annotation.

manifest, configuration, and layer bytes are preserved, including image metadata that the runtime does not execute. Loading keeps the original image digests. The local import time becomes the image record's creation time; the timestamp inside the image configuration is unchanged.

the current loader accepts single-platform OCI image manifests and Docker schema 2 image manifests inside an OCI layout. Layers can be uncompressed tar, gzip, or zstd. The outer archive must be uncompressed tar; decompress it before piping it to `load`. Nested image indexes, other digest algorithms, and Docker's legacy `manifest.json` archive format are not supported. Compatibility with a particular version of `docker load` or another tool has not been established.

an index descriptor without a reference annotation is stored as `loaded@<manifest-digest>`. It can also be run by its full `sha256:...` digest. Every referenced blob must be included in the archive, even if it is already cached locally.

## failure handling and limits

the loader checks blob hashes, descriptor sizes, manifest/config relationships, and image references before publishing any tags. All tag updates share a database transaction. A failed import can leave verified, unreferenced blobs in the local cache, which ordinary image pruning can reclaim. A save to a file replaces the destination only after the complete archive has been written successfully.

files are streamed with fixed buffers. Limits are 20 MiB per metadata document, 8 GiB minus one byte per blob, 1 TiB of file contents per archive, 65,536 archive entries, and 4,096 selected image references. The blob limit fits the portable tar size field. Archive paths cannot escape the layout, and symlinks and hard links are rejected. Extra regular files are ignored, as allowed for OCI layout extensions.

these commands transfer images. Container writable layers and mounted data are separate objects and are not included.
