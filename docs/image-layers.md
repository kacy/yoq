# image layer storage

Layer lists follow OCI manifest order: base first, newest last. The shared OverlayFS mount boundary reverses that list because the kernel gives its leftmost lower directory precedence. Container, build, and application paths use this same contract.

Image extraction converts empty OCI `.wh.name` files into native OverlayFS whiteouts, and `.wh..wh..opq` into opaque directory metadata. Conversion happens before publishing the immutable cache entry. Whiteouts affect older layers, so a file recreated in the same layer survives regardless of archive order; a recreated directory hides its former children. Generic tar extraction, including ADD archives, leaves these names alone. Layer creation converts kernel deletion metadata back into OCI markers, so RUN deletions survive image export and later pulls.

The extraction cache is now `layers/v4/sha256`. Earlier cache directories remain intact for existing containers. New assembly rebuilds v4 entries from verified blobs; an older completion marker cannot satisfy the new format. Cache cleanup operates on the current version and does not remove older directories still used by running containers.

`yoq pull` still works without root and downloads verified image blobs. Unprivileged pulls defer native filesystem extraction. On the supported Linux 6.1 baseline, preparing native whiteouts and trusted opaque-directory attributes requires privilege. Unprivileged extraction of a layer containing OCI whiteouts returns `WhiteoutRequiresPrivilege`; it never exposes deleted files as a fallback. Marker-free unprivileged extraction remains available. USER namespace support by itself does not make the complete cgroup, network, and native image-preparation path rootless.

The conversion follows the [OCI layer whiteout rules](https://github.com/opencontainers/image-spec/blob/main/layer.md#whiteouts) and [Linux OverlayFS ordering and deletion metadata](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html).
