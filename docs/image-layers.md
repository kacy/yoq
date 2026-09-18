# image layer storage

registry pulls preserve layer media types and support raw tar, gzip, and zstd. the download limit defaults to 512 mib per layer and can be set with `YOQ_MAX_LAYER_BYTES`. see [registry authentication and layer limits](registry-auth.md#layer-formats-and-size-limits) for the supported formats and extraction limits.

Layer lists follow OCI manifest order: base first, newest last. The shared OverlayFS mount boundary reverses that list because the kernel gives its leftmost lower directory precedence. Container, build, and application paths use this same contract.

Image extraction converts empty OCI `.wh.name` files into native OverlayFS whiteouts, and `.wh..wh..opq` into opaque directory metadata. Conversion happens before publishing the immutable cache entry. Whiteouts affect older layers, so a file recreated in the same layer survives regardless of archive order; a recreated directory hides its former children. Generic tar extraction, including ADD archives, leaves these names alone. Layer creation converts kernel deletion metadata back into OCI markers, so RUN deletions survive image export and later pulls.

The extraction cache is now `layers/v4/sha256`. Earlier cache directories remain intact for existing containers. New assembly rebuilds v4 entries from verified blobs; an older completion marker cannot satisfy the new format. Cache cleanup operates on the current version and does not remove older directories still used by running containers.

`yoq pull` still works without root and downloads verified image blobs. Unprivileged pulls defer native filesystem extraction. On the supported Linux 6.1 baseline, preparing native whiteouts and trusted opaque-directory attributes requires privilege. Unprivileged extraction of a layer containing OCI whiteouts returns `WhiteoutRequiresPrivilege`; it never exposes deleted files as a fallback. Marker-free unprivileged extraction remains available. USER namespace support by itself does not make the complete cgroup, network, and native image-preparation path rootless.

The conversion follows the [OCI layer whiteout rules](https://github.com/opencontainers/image-spec/blob/main/layer.md#whiteouts) and [Linux OverlayFS ordering and deletion metadata](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html).

hard links use archive-root-relative targets and preserve the target file's inode and metadata. targets may appear before or after the link entry; a forward reference binds when its target first becomes available. replacing the target later leaves the existing link attached to the original inode. a later entry at the link's own path replaces that pending link. GNU long names and PAX path, linkpath, and size fields are supported.

extraction resolves both paths within the destination root, rejects absolute or parent-traversing hard-link targets, and requires the final target to be a regular file. directory symlinks remain confined to that root; a final symlink cannot be a hard-link target. missing targets and cycles fail extraction before an image cache entry is published. hard links require access to `/proc/self/fd`.

forward references are limited to 4,096 pending links, 4 mib of stored paths, and 1,048,576 resolution attempts per archive. these bounds also apply to unresolved chains. device nodes, fifos, and sparse archive entries remain unsupported; global PAX headers are ignored.

## local image references and pruning

local references include the registry host and port, repository, and tag or digest. docker hub names such as `alpine`, `docker.io/library/alpine:latest`, and `registry-1.docker.io/library/alpine:latest` identify the same reference. different registries and ports remain separate. pulling a changed tag replaces that reference; other tags for the previous content remain available.

`yoq rmi <image>` removes only the named reference. removing its last reference also removes its content record; a later `yoq prune` reclaims unused blobs and extracted layers. the image api's delete-by-id operation removes all references to that id. `yoq images` includes the registry, and its json output has a `registry` field.

older databases did not record the registry origin. their content records remain available by id and are retained by prune, but name lookup does not guess an origin. pull or build the image again to establish its full reference. legacy entries appear with `<unknown>` in the registry column; remove them by id through the image api if they are no longer needed.

prune reads every saved manifest, config, and build-cache digest before deleting anything. unreadable or malformed metadata and allocation failures abort the mark phase. digest marks own their bytes, so they remain valid after parsed documents are released.

stop workloads and finish image pulls and builds before pruning. prune does not yet coordinate with active image writers or track the lower directories of running overlays. in particular, do not remove an image's last reference while a container still uses its layers.
