# copying files and inspecting changes

`yoq cp` copies regular files, directories, and symlinks between the host and a local container. Use an ID or name before the colon:

```sh
yoq cp ./config.json web:/app/config.json
yoq cp web:/app/results ./results
yoq cp ./assets/. web:/app/assets
```

container paths start at the container root, whether or not they begin with `/`. A source directory copied to an existing directory retains its basename. A source ending in `/.` copies its contents. Destination parent directories must already exist. Prefix a host filename containing a colon with `./` to distinguish it from a container reference.

copying works while an image container is running or stopped. The stopped-container helper mounts the saved image layers and writable layer in a temporary private mount namespace, then unmounts the view when copying finishes. It does not start the container or remove its writable layer. A running copy uses its current root, including active mounts; a stopped copy sees the image and writable layer without bind mounts or volumes attached.

ordinary file and directory permissions and symlink targets are preserved. Symlinks are copied as links. Ownership, timestamps, extended attributes, ACLs, and hardlink relationships are not preserved. Device files, sockets, and FIFOs are unsupported. Existing destination directory symlinks within a copied tree are not traversed. Archive streams, `-` for stdin/stdout, and container-to-container copies are not supported. Live application writes can change files during copying; this is not a snapshot or backup command.

use `yoq diff` to inspect the writable image layer:

```sh
yoq diff web
# A /app/new-file
# C /app/config.json
# D /app/deleted-file
```

`A` means added, `C` means copied up or changed relative to the image, and `D` means deleted. Native OverlayFS whiteouts and opaque directories are included. A removed directory is reported once, rather than listing every descendant. Results describe layer metadata; `C` does not imply that file bytes differ, and output order is unspecified. Volume and bind-mount contents are excluded. A raw-rootfs container has no immutable image baseline, so `diff` requires an image container.

these commands require permission to access the container root. Stopped image copies and image-layer comparisons also require mount namespace and OverlayFS privileges. Lifecycle commands wait for the filesystem operation to finish; automatic workload writes remain possible for running containers.
