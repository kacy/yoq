# copying files and inspecting changes

`yoq cp` copies regular files, directories, and symlinks between the host and a local container. use an ID or name before the colon:

```sh
yoq cp ./config.json web:/app/config.json
yoq cp web:/app/results ./results
yoq cp ./assets/. web:/app/assets
```

container paths start at the container root, whether or not they begin with `/`. a source directory copied to an existing directory retains its basename. a source ending in `/.` copies its contents. destination parent directories must already exist. prefix a host filename containing a colon with `./` to distinguish it from a container reference.

copying works while an image container is running or stopped. the helper for a stopped container mounts the saved image layers and writable layer in a temporary private mount namespace, then unmounts the view when copying finishes. it does not start the container or remove its writable layer. a running copy uses its current root, including active mounts; a stopped copy sees the image and writable layer without bind mounts or volumes attached.

ordinary file and directory permissions and symlink targets are preserved. symlinks are copied as links. ownership, timestamps, extended attributes, ACLs, and hardlink relationships are not preserved. device files, sockets, and FIFOs are unsupported. existing destination directory symlinks within a copied tree are not traversed. archive streams, `-` for stdin/stdout, and copies between two containers are not supported. live application writes can change files during copying; this is not a snapshot or backup command.

use `yoq diff` to inspect the writable image layer:

```sh
yoq diff web
# A /app/new-file
# C /app/config.json
# D /app/deleted-file
```

`A` means added, `C` means copied up or changed relative to the image, and `D` means deleted. native OverlayFS whiteouts and opaque directories are included. a removed directory is reported once, rather than listing every descendant. results describe layer metadata; `C` does not imply that file bytes differ, and output order is unspecified. volume and bind-mount contents are excluded. a raw-rootfs container has no immutable image baseline, so `diff` requires an image container.

these commands require permission to access the container root. stopped image copies and image-layer comparisons also require mount namespace and OverlayFS privileges. lifecycle commands wait for the filesystem operation to finish; automatic workload writes remain possible for running containers.
