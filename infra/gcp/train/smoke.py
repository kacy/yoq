#!/usr/bin/env python3
import os


def emit(name: str) -> None:
    value = os.environ.get(name, "")
    print(f"{name}={value}")


def main() -> None:
    for key in (
        "MASTER_ADDR",
        "MASTER_PORT",
        "WORLD_SIZE",
        "RANK",
        "LOCAL_RANK",
        "CUDA_VISIBLE_DEVICES",
        "NCCL_TOPO_FILE",
    ):
        emit(key)


if __name__ == "__main__":
    main()
