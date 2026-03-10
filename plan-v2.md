# YOQ: Industry-Leading Cluster Software for <1000 VMs & GPUs

**Single binary. No boat. Production-grade GPU mesh for the rest of us.**

---

## Part 1: Production Roadmap (24 Weeks to v1.0)

**Goal:** Take yoq from MVP+ to production-grade with GPU mesh capabilities.

**Principles:**
- Every feature ships as part of the single binary — no sidecars, operators, or plugin frameworks
- Linux-native: use kernel primitives (cgroups, eBPF, VFIO, DRM) not abstraction layers
- Test at scale continuously, not as an afterthought
- Cut scope aggressively — if it doesn't serve 10-1000 node clusters, skip it

---

### Phase 1: Foundation Hardening (Weeks 1-4)

**Theme:** Make the existing system production-trustworthy before adding new capabilities.

#### Week 1-2: State & Scheduling Resilience

- **SQLite throughput fix:** Batch agent heartbeats — agents report every 5s but server processes in batch every 2s. Reduce write amplification by 10x at 500 nodes.
- **Scheduler upgrade:** Add resource-aware bin-packing. The scheduler needs to track CPU, memory, and (soon) GPU as allocatable resources per agent. Add constraint-based placement (node labels, required resources).
- **Agent-side state cache:** Agents should cache their assigned workloads locally so they survive brief server outages without re-pulling state. SQLite on the agent side, synced on heartbeat.

#### Week 3-4: Networking at Scale

- **WireGuard hub-and-spoke:** Replace full-mesh with a tiered topology. Server nodes act as WireGuard hubs; agents connect only to servers (max 5 connections per agent vs 500 in full-mesh). Inter-agent traffic routes through the nearest server.
- **Gossip tuning:** Make SWIM fan-out and suspicion multiplier configurable. At 500 nodes, fan-out should be ~log(N) = 9, suspicion multiplier ~5.
- **eBPF load balancer improvements:** Add consistent hashing for sticky sessions.

**Exit criteria:** 100-node cluster runs for 72 hours with rolling deploys, leader failover, and network partitions injected. Zero data loss, <30s recovery.

---

### Phase 2: Storage Layer (Weeks 5-8)

**Theme:** Add distributed storage without importing Kubernetes's CSI complexity.

#### Week 5-6: Volume Abstraction

```toml
[volumes.data]
type = "host"
path = "/mnt/ssd/app-data"

[volumes.shared]
type = "nfs"
server = "storage.internal"
path = "/exports/shared"

[volumes.block]
type = "block"
device = "/dev/nvme1n1p1"
```

- Volume lifecycle: create, attach, detach, destroy. Track in SQLite.
- Volume scheduling constraint: pin containers to nodes with their storage.

#### Week 7-8: Distributed Storage Integration

- **NFS client:** Built-in NFS v4.1 mount support (kernel mount, no FUSE).
- **Object storage gateway:** Thin S3-compatible API — 10 API calls that cover 95% of usage.
- **Storage metrics:** eBPF-based I/O tracking per container.
- **Parallel filesystem passthrough:** Bind-mount Lustre/GPFS/BeeGFS into containers for GPU training data pipelines.

**Exit criteria:** 50-node cluster with 20TB NFS shared storage, 200 containers with volume mounts.

---

### Phase 3: GPU Mesh (Weeks 9-14)

**Theme:** First-class GPU support — discovery, scheduling, isolation, and multi-node GPU mesh networking.

#### Week 9-10: GPU Discovery & Isolation

**Detection strategy (NVIDIA-only, dlopen at runtime):**
1. Scan `/dev/nvidia*` for device nodes
2. `dlopen("libnvidia-ml.so.1")` -> NVML for UUID, model, VRAM, compute capability, NVLink topology, MIG state
3. Fallback to `/proc/driver/nvidia/gpus/*/information` and sysfs if NVML unavailable
4. Detect PCIe bus IDs from sysfs for topology awareness
5. Detect NUMA node for CPU/memory affinity

**Passthrough (no nvidia-container-runtime dependency):**
- Bind-mount GPU device nodes: `/dev/nvidia0`, `/dev/nvidiactl`, `/dev/nvidia-uvm`
- Bind-mount NVIDIA userspace libraries from host
- cgroup device controller rules to restrict which GPUs are accessible
- Set `NVIDIA_VISIBLE_DEVICES` and `CUDA_VISIBLE_DEVICES` env vars

```toml
[service.inference]
image = "llama-server:latest"
gpu = { count = 2, vram = "24GB" }
```

#### Week 11-12: GPU Scheduling & Partitioning

- **Gang scheduling:** All ranks of a training job placed atomically — all or none.
- **Topology-aware placement:** Prefer co-locating communicating ranks on same leaf switch.
- **NUMA affinity:** Bind container CPU/memory to GPU's NUMA node.
- **MIG partitioning:** For A100/H100, slice one GPU into isolated instances:
  ```toml
  gpu = { count = 1, partition = "3g.20gb" }
  ```
- **GPU health monitoring:** Poll temperature, utilization, ECC errors via NVML. Mark GPUs as unhealthy and drain workloads if ECC errors exceed threshold.
- **Time-slicing fallback:** NVIDIA MPS for GPUs without MIG support.

#### Week 13-14: GPU Mesh Networking

**Dual-network architecture:**
```
InfiniBand NDR (400G):  GPU-to-GPU traffic (NCCL, all-reduce, P2P)
WireGuard mesh (25G):   Control plane, health checks, scheduling, logs
```

- **RDMA detection:** Scan `/sys/class/infiniband/` for IB devices, detect GPUDirect RDMA capability (`nvidia-peermem` module), report link speed and GID.
- **IB device passthrough:** Bind-mount `/dev/infiniband/uverbs0`, `/dev/infiniband/rdma_cm`, mount `libibverbs`, `librdmacm`, `libmlx5` from host.
- **NCCL topology generation:** Auto-generate topology XML from detected GPU/NIC/switch layout. Match GPUs to closest NIC by PCIe locality.
- **eBPF traffic prioritization:** TC egress program on `wg-yoq` marks GPU mesh ports (29500-29600) with `TC_PRIO_INTERACTIVE` for priority queueing.
- **Automatic env injection:**
  ```
  MASTER_ADDR=10.40.0.{rank0_node}
  MASTER_PORT=29500
  WORLD_SIZE=N
  RANK=R
  LOCAL_RANK=LR
  NCCL_IB_HCA=mlx5_0
  NCCL_NET_GDR_LEVEL=5
  NCCL_TOPO_FILE=/etc/yoq/nccl_topo.xml
  ```

**Manifest for distributed training:**
```toml
[service.training]
image = "pytorch-dist:latest"
replicas = 4
gpu = { count = 8, model = "H100" }
gpu.mesh = { enabled = true, backend = "nccl" }
```

**Exit criteria:** PyTorch DDP across 4 nodes x 8 GPUs, >90% scaling efficiency. GPU failover within 120s.

---

### Phase 4: Observability & Operations (Weeks 15-18)

- **Prometheus `/metrics` endpoint:** CPU, memory, disk, network, GPU utilization/VRAM/temp/power, IB bandwidth per container.
- **Built-in alerting:** Thresholds in manifest, webhook notifications.
- **Structured logging:** JSON with trace IDs spanning API -> scheduler -> agent -> container.
- **Rolling upgrade:** Raft leader steps down, upgrades, rejoins. Version negotiation.
- **`yoq backup/restore`:** SQLite state + volume metadata snapshots.
- **`yoq doctor`:** Pre-flight checks for kernel, cgroups, eBPF, GPU drivers, WireGuard, IB.
- **`yoq gpu topo`:** Show IB connectivity, NVLink topology, GPUDirect status.

**Exit criteria:** 100-node GPU cluster running 7 days. All metrics in Grafana. 3+ simulated failures detected within 30s.

---

### Phase 5: Scale Validation & Hardening (Weeks 19-22)

- **500-node burst test:** 5 servers, 495 agents, mixed workload (2000 web + 200 DB + 50 GPU inference + 10 distributed training).
- **Chaos testing:** kill -9 agents, network partitions, disk failures, GPU ECC errors.
- **Fuzz testing:** API server, manifest parser, DNS resolver, WireGuard handshake.
- **Security audit round 2:** GPU passthrough isolation, WireGuard key management, API auth at scale.

**Exit criteria:** 48 hours continuous chaos, <1 minute P99 recovery, zero data loss, zero high/critical security findings.

---

### Phase 6: Cut & Ship (Weeks 23-24)

- Feature freeze week 22. Cut anything that isn't solid.
- Binary size audit (<50MB with GPU support via dlopen).
- Reproducible build, SHA256 checksums, changelog, upgrade guide.
- **Tag v1.0.**

---

## Part 2: GPU Mesh Technical Architecture

### New Module: `src/gpu/` (6 files, ~2,730 lines)

#### `src/gpu/detect.zig` (~350 lines) — GPU Discovery

```zig
pub const GpuInfo = struct {
    index: u8,
    vendor: GpuVendor,
    uuid: [64]u8,
    uuid_len: u8,
    model: [64]u8,
    model_len: u8,
    vram_mb: u32,
    compute_capability: u16,       // e.g., 90 for sm_90 (H100)
    pcie_bus_id: [16]u8,
    pcie_bus_id_len: u8,
    nvlink_peers: [8]u8,           // GPU indices connected via NVLink
    nvlink_peer_count: u8,
    mig_capable: bool,
    mig_enabled: bool,
    numa_node: u8,                 // NUMA node for CPU affinity
    dev_path: [32]u8,
    dev_path_len: u8,
};

pub const GpuInventory = struct {
    gpus: [16]GpuInfo,             // max 16 GPUs per node (covers DGX H100)
    count: u8,
    driver_version: [32]u8,
    driver_version_len: u8,
    cuda_version: [16]u8,
    cuda_version_len: u8,
    nvml_handle: ?*anyopaque,      // dlopen handle
};
```

#### `src/gpu/passthrough.zig` (~250 lines) — Device Isolation

- Bind-mount GPU device nodes + NVIDIA userspace libraries
- cgroup device controller rules (c 195:N rwm)
- No nvidia-container-runtime dependency
- Env var injection (CUDA_VISIBLE_DEVICES)

#### `src/gpu/scheduler.zig` (~300 lines) — GPU-Aware Placement

```zig
pub const GpuRequest = struct {
    count: u8 = 0,
    min_vram_mb: u32 = 0,
    model: ?[64]u8 = null,
    model_len: u8 = 0,
    partition: ?MigPartition = null,
    require_nvlink: bool = false,
};
```

**Gang scheduling for training jobs:**
```zig
fn scheduleTrainingJob(job: TrainingJob, agents: []Agent) ?[]Assignment {
    // Must place ALL ranks or NONE
    // Score agents by: GPU free + IB bandwidth + rack locality
    // Assign ranks to minimize cross-rack traffic
}
```

#### `src/gpu/health.zig` (~250 lines) — Health Monitoring

- Background thread polling NVML every 5s
- Temperature, utilization, ECC errors, power draw
- Thresholds: degraded at 90C, failed at 95C, any double-bit ECC -> failed
- Status reported in heartbeat; server marks GPU as unusable if failed

#### `src/gpu/mesh.zig` (~400 lines) — GPU Mesh Networking

```zig
pub const RdmaNic = struct {
    name: [16]u8,
    name_len: u8,
    port: u8,
    gid: [64]u8,
    gid_len: u8,
    link_speed_gbps: u16,          // e.g., 200 for HDR InfiniBand
    pcie_bus_id: [16]u8,
    pcie_bus_id_len: u8,
    supports_gdr: bool,            // GPUDirect RDMA capable
};
```

- RDMA detection from `/sys/class/infiniband/`
- NCCL topology XML generation from hardware scan
- GPU-NIC affinity by PCIe locality
- Env var injection for NCCL configuration

#### `src/gpu/mig.zig` (~200 lines) — MIG Partition Management

- Create/destroy MIG instances via NVML
- List available partitions per GPU
- Device path derivation for MIG instances

### Existing File Modifications (~400 lines across 7 files)

| File | Change |
|------|--------|
| `src/manifest/spec.zig` | Add `GpuSpec` and `GpuMeshSpec` to `Service` |
| `src/manifest/loader.zig` | Parse `gpu` and `gpu.mesh` TOML fields |
| `src/cluster/agent.zig` | GPU detection on registration, GPU metrics in heartbeat |
| `src/cluster/agent_types.zig` | Add `gpu_count`, `gpu_used`, `gpu_model`, `gpu_vram_mb`, `rdma_capable` |
| `src/cluster/scheduler.zig` | Extend `PlacementRequest` with `GpuRequest`, add GPU constraints to scheduling loop |
| `src/state/schema.zig` | GPU columns on agents table, new `gpu_allocations` table |
| `src/runtime/cgroups.zig` | Add `+devices` to subtree controllers, `writeDeviceRule()` |

### Schema Changes

```sql
-- Agents table migrations
ALTER TABLE agents ADD COLUMN gpu_count INTEGER DEFAULT 0;
ALTER TABLE agents ADD COLUMN gpu_used INTEGER DEFAULT 0;
ALTER TABLE agents ADD COLUMN gpu_model TEXT;
ALTER TABLE agents ADD COLUMN gpu_vram_mb INTEGER DEFAULT 0;
ALTER TABLE agents ADD COLUMN mig_capable INTEGER DEFAULT 0;
ALTER TABLE agents ADD COLUMN rdma_capable INTEGER DEFAULT 0;

-- GPU allocation tracking
CREATE TABLE IF NOT EXISTS gpu_allocations (
    assignment_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    gpu_index INTEGER NOT NULL,
    partition_id TEXT,
    allocated_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, gpu_index)
);

-- Assignments table extensions
ALTER TABLE assignments ADD COLUMN gpu_count INTEGER DEFAULT 0;
ALTER TABLE assignments ADD COLUMN gpu_model TEXT;
ALTER TABLE assignments ADD COLUMN gpu_vram_mb INTEGER DEFAULT 0;
ALTER TABLE assignments ADD COLUMN gpu_mesh_enabled INTEGER DEFAULT 0;
ALTER TABLE assignments ADD COLUMN gpu_mesh_rank INTEGER;
ALTER TABLE assignments ADD COLUMN gpu_mesh_world_size INTEGER;
```

---

## Part 3: Data Center Scenario — 100 H100s, 200 VMs, Petabyte Training

### Cluster Topology

```
                    +-----------------------------+
                    |      Spine Switches          |
                    |   (InfiniBand NDR 400G)      |
                    +--+----+----+----+----+---+--+
                       |    |    |    |    |   |
                 +-----+    |    |    |    |   +-----+
                 |          |    |    |    |         |
            +----+----+ +--+--+ |  +-+--+ |   +----+----+
            |  Leaf 1  | |Leaf2| .. |LeafN| |   | Storage |
            +--+--+--+  +-+--+    +-+--+  |   +----+----+
               |  |      |        |       |        |
     +----+--+ +----+--+ |  +----+--+    |   +---+----+
     | VM 1  | | VM 2  | |  | VM N  |    |   | Data   |
     | H100  | | H100  | |  | H100  |    |   | Nodes  |
     | Agent | | Agent | |  | Agent |    |   | (NFS/  |
     +-------+ +-------+ |  +-------+    |   | Lustre)|
                          |               |   +--------+
                    +----+--+       +----+--+
                    | CPU   |       | CPU   |
                    | VMs   |       | VMs   |
                    |(sched,|       |(data  |
                    | raft) |       | load) |
                    +-------+       +-------+

100 GPU VMs:  1x H100 + IB NIC each, run training ranks
~95 CPU VMs:  data preprocessing, tokenization, staging
3-5 CPU VMs:  yoq Raft servers (control plane)
Storage tier: parallel filesystem (Lustre/GPFS/BeeGFS)
```

### Performance Projections (InfiniBand NDR)

| Model Size | Parallelism | Scaling Efficiency | Notes |
|-----------|-------------|-------------------|-------|
| 7-13B | Pure data parallel (ZeRO-3) | 90-95% | Sweet spot |
| 30-70B | DP + Pipeline parallel | 80-90% | PP within racks, DP across |
| 70-200B | 3D parallel (TP+PP+DP) | 75-85% | Standard approach |
| 400B+ | 3D + expert parallel | 65-80% | Pushing limits of 100 GPUs |

```
All-Reduce (100 GPUs, 1GB):    ~45ms  (ring algorithm)
All-Reduce (100 GPUs, 100MB):  ~5ms
Point-to-point (GPU-to-GPU):   ~3us latency, 48 GB/s sustained
```

### Training Job Manifest

```toml
[training.my-llm]
image = "registry.internal/llm-trainer:v3"
command = "torchrun --nproc_per_node=1 train.py"
gpus = 100
gpu_type = "H100"

[training.my-llm.data]
dataset = "/mnt/lustre/pile-v2"
sharding = "file"
preprocessing = "tokenize"

[training.my-llm.checkpoint]
path = "/mnt/lustre/checkpoints/my-llm"
interval = "30m"
keep = 5

[training.my-llm.resources]
cpu = 16000
memory = "128GB"
ib_required = true

[training.my-llm.fault_tolerance]
spare_ranks = 5
auto_restart = true
max_restarts = 10
```

### Training Lifecycle Commands

```
yoq train start my-llm           # place all ranks, begin training
yoq train status my-llm          # show rank status, step count, loss
yoq train pause my-llm           # checkpoint and pause all ranks
yoq train resume my-llm          # restore from checkpoint, continue
yoq train stop my-llm            # final checkpoint and stop
yoq train scale my-llm --gpus 80 # elastic rescaling
yoq train logs my-llm --rank 0   # training logs from rank 0
yoq gpu topo                     # show IB, NVLink, GDR status
yoq gpu bench                    # run NCCL all-reduce benchmark
```

### Checkpoint Impact

```
70B model + optimizer state (ZeRO-3): ~400 GB total across 100 ranks
Each rank saves ~4 GB shard to Lustre
100 ranks x 4 GB = 400 GB, Lustre at 100 GB/s -> ~4s write
Checkpoint every 30 min -> <0.3% overhead
```

### Fault Tolerance

Mean time between failure for 100 H100s: ~2-5 days.

```
Rank 47 died (GPU ECC uncorrectable)
-> Emergency checkpoint saved at step 12,847
-> Spare VM gpu-spare-03 activated, assigned rank 47
-> Checkpoint restored, training resumed at step 12,847
-> Total downtime: ~90s
```

---

## Part 4: Competitive Analysis

### The Market Landscape

| Orchestrator | Self-Contained | Gang Scheduling | InfiniBand | Fault Recovery | Complexity |
|-------------|---------------|-----------------|------------|----------------|-----------|
| **yoq** | Single binary | Built-in | Device passthrough | Auto-restart + checkpoint | 1 TOML |
| **Slurm** | 2 daemons | Native | Native | Manual requeue | 1 conf |
| **K8s+KAI** | 15+ components | KAI (bolt-on) | RDMA plugin + Multus | Pod eviction | 10+ YAML |
| **Ray** | Python lib | Via KAI | Delegated | Elastic | Python |
| **Determined** | K8s/Slurm required | Built-in | Delegated | Built-in | 1 YAML |

### Where yoq Wins

1. **Operational simplicity** — The only fully self-contained GPU orchestrator. One binary, one TOML, one state store. No platform team required.
2. **Integrated training lifecycle** — `yoq train` commands are a genuine market gap. Nobody does checkpoint + fault recovery + gang scheduling in a standalone orchestrator.
3. **Dual-network architecture** — WireGuard (control) + InfiniBand (data) is clean. K8s struggles with this (Multus).
4. **eBPF networking without sidecars** — Cilium proved this works but requires K8s. yoq offers it standalone.
5. **Zig performance** — No GC pauses in control plane, no JVM warmup, ~10MB binary.

### Confidence by Scale

| Scale | Confidence | Notes |
|-------|-----------|-------|
| 50-200 GPUs | 85% | yoq's sweet spot. Simplest path to "run training on 100 GPUs" |
| 200-500 GPUs | 70% | Achievable with topology-aware scheduling and IB fabric awareness |
| 500-1000 GPUs | 55% | Gang scheduling 1000 GPUs atomically has more failure modes |
| 1000+ GPUs | 25% | Not the target. Leave this to custom systems at frontier labs |

### Strategic Positioning

> Train your 70B model on 100 H100s with one binary and one TOML file.
> No Kubernetes. No Slurm. No YAML. Built-in checkpointing, fault recovery,
> InfiniBand passthrough, and service discovery. Deploy in minutes, not days.

**Key differentiator:** Not performance (NCCL handles that). Not scale (K8s wins there). **Operational simplicity** — the only self-contained GPU training orchestrator that doesn't need another orchestrator underneath it.

---

## Part 5: What We're NOT Building

- No CRDs or custom resource types — TOML manifests only
- No operator pattern — everything in the binary
- No sidecar injection — eBPF handles it
- No plugin/extension system — upstream it or don't
- No web UI — CLI + Prometheus + Grafana
- No multi-cloud abstraction — Linux machines, any provider
- No auto-scaling — add nodes manually, yoq fills them
- No Windows/macOS — Linux only, kernel 6.1+
- No Helm equivalent — flat TOML, no templating
- No RBAC — binary auth (have the key or don't)

---

## Budget Allocation ($50K)

| Category | Amount | Details |
|----------|--------|---------|
| Sustained test cluster (Hetzner, 50 nodes, 6 months) | $19,500 | AX52 dedicated @ $65/mo |
| GPU test nodes (4 nodes, 3 months) | $12,000 | A100/H100 for GPU mesh validation |
| 500-node burst tests (3 runs, 72 hrs each) | $8,000 | Hetzner hourly dedicated |
| Network/bandwidth overages | $3,000 | Burst test data transfer |
| Monitoring stack (Grafana Cloud) | $1,500 | Metrics retention |
| Security audit (external, focused scope) | $5,000 | GPU isolation + API auth |
| Contingency | $1,000 | |
| **Total** | **$50,000** | |

---

## Total Effort Summary

| Phase | Weeks | New Lines | Risk |
|-------|-------|----------|------|
| 1. Foundation Hardening | 4 | ~2,000 | Low |
| 2. Storage Layer | 4 | ~2,500 | Medium |
| 3. GPU Mesh | 6 | ~3,500 | Medium-High |
| 4. Observability | 4 | ~2,000 | Low |
| 5. Scale Validation | 4 | ~1,000 | High (finding bugs) |
| 6. Cut & Ship | 2 | ~500 | Low |
| **Total** | **24** | **~11,500** | |

Training-specific extensions (checkpoint, data pipeline, fault tolerance): +8,000-12,000 lines over an additional 10-16 weeks for the full data center scenario.
