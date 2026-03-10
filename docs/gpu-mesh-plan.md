# GPU Mesh Plan: 100 H100s across 200 VMs

## Scenario

Private data center. Training a large model (likely 70B-400B+ parameters)
on petabytes of training data. 100 NVIDIA H100 GPUs, 200 VMs total.

---

## Executive Summary

yoq's control plane (Raft, SWIM, bin-packing scheduler) already handles 200
nodes trivially. The real engineering is in three areas that don't exist today:

1. **GPU passthrough & scheduling** — straightforward, ~2-3 weeks
2. **InfiniBand/RDMA data plane** — hard but essential, ~3-4 weeks
3. **Distributed training lifecycle** — checkpointing, data loading, fault
   recovery at petabyte scale — this is the bulk of the work, ~4-6 weeks

**Total estimate: ~8,000-12,000 lines of Zig, 10-16 weeks.**

**Performance verdict:** With InfiniBand NDR (standard in H100 data center
SKUs), expect **80-90% scaling efficiency** for data-parallel and hybrid-
parallel training across 100 GPUs. Competitive with purpose-built clusters
running Slurm. Without InfiniBand, drop to ~60-70% efficiency on 100GbE —
still usable but painful for large model training.

---

## Cluster Topology (Data Center)

```
                    ┌─────────────────────────────┐
                    │      Spine Switches          │
                    │   (InfiniBand NDR 400G)      │
                    └──┬────┬────┬────┬────┬───┬──┘
                       │    │    │    │    │   │
                 ┌─────┘    │    │    │    │   └─────┐
                 │          │    │    │    │         │
            ┌────┴────┐ ┌──┴──┐ │  ┌─┴──┐ │   ┌────┴────┐
            │  Leaf 1  │ │Leaf2│ .. │LeafN│ │   │ Storage │
            └──┬──┬──┘ └─┬──┘    └─┬──┘  │   └────┬────┘
               │  │      │        │      │        │
          ┌────┘  └──┐   │        │      │        │
     ┌────┴──┐  ┌────┴──┐│   ┌────┴──┐   │   ┌───┴────┐
     │ VM 1  │  │ VM 2  ││   │ VM N  │   │   │ Data   │
     │ H100  │  │ H100  ││   │ H100  │   │   │ Nodes  │
     │ Agent │  │ Agent ││   │ Agent │   │   │ (NFS/  │
     └───────┘  └───────┘│   └───────┘   │   │ Lustre/│
                         │               │   │ GPFS)  │
                    ┌────┴──┐       ┌────┴──┐└────────┘
                    │ CPU   │       │ CPU   │
                    │ VMs   │       │ VMs   │
                    │(sched,│       │(data  │
                    │ raft) │       │ load) │
                    └───────┘       └───────┘

100 GPU VMs:  1x H100 + IB NIC each, run training ranks
~95 CPU VMs:  data preprocessing, tokenization, staging
3-5 CPU VMs:  yoq Raft servers (control plane)
Storage tier: parallel filesystem (Lustre/GPFS/BeeGFS)
```

**Key assumption:** H100 data center SKU (SXM5) comes with InfiniBand NDR
(400 Gbps). This is the standard configuration for training clusters. The
plan assumes InfiniBand is available.

---

## Work Breakdown

### Phase 1: GPU Device Discovery & Passthrough (2-3 weeks, ~1,200 lines)

Same as before — detect GPUs, bind-mount `/dev/nvidia*` and driver libs,
extend agent resources, update seccomp filters. No changes from the previous
plan. This is well-understood work.

Additionally for data center:
- Detect GPU topology (PCIe bus ID, NUMA node) and report to scheduler
- Detect NVLink connectivity between GPUs on multi-GPU nodes
- NUMA-aware container placement: pin container to same NUMA node as its GPU

### Phase 2: GPU-Aware Scheduling (1-2 weeks, ~600 lines)

Extended from previous plan for training workloads:

- **Gang scheduling**: all ranks of a training job must be placed atomically.
  Either all 100 GPUs are allocated or none are. No partial placement.
- **Topology-aware placement**: prefer placing communicating ranks on the
  same leaf switch to minimize IB hops
- **NUMA affinity**: bind container CPU/memory to GPU's NUMA node
- **Rank assignment**: scheduler assigns `RANK`, `WORLD_SIZE`, `LOCAL_RANK`,
  `MASTER_ADDR`, `MASTER_PORT` environment variables
- **Job abstraction**: new concept — a "training job" is N containers that
  share a lifecycle (all start together, all stop if one dies)

**New scheduler concept — gang scheduling:**
```
fn scheduleTrainingJob(job: TrainingJob, agents: []Agent) ?[]Assignment {
    // Must place ALL ranks or NONE
    // Score agents by: GPU free + IB bandwidth + rack locality
    // Assign ranks to minimize cross-rack traffic
    // Return null if insufficient GPUs (don't partially place)
}
```

This is the biggest scheduler change. Current bin-packing places containers
independently — training requires atomic group placement.

### Phase 3: InfiniBand RDMA Data Plane (3-4 weeks, ~2,500 lines)

**Critical path for training performance.**

#### 3a. IB Device Passthrough
- Detect IB devices: `/sys/class/infiniband/`, `/dev/infiniband/`
- Bind-mount into containers: `/dev/infiniband/uverbs0`, `/dev/infiniband/rdma_cm`
- Mount `libibverbs`, `librdmacm`, `libmlx5` from host
- cgroup device allowlist for RDMA character devices
- Report IB port state, link speed, GUID in agent heartbeat

#### 3b. GPUDirect RDMA
- Detect `nvidia-peermem` kernel module
- Expose to containers via environment variable
- Verify P2P capability between GPU and IB NIC (same PCIe root complex)
- Report GDR capability per GPU in agent resources

#### 3c. NCCL Configuration
- Auto-generate NCCL topology XML from detected hardware
- Inject into containers:
  ```
  NCCL_IB_HCA=mlx5_0           # IB device
  NCCL_IB_GID_INDEX=3           # RoCE GID (if RoCE)
  NCCL_NET_GDR_LEVEL=5          # GPUDirect level
  NCCL_SOCKET_IFNAME=ib0        # IB interface for OOB
  NCCL_TOPO_FILE=/etc/nccl/topo.xml
  ```
- `yoq gpu topo` command: show IB connectivity, NVLink topology, GDR status
- `yoq gpu bench` command: run NCCL all-reduce benchmark across placed ranks

#### 3d. Dual-Network Architecture
```
InfiniBand NDR (400G):  GPU-to-GPU traffic (NCCL, all-reduce, P2P)
WireGuard mesh (25G):   Control plane, health checks, scheduling, logs
```
yoq's WireGuard mesh handles orchestration traffic. IB carries the actual
tensor data. These are separate networks — no interference.

**Performance with InfiniBand NDR:**
```
All-Reduce (100 GPUs, 1GB):    ~45ms  (ring algorithm)
All-Reduce (100 GPUs, 100MB):  ~5ms
Point-to-point (GPU-to-GPU):   ~3μs latency, 48 GB/s sustained
```

### Phase 4: Petabyte Data Pipeline (3-4 weeks, ~2,000 lines)

**This is new and critical.** 100 H100s will consume training data at
~50-100 GB/s aggregate. The data pipeline must keep up or GPUs idle.

#### 4a. Distributed Data Loading
- **Parallel filesystem mount**: bind-mount Lustre/GPFS/BeeGFS into training
  containers (host mount passthrough)
- **Shard assignment**: each rank reads a disjoint shard of the dataset.
  yoq assigns shard ranges based on rank ID:
  ```toml
  [job.training]
  dataset = "/mnt/lustre/training-data"
  sharding = "file"  # or "byte-range"
  ```
- **Data-local scheduling**: prefer placing ranks on VMs close to their
  data shards (same rack as storage nodes)
- **Prefetch coordination**: CPU VMs run data preprocessing containers that
  stage tokenized batches to local NVMe, GPU containers read from local disk

#### 4b. Checkpoint Management
At 100 H100s, model state is ~200-800 GB per checkpoint (depending on model
size, optimizer state, and whether using ZeRO). At petabyte training scale,
you checkpoint every 15-60 minutes.

- **Coordinated checkpoint**: all ranks pause, save shard, barrier, resume
- **Async checkpoint**: overlap checkpoint I/O with next training step
- **yoq checkpoint** command:
  ```
  yoq checkpoint save <job> --path /mnt/lustre/checkpoints/step-1000
  yoq checkpoint list <job>
  yoq checkpoint restore <job> --from /mnt/lustre/checkpoints/step-1000
  ```
- **Checkpoint-aware scheduling**: on job restart, restore from latest
  checkpoint automatically
- **Storage bandwidth**: 100 ranks × 8 GB/rank = 800 GB checkpoint.
  Lustre at 100 GB/s aggregate → ~8s per checkpoint write. Acceptable.

#### 4c. Data Integrity
- Verify dataset checksums before training starts
- Detect and skip corrupted shards (log warning, don't crash the job)
- Track which shards each rank has consumed (resume without re-reading)

### Phase 5: Fault Tolerance for Long Training Runs (2-3 weeks, ~1,500 lines)

Petabyte-scale training runs for days to weeks. Hardware failures are
inevitable with 100 GPUs. Mean time between failure for 100 H100s is
roughly **2-5 days**.

#### 5a. Failure Detection
- GPU health monitoring via NVML: ECC errors (SRAM/DRAM), thermal throttling,
  NVLink CRC errors, XID errors
- IB link monitoring: port state, symbol errors, link flaps
- SWIM gossip detects VM failure within ~10-15s (existing)
- Training process heartbeat: if a rank stops reporting, fail fast

#### 5b. Failure Response
- **Rank failure**: pause all ranks, save emergency checkpoint, report to user
- **Elastic restart**: replace dead rank's VM with a spare, restore from
  checkpoint, resume training
  ```
  Rank 47 died (GPU ECC uncorrectable)
  → Emergency checkpoint saved at step 12,847
  → Spare VM gpu-spare-03 activated, assigned rank 47
  → Checkpoint restored, training resumed at step 12,847
  → Total downtime: ~90s
  ```
- **Spare pool**: designate N CPU VMs as warm spares with GPU (kept idle,
  ready to replace failed rank)
- **Degraded mode**: optionally continue training with fewer ranks (reduce
  world size, adjust batch size)

#### 5c. Preemptive Health Actions
- If GPU shows rising ECC error rate, proactively migrate rank before failure
- If IB link degrades, alert and re-route if possible
- Thermal throttling triggers workload reduction warning

### Phase 6: Training Job Orchestration (2-3 weeks, ~1,500 lines)

The user-facing layer that ties it all together.

#### 6a. Training Job Manifest
```toml
[training.my-llm]
image = "registry.internal/llm-trainer:v3"
command = "torchrun --nproc_per_node=1 train.py"
gpus = 100
gpu_type = "H100"

[training.my-llm.data]
dataset = "/mnt/lustre/pile-v2"
sharding = "file"
preprocessing = "tokenize"  # run on CPU VMs

[training.my-llm.checkpoint]
path = "/mnt/lustre/checkpoints/my-llm"
interval = "30m"
keep = 5  # rolling window

[training.my-llm.resources]
cpu = 16000       # 16 cores per rank
memory = "128GB"  # per rank
ib_required = true

[training.my-llm.fault_tolerance]
spare_ranks = 5
auto_restart = true
max_restarts = 10
```

#### 6b. Training Lifecycle Commands
```
yoq train start my-llm           # place all ranks, begin training
yoq train status my-llm          # show rank status, step count, loss
yoq train pause my-llm           # checkpoint and pause all ranks
yoq train resume my-llm          # restore from checkpoint, continue
yoq train stop my-llm            # final checkpoint and stop
yoq train scale my-llm --gpus 80 # elastic rescaling (checkpoint, relaunch)
yoq train logs my-llm --rank 0   # training logs from rank 0
```

#### 6c. Monitoring Dashboard Data
- Per-rank GPU utilization, memory, temperature
- Aggregate training throughput (tokens/sec, samples/sec)
- IB bandwidth utilization (are we saturating the fabric?)
- Data pipeline throughput (are GPUs waiting for data?)
- Checkpoint history and duration
- Loss curve data points (parsed from rank 0 stdout)

### Phase 7: GPU Monitoring & Observability (1-2 weeks, ~800 lines)

- NVML integration for per-GPU metrics
- IB port counters for network metrics
- Extend `yoq metrics` with GPU and IB data
- eBPF metrics for IB traffic patterns (optional, extend `bpf/metrics.c`)
- Alert thresholds: ECC errors, thermal, IB errors, data pipeline stalls

---

## Performance Assessment for Large Model Training

### Scaling Efficiency (100 H100s, InfiniBand NDR)

| Model Size | Parallelism Strategy | Expected Efficiency | Notes |
|-----------|----------------------|--------------------|----|
| **7-13B** | Pure data parallel (ZeRO-3) | **90-95%** | Gradient all-reduce is small relative to compute. Sweet spot. |
| **30-70B** | DP + Pipeline parallel | **80-90%** | PP within racks, DP across racks. Pipeline bubbles are the main loss. |
| **70-200B** | 3D parallel (TP+PP+DP) | **75-85%** | TP within node (NVLink), PP+DP across nodes (IB). Standard approach. |
| **400B+** | 3D parallel + expert parallel | **65-80%** | Pushing limits of 100 GPUs. Communication starts to dominate. |

### Throughput Estimates

```
Model       Tokens/sec (100 H100s, IB NDR)    Time for 1T tokens
───────────────────────────────────────────────────────────────────
7B          ~800,000 tok/s                     ~14 days
70B         ~80,000 tok/s                      ~145 days
200B        ~25,000 tok/s                      ~463 days
```

These are in line with published numbers from Meta (Llama), Google (PaLM),
and others on similarly-sized clusters.

### Data Pipeline Throughput Requirements

```
100 H100s × ~2,000 tokens/s/GPU (70B model) = ~200,000 tokens/s
Average token = ~4 bytes → ~800 KB/s raw throughput (trivial)
But: tokenized batches with padding/metadata → ~5-10 GB/s aggregate read

Lustre parallel filesystem: 100+ GB/s aggregate → 10-20x headroom
Local NVMe staging: each VM has ~3.2 TB NVMe → buffer ~hours of data
```

**Data loading is NOT the bottleneck** with a properly configured parallel
filesystem. Petabytes of raw data is large, but the model only reads each
sample once per epoch, and a single epoch on petabyte data takes months.

### Checkpoint Impact

```
70B model + optimizer state (ZeRO-3): ~400 GB total across 100 ranks
Each rank saves ~4 GB shard to Lustre
100 ranks × 4 GB = 400 GB, Lustre at 100 GB/s → ~4s write
Checkpoint every 30 min → <0.3% overhead
```

---

## Comparison: yoq vs. Slurm vs. Kubernetes

| Capability | yoq (proposed) | Slurm | K8s + GPU Operator |
|-----------|---------------|-------|-------------------|
| GPU passthrough | Device bind mount | GRES plugin | Device plugin + GPU operator |
| Gang scheduling | Built-in (proposed) | `--ntasks` (native) | Volcano/Kueue (add-on) |
| InfiniBand | Device passthrough | Native support | RDMA device plugin (add-on) |
| Fault recovery | Auto-restart + checkpoint | Manual requeue | Custom controller needed |
| Data pipeline | Container + filesystem mount | Filesystem mount | PVC + CSI driver |
| Networking | WireGuard (control) + IB (data) | No overlay | Calico/Cilium + Multus |
| Complexity | Single binary | Multiple daemons | 15+ components |
| Maturity for HPC | New | 20+ years | Catching up |

**yoq's advantage:** Single binary, no operator sprawl, integrated fault
recovery. The WireGuard + IB dual-network model is clean.

**yoq's risk:** Slurm has 20 years of battle-testing in HPC. yoq's gang
scheduler and checkpoint coordination are new code that must be extremely
reliable for multi-week training runs.

---

## Total Effort Summary

| Phase | Weeks | Lines of Zig | Risk |
|-------|-------|-------------|------|
| 1. GPU Passthrough | 2-3 | ~1,200 | Low — well-understood |
| 2. Gang Scheduling | 1-2 | ~600 | Medium — new scheduling paradigm |
| 3. IB/RDMA Data Plane | 3-4 | ~2,500 | Medium — hardware-dependent |
| 4. Data Pipeline | 3-4 | ~2,000 | Medium — filesystem integration |
| 5. Fault Tolerance | 2-3 | ~1,500 | High — must be bulletproof |
| 6. Training Orchestration | 2-3 | ~1,500 | Low — UX layer |
| 7. Monitoring | 1-2 | ~800 | Low — read-only |
| **Total** | **10-16** | **~8,000-12,000** | |

### Critical Path

```
Phase 1 → Phase 2 → Phase 3 → Phase 6 (minimum viable training)
                 └→ Phase 4 (can overlap with 3)
                 └→ Phase 5 (can overlap with 3-4)
                 └→ Phase 7 (can start anytime after 1)
```

Minimum viable: Phases 1+2+3+6 = **8-12 weeks** to run a training job.
Add fault tolerance (Phase 5) before any production training run.

---

## Likelihood of Being Performant

**High — with one caveat.**

The performance of distributed training is ~95% determined by:
1. GPU hardware (H100 — excellent)
2. Interconnect (InfiniBand NDR — excellent)
3. Collective communication library (NCCL — excellent)
4. Parallelism strategy (well-studied for all model sizes)

yoq's role is to **get out of the way**: pass through devices correctly,
place ranks intelligently, and recover from failures quickly. It does NOT
sit in the data path during training. Once containers are running with
GPU + IB access, NCCL talks directly over InfiniBand — yoq's overhead is
zero on the hot path.

The risk is not performance. The risk is **reliability** — a bug in gang
scheduling, checkpoint coordination, or fault recovery that causes a
multi-week training run to fail silently or lose progress. This is why
Phase 5 (Fault Tolerance) is marked high-risk and must be thoroughly tested
before production use.

---

## Open Questions (Resolved)

| Question | Previous | Now |
|----------|----------|-----|
| VM environment | Cloud? | Private data center |
| Network fabric | Unknown | InfiniBand NDR (assumed, standard for H100 DC SKU) |
| Primary workload | Unknown | Large model training on petabytes |
| Physical topology | Unknown | 1 H100 per GPU VM, 200 VMs total |

## Remaining Questions

1. **Model size target?** 7B-70B is comfortable on 100 GPUs. 200B+ is
   feasible but slower. 400B+ may want more GPUs.
2. **Training framework?** PyTorch (torchrun), DeepSpeed, Megatron-LM?
   Affects NCCL config and checkpoint format.
3. **Parallel filesystem?** Lustre, GPFS, BeeGFS? Affects mount config.
4. **Multi-GPU nodes?** If physical servers have 8x H100 (DGX-style),
   NVLink is available intra-node. Current plan assumes 1 GPU per VM.
5. **Timeline pressure?** 10-16 weeks is the estimate. Can prioritize
   minimum viable (8-12 weeks) if needed.
