# Competitive Analysis: yoq GPU Mesh vs. The Market

## Context

yoq is a single-binary container orchestrator (Zig, ~52k lines) that replaces
Docker+Kubernetes+Istio. The GPU mesh plan adds support for 100 H100s across
200 VMs in a private data center, training large models on petabytes of data.
This document assesses how competitive yoq would be against existing GPU
orchestration solutions if the plan is fully executed.

---

## The Competitive Landscape (2025-2026)

### Tier 1: What the Big Labs Actually Use

| Lab | Stack | Scale |
|-----|-------|-------|
| **Meta** | Custom scheduler + Slurm + NCCL on RSC clusters | 600K+ GPUs |
| **Google** | Borg/Autopilot (internal) + JAX/XLA + TPU/GPU | 100K+ TPUs/GPUs |
| **Microsoft** | Singularity (internal) + custom scheduler | 100K+ GPUs |
| **Anthropic/OpenAI** | Custom internal + cloud partnerships | 10K-100K+ GPUs |

Nobody at frontier scale uses an off-the-shelf orchestrator without heavy
modification. At 100 H100s, yoq would compete in the **sub-frontier** tier
where the market is actually open.

### Tier 2: Open Source Orchestrators (direct competitors)

#### Slurm (SchedMD)
- **Maturity:** 20+ years, dominant in HPC/academia
- **GPU:** GRES plugin — native, well-tested
- **Gang scheduling:** `--ntasks` + `--nodes` — native
- **InfiniBand:** Native (bare metal, no passthrough needed)
- **Fault tolerance:** Job requeue on failure, no automatic checkpoint coordination
- **Checkpoint:** Not built-in. Relies on framework (PyTorch FSDP, DeepSpeed)
- **Data pipeline:** Filesystem mounts only
- **Complexity:** 2 daemons (slurmd + slurmctld). Simple but no service discovery,
  secrets, TLS, or rolling updates.
- **Who uses it:** Meta (RSC), most universities, national labs, AMD (MaxText-Slurm),
  Nebius
- **Weakness:** No containers. No service discovery. No secrets. No TLS. Manual
  checkpoint management. Cryptic config syntax.

#### Kubernetes + GPU Ecosystem
- **Components:** kubelet + kube-proxy + etcd + CNI (Calico/Cilium) + GPU Operator
  + NVIDIA device plugin + KAI Scheduler (or Volcano/Kueue) + RDMA device plugin
  + Multus (multi-network) + cert-manager + ...
- **Gang scheduling:** KAI Scheduler (open-sourced from Run:ai, April 2025) —
  topology-aware, hierarchical PodGroups
- **InfiniBand:** RDMA device plugin + Multus for secondary networks
- **Fault tolerance:** Pod eviction + PodDisruptionBudgets. No checkpoint coordination.
- **Scale:** CoreWeave demonstrates 50,000+ GPU clusters
- **Complexity:** 15+ components. Steep learning curve. YAML sprawl.
- **Who uses it:** CoreWeave, cloud providers, enterprises
- **Weakness:** Operational complexity. Not designed for HPC gang scheduling (bolted
  on). Multi-network (Multus) is painful.

#### Ray / Anyscale
- **Focus:** Distributed Python, not container orchestration
- **GPU:** Ray GPU resources, auto-scaling
- **Gang scheduling:** Via KAI Scheduler integration (November 2025)
- **Strength:** Great for Python-native ML workflows
- **Weakness:** Requires infrastructure underneath (K8s or cloud). Another layer.

#### SkyPilot (UC Berkeley)
- **Focus:** Multi-cloud job orchestration, not cluster management
- **GPU:** Abstracts provisioning across 20+ clouds + K8s + Slurm
- **Strength:** Cost optimization, cloud portability
- **Weakness:** Not for bare-metal data centers. Doesn't manage the cluster itself.

#### Determined AI (HPE)
- **Focus:** ML experiment management + training orchestration
- **GPU:** Native scheduling, elastic training
- **Gang scheduling:** Built-in
- **Fault tolerance:** Built-in checkpoint management + elastic retraining
- **Strength:** Best-in-class experiment tracking + training lifecycle
- **Weakness:** Requires Kubernetes or Slurm underneath. Not standalone.

### Tier 3: Managed GPU Platforms (not direct competitors)

CoreWeave, Lambda Labs, Together AI, Modal, Crusoe — these are **cloud
providers**, not orchestrators. yoq competes with the software they run on
top of their hardware.

### Tier 4: NVIDIA Proprietary Stack

- **Base Command Manager (BCM):** Cluster provisioning + management
- **Mission Control:** Full-stack management for DGX SuperPOD
- **KAI Scheduler (ex-Run:ai):** GPU scheduling, open-sourced April 2025
- **NeMo:** Training framework with Slurm-aware resiliency
- **Free with DGX hardware** but vendor-locked. yoq would be hardware-agnostic.

---

## Competitive Matrix

| Capability | yoq (proposed) | Slurm | K8s+KAI | Ray | SkyPilot | Determined |
|-----------|---------------|-------|---------|-----|----------|------------|
| **Self-contained** | Single binary | 2 daemons | 15+ components | Python lib | Python CLI | K8s/Slurm required |
| **Setup time** | Minutes | Hours | Days | Hours | Minutes | Hours |
| **Config** | 1 TOML | 1 conf | 10+ YAML | Python | 1 YAML | 1 YAML |
| **Gang scheduling** | Planned | Native | KAI (bolt-on) | Via KAI | Delegated | Built-in |
| **InfiniBand** | Planned | Native | RDMA plugin | Delegated | Delegated | Delegated |
| **Service discovery** | Built-in (eBPF) | None | CoreDNS | None | None | None |
| **Secrets** | Built-in | None | etcd | None | None | None |
| **TLS/ACME** | Built-in | None | cert-manager | None | None | None |
| **Checkpoint mgmt** | Planned | None | None | Framework | Framework | Built-in |
| **Fault recovery** | Planned | Requeue | Pod eviction | Elastic | Spot recovery | Elastic |
| **Multi-service** | Native | No | Native | Limited | No | No |
| **Maturity** | New | 20+ years | 10+ years | 5+ years | 3+ years | 5+ years |

---

## Where yoq Wins

### 1. Operational Simplicity (Strongest Advantage)

The GPU orchestration market has a complexity problem:
- Kubernetes GPU stack: 15+ components, each with its own config, upgrade
  cycle, and failure mode
- Slurm: simple daemon but no modern ops (no service discovery, secrets, TLS)
- Everyone else: requires K8s or Slurm underneath

yoq is the **only solution that is fully self-contained.** One binary, one
TOML, one state store. For a 50-200 GPU team without a dedicated platform
engineer, this is the pitch.

### 2. Integrated Training Lifecycle (Product Gap)

Nobody does training lifecycle well out of the box:
- Slurm: checkpoint is the user's problem
- Kubernetes: checkpoint is the user's problem
- Determined AI: closest, but requires K8s/Slurm underneath

yoq's `yoq train` commands (start, pause, resume, scale, checkpoint) would
be the **first fully integrated training lifecycle** in a standalone
orchestrator. This is a genuine market gap.

### 3. Dual-Network Architecture

WireGuard (control) + InfiniBand (data) is clean and correct. Kubernetes
struggles with this — Multus for secondary networks adds complexity. Slurm
doesn't have overlay networking, which limits container isolation.

### 4. Free, Open Source, Hardware-Agnostic

NVIDIA's stack is free with DGX but vendor-locked. yoq would be free,
open-source, and run on any hardware with H100s and IB.

---

## Where yoq Loses

### 1. Maturity and Battle-Testing (Biggest Risk)

Meta's RSC paper (HPCA 2025) shows that at 12K GPU scale, achieving >90%
effective training time ratio requires checkpoint writes under 1 minute and
robust fault recovery. This reliability takes years of production use to
build.

yoq's gang scheduler, checkpoint coordination, and fault recovery would be
brand new code. A single bug in checkpoint coordination can silently corrupt
a multi-week training run.

**Mitigation:** Start at 100 GPU scale where failures are less frequent.
Run parallel validation against Slurm.

### 2. Ecosystem and Integrations

- Slurm: deep integration with NeMo, DeepSpeed, PyTorch, every national lab
- Kubernetes: Prometheus, Grafana, ArgoCD, thousands of operators
- yoq: none

**Mitigation:** Training containers bring their own framework. yoq just
passes through devices. Prometheus metric export would help adoption.

### 3. Community and Hiring

Finding Slurm/K8s engineers: easy. Finding Zig/yoq engineers: hard.

**Mitigation:** yoq's simplicity means less specialized knowledge needed.

### 4. Multi-GPU Node Topology

The plan assumes 1 GPU per VM. Real data center nodes are 8x H100 (DGX)
with NVLink. Tensor parallelism within a node via NVLink is critical.

**Mitigation:** Support `gpu_limit > 1` per container and expose NVLink
topology. Straightforward extension.

---

## Confidence Ratings by Scale

### 50-500 GPUs: 80% Competitive

This is yoq's sweet spot. At this scale:
- Slurm works but is operationally dated
- Kubernetes is overkill (15+ components for batch training)
- Purpose-built tools (Determined, SkyPilot) need K8s/Slurm underneath

yoq would be the **simplest path to "run a training job on 100 GPUs"**
with production features (secrets, TLS, health checks, service discovery).

### 1,000 GPUs: 60% Competitive

SWIM gossip and Raft handle 1,000+ nodes, but:
- Gang scheduling 1,000 GPUs atomically has more failure modes
- IB fabric topology matters more (fat-tree, rail-optimized)
- Need topology-aware scheduling (rack, switch, rail)

### 10,000+ GPUs: 20% Competitive

Not competitive without major investment. Meta, Google, and Microsoft all
use custom systems with dedicated teams at this scale. Qualitatively
different requirements.

---

## Strategic Positioning

**Target market:** Teams running 50-500 GPUs who want production features
without the Kubernetes tax. This is a real and growing segment — most
organizations train at sub-1000 GPU scale.

**Pitch:**

> Train your 70B model on 100 H100s with one binary and one TOML file.
> No Kubernetes. No Slurm. No YAML. Built-in checkpointing, fault recovery,
> InfiniBand passthrough, and service discovery. Deploy in minutes, not days.

**Key differentiator:** Not performance (NCCL handles that). Not scale
(K8s wins there). **Operational simplicity** — the only self-contained GPU
training orchestrator that doesn't need another orchestrator underneath it.
