pub const agents_schema =
    \\CREATE TABLE agents (
    \\    id TEXT PRIMARY KEY,
    \\    address TEXT NOT NULL,
    \\    status TEXT NOT NULL DEFAULT 'active',
    \\    cpu_cores INTEGER NOT NULL DEFAULT 0,
    \\    memory_mb INTEGER NOT NULL DEFAULT 0,
    \\    cpu_used INTEGER NOT NULL DEFAULT 0,
    \\    memory_used_mb INTEGER NOT NULL DEFAULT 0,
    \\    containers INTEGER NOT NULL DEFAULT 0,
    \\    last_heartbeat INTEGER NOT NULL,
    \\    registered_at INTEGER NOT NULL,
    \\    node_id INTEGER,
    \\    wg_public_key TEXT,
    \\    overlay_ip TEXT,
    \\    role TEXT DEFAULT 'both',
    \\    region TEXT,
    \\    labels TEXT DEFAULT '',
    \\    gpu_count INTEGER DEFAULT 0,
    \\    gpu_used INTEGER DEFAULT 0,
    \\    gpu_model TEXT,
    \\    gpu_vram_mb INTEGER,
    \\    rdma_capable INTEGER DEFAULT 0
    \\);
;
