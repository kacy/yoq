const sqlite = @import("sqlite");

pub const SchemaError = error{InitFailed};

pub const secrets_create_table_sql =
    \\CREATE TABLE IF NOT EXISTS secrets (
    \\    name TEXT PRIMARY KEY,
    \\    encrypted_value BLOB NOT NULL,
    \\    nonce BLOB NOT NULL,
    \\    tag BLOB NOT NULL,
    \\    created_at INTEGER NOT NULL,
    \\    updated_at INTEGER NOT NULL
    \\);
;

pub fn initCoreTables(db: *sqlite.Db) SchemaError!void {
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS containers (
        \\    id TEXT PRIMARY KEY,
        \\    rootfs TEXT NOT NULL,
        \\    command TEXT NOT NULL,
        \\    hostname TEXT NOT NULL DEFAULT 'container',
        \\    status TEXT NOT NULL DEFAULT 'created',
        \\    pid INTEGER,
        \\    exit_code INTEGER,
        \\    ip_address TEXT,
        \\    veth_host TEXT,
        \\    app_name TEXT,
        \\    created_at INTEGER NOT NULL
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS images (
        \\    id TEXT PRIMARY KEY,
        \\    repository TEXT NOT NULL,
        \\    tag TEXT NOT NULL DEFAULT 'latest',
        \\    manifest_digest TEXT NOT NULL,
        \\    config_digest TEXT NOT NULL,
        \\    total_size INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS ip_allocations (
        \\    container_id TEXT PRIMARY KEY,
        \\    ip_address TEXT NOT NULL UNIQUE,
        \\    allocated_at INTEGER NOT NULL
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS build_cache (
        \\    cache_key TEXT PRIMARY KEY,
        \\    layer_digest TEXT NOT NULL,
        \\    diff_id TEXT NOT NULL,
        \\    layer_size INTEGER NOT NULL,
        \\    created_at INTEGER NOT NULL
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS service_names (
        \\    name TEXT NOT NULL,
        \\    container_id TEXT NOT NULL,
        \\    ip_address TEXT NOT NULL,
        \\    registered_at INTEGER NOT NULL,
        \\    PRIMARY KEY (name, container_id)
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS services (
        \\    service_name TEXT PRIMARY KEY,
        \\    vip_address TEXT NOT NULL UNIQUE,
        \\    lb_policy TEXT NOT NULL DEFAULT 'consistent_hash',
        \\    http_proxy_host TEXT,
        \\    http_proxy_path_prefix TEXT,
        \\    http_proxy_rewrite_prefix TEXT,
        \\    http_proxy_retries INTEGER,
        \\    http_proxy_connect_timeout_ms INTEGER,
        \\    http_proxy_request_timeout_ms INTEGER,
        \\    http_proxy_http2_idle_timeout_ms INTEGER,
        \\    http_proxy_target_port INTEGER,
        \\    http_proxy_preserve_host INTEGER,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS service_endpoints (
        \\    service_name TEXT NOT NULL,
        \\    endpoint_id TEXT NOT NULL,
        \\    container_id TEXT NOT NULL,
        \\    node_id INTEGER,
        \\    ip_address TEXT NOT NULL,
        \\    port INTEGER NOT NULL,
        \\    weight INTEGER NOT NULL DEFAULT 1,
        \\    admin_state TEXT NOT NULL DEFAULT 'active',
        \\    generation INTEGER NOT NULL,
        \\    registered_at INTEGER NOT NULL,
        \\    last_seen_at INTEGER NOT NULL,
        \\    PRIMARY KEY (service_name, endpoint_id)
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS service_http_routes (
        \\    service_name TEXT NOT NULL,
        \\    route_name TEXT NOT NULL,
        \\    host TEXT NOT NULL,
        \\    path_prefix TEXT NOT NULL DEFAULT '/',
        \\    rewrite_prefix TEXT,
        \\    mirror_service TEXT,
        \\    retries INTEGER NOT NULL DEFAULT 0,
        \\    connect_timeout_ms INTEGER NOT NULL DEFAULT 1000,
        \\    request_timeout_ms INTEGER NOT NULL DEFAULT 5000,
        \\    http2_idle_timeout_ms INTEGER NOT NULL DEFAULT 30000,
        \\    target_port INTEGER,
        \\    preserve_host INTEGER NOT NULL DEFAULT 1,
        \\    retry_on_5xx INTEGER NOT NULL DEFAULT 1,
        \\    circuit_breaker_threshold INTEGER NOT NULL DEFAULT 3,
        \\    circuit_breaker_timeout_ms INTEGER NOT NULL DEFAULT 30000,
        \\    route_order INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (service_name, route_name)
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS service_http_route_methods (
        \\    service_name TEXT NOT NULL,
        \\    route_name TEXT NOT NULL,
        \\    method TEXT NOT NULL,
        \\    match_order INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (service_name, route_name, match_order)
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS service_http_route_headers (
        \\    service_name TEXT NOT NULL,
        \\    route_name TEXT NOT NULL,
        \\    header_name TEXT NOT NULL,
        \\    header_value TEXT NOT NULL,
        \\    match_order INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (service_name, route_name, match_order)
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS service_http_route_backends (
        \\    service_name TEXT NOT NULL,
        \\    route_name TEXT NOT NULL,
        \\    backend_service TEXT NOT NULL,
        \\    weight INTEGER NOT NULL,
        \\    backend_order INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (service_name, route_name, backend_order)
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS deployments (
        \\    id TEXT PRIMARY KEY,
        \\    app_name TEXT,
        \\    service_name TEXT NOT NULL,
        \\    trigger TEXT NOT NULL DEFAULT 'apply',
        \\    source_release_id TEXT,
        \\    manifest_hash TEXT NOT NULL,
        \\    config_snapshot TEXT NOT NULL DEFAULT '',
        \\    completed_targets INTEGER NOT NULL DEFAULT 0,
        \\    failed_targets INTEGER NOT NULL DEFAULT 0,
        \\    status TEXT NOT NULL DEFAULT 'pending',
        \\    message TEXT,
        \\    created_at INTEGER NOT NULL
        \\);
    );
}

pub fn initClusterTables(db: *sqlite.Db) SchemaError!void {
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS agents (
        \\    id TEXT PRIMARY KEY,
        \\    address TEXT NOT NULL,
        \\    agent_api_port INTEGER,
        \\    status TEXT NOT NULL DEFAULT 'active',
        \\    cpu_cores INTEGER NOT NULL DEFAULT 0,
        \\    memory_mb INTEGER NOT NULL DEFAULT 0,
        \\    cpu_used INTEGER NOT NULL DEFAULT 0,
        \\    memory_used_mb INTEGER NOT NULL DEFAULT 0,
        \\    containers INTEGER NOT NULL DEFAULT 0,
        \\    last_heartbeat INTEGER NOT NULL,
        \\    registered_at INTEGER NOT NULL
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS assignments (
        \\    id TEXT PRIMARY KEY,
        \\    agent_id TEXT NOT NULL,
        \\    image TEXT NOT NULL,
        \\    command TEXT NOT NULL DEFAULT '',
        \\    status TEXT NOT NULL DEFAULT 'pending',
        \\    cpu_limit INTEGER NOT NULL DEFAULT 1000,
        \\    memory_limit_mb INTEGER NOT NULL DEFAULT 256,
        \\    app_name TEXT,
        \\    workload_kind TEXT,
        \\    workload_name TEXT,
        \\    health_check_json TEXT,
        \\    gang_rank INTEGER,
        \\    gang_world_size INTEGER,
        \\    gang_master_addr TEXT,
        \\    gang_master_port INTEGER,
        \\    created_at INTEGER NOT NULL
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS gpu_allocations (
        \\    assignment_id TEXT NOT NULL,
        \\    agent_id TEXT NOT NULL,
        \\    gpu_index INTEGER NOT NULL,
        \\    allocated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (agent_id, gpu_index)
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS wireguard_peers (
        \\    node_id INTEGER NOT NULL,
        \\    agent_id TEXT NOT NULL,
        \\    public_key TEXT NOT NULL,
        \\    endpoint TEXT NOT NULL,
        \\    overlay_ip TEXT NOT NULL,
        \\    container_subnet TEXT NOT NULL,
        \\    PRIMARY KEY (node_id)
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS cron_schedules (
        \\    app_name TEXT NOT NULL,
        \\    name TEXT NOT NULL,
        \\    every INTEGER NOT NULL,
        \\    spec_json TEXT NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (app_name, name)
        \\);
    );
}

pub fn initSecurityTables(db: *sqlite.Db) SchemaError!void {
    try exec(db, secrets_create_table_sql);
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS network_policies (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    source_service TEXT NOT NULL,
        \\    target_service TEXT NOT NULL,
        \\    action TEXT NOT NULL,
        \\    created_at INTEGER NOT NULL
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS certificates (
        \\    domain TEXT PRIMARY KEY,
        \\    cert_pem BLOB NOT NULL,
        \\    encrypted_key BLOB NOT NULL,
        \\    key_nonce BLOB NOT NULL,
        \\    key_tag BLOB NOT NULL,
        \\    not_after INTEGER NOT NULL,
        \\    source TEXT NOT NULL DEFAULT 'manual',
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL
        \\);
    );
}

pub fn initStorageTables(db: *sqlite.Db) SchemaError!void {
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS volumes (
        \\    name TEXT NOT NULL,
        \\    app_name TEXT NOT NULL,
        \\    driver TEXT NOT NULL DEFAULT 'local',
        \\    path TEXT NOT NULL,
        \\    status TEXT NOT NULL DEFAULT 'created',
        \\    node_id TEXT,
        \\    created_at INTEGER NOT NULL,
        \\    PRIMARY KEY (name, app_name)
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS s3_multipart_uploads (
        \\    upload_id TEXT PRIMARY KEY,
        \\    bucket TEXT NOT NULL,
        \\    key TEXT NOT NULL,
        \\    status TEXT NOT NULL DEFAULT 'in_progress',
        \\    created_at INTEGER NOT NULL
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS s3_upload_parts (
        \\    upload_id TEXT NOT NULL,
        \\    part_number INTEGER NOT NULL,
        \\    etag TEXT NOT NULL,
        \\    size INTEGER NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    PRIMARY KEY (upload_id, part_number)
        \\);
    );
}

pub fn initTrainingTables(db: *sqlite.Db) SchemaError!void {
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS training_jobs (
        \\    id TEXT PRIMARY KEY,
        \\    name TEXT NOT NULL,
        \\    app_name TEXT NOT NULL,
        \\    state TEXT NOT NULL DEFAULT 'pending',
        \\    image TEXT NOT NULL,
        \\    gpus INTEGER NOT NULL,
        \\    checkpoint_path TEXT,
        \\    checkpoint_interval INTEGER,
        \\    checkpoint_keep INTEGER,
        \\    restart_count INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL
        \\);
    );
    try exec(db,
        \\CREATE TABLE IF NOT EXISTS training_checkpoints (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    job_id TEXT NOT NULL,
        \\    step INTEGER NOT NULL,
        \\    path TEXT NOT NULL,
        \\    size_bytes INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    FOREIGN KEY (job_id) REFERENCES training_jobs(id)
        \\);
    );
}

fn exec(db: *sqlite.Db, comptime sql: []const u8) SchemaError!void {
    db.exec(sql, .{}, .{}) catch return SchemaError.InitFailed;
}
