const sqlite = @import("sqlite");

pub const SchemaError = error{InitFailed};

pub fn init(db: *sqlite.Db) SchemaError!void {
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_deployments_service
        \\    ON deployments (service_name, created_at DESC);
    );
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_training_checkpoints_job
        \\    ON training_checkpoints (job_id, created_at DESC);
    );
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_training_jobs_app
        \\    ON training_jobs (app_name, name);
    );
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_containers_app_name
        \\    ON containers (app_name);
    );
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_containers_status
        \\    ON containers (status);
    );
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_containers_hostname
        \\    ON containers (hostname);
    );
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_service_names_container
        \\    ON service_names (container_id);
    );
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_service_endpoints_service_admin_state
        \\    ON service_endpoints (service_name, admin_state);
    );
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_service_endpoints_container
        \\    ON service_endpoints (container_id);
    );
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_service_endpoints_node
        \\    ON service_endpoints (node_id);
    );
    try exec(db,
        \\CREATE UNIQUE INDEX IF NOT EXISTS idx_services_vip_address
        \\    ON services (vip_address);
    );
    try exec(db,
        \\CREATE INDEX IF NOT EXISTS idx_agents_status
        \\    ON agents (status);
    );
    try exec(db,
        \\CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policies_pair
        \\    ON network_policies (source_service, target_service);
    );
}

pub fn applyPragmas(db: *sqlite.Db) void {
    _ = sqlite.c.sqlite3_exec(db.db, "PRAGMA journal_mode=WAL;", null, null, null);
    _ = sqlite.c.sqlite3_exec(db.db, "PRAGMA synchronous=NORMAL;", null, null, null);
    _ = sqlite.c.sqlite3_exec(db.db, "PRAGMA busy_timeout=5000;", null, null, null);
}

fn exec(db: *sqlite.Db, comptime sql: []const u8) SchemaError!void {
    db.exec(sql, .{}, .{}) catch return SchemaError.InitFailed;
}
