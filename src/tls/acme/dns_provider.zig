const std = @import("std");
const http = std.http;

const json_support = @import("json_support.zig");
const acme_config = @import("config.zig");
const types = @import("types.zig");
const secrets = @import("../../state/secrets.zig");

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: acme_config.ManagedConfig,
    http_client: http.Client,
    state: State,

    const State = union(enum) {
        cloudflare: CloudflareState,
        route53: Route53State,
        gcloud: GcloudState,
        exec: ExecState,
    };

    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        config: acme_config.ManagedConfig,
        secrets_store: ?*secrets.SecretsStore,
    ) types.AcmeError!Runtime {
        var owned = config.clone(allocator) catch return types.AcmeError.AllocFailed;
        errdefer owned.deinit(allocator);

        return .{
            .allocator = allocator,
            .io = io,
            .config = owned,
            .http_client = .{ .io = io, .allocator = allocator },
            .state = try initState(allocator, owned, secrets_store),
        };
    }

    pub fn deinit(self: *Runtime) void {
        switch (self.state) {
            .cloudflare => |*state| state.deinit(self.allocator),
            .route53 => |*state| state.deinit(self.allocator),
            .gcloud => |*state| state.deinit(self.allocator),
            .exec => |*state| state.deinit(self.allocator),
        }
        self.http_client.deinit();
        self.config.deinit(self.allocator);
    }

    pub fn solver(self: *Runtime) types.DnsSolver {
        return switch (self.state) {
            .cloudflare => .{
                .ctx = self,
                .present_fn = presentCloudflare,
                .cleanup_fn = cleanupCloudflare,
            },
            .route53 => .{
                .ctx = self,
                .present_fn = presentRoute53,
                .cleanup_fn = cleanupRoute53,
            },
            .gcloud => .{
                .ctx = self,
                .present_fn = presentGcloud,
                .cleanup_fn = cleanupGcloud,
            },
            .exec => .{
                .ctx = self,
                .present_fn = presentExec,
                .cleanup_fn = cleanupExec,
            },
        };
    }
};

const CloudflareState = struct {
    api_token: []const u8,
    zone_id: []const u8,
    record_id: ?[]u8 = null,

    fn deinit(self: *CloudflareState, allocator: std.mem.Allocator) void {
        allocator.free(self.api_token);
        allocator.free(self.zone_id);
        if (self.record_id) |record_id| allocator.free(record_id);
    }
};

const Route53State = struct {
    access_key_id: []const u8,
    secret_access_key: []const u8,
    hosted_zone_id: []const u8,
    region: []const u8,

    fn deinit(self: *Route53State, allocator: std.mem.Allocator) void {
        allocator.free(self.access_key_id);
        allocator.free(self.secret_access_key);
        allocator.free(self.hosted_zone_id);
        allocator.free(self.region);
    }
};

const GcloudState = struct {
    access_token: []const u8,
    project: []const u8,
    managed_zone: []const u8,

    fn deinit(self: *GcloudState, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        allocator.free(self.project);
        allocator.free(self.managed_zone);
    }
};

const ExecState = struct {
    env_pairs: []const acme_config.KeyValueRef,

    fn deinit(self: *ExecState, allocator: std.mem.Allocator) void {
        for (self.env_pairs) |entry| entry.deinit(allocator);
        allocator.free(self.env_pairs);
    }
};

fn initState(
    allocator: std.mem.Allocator,
    config: acme_config.ManagedConfig,
    secrets_store: ?*secrets.SecretsStore,
) types.AcmeError!Runtime.State {
    const provider = config.dns_provider orelse return types.AcmeError.ChallengeFailed;
    return switch (provider) {
        .cloudflare => .{ .cloudflare = .{
            .api_token = try requireSecret(config, secrets_store, "api_token"),
            .zone_id = try requireConfigValue(allocator, config, "zone_id"),
        } },
        .route53 => .{ .route53 = .{
            .access_key_id = try requireSecret(config, secrets_store, "access_key_id"),
            .secret_access_key = try requireSecret(config, secrets_store, "secret_access_key"),
            .hosted_zone_id = try requireConfigValue(allocator, config, "hosted_zone_id"),
            .region = try optionalConfigValue(allocator, config, "region", "us-east-1"),
        } },
        .gcloud => .{ .gcloud = .{
            .access_token = try requireSecret(config, secrets_store, "access_token"),
            .project = try requireConfigValue(allocator, config, "project"),
            .managed_zone = try requireConfigValue(allocator, config, "managed_zone"),
        } },
        .exec => .{ .exec = .{
            .env_pairs = try resolveAllSecrets(allocator, config, secrets_store),
        } },
    };
}

fn presentCloudflare(ctx: *anyopaque, record_name: []const u8, value: []const u8) types.AcmeError!void {
    const runtime: *Runtime = @ptrCast(@alignCast(ctx));
    const state = switch (runtime.state) {
        .cloudflare => |*state| state,
        else => unreachable,
    };

    const body = std.fmt.allocPrint(
        runtime.allocator,
        "{{\"type\":\"TXT\",\"name\":\"{s}\",\"content\":\"{s}\",\"ttl\":120}}",
        .{ record_name, value },
    ) catch return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(body);

    var auth_buf: [1024]u8 = undefined;
    const auth = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{state.api_token}) catch
        return types.AcmeError.AllocFailed;
    const url = std.fmt.allocPrint(
        runtime.allocator,
        "https://api.cloudflare.com/client/v4/zones/{s}/dns_records",
        .{state.zone_id},
    ) catch return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(url);

    const response = sendRequest(
        runtime,
        .POST,
        url,
        "application/json",
        body,
        &.{
            .{ .name = "Authorization", .value = auth },
        },
    ) catch return types.AcmeError.ChallengeFailed;
    defer runtime.allocator.free(response.body);

    if (@intFromEnum(response.status) / 100 != 2) return types.AcmeError.ChallengeFailed;
    const record_id = json_support.extractJsonString(runtime.allocator, response.body, "id") catch
        return types.AcmeError.ChallengeFailed;
    if (state.record_id) |existing| runtime.allocator.free(existing);
    state.record_id = record_id;
}

fn cleanupCloudflare(ctx: *anyopaque, record_name: []const u8, value: []const u8) void {
    _ = record_name;
    _ = value;
    const runtime: *Runtime = @ptrCast(@alignCast(ctx));
    const state = switch (runtime.state) {
        .cloudflare => |*state| state,
        else => unreachable,
    };
    const record_id = state.record_id orelse return;

    var auth_buf: [1024]u8 = undefined;
    const auth = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{state.api_token}) catch return;
    const url = std.fmt.allocPrint(
        runtime.allocator,
        "https://api.cloudflare.com/client/v4/zones/{s}/dns_records/{s}",
        .{ state.zone_id, record_id },
    ) catch return;
    defer runtime.allocator.free(url);

    const response = sendRequest(
        runtime,
        .DELETE,
        url,
        null,
        null,
        &.{
            .{ .name = "Authorization", .value = auth },
        },
    ) catch return;
    runtime.allocator.free(response.body);
    runtime.allocator.free(record_id);
    state.record_id = null;
}

fn presentRoute53(ctx: *anyopaque, record_name: []const u8, value: []const u8) types.AcmeError!void {
    try route53Change(@ptrCast(@alignCast(ctx)), "UPSERT", record_name, value);
}

fn cleanupRoute53(ctx: *anyopaque, record_name: []const u8, value: []const u8) void {
    route53Change(@ptrCast(@alignCast(ctx)), "DELETE", record_name, value) catch {};
}

fn route53Change(runtime: *Runtime, action: []const u8, record_name: []const u8, value: []const u8) types.AcmeError!void {
    const state = switch (runtime.state) {
        .route53 => |*state| state,
        else => unreachable,
    };
    const name = ensureTrailingDot(runtime.allocator, record_name) catch return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(name);
    const quoted_value = std.fmt.allocPrint(runtime.allocator, "\"{s}\"", .{value}) catch
        return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(quoted_value);
    const body = std.fmt.allocPrint(
        runtime.allocator,
        "<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\">" ++
            "<ChangeBatch><Changes><Change><Action>{s}</Action><ResourceRecordSet>" ++
            "<Name>{s}</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>{s}</Value></ResourceRecord></ResourceRecords>" ++
            "</ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>",
        .{ action, name, quoted_value },
    ) catch return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(body);

    const host = "route53.amazonaws.com";
    const path = std.fmt.allocPrint(
        runtime.allocator,
        "/2013-04-01/hostedzone/{s}/rrset/",
        .{state.hosted_zone_id},
    ) catch return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(path);
    const url = std.fmt.allocPrint(runtime.allocator, "https://{s}{s}", .{ host, path }) catch
        return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(url);

    var amz_date_buf: [16]u8 = undefined;
    var short_date_buf: [8]u8 = undefined;
    formatAmzDate(&amz_date_buf, &short_date_buf);

    const payload_hash = sha256Hex(body);
    const auth_value = buildRoute53Authorization(
        runtime.allocator,
        state.access_key_id,
        state.secret_access_key,
        state.region,
        host,
        path,
        &amz_date_buf,
        &short_date_buf,
        payload_hash[0..],
    ) catch return types.AcmeError.ChallengeFailed;
    defer runtime.allocator.free(auth_value);

    const response = sendRequest(
        runtime,
        .POST,
        url,
        "application/xml",
        body,
        &.{
            .{ .name = "Authorization", .value = auth_value },
            .{ .name = "X-Amz-Date", .value = &amz_date_buf },
            .{ .name = "X-Amz-Content-Sha256", .value = payload_hash[0..] },
        },
    ) catch return types.AcmeError.ChallengeFailed;
    defer runtime.allocator.free(response.body);

    if (@intFromEnum(response.status) / 100 != 2) return types.AcmeError.ChallengeFailed;
}

fn presentGcloud(ctx: *anyopaque, record_name: []const u8, value: []const u8) types.AcmeError!void {
    try gcloudChange(@ptrCast(@alignCast(ctx)), "additions", record_name, value);
}

fn cleanupGcloud(ctx: *anyopaque, record_name: []const u8, value: []const u8) void {
    gcloudChange(@ptrCast(@alignCast(ctx)), "deletions", record_name, value) catch {};
}

fn gcloudChange(runtime: *Runtime, field_name: []const u8, record_name: []const u8, value: []const u8) types.AcmeError!void {
    const state = switch (runtime.state) {
        .gcloud => |*state| state,
        else => unreachable,
    };
    const name = ensureTrailingDot(runtime.allocator, record_name) catch return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(name);
    const quoted = std.fmt.allocPrint(runtime.allocator, "\"{s}\"", .{value}) catch
        return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(quoted);
    const body = std.fmt.allocPrint(
        runtime.allocator,
        "{{\"{s}\":[{{\"name\":\"{s}\",\"type\":\"TXT\",\"ttl\":60,\"rrdatas\":[{s}]}}]}}",
        .{ field_name, name, quoted },
    ) catch return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(body);

    var auth_buf: [2048]u8 = undefined;
    const auth = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{state.access_token}) catch
        return types.AcmeError.AllocFailed;
    const url = std.fmt.allocPrint(
        runtime.allocator,
        "https://dns.googleapis.com/dns/v1/projects/{s}/managedZones/{s}/changes",
        .{ state.project, state.managed_zone },
    ) catch return types.AcmeError.AllocFailed;
    defer runtime.allocator.free(url);

    const response = sendRequest(
        runtime,
        .POST,
        url,
        "application/json",
        body,
        &.{
            .{ .name = "Authorization", .value = auth },
        },
    ) catch return types.AcmeError.ChallengeFailed;
    defer runtime.allocator.free(response.body);

    if (@intFromEnum(response.status) / 100 != 2) return types.AcmeError.ChallengeFailed;
}

fn presentExec(ctx: *anyopaque, record_name: []const u8, value: []const u8) types.AcmeError!void {
    const runtime: *Runtime = @ptrCast(@alignCast(ctx));
    execHook(runtime, "present", record_name, value) catch return types.AcmeError.ChallengeFailed;
}

fn cleanupExec(ctx: *anyopaque, record_name: []const u8, value: []const u8) void {
    const runtime: *Runtime = @ptrCast(@alignCast(ctx));
    execHook(runtime, "cleanup", record_name, value) catch {};
}

fn execHook(runtime: *Runtime, action: []const u8, record_name: []const u8, value: []const u8) !void {
    if (runtime.config.hook_command.len == 0) return error.MissingHook;

    var env_map = std.process.Environ.Map.init(runtime.allocator);
    defer env_map.deinit();
    try seedHookEnv(&env_map);
    try env_map.put("YOQ_ACME_CHALLENGE", "dns-01");
    try env_map.put("YOQ_ACME_ACTION", action);
    try env_map.put("YOQ_ACME_DOMAIN", domainFromRecord(record_name));
    try env_map.put("YOQ_ACME_RECORD", record_name);
    try env_map.put("YOQ_ACME_VALUE", value);
    try env_map.put("YOQ_ACME_DIRECTORY_URL", runtime.config.directory_url);

    const exec_state = switch (runtime.state) {
        .exec => |*state| state,
        else => unreachable,
    };
    for (exec_state.env_pairs) |entry| {
        try env_map.put(entry.key, entry.value);
    }

    const argv = try buildHookArgv(runtime.allocator, runtime.config.hook_command, action);
    defer runtime.allocator.free(argv);

    var child = try std.process.spawn(runtime.io, .{
        .argv = argv,
        .environ_map = &env_map,
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(runtime.io);
    switch (term) {
        .exited => |code| if (code == 0) return else return error.HookFailed,
        else => return error.HookFailed,
    }
}

fn sendRequest(
    runtime: *Runtime,
    method: http.Method,
    url: []const u8,
    content_type: ?[]const u8,
    body: ?[]const u8,
    extra_headers: []const http.Header,
) !HttpResponse {
    const uri = try std.Uri.parse(url);
    var req = try runtime.http_client.request(method, uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .headers = .{
            .content_type = if (content_type) |value| .{ .override = value } else .default,
        },
        .extra_headers = extra_headers,
    });
    defer req.deinit();

    if (body) |payload| {
        try req.sendBodyComplete(@constCast(payload));
    } else {
        try req.sendBodiless();
    }

    var head_buf: [16384]u8 = undefined;
    var response = try req.receiveHead(&head_buf);

    var transfer_buf: [8192]u8 = undefined;
    const body_reader = response.reader(&transfer_buf);
    var aw: std.Io.Writer.Allocating = .init(runtime.allocator);
    defer aw.deinit();
    _ = try body_reader.streamRemaining(&aw.writer);

    return .{
        .status = response.head.status,
        .body = try runtime.allocator.dupe(u8, aw.writer.buffer[0..aw.writer.end]),
    };
}

const HttpResponse = struct {
    status: http.Status,
    body: []u8,
};

fn requireSecret(
    config: acme_config.ManagedConfig,
    secrets_store: ?*secrets.SecretsStore,
    key: []const u8,
) types.AcmeError![]const u8 {
    const store = secrets_store orelse return types.AcmeError.ChallengeFailed;
    const secret_name = findPairValue(config.secret_refs, key) orelse return types.AcmeError.ChallengeFailed;
    return store.get(secret_name) catch return types.AcmeError.ChallengeFailed;
}

fn requireConfigValue(
    allocator: std.mem.Allocator,
    config: acme_config.ManagedConfig,
    key: []const u8,
) types.AcmeError![]const u8 {
    const value = findPairValue(config.config_pairs, key) orelse return types.AcmeError.ChallengeFailed;
    return allocator.dupe(u8, value) catch return types.AcmeError.AllocFailed;
}

fn optionalConfigValue(
    allocator: std.mem.Allocator,
    config: acme_config.ManagedConfig,
    key: []const u8,
    default_value: []const u8,
) types.AcmeError![]const u8 {
    const value = findPairValue(config.config_pairs, key) orelse default_value;
    return allocator.dupe(u8, value) catch return types.AcmeError.AllocFailed;
}

fn resolveAllSecrets(
    allocator: std.mem.Allocator,
    config: acme_config.ManagedConfig,
    secrets_store: ?*secrets.SecretsStore,
) types.AcmeError![]const acme_config.KeyValueRef {
    if (config.secret_refs.len == 0) {
        return allocator.alloc(acme_config.KeyValueRef, 0) catch return types.AcmeError.AllocFailed;
    }
    const store = secrets_store orelse return types.AcmeError.ChallengeFailed;
    var out: std.ArrayListUnmanaged(acme_config.KeyValueRef) = .empty;
    errdefer {
        for (out.items) |entry| entry.deinit(allocator);
        out.deinit(allocator);
    }

    for (config.secret_refs) |entry| {
        const value = store.get(entry.value) catch return types.AcmeError.ChallengeFailed;
        errdefer {
            allocator.free(value);
        }
        out.append(allocator, .{
            .key = allocator.dupe(u8, entry.key) catch return types.AcmeError.AllocFailed,
            .value = value,
        }) catch return types.AcmeError.AllocFailed;
    }
    return out.toOwnedSlice(allocator) catch return types.AcmeError.AllocFailed;
}

fn findPairValue(entries: []const acme_config.KeyValueRef, key: []const u8) ?[]const u8 {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry.value;
    }
    return null;
}

fn ensureTrailingDot(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    if (std.mem.endsWith(u8, value, ".")) return allocator.dupe(u8, value);
    return std.fmt.allocPrint(allocator, "{s}.", .{value});
}

fn domainFromRecord(record_name: []const u8) []const u8 {
    const prefix = "_acme-challenge.";
    if (std.mem.startsWith(u8, record_name, prefix)) return record_name[prefix.len..];
    return record_name;
}

fn buildHookArgv(
    allocator: std.mem.Allocator,
    hook_command: []const []const u8,
    action: []const u8,
) ![][]const u8 {
    var argv = try allocator.alloc([]const u8, hook_command.len + 1);
    argv[0] = hook_command[0];
    for (hook_command[1..], 0..) |arg, idx| argv[idx + 1] = arg;
    argv[hook_command.len] = action;
    return argv;
}

fn seedHookEnv(env_map: *std.process.Environ.Map) !void {
    if (lookupEnv("PATH")) |value| try env_map.put("PATH", value);
    if (lookupEnv("HOME")) |value| try env_map.put("HOME", value);
    if (lookupEnv("USER")) |value| try env_map.put("USER", value);
}

fn lookupEnv(name: [:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name.ptr) orelse return null;
    return std.mem.span(value);
}

fn formatAmzDate(amz_date_buf: *[16]u8, short_date_buf: *[8]u8) void {
    const now_secs = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(now_secs) };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();

    _ = std.fmt.bufPrint(
        amz_date_buf,
        "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        },
    ) catch unreachable;
    @memcpy(short_date_buf, amz_date_buf[0..8]);
}

fn buildRoute53Authorization(
    allocator: std.mem.Allocator,
    access_key_id: []const u8,
    secret_access_key: []const u8,
    region: []const u8,
    host: []const u8,
    path: []const u8,
    amz_date: []const u8,
    short_date: []const u8,
    payload_hash: []const u8,
) ![]u8 {
    const canonical_headers = try std.fmt.allocPrint(
        allocator,
        "content-type:application/xml\nhost:{s}\nx-amz-content-sha256:{s}\nx-amz-date:{s}\n",
        .{ host, payload_hash, amz_date },
    );
    defer allocator.free(canonical_headers);

    const signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";
    const canonical_request = try std.fmt.allocPrint(
        allocator,
        "POST\n{s}\n\n{s}\n{s}\n{s}",
        .{ path, canonical_headers, signed_headers, payload_hash },
    );
    defer allocator.free(canonical_request);

    const canonical_hash = sha256Hex(canonical_request);
    const credential_scope = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}/route53/aws4_request",
        .{ short_date, region },
    );
    defer allocator.free(credential_scope);

    const string_to_sign = try std.fmt.allocPrint(
        allocator,
        "AWS4-HMAC-SHA256\n{s}\n{s}\n{s}",
        .{ amz_date, credential_scope, canonical_hash[0..] },
    );
    defer allocator.free(string_to_sign);

    const signature = try signAwsV4(allocator, secret_access_key, short_date, region, "route53", string_to_sign);
    defer allocator.free(signature);

    return std.fmt.allocPrint(
        allocator,
        "AWS4-HMAC-SHA256 Credential={s}/{s}, SignedHeaders={s}, Signature={s}",
        .{ access_key_id, credential_scope, signed_headers, signature },
    );
}

fn signAwsV4(
    allocator: std.mem.Allocator,
    secret_access_key: []const u8,
    short_date: []const u8,
    region: []const u8,
    service: []const u8,
    string_to_sign: []const u8,
) ![]u8 {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

    const key_seed = try std.fmt.allocPrint(allocator, "AWS4{s}", .{secret_access_key});
    defer allocator.free(key_seed);

    var date_key: [32]u8 = undefined;
    HmacSha256.create(&date_key, short_date, key_seed);
    var region_key: [32]u8 = undefined;
    HmacSha256.create(&region_key, region, &date_key);
    var service_key: [32]u8 = undefined;
    HmacSha256.create(&service_key, service, &region_key);
    var signing_key: [32]u8 = undefined;
    HmacSha256.create(&signing_key, "aws4_request", &service_key);
    var signature: [32]u8 = undefined;
    HmacSha256.create(&signature, string_to_sign, &signing_key);

    return allocator.dupe(u8, std.fmt.bytesToHex(signature, .lower)[0..]);
}

fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

test "domainFromRecord strips acme prefix" {
    try std.testing.expectEqualStrings("example.com", domainFromRecord("_acme-challenge.example.com"));
}

test "buildHookArgv appends action" {
    const argv = try buildHookArgv(std.testing.allocator, &.{ "/bin/hook", "--flag" }, "present");
    defer std.testing.allocator.free(argv);

    try std.testing.expectEqual(@as(usize, 3), argv.len);
    try std.testing.expectEqualStrings("/bin/hook", argv[0]);
    try std.testing.expectEqualStrings("--flag", argv[1]);
    try std.testing.expectEqualStrings("present", argv[2]);
}

test "buildRoute53Authorization includes credential scope" {
    const auth = try buildRoute53Authorization(
        std.testing.allocator,
        "AKID",
        "SECRET",
        "us-east-1",
        "route53.amazonaws.com",
        "/2013-04-01/hostedzone/Z123/rrset/",
        "20260426T120000Z",
        "20260426",
        "abc",
    );
    defer std.testing.allocator.free(auth);

    try std.testing.expect(std.mem.indexOf(u8, auth, "Credential=AKID/20260426/us-east-1/route53/aws4_request") != null);
    try std.testing.expect(std.mem.indexOf(u8, auth, "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date") != null);
}
