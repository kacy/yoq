const std = @import("std");

const dns_runtime = @import("dns_runtime.zig");
const types = @import("types.zig");

pub fn issueAndExport(self: anytype, options: types.IssuanceOptions) types.AcmeError!types.ExportResult {
    try self.fetchDirectory();
    try self.createAccount(options.email);

    var order = try self.createOrder(options.domain);
    defer order.deinit();

    if (order.authorization_urls.len > 0) {
        switch (options.challenge_type) {
            .http_01 => {
                const registrar = options.challenge_registrar orelse return types.AcmeError.ChallengeFailed;
                var challenge = try self.getHttpChallenge(order.authorization_urls[0]);
                defer challenge.deinit();

                try registrar.set(challenge.token, challenge.key_authorization);
                defer registrar.remove(challenge.token);
                try self.respondToChallenge(challenge.url);
            },
            .dns_01 => {
                const dns_solver = options.dns_solver orelse return types.AcmeError.ChallengeFailed;
                var challenge = try self.getDnsChallenge(order.authorization_urls[0], options.domain);
                defer challenge.deinit();

                try dns_solver.present(challenge.record_name, challenge.record_value);
                defer dns_solver.cleanup(challenge.record_name, challenge.record_value);
                try dns_runtime.waitForTxt(
                    challenge.record_name,
                    challenge.record_value,
                    options.dns_propagation_timeout_secs,
                    options.dns_poll_interval_secs,
                );
                try self.respondToChallenge(challenge.url);
            },
        }
        try self.waitForAuthorizationValid(order.authorization_urls[0]);
        try self.waitForOrderReady(&order);
    }

    return self.finalizeAndExport(&order, options.domain);
}
