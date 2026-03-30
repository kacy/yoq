const std = @import("std");

const types = @import("types.zig");

pub fn issueAndExport(self: anytype, options: types.IssuanceOptions) types.AcmeError!types.ExportResult {
    try self.fetchDirectory();
    try self.createAccount(options.email);

    var order = try self.createOrder(options.domain);
    defer order.deinit();

    if (order.authorization_urls.len > 0) {
        var challenge = try self.getHttpChallenge(order.authorization_urls[0]);
        defer challenge.deinit();

        try options.challenge_registrar.set(challenge.token, challenge.key_authorization);
        defer options.challenge_registrar.remove(challenge.token);

        try self.respondToChallenge(challenge.url);
        try self.waitForAuthorizationValid(order.authorization_urls[0]);
        try self.waitForOrderReady(&order);
    }

    return self.finalizeAndExport(&order, options.domain);
}
