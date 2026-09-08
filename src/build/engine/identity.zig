// Build and workload execution share account lookup and credential changes.
const identity = @import("../../runtime/identity.zig");
pub const Identity = identity.Identity;
pub const IdentityError = identity.IdentityError;
pub const resolve = identity.resolve;
pub const resolveAccounts = identity.resolveAccounts;
pub const validate = identity.validate;
pub const apply = identity.apply;
test {
    _ = identity;
}
