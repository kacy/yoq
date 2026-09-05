const master_key = @import("../../lib/master_key.zig");

pub const KeyError = master_key.KeyError;
pub const loadOrCreateKey = master_key.loadOrCreateKey;
pub const readKeyFile = master_key.readKeyFile;
pub const secureZero = master_key.secureZero;
