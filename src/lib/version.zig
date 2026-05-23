// version — single source of truth for the running binary's version string.
//
// keep this in sync with the package version in build.zig.zon. everything that
// reports a version (the `yoq version` command, the cluster version endpoint,
// version-skew checks) reads it from here so there is one place to bump.

pub const string = "0.2.0";
