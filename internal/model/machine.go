package model

// The reference state-machine harness that enumerates action interleavings lives
// in package interleave. It is kept separate from this package to avoid an
// import cycle with the scenario builder, which constructs signed event logs.
//
// See internal/interleave for the action alphabet (reauthorize, rotate,
// transfer, expire, ban, compaction, restart, path switch) and the invariant
// checks (independent-path, revoked-stays-dead, ban-monotone,
// non-revoked-stays-live, expiry-honored, certificate-verify).
