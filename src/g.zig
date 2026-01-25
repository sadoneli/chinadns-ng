//! global variables

const std = @import("std");
const cc = @import("cc.zig");
const ipset = @import("ipset.zig");
const DynStr = @import("DynStr.zig");
const StrList = @import("StrList.zig");
const EvLoop = @import("EvLoop.zig");
const Tag = @import("tag.zig").Tag;

comptime {
    // @compileLog("sizeof(flags)", @sizeOf(@TypeOf(flags)));
}

pub var flags: packed struct {
    verbose: bool = false,
    reuse_port: bool = false,
    noip_as_chnip: bool = false,
    gfwlist_first: bool = true,
} = .{};

pub inline fn verbose() bool {
    return flags.verbose;
}

pub var filter_qtypes: []u16 = &.{};

/// default tag for domains that do not match any list
pub var default_tag: Tag = .none;

/// for ip test (tag:none or no-AAAA)
pub var chnroute_name: DynStr = .{};
pub var chnroute6_name: DynStr = .{};
pub var chnroute_testctx: *const ipset.testctx_t = undefined;

/// ["ip1", "ip2", ...]
pub var bind_ips: StrList = .{};

pub const BindPort = struct {
    port: u16,
    tcp: bool,
    udp: bool,
};
pub var bind_ports: []BindPort = &.{};

/// too large may cause stack overflow
pub const TRUSTDNS_PACKET_MAX: u8 = 5;

/// number of packets to send (udp)
pub var trustdns_packet_n: u8 = 1;

/// in seconds
pub var upstream_timeout: u8 = 5;

/// global pending query upper bound (all clients combined)
pub var pending_query_max: u32 = 4096;

/// per-upstream pending upper bound (per session, tcp/udp)
pub var upstream_pending_max: u32 = 2048;

/// consecutive failures before marking an upstream temporarily down
pub var upstream_fail_threshold: u8 = 3;

/// circuit-breaker base/backoff window in ms (clamped by `upstream_down_max_ms`)
pub var upstream_down_ms: u32 = 10_000;
pub var upstream_down_max_ms: u32 = 60_000;

/// dns cache (0 means disable)
pub var cache_size: u16 = 0;

/// allow stale cache
/// - `0`: disable
/// - `N`: N is the max expired_sec
pub var cache_stale: u32 = 0;

/// refresh current cache if TTL <= N(%)
pub var cache_refresh: u8 = 0;

/// good_msg && no-records
pub var cache_nodata_ttl: i32 = 60;

/// set ttl to this (if rr.ttl < min_ttl)
pub var cache_min_ttl: i32 = 0;

/// set ttl to this (if rr.ttl > max_ttl)
pub var cache_max_ttl: i32 = 0;

/// load/dump cache from/to this file
pub var cache_db: ?cc.ConstStr = null;

/// [tag:none] verdict cache size
pub var verdict_cache_size: u16 = 0;

/// load/dump verdict cache from/to this file
pub var verdict_cache_db: ?cc.ConstStr = null;

pub var evloop: EvLoop = undefined;

/// global memory allocator
pub var allocator: std.mem.Allocator = undefined;

pub var cert_verify: bool = false;

/// the location of CA certs
pub var ca_certs: DynStr = .{};

/// proxy for trust upstream dns (socks5://ip:port)
pub var proxy_server: ?cc.ConstStr = null;
pub var proxy_addr: ?cc.SockAddr = null;
pub var proxy_group_mask: u16 = 0; // bitset: 1 << Tag.int()
pub const PROXY_PROTO_TCP: u8 = 1 << 0;
pub const PROXY_PROTO_TLS: u8 = 1 << 1;
pub const PROXY_PROTO_UDP: u8 = 1 << 2;
pub const PROXY_PROTO_ALL: u8 = PROXY_PROTO_TCP | PROXY_PROTO_TLS | PROXY_PROTO_UDP;
pub var proxy_proto_mask: u8 = PROXY_PROTO_ALL; // bitset for upstream proto

// proxy error log throttling (shared counters)
pub var proxy_error_counter: u32 = 0;
pub var proxy_error_last_ms: u64 = 0;

// tcp server read error throttling
pub var tcp_read_err_counter: u32 = 0;
pub var tcp_read_err_last_ms: u64 = 0;

// tcp accept error throttling
pub var tcp_accept_err_counter: u32 = 0;
pub var tcp_accept_err_last_ms: u64 = 0;

// socket creation error throttling
pub var socket_err_counter: u32 = 0;
pub var socket_err_last_ms: u64 = 0;
pub var socket_backoff_until: u64 = 0; // stop opening new sockets until this time
pub var socket_backoff_ms: u32 = 10_000; // EMFILE backoff duration

// proxy failure backoff (monotonic ms, from evloop.time)
pub var proxy_backoff_until: u64 = 0;
pub var proxy_backoff_step: u8 = 0;

pub inline fn proxy_can_try() bool {
    return evloop.time >= proxy_backoff_until;
}

pub fn proxy_note_success() void {
    proxy_backoff_until = 0;
    proxy_backoff_step = 0;
}

pub fn proxy_note_fail() void {
    const now = evloop.time;

    // Exponential backoff: 200ms, 400ms, 800ms ... up to 30s
    if (proxy_backoff_step < 10)
        proxy_backoff_step += 1;

    const shift: u6 = @intCast(u6, if (proxy_backoff_step > 1) proxy_backoff_step - 1 else 0);
    var delay: u64 = 200;
    delay = delay << shift;
    if (delay > 30_000) delay = 30_000;

    proxy_backoff_until = now + delay;
}
