const std = @import("std");
const build_opts = @import("build_opts");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const co = @import("co.zig");
const opt = @import("opt.zig");
const net = @import("net.zig");
const dns = @import("dns.zig");
const log = @import("log.zig");
const server = @import("server.zig");
const Tag = @import("tag.zig").Tag;
const EvLoop = @import("EvLoop.zig");
const RcMsg = @import("RcMsg.zig");
const Node = @import("Node.zig");
const str2int = @import("str2int.zig");
const socks5 = @import("socks5.zig");
const assert = std.debug.assert;

const session_magic_alive: u32 = 0x53455353; // "SESS"
const session_magic_freed: u32 = 0xDEAD5E55;
const SessionHandle = u64;
const SessionKind = enum { udp, tcp };
const SessionSlot = struct {
    ptr: ?*anyopaque = null,
    upstream: ?*Upstream = null,
    kind: SessionKind = .udp,
    generation: u32 = 1,
    next_free: ?u32 = null,
};

fn use_proxy(upstream: *const Upstream) bool {
    if (g.proxy_addr == null)
        return false;
    if (g.proxy_group_mask == 0)
        return false;
    // protocol filter (default allow all unless overridden)
    const proto_mask = switch (upstream.proto) {
        .udp, .udpi => g.PROXY_PROTO_UDP,
        .tcp, .tcpi => g.PROXY_PROTO_TCP,
        .tls => g.PROXY_PROTO_TLS,
        else => g.PROXY_PROTO_ALL,
    };
    if ((g.proxy_proto_mask & proto_mask) == 0)
        return false;
    const tag_int = upstream.tag.int();
    if (tag_int >= 16)
        return false;
    return (g.proxy_group_mask & (@as(u16, 1) << @intCast(u4, tag_int))) != 0;
}

// ======================================================

comptime {
    // @compileLog("sizeof(Upstream):", @sizeOf(Upstream), "alignof(Upstream):", @alignOf(Upstream));
    // @compileLog("sizeof([]const u8):", @sizeOf([]const u8), "alignof([]const u8):", @alignOf([]const u8));
    // @compileLog("sizeof([:0]const u8):", @sizeOf([:0]const u8), "alignof([:0]const u8):", @alignOf([:0]const u8));
    // @compileLog("sizeof(cc.SockAddr):", @sizeOf(cc.SockAddr), "alignof(cc.SockAddr):", @alignOf(cc.SockAddr));
    // @compileLog("sizeof(Proto):", @sizeOf(Proto), "alignof(Proto):", @alignOf(Proto));
    // @compileLog("sizeof(UDP):", @sizeOf(UDP), "alignof(UDP):", @alignOf(UDP));
    // @compileLog("sizeof(TCP):", @sizeOf(TCP), "alignof(TCP):", @alignOf(TCP));
}

const Upstream = @This();

// session handle (0 means none)
session_id: SessionHandle = 0,

// config
host: ?cc.ConstStr, // DoT SNI
url: cc.ConstStr, // for printing
addr: cc.SockAddr,
count: ParamValue, // max queries per session (0 means no limit)
life: ParamValue, // max lifetime(sec) per session (0 means no limit)
proto: Proto,
tag: Tag,
backoff_until: u64 = 0,
backoff_step: u8 = 0,
fail_streak: u8 = 0,
down_until: u64 = 0,

const ParamValue = u16;
const DEFAULT_COUNT: ParamValue = 10;
const DEFAULT_LIFE: ParamValue = 10;
const PENDING_HARD_MAX: u32 = std.math.maxInt(u16);
const REUSE_MAX_TCP: u16 = c.DNS_EDNS_MAXSIZE;
const REUSE_MAX_UDP: u16 = c.DNS_EDNS_MAXSIZE + socks5.UDP_OVERHEAD_MAX;

inline fn pending_limit() u16 {
    const max_allowed = std.math.min(PENDING_HARD_MAX, g.upstream_pending_max);
    return @intCast(u16, std.math.max(@as(u32, 1), max_allowed));
}

// ======================================================

/// for `Group.do_add` (at startup)
fn eql(self: *const Upstream, proto: Proto, addr: *const cc.SockAddr, host: []const u8) bool {
    return self.proto == proto and
        self.addr.eql(addr) and
        std.mem.eql(u8, cc.strslice_c(self.host orelse ""), host);
}

/// for `Group.do_add` (at startup)
fn init(
    tag: Tag,
    proto: Proto,
    addr: *const cc.SockAddr,
    host: []const u8,
    ip: []const u8,
    port: u16,
    count: ParamValue,
    life: ParamValue,
) Upstream {
    const dupe_host: ?cc.ConstStr = if (host.len > 0)
        (g.allocator.dupeZ(u8, host) catch unreachable).ptr
    else
        null;

    var portbuf: [10]u8 = undefined;
    const url = cc.to_cstr_x(&.{
        // tcp://
        proto.to_str(),
        // host@
        host,
        cc.b2v(host.len > 0, "@", ""),
        // ip
        ip,
        // #port
        cc.b2v(proto.is_std_port(port), "", cc.snprintf(&portbuf, "#%u", .{cc.to_uint(port)})),
    });
    const dupe_url = (g.allocator.dupeZ(u8, cc.strslice_c(url)) catch unreachable).ptr;

    return .{
        .tag = tag,
        .proto = proto,
        .addr = addr.*,
        .host = dupe_host,
        .url = dupe_url,
        .count = count,
        .life = life,
    };
}

/// for `Group.rm_useless` (at startup)
fn deinit(self: *const Upstream) void {
    assert(self.session_id == 0);

    if (self.host) |host|
        g.allocator.free(cc.strslice_c(host));

    g.allocator.free(cc.strslice_c(self.url));
}

// ======================================================

var _session_slots: std.ArrayListUnmanaged(SessionSlot) = .{};
var _session_free: ?u32 = null;
var _session_ptrs: std.AutoHashMapUnmanaged(usize, SessionHandle) = .{};

pub const SessionStats = struct {
    slots_total: usize = 0,
    slots_active: usize = 0,
    udp_sessions: usize = 0,
    tcp_sessions: usize = 0,
    udp_pending: usize = 0,
    udp_proxy_pending: usize = 0,
    tcp_pending: usize = 0,
    tcp_ack: usize = 0,
    tcp_sendq: usize = 0,
    udp_pending_cap: usize = 0,
    tcp_ack_cap: usize = 0,
};

pub fn session_ptrs_count() usize {
    return _session_ptrs.count();
}

pub fn session_ptrs_capacity() usize {
    return _session_ptrs.capacity();
}

pub fn collect_session_stats() SessionStats {
    var stats: SessionStats = .{};
    stats.slots_total = _session_slots.items.len;

    for (_session_slots.items) |slot, idx| {
        if (slot.ptr == null)
            continue;

        const handle = get_session_ptr_handle(slot.ptr.?) orelse continue;
        const expected = make_session_handle(@intCast(u32, idx), slot.generation);
        if (handle != expected)
            continue;

        stats.slots_active += 1;
        switch (slot.kind) {
            .udp => {
                stats.udp_sessions += 1;
                const udp = @ptrCast(*UDP, @alignCast(@alignOf(UDP), slot.ptr.?));
                if (!udp.session_node.is_alive())
                    continue;
                stats.udp_pending += udp.query_list.count();
                stats.udp_pending_cap += udp.query_list.capacity();
                stats.udp_proxy_pending += udp.proxy_pending.items.len;
            },
            .tcp => {
                stats.tcp_sessions += 1;
                const tcp = @ptrCast(*TCP, @alignCast(@alignOf(TCP), slot.ptr.?));
                if (!tcp.session_node.is_alive())
                    continue;
                const ack_cnt = tcp.ack_list.count();
                stats.tcp_pending += tcp.pending_n;
                stats.tcp_ack += ack_cnt;
                stats.tcp_ack_cap += tcp.ack_list.capacity();
                stats.tcp_sendq += if (tcp.pending_n >= ack_cnt) tcp.pending_n - ack_cnt else 0;
            },
        }
    }

    return stats;
}

pub fn module_init() void {
    _session_slots.deinit(g.allocator);
    _session_slots = .{};
    _session_free = null;
    _session_ptrs.deinit(g.allocator);
    _session_ptrs = .{};
}

/// Shrink global session data structures if they are over-allocated
pub fn shrink_memory() void {
    // Shrink _session_ptrs if very sparse (count < 25% of capacity and capacity > 64)
    const cap = _session_ptrs.capacity();
    const cnt = _session_ptrs.count();
    if (cap > 64 and cnt * 4 < cap) {
        if (cnt == 0) {
            _session_ptrs.clearAndFree(g.allocator);
            return;
        }

        var new_ptrs: @TypeOf(_session_ptrs) = .{};
        new_ptrs.ensureTotalCapacity(g.allocator, cnt) catch return;

        var it = _session_ptrs.iterator();
        while (it.next()) |entry| {
            new_ptrs.put(g.allocator, entry.key_ptr.*, entry.value_ptr.*) catch {
                new_ptrs.deinit(g.allocator);
                return;
            };
        }
        _session_ptrs.deinit(g.allocator);
        _session_ptrs = new_ptrs;
    }
}

var _next_shrink_ms: u64 = 0;
var _next_session_sweep_ms: u64 = 0;

fn sweep_orphan_sessions(timer: *EvLoop.Timer, now: u64) void {
    for (_session_slots.items) |slot, idx| {
        if (slot.ptr == null)
            continue;

        const handle = get_session_ptr_handle(slot.ptr.?) orelse continue;
        const expected = make_session_handle(@intCast(u32, idx), slot.generation);
        if (handle != expected)
            continue;

        if (slot.upstream != null and slot.upstream.?.session_id == handle)
            continue; // handled by per-upstream timeout checks

        switch (slot.kind) {
            .udp => {
                const udp = @ptrCast(*UDP, @alignCast(@alignOf(UDP), slot.ptr.?));
                if (!udp.session_node.is_alive())
                    continue;
                udp.cleanup_stale_queries(now);
                if (udp.is_idle()) {
                    if (udp.should_retire())
                        udp.free();
                } else if (timer.check_deadline(udp.get_deadline())) {
                    udp.free();
                }
            },
            .tcp => {
                const tcp = @ptrCast(*TCP, @alignCast(@alignOf(TCP), slot.ptr.?));
                if (!tcp.session_node.is_alive())
                    continue;
                tcp.cleanup_stale_queries(timer);
                if (tcp.is_idle()) {
                    if (tcp.should_retire())
                        tcp.free();
                } else if (timer.check_deadline(tcp.get_deadline())) {
                    tcp.free();
                }
            },
        }
    }
}

pub fn check_timeout(timer: *EvLoop.Timer) void {
    const now = g.evloop.time;
    if (_next_shrink_ms == 0)
        _next_shrink_ms = now + 10_000;
    if (_next_session_sweep_ms == 0)
        _next_session_sweep_ms = now + 5_000;

    if (timer.check_deadline(_next_session_sweep_ms)) {
        _next_session_sweep_ms = now + 5_000;
        sweep_orphan_sessions(timer, now);
    }

    if (timer.check_deadline(_next_shrink_ms)) {
        _next_shrink_ms = now + 10_000;
        shrink_memory();
    }
}

inline fn make_session_handle(index: u32, generation: u32) SessionHandle {
    return (@as(SessionHandle, generation) << 32) | @as(SessionHandle, index);
}

inline fn session_handle_index(handle: SessionHandle) u32 {
    return @intCast(u32, handle & 0xffff_ffff);
}

inline fn session_handle_generation(handle: SessionHandle) u32 {
    return @intCast(u32, handle >> 32);
}

fn allocate_session_slot(ptr: anytype, upstream: *Upstream, kind: SessionKind) SessionHandle {
    var index: u32 = undefined;
    if (_session_free) |free_index| {
        index = free_index;
        var slot = &_session_slots.items[index];
        _session_free = slot.next_free;
        slot.next_free = null;
        slot.ptr = @ptrCast(*anyopaque, ptr);
        slot.upstream = upstream;
        slot.kind = kind;
        if (slot.generation == 0)
            slot.generation = 1;
        return make_session_handle(index, slot.generation);
    }

    assert(_session_slots.items.len < std.math.maxInt(u32));
    index = @intCast(u32, _session_slots.items.len);
    _session_slots.append(g.allocator, .{
        .ptr = @ptrCast(*anyopaque, ptr),
        .upstream = upstream,
        .kind = kind,
        .generation = 1,
        .next_free = null,
    }) catch unreachable;
    return make_session_handle(index, 1);
}

fn release_session_slot(handle: SessionHandle) void {
    if (handle == 0)
        return;
    const index = session_handle_index(handle);
    if (index >= _session_slots.items.len)
        return;
    var slot = &_session_slots.items[index];
    if (slot.generation != session_handle_generation(handle))
        return;
    slot.ptr = null;
    slot.upstream = null;
    slot.kind = .udp;
    slot.generation +%= 1;
    if (slot.generation == 0)
        slot.generation = 1;
    slot.next_free = _session_free;
    _session_free = index;
}

fn get_session_slot(handle: SessionHandle) ?*SessionSlot {
    if (handle == 0)
        return null;
    const index = session_handle_index(handle);
    if (index >= _session_slots.items.len)
        return null;
    const slot = &_session_slots.items[index];
    if (slot.ptr == null)
        return null;
    if (slot.generation != session_handle_generation(handle))
        return null;
    return slot;
}

fn register_session_ptr(ptr: anytype, handle: SessionHandle) void {
    _ = _session_ptrs.put(g.allocator, @ptrToInt(ptr), handle) catch unreachable;
}

fn unregister_session_ptr(ptr: anytype) void {
    _ = _session_ptrs.remove(@ptrToInt(ptr));
}

fn get_session_ptr_handle(ptr: *anyopaque) ?SessionHandle {
    return _session_ptrs.get(@ptrToInt(ptr));
}

fn install_session(upstream: *Upstream, session: anytype, kind: SessionKind) void {
    const handle = allocate_session_slot(session, upstream, kind);
    register_session_ptr(session, handle);
    session.session_node.id = handle;
    upstream.session_id = handle;
}

fn session_kind_matches(comptime T: type, kind: SessionKind) bool {
    if (T == UDP)
        return kind == .udp;
    if (T == TCP)
        return kind == .tcp;
    return false;
}

/// [nosuspend] send query to upstream
fn send(self: *Upstream, qmsg: *RcMsg) bool {
    return nosuspend switch (self.proto) {
        .udpi, .udp => if (self.udp_session()) |s| s.send_query(qmsg) else false,
        .tcpi, .tcp, .tls => if (self.tcp_session()) |s| s.send_query(qmsg) else false,
        else => unreachable,
    };
}

fn udp_session(self: *Upstream) ?*UDP {
    if (!self.can_try())
        return null;
    return self.get_session(UDP, .udp);
}

fn tcp_session(self: *Upstream) ?*TCP {
    if (!self.can_try())
        return null;
    return self.get_session(TCP, .tcp);
}

fn get_session(self: *Upstream, comptime T: type, kind: SessionKind) ?*T {
    if (self.session_id != 0) {
        if (get_session_slot(self.session_id)) |slot| {
            const handle = get_session_ptr_handle(slot.ptr.?) orelse {
                log.err(@src(), "session ptr missing, reset: %llu", .{cc.to_ulonglong(self.session_id)});
                unregister_session_ptr(slot.ptr.?);
                release_session_slot(self.session_id);
                self.session_id = 0;
                return null;
            };
            if (handle != self.session_id) {
                log.err(@src(), "session ptr mismatch, reset: %llu", .{cc.to_ulonglong(self.session_id)});
                unregister_session_ptr(slot.ptr.?);
                release_session_slot(self.session_id);
                self.session_id = 0;
                return null;
            }
            if (slot.upstream != null and slot.upstream.? == self and session_kind_matches(T, slot.kind)) {
                const session = cc.ptrcast(*T, slot.ptr.?);
                if (session.session_node.is_alive() and session.session_node.id == self.session_id)
                    return session;
                log.err(@src(), "session stale, reset: %llu", .{cc.to_ulonglong(self.session_id)});
                release_session_slot(self.session_id);
                self.session_id = 0;
                return null;
            }
            log.err(@src(), "session id mismatch, reset: %llu", .{cc.to_ulonglong(self.session_id)});
        } else {
            log.err(@src(), "session id missing, reset: %llu", .{cc.to_ulonglong(self.session_id)});
        }
        self.session_id = 0;
    }

    if (self.session_id == 0) {
        const session = if (T == UDP)
            T.new(self) orelse return null
        else
            T.new(self);
        install_session(self, session, kind);
        return session;
    }
    return null;
}

fn session_eql(self: *const Upstream, session_id: SessionHandle) bool {
    return session_id != 0 and self.session_id == session_id;
}

fn can_try(self: *const Upstream) bool {
    const now = g.evloop.time;
    return now >= self.backoff_until and now >= self.down_until;
}

fn note_success(self: *Upstream) void {
    self.backoff_until = 0;
    self.backoff_step = 0;
    self.fail_streak = 0;
    self.down_until = 0;
}

fn note_fail(self: *Upstream) void {
    if (self.backoff_step < 10)
        self.backoff_step += 1;
    const shift: u6 = @intCast(u6, if (self.backoff_step > 1) self.backoff_step - 1 else 0);
    var delay: u64 = 200;
    delay = delay << shift;
    if (delay > 30_000) delay = 30_000;
    self.backoff_until = g.evloop.time + delay;

    if (self.fail_streak < std.math.maxInt(@TypeOf(self.fail_streak)))
        self.fail_streak += 1;
    if (self.fail_streak >= g.upstream_fail_threshold) {
        const cb_shift: u6 = @intCast(u6, std.math.min(@as(u32, self.fail_streak - g.upstream_fail_threshold), 8));
        const base = @as(u64, g.upstream_down_ms);
        var down = base << cb_shift;
        const down_max: u64 = g.upstream_down_max_ms;
        if (down > down_max) down = down_max;
        self.down_until = g.evloop.time + down;
    }
}

// ======================================================

pub fn check_timeout_upstream(upstream: *Upstream, timer: *EvLoop.Timer) void {
    const session_id = upstream.session_id;
    if (session_id == 0)
        return;
    const slot = get_session_slot(session_id) orelse {
        upstream.session_id = 0;
        return;
    };
    const handle = get_session_ptr_handle(slot.ptr.?) orelse {
        log.err(@src(), "timeout session ptr missing, reset: %llu", .{cc.to_ulonglong(session_id)});
        unregister_session_ptr(slot.ptr.?);
        release_session_slot(session_id);
        upstream.session_id = 0;
        return;
    };
    if (handle != session_id) {
        log.err(@src(), "timeout session ptr mismatch, reset: %llu", .{cc.to_ulonglong(session_id)});
        unregister_session_ptr(slot.ptr.?);
        release_session_slot(session_id);
        upstream.session_id = 0;
        return;
    }
    if (slot.upstream == null or slot.upstream.? != upstream) {
        log.err(@src(), "timeout session mismatch, reset: %llu", .{cc.to_ulonglong(session_id)});
        upstream.session_id = 0;
        return;
    }
    switch (slot.kind) {
        .udp => {
            const session = cc.ptrcast(*UDP, slot.ptr.?);
            if (!session.session_node.is_alive() or session.session_node.id != session_id) {
                log.err(@src(), "timeout session stale, reset: %llu", .{cc.to_ulonglong(session_id)});
                release_session_slot(session_id);
                upstream.session_id = 0;
                return;
            }
            if (session.is_idle())
                return;
            if (timer.check_deadline(session.get_deadline()))
                session.free();
        },
        .tcp => {
            const session = cc.ptrcast(*TCP, slot.ptr.?);
            if (!session.session_node.is_alive() or session.session_node.id != session_id) {
                log.err(@src(), "timeout session stale, reset: %llu", .{cc.to_ulonglong(session_id)});
                release_session_slot(session_id);
                upstream.session_id = 0;
                return;
            }
            session.cleanup_stale_queries(timer);
            if (session.is_idle())
                return;
            if (timer.check_deadline(session.get_deadline()))
                session.free();
        },
    }
}

const SessionNode = struct {
    type: enum { udp, tcp }, // `struct UDP` or `struct TCP`
    node: Node = undefined, // legacy list node (unused)
    linked: bool = false,
    magic: u32 = session_magic_alive,
    id: SessionHandle = 0,

    pub fn from(node: *Node) *SessionNode {
        return @fieldParentPtr(SessionNode, "node", node);
    }

    pub fn udp(self: *SessionNode) *UDP {
        assert(self.type == .udp);
        return @fieldParentPtr(UDP, "session_node", self);
    }

    pub fn tcp(self: *SessionNode) *TCP {
        assert(self.type == .tcp);
        return @fieldParentPtr(TCP, "session_node", self);
    }

    pub fn on_work(self: *SessionNode, from_idle_state: bool) void {
        _ = from_idle_state;
        if (!self.is_alive())
            return;
        self.linked = true;
    }

    pub fn on_idle(self: *SessionNode) void {
        if (!self.is_alive())
            return;
        self.linked = false;
    }

    pub fn is_alive(self: *const SessionNode) bool {
        return self.magic == session_magic_alive;
    }

    pub fn mark_freed(self: *SessionNode) void {
        self.magic = session_magic_freed;
    }
};

// ======================================================

/// udp session
const UDP = struct {
    session_node: SessionNode = .{ .type = .udp }, // _session_list node
    upstream: *Upstream,
    fdobj: *EvLoop.Fd,
    proxy_fdobj: ?*EvLoop.Fd = null, // socks5 tcp control channel (UDP ASSOCIATE)
    fd_canceled: bool = false,
    proxy_fd_canceled: bool = false,
    query_list: std.AutoHashMapUnmanaged(u16, u64) = .{}, // outstanding queries (qid => sent_at ms)
    stale_buf: std.ArrayListUnmanaged(u16) = .{},
    create_time: u64,
    query_time: u64 = undefined, // last query time
    oldest_query_time: u64 = 0, // oldest outstanding query time
    query_count: u16 = 0, // total query count
    freed: bool = false,
    closing: bool = false,
    freeing: bool = false, // guard re-entrant free during cancel
    pending_free: bool = false,
    active: u8 = 0, // running coroutines (reply_receiver/proxy_init)
    proxy_enabled: bool = false,
    proxy_ready: bool = false,
    proxy_starting: bool = false,
    proxy_pending: std.ArrayListUnmanaged(*RcMsg) = .{},
    proxy_relay: cc.SockAddr = undefined, // udp relay addr from proxy
    proxy_prefix: [socks5.UDP_OVERHEAD_MAX]u8 = undefined, // socks5 udp request header prefix
    proxy_prefix_len: u8 = 0,

    pub fn new(upstream: *Upstream) ?*UDP {
        const self = g.allocator.create(UDP) catch unreachable;
        self.* = .{ .upstream = upstream, .fdobj = undefined, .create_time = g.evloop.time };
        var ok = false;
        defer if (!ok) g.allocator.destroy(self);

        self.proxy_enabled = use_proxy(upstream);

        const family = if (self.proxy_enabled)
            g.proxy_addr.?.family()
        else
            upstream.addr.family();

        const fd = net.new_sock(family, .udp) orelse return null;
        self.fdobj = EvLoop.Fd.new(fd);

        ok = true;
        return self;
    }

    /// call path:
    /// - reply_receiver
    /// - check_timeout
    fn free(self: *UDP) void {
        const handle = get_session_ptr_handle(@ptrCast(*anyopaque, self)) orelse
            return;
        if (!self.session_node.is_alive())
            return;
        if (self.freed) return;
        if (self.freeing) {
            self.pending_free = true;
            return;
        }
        self.freeing = true;
        var free_guard = true;
        defer {
            if (free_guard)
                self.freeing = false;
        }
        if (self.active > 0) {
            self.closing = true;
            if (self.upstream.session_eql(self.session_node.id))
                self.upstream.session_id = 0;
            self.session_node.on_idle();
            const proxy_fdobj = self.proxy_fdobj;
            const need_proxy_cancel = proxy_fdobj != null and !self.proxy_fd_canceled;
            const need_fd_cancel = !self.fd_canceled;

            if (need_proxy_cancel)
                self.proxy_fd_canceled = true;
            if (need_fd_cancel)
                self.fd_canceled = true;

            if (need_proxy_cancel)
                proxy_fdobj.?.cancel();
            if (need_fd_cancel)
                self.fdobj.cancel();

            if (self.active > 0)
                return;
        }

        self.pending_free = false;
        self.freed = true;

        for (self.proxy_pending.items) |qmsg|
            qmsg.unref();
        self.proxy_pending.clearAndFree(g.allocator);

        self.session_node.on_idle();

        if (self.upstream.session_eql(self.session_node.id))
            self.upstream.session_id = 0;

        if (!self.fd_canceled) {
            self.fdobj.cancel();
            self.fd_canceled = true;
        }
        // close fd to avoid leaks
        self.fdobj.free();

        if (self.proxy_fdobj) |pfdobj| if (!self.proxy_fd_canceled) {
            pfdobj.cancel();
            self.proxy_fd_canceled = true;
        };
        if (self.proxy_fdobj) |pfdobj| {
            pfdobj.free();
            self.proxy_fdobj = null;
            self.proxy_fd_canceled = false;
        }

        self.stale_buf.clearAndFree(g.allocator);
        self.query_list.clearAndFree(g.allocator);
        self.session_node.mark_freed();
        release_session_slot(handle);
        self.session_node.id = 0;
        unregister_session_ptr(self);
        self.freeing = false;
        free_guard = false;
        g.allocator.destroy(self);
    }

    pub fn get_deadline(self: *const UDP) u64 {
        assert(!self.is_idle());
        return self.query_time + cc.to_u64(g.upstream_timeout) * 1000;
    }

    /// [nosuspend]
    pub fn send_query(self: *UDP, qmsg: *RcMsg) bool {
        if (get_session_ptr_handle(@ptrCast(*anyopaque, self)) == null or !self.session_node.is_alive())
            return false;
        const limit = pending_limit();
        if (self.query_list.count() >= limit) {
            log.warn(@src(), "too many pending udp queries to %s: %u (limit:%u)", .{
                self.upstream.url,
                cc.to_uint(self.query_list.count()),
                cc.to_uint(limit),
            });
            return false;
        }

        if (self.should_retire()) {
            if (!self.upstream.session_eql(self.session_node.id))
                return false;
            if (self.is_idle()) {
                self.retire();
                const new_session = new(self.upstream);
                if (new_session) |s| {
                    install_session(self.upstream, s, .udp);
                    return nosuspend s.send_query(qmsg);
                }

                if (self.is_idle())
                    self.free();

                return false;
            }
        }

        if (self.proxy_enabled and !self.proxy_ready) {
            // Don't queue queries while the proxy isn't ready; otherwise a boot-time proxy outage
            // can retain many qmsg buffers and OOM the process. Let server reply SERVFAIL.
            if (!g.proxy_can_try())
                return false;

            if (!self.proxy_starting) {
                self.proxy_starting = true;
                co.start(proxy_init, .{self});
            }
            return false;
        }

        self.send_query_now(qmsg);
        return true;
    }

    fn send_query_now(self: *UDP, qmsg: *RcMsg) void {
        assert(!self.proxy_enabled or self.proxy_ready);
        const now = g.evloop.time;

        self.cleanup_stale_queries(now);

        if (self.upstream.tag == .gfw and g.trustdns_packet_n > 1) {
            var iov = [_]cc.iovec_t{
                .{ .iov_base = qmsg.msg().ptr, .iov_len = qmsg.len },
                undefined, // proxy header (optional)
            };

            const msg_iov = if (self.proxy_enabled) b: {
                // keep header first
                iov[0] = .{
                    .iov_base = @ptrCast([*]u8, &self.proxy_prefix[0]),
                    .iov_len = cc.to_usize(self.proxy_prefix_len),
                };
                iov[1] = .{
                    .iov_base = qmsg.msg().ptr,
                    .iov_len = qmsg.len,
                };
                break :b iov[0..2];
            } else iov[0..1];

            var msgv: [g.TRUSTDNS_PACKET_MAX]cc.mmsghdr_t = undefined;

            const dst = if (self.proxy_enabled) &self.proxy_relay else &self.upstream.addr;

            msgv[0] = .{
                .msg_hdr = .{
                    .msg_name = dst,
                    .msg_namelen = dst.len(),
                    .msg_iov = msg_iov.ptr,
                    .msg_iovlen = msg_iov.len,
                },
            };

            // repeat msg
            var i: u8 = 1;
            while (i < g.trustdns_packet_n) : (i += 1)
                msgv[i] = msgv[0];

            _ = cc.sendmmsg(self.fdobj.fd, &msgv, 0) orelse self.on_error("send");
        } else {
            if (self.proxy_enabled) {
                var iov = [_]cc.iovec_t{
                    .{ .iov_base = @ptrCast([*]u8, &self.proxy_prefix[0]), .iov_len = cc.to_usize(self.proxy_prefix_len) },
                    .{ .iov_base = qmsg.msg().ptr, .iov_len = qmsg.len },
                };
                const msghdr = cc.msghdr_t{
                    .msg_name = &self.proxy_relay,
                    .msg_namelen = self.proxy_relay.len(),
                    .msg_iov = &iov,
                    .msg_iovlen = iov.len,
                };
                _ = cc.sendmsg(self.fdobj.fd, &msghdr, 0) orelse self.on_error("send");
            } else {
                _ = cc.sendto(self.fdobj.fd, qmsg.msg(), 0, &self.upstream.addr) orelse self.on_error("send");
            }
        }

        self.session_node.on_work(self.is_idle());

        self.query_list.put(g.allocator, dns.get_id(qmsg.msg()), now) catch unreachable;
        if (self.oldest_query_time == 0)
            self.oldest_query_time = now;
        self.query_time = now;
        self.query_count +|= 1;

        // start recv coroutine, must be at the end
        if (self.query_count == 1)
            co.start(reply_receiver, .{self}); // may call self.free()
    }

    fn proxy_init(self: *UDP) void {
        defer co.terminate(@frame(), @frameSize(proxy_init));

        self.active += 1;
        defer {
            self.proxy_starting = false;
            assert(self.active > 0);
            self.active -= 1;
            self.free();
        }

        if (!self.proxy_enabled)
            return;

        if (self.closing)
            return;

        const proxy_addr = g.proxy_addr orelse return;
        if (!g.proxy_can_try())
            return;

        const proxy: cc.ConstStr = g.proxy_server orelse @ptrCast(cc.ConstStr, cc.to_cstr("(proxy)"));

        const drop_pending = struct {
            fn f(self_: *UDP) void {
                for (self_.proxy_pending.items) |qmsg|
                    qmsg.unref();
                self_.proxy_pending.clearAndFree(g.allocator);
            }
        }.f;

        const tcp_fd = net.new_tcp_conn_sock(proxy_addr.family()) orelse return;
        const pfdobj = EvLoop.Fd.new(tcp_fd);

        var ok = false;
        defer if (!ok) {
            pfdobj.cancel();
            pfdobj.free();
        };

        g.evloop.connect(pfdobj, &proxy_addr) orelse {
            log.warn(@src(), "connect(%s) failed: (%d) %m", .{ proxy, cc.errno() });
            g.proxy_note_fail();
            drop_pending(self);
            return;
        };

        if (socks5.greet_noauth(pfdobj)) |err| {
            log.warn(@src(), "connect(%s) failed: %s", .{ proxy, err });
            g.proxy_note_fail();
            drop_pending(self);
            return;
        }

        // bind local udp port and tell proxy our udp endpoint (some servers require this)
        var tcp_local: cc.SockAddr = undefined;
        if (cc.getsockname(pfdobj.fd, &tcp_local) == null) {
            log.warn(@src(), "getsockname(%s) failed: (%d) %m", .{ proxy, cc.errno() });
            g.proxy_note_fail();
            drop_pending(self);
            return;
        }

        var udp_bind = tcp_local;
        if (udp_bind.is_sin())
            udp_bind.sin.sin_port = 0
        else
            udp_bind.sin6.sin6_port = 0;

        if (cc.bind(self.fdobj.fd, &udp_bind) == null) {
            log.warn(@src(), "bind(udp for %s) failed: (%d) %m", .{ proxy, cc.errno() });
            g.proxy_note_fail();
            drop_pending(self);
            return;
        }

        var udp_local: cc.SockAddr = undefined;
        if (cc.getsockname(self.fdobj.fd, &udp_local) == null) {
            log.warn(@src(), "getsockname(udp for %s) failed: (%d) %m", .{ proxy, cc.errno() });
            g.proxy_note_fail();
            drop_pending(self);
            return;
        }

        if (socks5.request_udp_associate(pfdobj, &proxy_addr, &udp_local, &self.proxy_relay)) |err| {
            log.warn(@src(), "connect(%s) failed: %s", .{ proxy, err });
            g.proxy_note_fail();
            drop_pending(self);
            return;
        }

        const n = socks5.build_udp_datagram_prefix(&self.proxy_prefix, &self.upstream.addr) orelse {
            g.proxy_note_fail();
            drop_pending(self);
            return;
        };
        self.proxy_prefix_len = cc.to_u8(n);

        self.proxy_fdobj = pfdobj;
        self.proxy_ready = true;
        ok = true;
        g.proxy_note_success();

        if (g.verbose()) {
            var ip: cc.IpStrBuf = undefined;
            var port: u16 = undefined;
            self.proxy_relay.to_text(&ip, &port);
            log.info(@src(), "socks5 udp relay: %s#%u", .{ &ip, cc.to_uint(port) });
        }

        // flush pending queries
        for (self.proxy_pending.items) |qmsg| {
            nosuspend self.send_query_now(qmsg);
            qmsg.unref();
        }
        self.proxy_pending.clearAndFree(g.allocator);
    }

    /// no outstanding queries
    fn is_idle(self: *const UDP) bool {
        return self.query_list.count() == 0;
    }

    /// no more queries will be sent. \
    /// freed when the queries completes.
    fn should_retire(self: *const UDP) bool {
        if (!self.upstream.session_eql(self.session_node.id))
            return true;

        if ((self.upstream.count > 0 and self.query_count >= self.upstream.count) or
            (self.upstream.life > 0 and g.evloop.time >= self.create_time + cc.to_u64(self.upstream.life) * 1000))
            return true;

        return false;
    }

    fn retire(self: *UDP) void {
        if (self.upstream.session_eql(self.session_node.id))
            self.upstream.session_id = 0;
    }

    fn cleanup_stale_queries(self: *UDP, now: u64) void {
        const was_idle = self.is_idle();
        if (self.query_list.count() == 0) {
            self.oldest_query_time = 0;
            return;
        }

        const timeout_ms = cc.to_u64(g.upstream_timeout) * 1000;
        if (timeout_ms == 0)
            return;

        if (self.oldest_query_time != 0 and now < self.oldest_query_time + timeout_ms)
            return;

        var oldest: u64 = 0;
        // Shrink stale_buf if capacity is too large
        if (self.stale_buf.capacity > 64 and self.stale_buf.items.len == 0) {
            self.stale_buf.clearAndFree(g.allocator);
        } else {
            self.stale_buf.clearRetainingCapacity();
        }

        var it = self.query_list.iterator();
        while (it.next()) |entry| {
            const qid = entry.key_ptr.*;
            const sent_at = entry.value_ptr.*;
            if (now - sent_at >= timeout_ms) {
                self.stale_buf.append(g.allocator, qid) catch unreachable;
                continue;
            }
            if (oldest == 0 or sent_at < oldest)
                oldest = sent_at;
        }

        for (self.stale_buf.items) |qid|
            _ = self.query_list.remove(qid);

        if (!was_idle and self.is_idle())
            self.session_node.on_idle();

        self.oldest_query_time = oldest;
    }

    fn reply_receiver(self: *UDP) void {
        defer co.terminate(@frame(), @frameSize(reply_receiver));

        self.active += 1;
        defer {
            assert(self.active > 0);
            self.active -= 1;
            self.free();
        }

        var free_rmsg: ?*RcMsg = null;
        defer if (free_rmsg) |rmsg| rmsg.free();

        while (true) {
            const cap: u16 = if (self.proxy_enabled)
                cc.to_u16(c.DNS_EDNS_MAXSIZE + socks5.UDP_OVERHEAD_MAX)
            else
                c.DNS_EDNS_MAXSIZE;

            const rmsg = free_rmsg orelse RcMsg.new(cap);
            free_rmsg = null;

            // Keep a guard ref during processing to avoid premature free if refcount is corrupted elsewhere.
            _ = rmsg.ref();
            defer {
                const refs = rmsg.ref_count();
                rmsg.unref(); // drop guard
                if (refs == 2) {
                    if (rmsg.cap <= REUSE_MAX_UDP) {
                        free_rmsg = rmsg;
                    } else {
                        // drop receiver ref to free oversized buffer
                        rmsg.unref();
                    }
                } else if (refs > 2) {
                    rmsg.unref(); // drop receiver ref
                }
            }

            const raw_len = g.evloop.read_udp(self.fdobj, rmsg.buf(), null) orelse return self.on_error("recv");
            const len: usize = if (self.proxy_enabled)
                (socks5.decode_udp_datagram_inplace(rmsg.buf(), raw_len) orelse continue)
            else
                raw_len;
            rmsg.len = cc.to_u16(len);

            const prev_idle = self.is_idle();

            // update query_list
            if (len >= dns.header_len()) {
                const qid = dns.get_id(rmsg.msg());
                if (self.query_list.get(qid)) |sent_at| {
                    _ = self.query_list.remove(qid);
                    if (sent_at == self.oldest_query_time or self.query_list.count() == 0)
                        self.oldest_query_time = 0;
                }
            }

            // will modify the msg.id
            nosuspend server.on_reply(rmsg, self.upstream);

            // all queries completed
            if (self.is_idle()) {
                if (!prev_idle)
                    self.session_node.on_idle();

                if (self.should_retire()) {
                    self.retire();
                    return; // free
                }
            }
        }
    }

    fn on_error(self: *const UDP, op: cc.ConstStr) void {
        if (!self.fdobj.canceled)
            log.warn(@src(), "%s(%s) failed: (%d) %m", .{ op, self.upstream.url, cc.errno() });
    }
};

// ======================================================

pub const has_tls = build_opts.enable_wolfssl;

pub const TLS = struct {
    ssl: ?*c.WOLFSSL = null,

    var _ctx: ?*c.WOLFSSL_CTX = null;

    /// called at startup
    pub fn init() void {
        if (_ctx != null) return;

        cc.SSL_library_init();

        const ctx = cc.SSL_CTX_new();
        _ctx = ctx;

        if (g.cert_verify) {
            const src = @src();
            if (g.ca_certs.is_null())
                cc.SSL_CTX_load_sys_CA_certs(ctx) orelse {
                    log.err(src, "failed to load system CA certs, please provide --ca-certs", .{});
                    cc.exit(1);
                }
            else
                cc.SSL_CTX_load_CA_certs(ctx, g.ca_certs.cstr()) orelse {
                    log.err(src, "failed to load CA certs: %s", .{g.ca_certs.cstr()});
                    cc.exit(1);
                };
        }
    }

    pub fn new_ssl(self: *TLS, fd: c_int, host: ?cc.ConstStr) ?void {
        assert(self.ssl == null);

        const ssl = cc.SSL_new(_ctx.?);

        var ok = false;
        defer if (!ok) cc.SSL_free(ssl);

        cc.SSL_set_fd(ssl, fd) orelse return null;
        cc.SSL_set_host(ssl, host, g.cert_verify) orelse return null;

        ok = true;
        self.ssl = ssl;
    }

    // free the ssl obj
    pub fn on_close(self: *TLS) void {
        const ssl = self.ssl orelse return;
        self.ssl = null;

        cc.SSL_free(ssl);
    }
};

/// tcp/tls session
const TCP = struct {
    session_node: SessionNode = .{ .type = .tcp }, // _session_list node
    upstream: *Upstream,
    fdobj: ?*EvLoop.Fd = null, // tcp connection
    tls: TLS_ = .{}, // tls connection (DoT)
    send_list: MsgQueue = .{}, // qmsg to be sent
    ack_list: std.AutoHashMapUnmanaged(u16, AckEntry) = .{}, // qmsg to be ack
    stale_buf: std.ArrayListUnmanaged(u16) = .{},
    fd_canceled: bool = false,
    create_time: u64, // last connect time
    query_time: u64 = undefined, // last query time
    oldest_query_time: u64 = 0, // oldest outstanding query time
    query_count: u16 = 0, // total query count
    pending_n: u16 = 0, // outstanding queries: send_list + ack_list
    active: u8 = 0, // running coroutines (query_sender/reply_receiver)
    flags: packed struct {
        freed: bool = false, // free()
        closing: bool = false, // close requested, waiting for active coroutines
        freeing: bool = false, // guard re-entrant free during cancel
        pending_free: bool = false,
        starting: bool = false, // start()
        stopping: bool = false, // stop()
        in_sender: bool = false, // query_sender()
        stop_requested: bool = false, // stop requested while query_sender is active
    } = .{},

    const TLS_ = if (has_tls) TLS else struct {};

    const MsgQueue = struct {
        head: ?*Msg = null,
        tail: ?*Msg = null,
        waiter: ?anyframe = null,
        const Msg = struct {
            msg: *RcMsg,
            next: *Msg,
        };

        fn co_data() *?*RcMsg {
            return co.data(?*RcMsg);
        }

        fn do_push(self: *MsgQueue, msg: *RcMsg, pos: enum { front, back }) void {
            if (self.waiter) |waiter| {
                assert(self.is_empty());
                co_data().* = msg;
                co.do_resume(waiter);
                return;
            }

            const node = self.acquire_node();
            node.* = .{
                .msg = msg,
                .next = undefined,
            };

            if (self.is_empty()) {
                self.head = node;
                self.tail = node;
            } else switch (pos) {
                .front => {
                    node.next = self.head.?;
                    self.head = node;
                },
                .back => {
                    self.tail.?.next = node;
                    self.tail = node;
                },
            }
        }

        pub fn push(self: *MsgQueue, msg: *RcMsg) void {
            return self.do_push(msg, .back);
        }

        pub fn push_front(self: *MsgQueue, msg: *RcMsg) void {
            return self.do_push(msg, .front);
        }

        /// `null`: cancel wait
        pub fn pop(self: *MsgQueue, comptime suspending: bool) ?*RcMsg {
            if (self.head) |node| {
                if (node == self.tail) {
                    self.head = null;
                    self.tail = null;
                } else {
                    self.head = node.next;
                    assert(self.tail != null);
                }
                const msg = node.msg;
                self.release_node(node);
                return msg;
            } else {
                if (!suspending)
                    return null;
                self.waiter = @frame();
                suspend {}
                self.waiter = null;
                return co_data().*;
            }
        }

        pub fn cancel_wait(self: *const MsgQueue) void {
            if (self.waiter) |waiter| {
                assert(self.is_empty());
                co_data().* = null;
                co.do_resume(waiter);
            }
        }

        pub fn is_empty(self: *const MsgQueue) bool {
            return self.head == null;
        }


        /// clear && msg.unref()
        pub fn clear(self: *MsgQueue) void {
            while (self.pop(false)) |msg|
                msg.unref();
        }

        fn acquire_node(_: *MsgQueue) *Msg {
            return g.allocator.create(Msg) catch unreachable;
        }

        fn release_node(_: *MsgQueue, node: *Msg) void {
            g.allocator.destroy(node);
        }
    };

    const AckEntry = struct {
        msg: *RcMsg,
        sent_at: u64,
    };

    pub fn new(upstream: *Upstream) *TCP {
        const self = g.allocator.create(TCP) catch unreachable;
        self.* = .{
            .upstream = upstream,
            .create_time = g.evloop.time,
        };
        return self;
    }

    pub fn free(self: *TCP) void {
        const handle = get_session_ptr_handle(@ptrCast(*anyopaque, self)) orelse
            return;
        if (!self.session_node.is_alive())
            return;
        if (self.flags.freed) return;
        if (self.flags.freeing) {
            self.flags.pending_free = true;
            return;
        }
        self.flags.freeing = true;
        var free_guard = true;
        defer {
            if (free_guard)
                self.flags.freeing = false;
        }
        if (self.active > 0) {
            self.flags.closing = true;
            if (self.upstream.session_eql(self.session_node.id))
                self.upstream.session_id = 0;
            self.session_node.on_idle();
            self.send_list.cancel_wait();
            if (self.fdobj) |fdobj| if (!self.fd_canceled) {
                self.fd_canceled = true;
                fdobj.cancel();
            };
            if (self.active > 0)
                return;
        }

        self.flags.pending_free = false;
        self.flags.freed = true;

        self.session_node.on_idle();

        if (self.upstream.session_eql(self.session_node.id))
            self.upstream.session_id = 0;

        self.send_list.cancel_wait();

        if (self.fdobj) |fdobj| if (!self.fd_canceled) {
            fdobj.cancel();
            self.fd_canceled = true;
        };
        if (self.fdobj) |fdobj| {
            fdobj.free();
            self.fdobj = null;
            self.fd_canceled = false;
        }

        if (has_tls)
            self.tls.on_close();

        self.send_list.clear();
        self.clear_ack_list(.unref);
        self.ack_list.clearAndFree(g.allocator);
        self.stale_buf.clearAndFree(g.allocator);
        self.session_node.mark_freed();
        release_session_slot(handle);
        self.session_node.id = 0;
        unregister_session_ptr(self);
        self.flags.freeing = false;
        free_guard = false;
        g.allocator.destroy(self);
    }

    pub fn get_deadline(self: *const TCP) u64 {
        assert(!self.is_idle());
        return self.query_time + cc.to_u64(g.upstream_timeout) * 1000;
    }

    /// no outstanding queries
    fn is_idle(self: *const TCP) bool {
        return self.pending_n == 0;
    }

    /// no more queries will be sent. \
    /// freed when the queries completes.
    fn should_retire(self: *const TCP) bool {
        if (!self.upstream.session_eql(self.session_node.id))
            return true;

        if ((self.upstream.count > 0 and self.query_count >= self.upstream.count) or
            (self.upstream.life > 0 and g.evloop.time >= self.create_time + cc.to_u64(self.upstream.life) * 1000))
            return true;

        return false;
    }

    fn retire(self: *const TCP) void {
        if (self.upstream.session_eql(self.session_node.id))
            self.upstream.session_id = 0;
    }

    /// add to send queue, `qmsg.ref++`
    pub fn send_query(self: *TCP, qmsg: *RcMsg) bool {
        if (get_session_ptr_handle(@ptrCast(*anyopaque, self)) == null or !self.session_node.is_alive())
            return false;
        const proxied = use_proxy(self.upstream);

        if (!self.upstream.can_try())
            return false;

        if (self.is_idle() and self.should_retire()) {
            self.retire();
            const new_session = new(self.upstream);
            install_session(self.upstream, new_session, .tcp);

            const ok = nosuspend new_session.send_query(qmsg);
            if (self.is_idle())
                self.free();

            return ok;
        }

        if (proxied and !g.proxy_can_try())
            return false;

        // If proxy is enabled but the TCP session isn't connected yet, start connecting in background.
        // We don't queue qmsg here; let server reply SERVFAIL and rely on client retry.
        if (proxied and self.fdobj == null) {
            if (!self.flags.starting)
                self.start();
            return false;
        }

        const limit: u16 = pending_limit();
        if (self.pending_n >= limit) {
            log.warn(@src(), "too many pending tcp queries to %s: %u (limit:%u)", .{
                self.upstream.url,
                cc.to_uint(self.pending_n),
                cc.to_uint(limit),
            });
            return false; // caller will reply SERVFAIL
        }

        self.session_node.on_work(self.is_idle());

        self.pending_n += 1;
        self.send_list.push(qmsg.ref());

        self.query_time = g.evloop.time;
        self.query_count +|= 1;

        // must be at the end
        if (self.fdobj == null)
            self.start();

        return true;
    }

    /// [suspending] pop from send_list && add to ack_list
    fn pop_qmsg(self: *TCP) ?*RcMsg {
        const qmsg = self.send_list.pop(true) orelse return null;
        self.on_send_msg(qmsg);
        return qmsg;
    }

    /// add qmsg to ack_list
    fn on_send_msg(self: *TCP, qmsg: *RcMsg) void {
        const qid = dns.get_id(qmsg.msg());
        const now = g.evloop.time;
        if (self.ack_list.fetchPut(g.allocator, qid, .{ .msg = qmsg, .sent_at = now }) catch unreachable) |old| {
            old.value.msg.unref();
            if (self.pending_n > 0)
                self.pending_n -= 1
            else
                self.pending_n = 0;
            if (old.value.sent_at == self.oldest_query_time)
                self.recalc_oldest_query_time();
            log.warn(@src(), "duplicated qid:%u to %s", .{ cc.to_uint(qid), self.upstream.url });
        }
        if (self.oldest_query_time == 0 or now < self.oldest_query_time)
            self.oldest_query_time = now;
    }

    /// remove qmsg from ack_list && qmsg.unref()
    fn on_recv_msg(self: *TCP, rmsg: *const RcMsg) void {
        const qid = dns.get_id(rmsg.msg());
        if (self.ack_list.fetchRemove(qid)) |kv| {
            if (self.pending_n > 0)
                self.pending_n -= 1
            else
                self.pending_n = 0;
            kv.value.msg.unref();
            if (kv.value.sent_at == self.oldest_query_time)
                self.recalc_oldest_query_time();
        } else {
            log.warn(@src(), "unexpected msg_id:%u from %s", .{ cc.to_uint(qid), self.upstream.url });
        }
    }

    fn stop(self: *TCP) void {
        if (self.active > 1 or self.flags.in_sender) {
            self.flags.stop_requested = true;
            self.send_list.cancel_wait();
            if (self.fdobj) |fdobj| if (!self.fd_canceled) {
                fdobj.cancel();
                self.fd_canceled = true;
            };
            return;
        }

        if (self.flags.stopping or self.flags.freed)
            return;

        {
            // cleanup
            self.flags.stopping = true;
            defer self.flags.stopping = false;
            self.flags.stop_requested = false;

            self.send_list.cancel_wait();

            if (self.fdobj) |fdobj| {
                if (!self.fd_canceled) {
                    fdobj.cancel();
                    self.fd_canceled = true;
                }
                // tear down stale fd before any restart to avoid stale frame assertions
                fdobj.free();
                self.fdobj = null;
                self.fd_canceled = false;
            }

            if (has_tls)
                self.tls.on_close();
        }

        if (self.flags.closing) {
            const had_pending = self.pending_n > 0;
            self.clear_ack_list(.unref);
            self.send_list.clear();
            self.pending_n = 0;
            if (had_pending)
                self.session_node.on_idle();
            return;
        }

        if (self.pending_n > 0) {
            // If proxy is failing, drop queued qmsgs to avoid infinite reconnect loops + memory retention.
            if (use_proxy(self.upstream) and !g.proxy_can_try()) {
                self.clear_ack_list(.unref);
                self.send_list.clear();
                self.pending_n = 0;
                self.session_node.on_idle();
                return;
            }
            if (!self.flags.starting) {
                // restart
                self.clear_ack_list(.resend);
                self.start(); // must be at the end
            } else {
                // local error
                self.clear_ack_list(.unref);
                self.send_list.clear();
                self.pending_n = 0;
                self.session_node.on_idle();
            }
        } else {
            // idle
            if (!self.flags.starting and self.should_retire()) {
                self.retire();
                self.free();
            }
        }
    }

    fn clear_ack_list(self: *TCP, op: enum { resend, unref }) void {
        var it = self.ack_list.valueIterator();
        while (it.next()) |value_ptr| {
            const qmsg = value_ptr.msg;
            switch (op) {
                .resend => self.send_list.push_front(qmsg),
                .unref => qmsg.unref(),
            }
        }
        // Shrink ack_list if capacity is too large
        if (self.ack_list.capacity() > 64 and self.ack_list.count() == 0) {
            self.ack_list.clearAndFree(g.allocator);
        } else {
            self.ack_list.clearRetainingCapacity();
        }
        self.oldest_query_time = 0;
    }

    fn recalc_oldest_query_time(self: *TCP) void {
        var oldest: u64 = 0;
        var it = self.ack_list.valueIterator();
        while (it.next()) |value_ptr| {
            const sent_at = value_ptr.sent_at;
            if (oldest == 0 or sent_at < oldest)
                oldest = sent_at;
        }
        self.oldest_query_time = oldest;
    }

    fn cleanup_stale_queries(self: *TCP, timer: *EvLoop.Timer) void {
        if (self.ack_list.count() == 0) {
            self.oldest_query_time = 0;
            return;
        }

        const timeout_ms = cc.to_u64(g.upstream_timeout) * 1000;
        if (timeout_ms == 0)
            return;

        if (self.oldest_query_time == 0)
            self.recalc_oldest_query_time();
        if (self.oldest_query_time == 0)
            return;

        if (!timer.check_deadline(self.oldest_query_time + timeout_ms))
            return;

        const now = g.evloop.time;
        // Shrink stale_buf if capacity is too large
        if (self.stale_buf.capacity > 64 and self.stale_buf.items.len == 0) {
            self.stale_buf.clearAndFree(g.allocator);
        } else {
            self.stale_buf.clearRetainingCapacity();
        }

        var oldest: u64 = 0;
        var it = self.ack_list.iterator();
        while (it.next()) |entry| {
            const sent_at = entry.value_ptr.sent_at;
            if (now - sent_at >= timeout_ms) {
                self.stale_buf.append(g.allocator, entry.key_ptr.*) catch unreachable;
                continue;
            }
            if (oldest == 0 or sent_at < oldest)
                oldest = sent_at;
        }

        for (self.stale_buf.items) |qid| {
            if (self.ack_list.fetchRemove(qid)) |kv| {
                if (self.pending_n > 0)
                    self.pending_n -= 1
                else
                    self.pending_n = 0;
                kv.value.msg.unref();
            }
        }
        // Shrink stale_buf after use if it grew large
        if (self.stale_buf.capacity > 64) {
            self.stale_buf.clearAndFree(g.allocator);
        } else {
            self.stale_buf.clearRetainingCapacity();
        }
        self.oldest_query_time = oldest;

        if (self.pending_n == 0)
            self.session_node.on_idle();
    }

    /// may call `self.free()`
    fn start(self: *TCP) void {
        assert(self.fdobj == null);
        assert(self.ack_list.count() == 0);
        if (self.pending_n == 0)
            assert(self.send_list.is_empty());

        self.create_time = g.evloop.time;

        self.flags.starting = true;
        co.start(query_sender, .{self});
        self.flags.starting = false;

        if (self.is_idle() and self.should_retire()) {
            self.retire();
            self.free();
        }
    }

    fn query_sender(self: *TCP) void {
        defer co.terminate(@frame(), @frameSize(query_sender));

        self.active += 1;
        defer {
            self.flags.in_sender = false;
            self.stop();
            assert(self.active > 0);
            self.active -= 1;
            if (self.flags.closing)
                self.free();
        }
        self.flags.in_sender = true;

        const family = if (use_proxy(self.upstream))
            g.proxy_addr.?.family()
        else
            self.upstream.addr.family();
        const fd = net.new_tcp_conn_sock(family) orelse return;
        self.fdobj = EvLoop.Fd.new(fd);

        self.connect() orelse return;

        co.start(reply_receiver, .{self});

        if (self.flags.stop_requested) {
            self.flags.stop_requested = false;
            return; // do stop()
        }

        while (self.pop_qmsg()) |qmsg| {
            if (self.flags.stop_requested) {
                self.flags.stop_requested = false;
                return;
            }
            self.send(qmsg) orelse return;
        }
    }

    fn reply_receiver(self: *TCP) void {
        defer co.terminate(@frame(), @frameSize(reply_receiver));

        self.active += 1;
        defer {
            self.stop();
            assert(self.active > 0);
            self.active -= 1;
            if (self.flags.closing)
                self.free();
        }

        var free_rmsg: ?*RcMsg = null;
        defer if (free_rmsg) |rmsg| rmsg.free();

        while (true) {
            // read the len
            var len: u16 = undefined;
            self.recv(std.mem.asBytes(&len)) orelse return;

            // check the len
            len = cc.ntohs(len);
            if (len < dns.header_len()) {
                log.warn(@src(), "recv(%s) failed: invalid len:%u", .{ self.upstream.url, cc.to_uint(len) });
                return;
            }
            if (len > c.DNS_MSG_MAXSIZE) {
                log.warn(@src(), "recv(%s) failed: oversize len:%u", .{ self.upstream.url, cc.to_uint(len) });
                return;
            }

            const rmsg: *RcMsg = if (free_rmsg) |rmsg| rmsg.realloc(len) else RcMsg.new(len);
            free_rmsg = null;

            // Keep a guard ref during processing to avoid premature free if refcount is corrupted elsewhere.
            _ = rmsg.ref();
            defer {
                const refs = rmsg.ref_count();
                rmsg.unref(); // drop guard
                if (refs == 2) {
                    if (rmsg.cap <= REUSE_MAX_TCP) {
                        free_rmsg = rmsg;
                    } else {
                        rmsg.unref(); // drop receiver ref to free oversized buffer
                    }
                } else if (refs > 2) {
                    rmsg.unref(); // drop receiver ref
                }
            }

            // read the msg
            rmsg.len = len;
            self.recv(rmsg.msg()) orelse return;

            const prev_idle = self.is_idle();

            // update ack_list
            self.on_recv_msg(rmsg);

            // will modify the msg.id
            nosuspend server.on_reply(rmsg, self.upstream);

            // all queries completed
            if (self.is_idle()) {
                if (!prev_idle)
                    self.session_node.on_idle();

                if (self.should_retire()) {
                    self.retire();
                    return; // stop and free
                }
            }
        }
    }

    /// `errmsg`: null means strerror(errno)
    fn on_error(self: *TCP, op: cc.ConstStr, errmsg: ?cc.ConstStr) ?void {
        if (self.fdobj.?.canceled)
            return null;

        const src = @src();
        self.upstream.note_fail();
        // throttle repetitive errors to avoid log flooding
        const now = g.evloop.time;
        const suppress_window_ms: u64 = 5000;
        const flush_every: u32 = 100;
        var counter_ref = &g.proxy_error_counter;
        var last_ref = &g.proxy_error_last_ms;

        counter_ref.* +|= 1;
        if (counter_ref.* == 1 or now - last_ref.* >= suppress_window_ms or (counter_ref.* % flush_every) == 0) {
            last_ref.* = now;
            if (errmsg) |msg|
                log.warn(src, "%s(%s) failed: %s [cnt:%u]", .{ op, self.upstream.url, msg, cc.to_uint(counter_ref.*) })
            else
                log.warn(src, "%s(%s) failed: (%d) %m [cnt:%u]", .{ op, self.upstream.url, cc.errno(), cc.to_uint(counter_ref.*) });
            counter_ref.* = 0;
        }

        return null;
    }

    fn ssl(self: *const TCP) *c.WOLFSSL {
        return self.tls.ssl.?;
    }

    fn connect(self: *TCP) ?void {
        if (!self.upstream.can_try())
            return null;
        // null means strerror(errno)
        const errmsg: ?cc.ConstStr = e: {
            const fdobj = self.fdobj.?;
            if (use_proxy(self.upstream)) {
                if (!g.proxy_can_try())
                    break :e "proxy backoff";
                const proxy_addr = g.proxy_addr.?;
                g.evloop.connect(fdobj, &proxy_addr) orelse {
                    self.upstream.note_fail();
                    g.proxy_note_fail();
                    break :e null;
                };

                if (socks5.greet_noauth(fdobj)) |err| {
                    self.upstream.note_fail();
                    g.proxy_note_fail();
                    break :e err;
                }

                if (socks5.request_connect(fdobj, &self.upstream.addr)) |err| {
                    self.upstream.note_fail();
                    g.proxy_note_fail();
                    break :e err;
                }
                g.proxy_note_success();
            } else {
                g.evloop.connect(fdobj, &self.upstream.addr) orelse {
                    self.upstream.note_fail();
                    break :e null;
                };
            }
            self.upstream.note_success();

            if (has_tls and self.upstream.proto == .tls) {
                self.tls.new_ssl(fdobj.fd, self.upstream.host) orelse break :e "unable to create ssl object";

                while (true) {
                    var err: c_int = undefined;
                    cc.SSL_connect(self.ssl(), &err) orelse switch (err) {
                        c.WOLFSSL_ERROR_WANT_READ => {
                            g.evloop.wait_readable(fdobj) orelse return null;
                            continue;
                        },
                        c.WOLFSSL_ERROR_WANT_WRITE => {
                            g.evloop.wait_writable(fdobj) orelse return null;
                            continue;
                        },
                        else => {
                            break :e cc.SSL_error_string(err);
                        },
                    };
                    break;
                }

                if (g.verbose())
                    log.info(@src(), "%s | %s | %s", .{
                        self.upstream.url,
                        cc.SSL_get_version(self.ssl()),
                        cc.SSL_get_cipher(self.ssl()),
                    });
            }

            return;
        };

        return self.on_error("connect", errmsg);
    }

    fn send(self: *TCP, qmsg: *RcMsg) ?void {
        // null means strerror(errno)
        const errmsg: ?cc.ConstStr = e: {
            const fdobj = self.fdobj.?;

            if (self.upstream.proto != .tls) {
                var iovec = [_]cc.iovec_t{
                    .{
                        .iov_base = std.mem.asBytes(&cc.htons(qmsg.len)),
                        .iov_len = @sizeOf(u16),
                    },
                    .{
                        .iov_base = qmsg.msg().ptr,
                        .iov_len = qmsg.len,
                    },
                };
                g.evloop.writev(fdobj, &iovec) orelse break :e null;
            } else if (has_tls) {
                // merge into one ssl record
                var buf: [2 + c.DNS_QMSG_MAXSIZE]u8 align(2) = undefined;
                const data = buf[0 .. 2 + qmsg.len];
                std.mem.bytesAsValue(u16, data[0..2]).* = cc.htons(qmsg.len);
                @memcpy(data[2..].ptr, qmsg.msg().ptr, qmsg.len);

                while (true) {
                    var err: c_int = undefined;
                    cc.SSL_write(self.ssl(), data, &err) orelse switch (err) {
                        c.WOLFSSL_ERROR_WANT_WRITE => {
                            g.evloop.wait_writable(fdobj) orelse return null;
                            continue;
                        },
                        else => {
                            break :e cc.SSL_error_string(err);
                        },
                    };
                    break;
                }
            } else unreachable;

            return;
        };

        return self.on_error("send", errmsg);
    }

    /// read the `buf` full
    fn recv(self: *TCP, buf: []u8) ?void {
        // null means strerror(errno)
        const errmsg: ?cc.ConstStr = e: {
            const fdobj = self.fdobj.?;

            if (self.upstream.proto != .tls) {
                g.evloop.read(fdobj, buf) catch |err| switch (err) {
                    error.eof => return null,
                    error.errno => break :e null,
                };
            } else if (has_tls) {
                var nread: usize = 0;
                while (nread < buf.len) {
                    var err: c_int = undefined;
                    const n = cc.SSL_read(self.ssl(), buf[nread..], &err) orelse switch (err) {
                        c.WOLFSSL_ERROR_ZERO_RETURN => { // TLS EOF
                            return null;
                        },
                        c.WOLFSSL_ERROR_WANT_READ => {
                            g.evloop.wait_readable(fdobj) orelse return null;
                            continue;
                        },
                        else => {
                            break :e cc.SSL_error_string(err);
                        },
                    };
                    nread += n;
                }
            } else unreachable;

            return;
        };

        return self.on_error("recv", errmsg);
    }
};

// ======================================================

pub const Proto = enum {
    raw, // "1.1.1.1" (tcpi + udpi) only exists in the parsing stage
    udpi, // "udpi://1.1.1.1" (enabled when the query msg is received over udp)
    tcpi, // "tcpi://1.1.1.1" (enabled when the query msg is received over tcp)

    udp, // "udp://1.1.1.1"
    tcp, // "tcp://1.1.1.1"
    tls, // "tls://1.1.1.1"

    /// "tcp://"
    pub fn from_str(str: []const u8) ?Proto {
        const map = if (has_tls) .{
            .{ .str = "udp://", .proto = .udp },
            .{ .str = "tcp://", .proto = .tcp },
            .{ .str = "tls://", .proto = .tls },
        } else .{
            .{ .str = "udp://", .proto = .udp },
            .{ .str = "tcp://", .proto = .tcp },
        };
        inline for (map) |v| {
            if (std.mem.eql(u8, str, v.str))
                return v.proto;
        }
        return null;
    }

    /// "tcp://" (string literal)
    pub fn to_str(self: Proto) [:0]const u8 {
        return switch (self) {
            .udpi => "udpi://",
            .tcpi => "tcpi://",
            .udp => "udp://",
            .tcp => "tcp://",
            .tls => "tls://",
            else => unreachable,
        };
    }

    pub fn require_host(self: Proto) bool {
        return self == .tls;
    }

    pub fn std_port(self: Proto) u16 {
        return switch (self) {
            .tls => 853,
            else => 53,
        };
    }

    pub fn is_std_port(self: Proto, port: u16) bool {
        return port == self.std_port();
    }
};

// ======================================================

pub const Group = struct {
    list: std.ArrayListUnmanaged(Upstream) = .{},

    pub inline fn items(self: *const Group) []Upstream {
        return self.list.items;
    }

    pub inline fn is_empty(self: *const Group) bool {
        return self.items().len == 0;
    }

    // ======================================================

    fn parse_failed(msg: [:0]const u8, value: []const u8) ?void {
        opt.print(@src(), msg, value);
        return null;
    }

    /// "[proto://][host@]ip[#port][?count=N][?life=N]"
    pub fn add(self: *Group, tag: Tag, url: []const u8) ?void {
        @setCold(true);

        var rest = url;

        // proto
        const proto = b: {
            if (std.mem.indexOf(u8, rest, "://")) |i| {
                const proto = rest[0 .. i + 3];
                rest = rest[i + 3 ..];
                break :b Proto.from_str(proto) orelse
                    return parse_failed("invalid proto", proto);
            }
            break :b Proto.raw;
        };

        // host, only DoT needs it
        const host = b: {
            if (std.mem.indexOf(u8, rest, "@")) |i| {
                const host = rest[0..i];
                rest = rest[i + 1 ..];
                if (host.len == 0)
                    return parse_failed("invalid host", host);
                if (!proto.require_host())
                    return parse_failed("no host required", host);
                break :b host;
            }
            break :b "";
        };

        var count = DEFAULT_COUNT;
        var life = DEFAULT_LIFE;

        // ?param=value
        while (std.mem.lastIndexOfScalar(u8, rest, '?')) |i| {
            const name_value = rest[i + 1 ..];
            rest = rest[0..i];
            const sep = std.mem.indexOfScalar(u8, name_value, '=') orelse
                return parse_failed("invalid param format", name_value);
            const name = name_value[0..sep];
            const value_str = name_value[sep + 1 ..];
            const value_int = str2int.parse(ParamValue, value_str, 10) orelse
                return parse_failed("invalid param value", name_value);
            if (std.mem.eql(u8, name, "count")) {
                count = value_int;
            } else if (std.mem.eql(u8, name, "life")) {
                life = value_int;
            } else {
                return parse_failed("unknown param name", name_value);
            }
        }

        // port
        const port = b: {
            if (std.mem.lastIndexOfScalar(u8, rest, '#')) |i| {
                const port = rest[i + 1 ..];
                rest = rest[0..i];
                break :b opt.check_port(port) orelse return null;
            }
            break :b proto.std_port();
        };

        // ip
        const ip = rest;
        opt.check_ip(ip) orelse return null;

        if (proto == .raw) {
            // `bind_tcp/bind_udp` conditions can't be checked because `opt.parse()` is being executed
            self.do_add(tag, .udpi, host, ip, port, count, life);
            self.do_add(tag, .tcpi, host, ip, port, count, life);
        } else {
            self.do_add(tag, proto, host, ip, port, count, life);
        }
    }

    fn do_add(
        self: *Group,
        tag: Tag,
        proto: Proto,
        host: []const u8,
        ip: []const u8,
        port: u16,
        count: ParamValue,
        life: ParamValue,
    ) void {
        const addr = cc.SockAddr.from_text(cc.to_cstr(ip), port);

        for (self.items()) |*upstream| {
            if (upstream.eql(proto, &addr, host)) {
                upstream.count = count;
                upstream.life = life;
                return;
            }
        }

        const ptr = self.list.addOne(g.allocator) catch unreachable;
        ptr.* = Upstream.init(tag, proto, &addr, host, ip, port, count, life);
    }

    pub fn rm_useless(self: *Group) void {
        @setCold(true);

        var has_udpi = false;
        var has_tcpi = false;
        for (g.bind_ports) |p| {
            if (p.udp) has_udpi = true;
            if (p.tcp) has_tcpi = true;
        }

        var len = self.items().len;
        while (len > 0) : (len -= 1) {
            const i = len - 1;
            const upstream = &self.items()[i];
            const rm = switch (upstream.proto) {
                .udpi => !has_udpi,
                .tcpi => !has_tcpi,
                else => continue,
            };
            if (rm) {
                upstream.deinit();
                _ = self.list.orderedRemove(i);
            }
        }
    }

    // ======================================================

    /// [nosuspend]
    pub fn send(self: *Group, qmsg: *RcMsg, udpi: bool) bool {
        const verbose_info = if (g.verbose()) .{
            .qid = dns.get_id(qmsg.msg()),
            .from = cc.b2s(udpi, "udp", "tcp"),
        } else undefined;

        const in_proto: Proto = if (udpi) .udpi else .tcpi;

        var sent = false;
        for (self.items()) |*upstream| {
            if (upstream.proto == .udpi or upstream.proto == .tcpi)
                if (upstream.proto != in_proto) continue;

            if (g.verbose())
                log.info(
                    @src(),
                    "forward query(qid:%u, from:%s) to upstream %s",
                    .{ cc.to_uint(verbose_info.qid), verbose_info.from, upstream.url },
                );

            sent = nosuspend upstream.send(qmsg) or sent;
        }

        return sent;
    }
};
