const std = @import("std");
const builtin = @import("builtin");
const build_opts = @import("build_opts");
const modules = @import("modules.zig");
const tests = @import("tests.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const g = @import("g.zig");
const log = @import("log.zig");
const opt = @import("opt.zig");
const net = @import("net.zig");
const ipset = @import("ipset.zig");
const server = @import("server.zig");
const EvLoop = @import("EvLoop.zig");
const co = @import("co.zig");
const groups = @import("groups.zig");
const cache = @import("cache.zig");
const Upstream = @import("Upstream.zig");
const verdict_cache = @import("verdict_cache.zig");
const str2int = @import("str2int.zig");
const Tag = @import("tag.zig").Tag;
const assert = std.debug.assert;

// ============================================================================

/// the rewrite is to avoid generating unnecessary code in release mode.
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    @setCold(true);
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe)
        std.builtin.default_panic(msg, error_return_trace, ret_addr)
    else
        cc.abort();
}

// ============================================================================

const FnEnum = enum {
    module_init,
    module_deinit,
    check_timeout,
};

pub fn call_module_fn(comptime fn_enum: FnEnum, args: anytype) void {
    const fn_name = comptime @tagName(fn_enum);
    comptime var i = 0;
    inline while (i < modules.module_list.len) : (i += 1) {
        const module = modules.module_list[i];
        const module_name: cc.ConstStr = modules.name_list[i];
        if (@hasDecl(module, fn_name)) {
            if (false) log.debug(@src(), "%s.%s()", .{ module_name, fn_name.ptr });
            const options: std.builtin.CallOptions = .{};
            const func = @field(module, fn_name);
            @call(options, func, args);
        }
    }
}

// ============================================================================

const _debug = builtin.mode == .Debug;

const gpa_t = if (_debug) std.heap.GeneralPurposeAllocator(.{}) else void;
var _gpa: gpa_t = undefined;

const MemReport = struct {
    rss: u32 = 0,
    size: u32 = 0,
    data: u32 = 0,
    peak: u32 = 0,
    hwm: u32 = 0,
};

var _next_mem_report_ms: u64 = 0;

fn parse_kb(line: []const u8, prefix: []const u8) ?u32 {
    if (!std.mem.startsWith(u8, line, prefix))
        return null;

    var i: usize = prefix.len;
    while (i < line.len and (line[i] == ' ' or line[i] == '\t')) : (i += 1) {}
    var j: usize = i;
    while (j < line.len and line[j] >= '0' and line[j] <= '9') : (j += 1) {}
    if (j == i)
        return null;
    return str2int.parse(u32, line[i..j], 10) orelse null;
}

fn read_mem_report() ?MemReport {
    const fd = cc.open("/proc/self/status", c.O_RDONLY | c.O_CLOEXEC, null) orelse return null;
    defer _ = cc.close(fd);

    var buf: [2048]u8 = undefined;
    const n = cc.read(fd, buf[0..]) orelse return null;
    const data = buf[0..n];

    var report: MemReport = .{};
    var it = std.mem.split(u8, data, "\n");
    while (it.next()) |line| {
        if (parse_kb(line, "VmRSS:")) |v| report.rss = v
        else if (parse_kb(line, "VmSize:")) |v| report.size = v
        else if (parse_kb(line, "VmData:")) |v| report.data = v
        else if (parse_kb(line, "VmPeak:")) |v| report.peak = v
        else if (parse_kb(line, "VmHWM:")) |v| report.hwm = v;
    }

    if (report.rss == 0 and report.size == 0 and report.data == 0 and report.peak == 0 and report.hwm == 0)
        return null;

    return report;
}

pub fn check_timeout(timer: *EvLoop.Timer) void {
    if (!build_opts.mem_report)
        return;
    if (g.mem_report_sec == 0)
        return;

    const now = g.evloop.time;
    if (_next_mem_report_ms == 0)
        _next_mem_report_ms = now + cc.to_u64(g.mem_report_sec) * 1000;

    if (timer.check_deadline(_next_mem_report_ms)) {
        _next_mem_report_ms = now + cc.to_u64(g.mem_report_sec) * 1000;
        if (read_mem_report()) |r| {
            const q_cnt = server.pending_query_count();
            const q_cap = server.pending_query_capacity();
            const tcp_n = server.tcp_conn_active();
            const sess_cnt = Upstream.session_ptrs_count();
            const sess_cap = Upstream.session_ptrs_capacity();
            const sess_stats = Upstream.collect_session_stats();
            const cache_cnt = cache.count();
            const vcache_cnt = verdict_cache.count();

            log.info(
                @src(),
                "mem: VmRSS:%u kB VmSize:%u kB VmData:%u kB VmPeak:%u kB VmHWM:%u kB objs: q=%zu/%zu conn_tcp=%u sp=%zu/%zu slot=%zu/%zu sess_udp=%zu sess_tcp=%zu udp_pend=%zu/%zu udp_proxy=%zu tcp_pend=%zu tcp_ack=%zu/%zu tcp_send=%zu cache=%zu vcache=%zu",
                .{
                    cc.to_uint(r.rss),
                    cc.to_uint(r.size),
                    cc.to_uint(r.data),
                    cc.to_uint(r.peak),
                    cc.to_uint(r.hwm),
                    cc.to_usize(q_cnt),
                    cc.to_usize(q_cap),
                    cc.to_uint(tcp_n),
                    cc.to_usize(sess_cnt),
                    cc.to_usize(sess_cap),
                    cc.to_usize(sess_stats.slots_total),
                    cc.to_usize(sess_stats.slots_active),
                    cc.to_usize(sess_stats.udp_sessions),
                    cc.to_usize(sess_stats.tcp_sessions),
                    cc.to_usize(sess_stats.udp_pending),
                    cc.to_usize(sess_stats.udp_pending_cap),
                    cc.to_usize(sess_stats.udp_proxy_pending),
                    cc.to_usize(sess_stats.tcp_pending),
                    cc.to_usize(sess_stats.tcp_ack),
                    cc.to_usize(sess_stats.tcp_ack_cap),
                    cc.to_usize(sess_stats.tcp_sendq),
                    cc.to_usize(cache_cnt),
                    cc.to_usize(vcache_cnt),
                },
            );
        }
    }
}

// ============================================================================

var _pipe_fds: [2]c_int = undefined;

fn sig_handler(sig: c_int) callconv(.C) void {
    _ = cc.write(_pipe_fds[1], std.mem.asBytes(&sig));
}

fn sig_listener() void {
    defer co.terminate(@frame(), @frameSize(sig_listener));

    const src = @src();

    cc.pipe2(&_pipe_fds, c.O_CLOEXEC | c.O_NONBLOCK) orelse {
        log.err(src, "pipe() failed: (%d) %m", .{cc.errno()});
        return;
    };

    // read side
    const fdobj = EvLoop.Fd.new(_pipe_fds[0]);
    defer fdobj.free();

    // write side
    defer _ = cc.close(_pipe_fds[1]);

    // register signal handler
    _ = cc.signal(c.SIGINT, sig_handler); // CTRL C
    _ = cc.signal(c.SIGTERM, sig_handler); // kill <PID>
    _ = cc.signal(c.SIGUSR1, sig_handler); // dump cache to file
    if (_debug) _ = cc.signal(c.SIGUSR2, sig_handler); // detect memory leaks

    // listening for signal
    while (true) {
        var sig: c_int = undefined;

        g.evloop.read(fdobj, std.mem.asBytes(&sig)) catch |err| switch (err) {
            error.eof => return log.err(src, "read(fd:%d) failed: EOF", .{fdobj.fd}),
            error.errno => return log.err(src, "read(fd:%d) failed: (%d) %m", .{ fdobj.fd, cc.errno() }),
        };

        switch (sig) {
            c.SIGINT, c.SIGTERM => {
                cache.dump(.on_exit);
                verdict_cache.dump(.on_exit);
                cc.exit(0);
            },
            c.SIGUSR1 => {
                cache.dump(.on_manual);
                verdict_cache.dump(.on_manual);
            },
            c.SIGUSR2 => {
                if (_debug)
                    _ = _gpa.detectLeaks()
                else
                    unreachable;
            },
            else => unreachable,
        }
    }
}

// ============================================================================

pub fn main() u8 {
    g.allocator = if (_debug) b: {
        _gpa = .{};
        break :b _gpa.allocator();
    } else std.heap.c_allocator;

    defer {
        if (_debug)
            _ = _gpa.deinit();
    }

    // ============================================================================

    _ = cc.signal(c.SIGPIPE, cc.SIG_IGN());

    _ = cc.setvbuf(cc.stdout, null, c._IOLBF, 256);
    _ = cc.set_nonblock(c.STDOUT_FILENO);
    _ = cc.set_nonblock(c.STDERR_FILENO);

    // setting default values for TZ
    _ = cc.setenv("TZ", ":/etc/localtime", false);

    // ============================================================================

    g.evloop = EvLoop.init();

    // used only for business-independent initialization, such as global variables
    call_module_fn(.module_init, .{});
    defer if (_debug) call_module_fn(.module_deinit, .{});

    // ============================================================================

    if (build_opts.is_test)
        return tests.main();

    // ============================================================================

    opt.parse();

    net.init();

    const src = @src();

    for (g.bind_ips.items()) |ip| {
        for (g.bind_ports) |p| {
            const proto: cc.ConstStr = if (p.tcp and p.udp) "" else if (p.tcp) "@tcp" else "@udp";
            log.info(src, "local listen addr: %s#%u%s", .{ ip, cc.to_uint(p.port), proto });
        }
    }

    groups.on_start();

    if (g.default_tag == .none or groups.require_ip_test()) {
        const name46 = cc.to_cstr_x(&.{ g.chnroute_name.slice(), ",", g.chnroute6_name.slice() });
        g.chnroute_testctx = ipset.new_testctx(name46);
        log.info(src, "ip test db: %s", .{name46});
    }

    log.info(src, "default domain name tag: %s", .{g.default_tag.name()});

    if (g.proxy_server) |proxy| {
        var buf: [128:0]u8 = undefined;
        var n: usize = 0;

        var tag_v: u8 = 0; // make zls 0.12 happy
        while (tag_v <= c.TAG_NONE) : (tag_v += 1) {
            const tag = Tag.from_int(tag_v);
            if (!tag.valid() or tag == .none or tag.is_null())
                continue;
            if (tag_v >= 16)
                continue;
            if ((g.proxy_group_mask & (@as(u16, 1) << @intCast(u4, tag_v))) == 0)
                continue;

            const name = cc.strslice_c(tag.name());
            if (n > 0 and n + 1 < buf.len) {
                buf[n] = ',';
                n += 1;
            }
            const need = std.math.min(name.len, buf.len - 1 - n);
            @memcpy(buf[n .. n + need].ptr, name.ptr, need);
            n += need;
        }
        buf[n] = 0;

        log.info(src, "proxy server: %s (groups:%s)", .{ proxy, &buf });
    }

    if (g.cache_size > 0) {
        log.info(src, "enable dns cache, capacity: %u", .{cc.to_uint(g.cache_size)});

        if (g.cache_stale > 0)
            log.info(src, "use stale cache, excess TTL: %lu", .{cc.to_ulong(g.cache_stale)});

        if (g.cache_refresh > 0)
            log.info(src, "pre-refresh cache, remain TTL: %u%%", .{cc.to_uint(g.cache_refresh)});

        if (g.cache_nodata_ttl > 0)
            log.info(src, "cache NODATA response, TTL: %ld", .{cc.to_long(g.cache_nodata_ttl)});

        if (g.cache_min_ttl > 0)
            log.info(src, "cache TTL overwrite, min TTL: %ld", .{cc.to_long(g.cache_min_ttl)});

        if (g.cache_max_ttl > 0)
            log.info(src, "cache TTL overwrite, max TTL: %ld", .{cc.to_long(g.cache_max_ttl)});

        cache.load();
    }

    if (g.verdict_cache_size > 0) {
        log.info(src, "enable verdict cache, capacity: %u", .{cc.to_uint(g.verdict_cache_size)});

        verdict_cache.load();
    }

    log.info(src, "response timeout of upstream: %u", .{cc.to_uint(g.upstream_timeout)});

    if (g.trustdns_packet_n > 1)
        log.info(src, "num of packets to trustdns: %u", .{cc.to_uint(g.trustdns_packet_n)});

    if (g.default_tag == .none) {
        const action = cc.b2s(g.flags.noip_as_chnip, "accept", "filter");
        log.info(src, "%s no-ip reply from chinadns", .{action});
    }

    if (g.flags.reuse_port)
        log.info(src, "SO_REUSEPORT for listening socket", .{});

    if (g.tcp_conn_max > 0)
        log.info(src, "tcp client conn max: %u", .{cc.to_uint(g.tcp_conn_max)});

    if (g.tcp_idle_sec > 0)
        log.info(src, "tcp client idle timeout: %us", .{cc.to_uint(g.tcp_idle_sec)});

    if (build_opts.mem_report and g.mem_report_sec > 0)
        log.info(src, "memory report interval: %us", .{cc.to_uint(g.mem_report_sec)});

    if (g.verbose())
        log.info(src, "printing the verbose runtime log", .{});

    // ============================================================================

    server.start();

    co.start(sig_listener, .{});

    g.evloop.run();

    return 0;
}
