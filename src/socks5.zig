const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const EvLoop = @import("EvLoop.zig");
const assert = std.debug.assert;

pub const UDP_OVERHEAD_MAX: usize = 2 + 1 + 1 + 16 + 2;

const VER: u8 = 0x05;

const METHOD_NOAUTH: u8 = 0x00;
const METHOD_NOACCEPT: u8 = 0xff;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;

fn encode_atyp_addr_port(out: []u8, addr: *const cc.SockAddr) ?usize {
    var i: usize = 0;

    if (addr.is_sin()) {
        if (out.len < 1 + 4 + 2)
            return null;
        out[i] = ATYP_IPV4;
        i += 1;
        @memcpy(out[i..].ptr, @ptrCast([*]const u8, &addr.sin.sin_addr), 4);
        i += 4;
        @memcpy(out[i..].ptr, @ptrCast([*]const u8, &addr.sin.sin_port), 2);
        i += 2;
    } else {
        assert(addr.is_sin6());
        if (out.len < 1 + 16 + 2)
            return null;
        out[i] = ATYP_IPV6;
        i += 1;
        @memcpy(out[i..].ptr, @ptrCast([*]const u8, &addr.sin6.sin6_addr), 16);
        i += 16;
        @memcpy(out[i..].ptr, @ptrCast([*]const u8, &addr.sin6.sin6_port), 2);
        i += 2;
    }

    return i;
}

pub fn greet_noauth(fdobj: *EvLoop.Fd) ?cc.ConstStr {
    const req = [_]u8{ VER, 1, METHOD_NOAUTH };
    g.evloop.write(fdobj, &req) orelse return "socks5 write (greet) failed";

    var res: [2]u8 = undefined;
    g.evloop.read(fdobj, &res) catch return "socks5 read (greet) failed";

    if (res[0] != VER)
        return "socks5 invalid version";
    if (res[1] == METHOD_NOACCEPT)
        return "socks5 no acceptable auth method";
    if (res[1] != METHOD_NOAUTH)
        return "socks5 auth method not supported (need no-auth)";

    return null;
}

fn read_reply_and_discard_addr(fdobj: *EvLoop.Fd, p_rep: *u8) ?cc.ConstStr {
    var head: [4]u8 = undefined;
    g.evloop.read(fdobj, &head) catch return "socks5 read (reply head) failed";

    if (head[0] != VER)
        return "socks5 invalid version";

    const rep = head[1];
    p_rep.* = rep;

    if (head[2] != 0x00)
        return "socks5 invalid RSV";

    const atyp = head[3];
    const addr_len: usize = switch (atyp) {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        0x03 => b: { // domain
            var dom_len: [1]u8 = undefined;
            g.evloop.read(fdobj, &dom_len) catch return "socks5 read (domain len) failed";
            break :b dom_len[0];
        },
        else => return "socks5 invalid ATYP",
    };

    if (addr_len > 0) {
        var tmp: [256]u8 = undefined;
        if (addr_len > tmp.len)
            return "socks5 address too long";
        g.evloop.read(fdobj, tmp[0..addr_len]) catch return "socks5 read (reply addr) failed";
    }

    var port: [2]u8 = undefined;
    g.evloop.read(fdobj, &port) catch return "socks5 read (reply port) failed";

    return null;
}

pub fn request_connect(fdobj: *EvLoop.Fd, target: *const cc.SockAddr) ?cc.ConstStr {
    var req: [4 + (1 + 16 + 2)]u8 = undefined;
    req[0] = VER;
    req[1] = CMD_CONNECT;
    req[2] = 0x00;

    const n = encode_atyp_addr_port(req[3..], target) orelse return "socks5 encode addr failed";
    g.evloop.write(fdobj, req[0 .. 3 + n]) orelse return "socks5 write (connect) failed";

    var rep: u8 = 0xff;
    if (read_reply_and_discard_addr(fdobj, &rep)) |err|
        return err;
    if (rep != 0x00)
        return "socks5 connect rejected";

    return null;
}

fn is_unspecified_addr(addr: *const cc.SockAddr) bool {
    if (addr.is_sin()) {
        return addr.sin.sin_addr.s_addr == 0;
    }
    assert(addr.is_sin6());
    const raw = @ptrCast([*]const u8, &addr.sin6.sin6_addr);
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        if (raw[i] != 0)
            return false;
    }
    return true;
}

pub fn request_udp_associate(
    fdobj: *EvLoop.Fd,
    proxy_addr: *const cc.SockAddr,
    client_udp_addr: *const cc.SockAddr,
    out_relay: *cc.SockAddr,
) ?cc.ConstStr {

    var req: [4 + (1 + 16 + 2)]u8 = undefined;
    req[0] = VER;
    req[1] = CMD_UDP_ASSOCIATE;
    req[2] = 0x00;

    const n = encode_atyp_addr_port(req[3..], client_udp_addr) orelse return "socks5 encode addr failed";
    g.evloop.write(fdobj, req[0 .. 3 + n]) orelse return "socks5 write (udp associate) failed";

    var head: [4]u8 = undefined;
    g.evloop.read(fdobj, &head) catch return "socks5 read (udp associate head) failed";

    if (head[0] != VER)
        return "socks5 invalid version";
    if (head[2] != 0x00)
        return "socks5 invalid RSV";
    if (head[1] != 0x00)
        return "socks5 udp associate rejected";

    const atyp = head[3];

    var ip: cc.IpStrBuf = undefined;
    var port: u16 = undefined;

    switch (atyp) {
        ATYP_IPV4 => {
            var raw: [4]u8 = undefined;
            var raw_port: [2]u8 = undefined;
            g.evloop.read(fdobj, &raw) catch return "socks5 read (udp relay ipv4) failed";
            g.evloop.read(fdobj, &raw_port) catch return "socks5 read (udp relay port) failed";
            const sin = &out_relay.sin;
            @memset(std.mem.asBytes(out_relay), 0, @sizeOf(cc.SockAddr));
            sin.sin_family = c.AF_INET;
            @memcpy(@ptrCast([*]u8, &sin.sin_addr), @ptrCast([*]const u8, &raw), 4);
            @memcpy(@ptrCast([*]u8, &sin.sin_port), @ptrCast([*]const u8, &raw_port), 2);
            out_relay.to_text(&ip, &port);
        },
        ATYP_IPV6 => {
            var raw: [16]u8 = undefined;
            var raw_port: [2]u8 = undefined;
            g.evloop.read(fdobj, &raw) catch return "socks5 read (udp relay ipv6) failed";
            g.evloop.read(fdobj, &raw_port) catch return "socks5 read (udp relay port) failed";
            const sin6 = &out_relay.sin6;
            @memset(std.mem.asBytes(out_relay), 0, @sizeOf(cc.SockAddr));
            sin6.sin6_family = c.AF_INET6;
            @memcpy(@ptrCast([*]u8, &sin6.sin6_addr), @ptrCast([*]const u8, &raw), 16);
            @memcpy(@ptrCast([*]u8, &sin6.sin6_port), @ptrCast([*]const u8, &raw_port), 2);
            out_relay.to_text(&ip, &port);
        },
        else => return "socks5 invalid udp relay ATYP",
    }

    if (is_unspecified_addr(out_relay)) {
        const relay_port = if (out_relay.is_sin()) out_relay.sin.sin_port else out_relay.sin6.sin6_port;
        out_relay.* = proxy_addr.*;
        if (out_relay.is_sin())
            out_relay.sin.sin_port = relay_port
        else
            out_relay.sin6.sin6_port = relay_port;
    }

    return null;
}

pub fn build_udp_datagram_prefix(out: []u8, target: *const cc.SockAddr) ?usize {
    if (out.len < UDP_OVERHEAD_MAX)
        return null;

    out[0] = 0;
    out[1] = 0;
    out[2] = 0; // FRAG

    const n = encode_atyp_addr_port(out[3..], target) orelse return null;
    return 3 + n;
}

pub fn decode_udp_datagram_inplace(buf: []u8, in_len: usize) ?usize {
    if (in_len < 4)
        return null;
    if (buf[0] != 0 or buf[1] != 0)
        return null;
    if (buf[2] != 0)
        return null; // FRAG not supported

    const atyp = buf[3];
    var off: usize = 4;

    switch (atyp) {
        ATYP_IPV4 => off += 4,
        ATYP_IPV6 => off += 16,
        0x03 => {
            if (off >= in_len)
                return null;
            const n = buf[off];
            off += 1 + n;
        },
        else => return null,
    }

    off += 2; // port

    if (off > in_len)
        return null;

    const payload_len = in_len - off;
    var i: usize = 0;
    while (i < payload_len) : (i += 1)
        buf[i] = buf[off + i];
    return payload_len;
}
