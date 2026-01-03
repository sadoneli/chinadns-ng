const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const log = @import("log.zig");
const Tag = @import("tag.zig").Tag;
const testing = std.testing;

/// {"a.txt", "b.txt", null}
pub const filenames_t = [*:null]?cc.ConstStr;

pub inline fn init(tag_to_filenames: *const [c.TAG__MAX + 1]?filenames_t) void {
    return c.dnl_init(tag_to_filenames, g.flags.gfwlist_first);
}

pub inline fn is_empty() bool {
    return c.dnl_is_empty();
}

pub inline fn get_tag(name: [*]const u8, namelen: c_int) Tag {
    return if (namelen > 0 and !is_empty())
        Tag.from_int(c.dnl_get_tag(name, namelen, g.default_tag.int()))
    else
        g.default_tag;
}

fn readToken(reader: anytype, buf_z: []u8) !?usize {
    var i: usize = 0;

    // skip leading whitespace
    while (true) {
        const b = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return err,
        };
        if (!std.ascii.isWhitespace(b)) {
            buf_z[0] = b;
            i = 1;
            break;
        }
    }

    // read token bytes
    while (true) {
        const b = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (std.ascii.isWhitespace(b)) break;

        if (i + 1 < buf_z.len) {
            buf_z[i] = b;
            i += 1;
            continue;
        }

        // token too long: consume until whitespace/end, then mark as empty/invalid
        while (true) {
            const b2 = reader.readByte() catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (std.ascii.isWhitespace(b2)) break;
        }
        buf_z[0] = 0;
        return 0;
    }

    buf_z[i] = 0;
    return i;
}

/// Called from `src/dnl.c` when a domain list filename ends with `.gz`.
/// Decompresses the gzip stream and feeds tokens into dnl's internal allocator.
pub export fn dnl_load_list_gz(tag: u8, fname_z: [*:0]const u8, p_addr0: *u32, p_count: *u32) bool {
    const path = std.mem.span(fname_z);
    var file = std.fs.cwd().openFile(path, .{ .mode = .read_only }) catch |err| {
        log.warn(@src(), "failed to open gzip dnl '%.*s': %s", .{ @intCast(c_int, path.len), path.ptr, @errorName(err).ptr });
        return false;
    };
    defer file.close();

    var br = std.io.bufferedReader(file.reader());
    var gz = std.compress.gzip.gzipStream(g.allocator, br.reader()) catch |err| {
        log.warn(@src(), "failed to init gzip stream '%.*s': %s", .{ @intCast(c_int, path.len), path.ptr, @errorName(err).ptr });
        return false;
    };
    defer gz.deinit();

    var ubr = std.io.bufferedReader(gz.reader());
    var reader = ubr.reader();

    var buf: [c.DNS_NAME_MAXLEN + 1]u8 = undefined;
    var addr0: u32 = 0;
    var count: u32 = 0;

    while (true) {
        const tok_len = readToken(reader, buf[0..]) catch |err| {
            log.warn(@src(), "failed to read gzip dnl '%.*s': %s", .{ @intCast(c_int, path.len), path.ptr, @errorName(err).ptr });
            break;
        } orelse break;

        if (tok_len == 0) continue;

        const p = c.dnl_check_name(@ptrCast([*c]const u8, &buf[0]));
        if (p != null) {
            const nameaddr = c.dnl_add_name(p, tag);
            if (count == 0) addr0 = nameaddr;
            count += 1;
        }
    }

    p_addr0.* = addr0;
    p_count.* = count;
    return true;
}
