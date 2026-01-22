const std = @import("std");
const g = @import("g.zig");
const assert = std.debug.assert;

const FrameAlloc = struct {
    frame_ptr: [*]u8,
    base: [*]u8,
    len: usize,
    alignment: u29,
    terminated: bool = false,
    next: ?*FrameAlloc = null,
};

/// create and start a new coroutine
pub fn start(comptime func: anytype, args: anytype) void {
    const Frame = @Frame(func);
    const frame_align = @alignOf(Frame);
    const frame_size = @frameSize(func);
    const alloc_len = frame_size + (frame_align - 1);

    const base = g.allocator.alignedAlloc(u8, frame_align, alloc_len) catch unreachable;
    const base_addr = @ptrToInt(base.ptr);
    const frame_addr = std.mem.alignForward(base_addr, frame_align);
    const frame_ptr = @intToPtr([*]u8, frame_addr);

    const fa = g.allocator.create(FrameAlloc) catch unreachable;
    fa.* = .{
        .frame_ptr = frame_ptr,
        .base = base.ptr,
        .len = alloc_len,
        .alignment = @intCast(u29, frame_align),
        .terminated = false,
        .next = _frames,
    };
    _frames = fa;

    const FrameBuf = []align(frame_align) u8;
    const frame_buf = @ptrCast(FrameBuf, frame_ptr[0..frame_size]);
    _ = @asyncCall(frame_buf, {}, func, args);

    check_terminated();
}

/// if the coroutine is at the last suspend point, its memory will be freed after resume
pub fn do_resume(frame: anyframe) void {
    resume frame;
    check_terminated();
}

/// called when the coroutine is about to terminate: `defer co.terminate(@frame(), frame_size)`
pub fn terminate(top_frame: anyframe, frame_size: usize) void {
    _ = frame_size;
    const frame_ptr = @intToPtr([*]u8, @ptrToInt(top_frame));
    var it = _frames;
    while (it) |fa| : (it = fa.next) {
        if (fa.frame_ptr == frame_ptr) {
            fa.terminated = true;
            break;
        }
    }
}

// ========================================================================

const SIZE = 64;
const ALIGN = @alignOf(std.c.max_align_t);
var _data: [SIZE]u8 align(ALIGN) = undefined;

/// pass data to the target coroutine on resume
pub fn data(comptime T: type) *T {
    comptime assert(@sizeOf(T) <= SIZE);
    comptime assert(@alignOf(T) <= ALIGN);
    return std.mem.bytesAsValue(T, _data[0..@sizeOf(T)]);
}

// ========================================================================

var _frames: ?*FrameAlloc = null;

/// free the memory of a terminated coroutine
fn check_terminated() void {
    var prev: ?*FrameAlloc = null;
    var cur = _frames;
    while (cur) |fa| {
        const next = fa.next;
        if (fa.terminated) {
            if (prev) |p|
                p.next = next
            else
                _frames = next;

            g.allocator.rawFree(fa.base[0..fa.len], fa.alignment, @returnAddress());
            g.allocator.destroy(fa);
        } else {
            prev = fa;
        }
        cur = next;
    }
}
