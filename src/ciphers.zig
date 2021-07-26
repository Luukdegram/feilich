//! Contains imlementations of cipher suites, required (or supported)
//! for TLS 1.3
//! All implementations are done, with 'streaming' support, required
//! to be able to read in parts from a connection as users may not always
//! provide a buffer large enough that entails the entire payload.

const std = @import("std");
const tls = @import("tls.zig");
const mem = std.mem;
const crypto = std.crypto;
const modes = crypto.core.modes;
const Ghash = crypto.onetimeauth.Ghash;

fn ReturnType(comptime T: type) type {
    return @typeInfo(T).Fn.return_type.?;
}

pub const Aes128 = struct {
    ctx: ReturnType(@TypeOf(StdAes128.initEnc)),
    mac: crypto.onetimeauth.Ghash,
    t: u128,
    j: u128,

    const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
    const StdAes128 = crypto.core.aes.Aes128;

    pub const suite: tls.CipherSuite = .tls_aes_128_gcm_sha256;
    pub const tag_length = Aes128Gcm.tag_length;
    pub const nonce_length = Aes128Gcm.nonce_length;
    pub const key_length = Aes128Gcm.key_length;

    pub fn init(key: [key_length]u8, iv: [nonce_length]u8, sequence: u64, ad: []const u8) Aes128 {
        const ctx = StdAes128.initEnc(key);
        var h: [16]u8 = undefined;
        ctx.encrypt(&h, &[_]u8{0} ** 16);

        var iv_copy = iv;
        xorIv(&iv_copy, sequence);

        var t: [16]u8 = undefined;
        var j: [16]u8 = undefined;
        mem.copy(u8, j[0..nonce_length], &iv);
        mem.writeIntBig(u32, j[nonce_length..][0..4], 1);
        ctx.encrypt(&t, &j);

        var mac = Ghash.init(&h);
        mac.update(ad);
        mac.pad();

        mem.writeIntBig(u32, j[nonce_length..][0..4], 2);
        return .{
            .ctx = ctx,
            .mac = mac,
            .t = mem.readIntBig(u128, &t),
            .j = mem.readIntBig(u128, &j),
        };
    }

    /// Decrypts a partial message, writing the decrypted data to `out`.
    /// Also writes the read length to `idx`.
    /// NOTE: This does not validate the data.
    /// Ensure all data is correct by calling `verify` once all data is received.
    pub fn decryptPartial(self: *Aes128, out: []u8, data: []const u8, idx: *usize) void {
        self.mac.update(data);
        self.mac.pad();

        // var j: [16]u8 = undefined;
        // mem.writeIntBig(u128, &j, self.j);
        ctr(@TypeOf(self.ctx), self.ctx, out, data, &self.j, idx, .Big);
    }

    /// Verifies that all decrypted data til this point was valid.
    /// NOTE: Usage of this instance is illegal behavior after calling verify
    pub fn verify(self: *Aes128, auth_tag: [tag_length]u8, message_length: usize) !void {
        defer self.deinit();

        var final_block: [16]u8 = undefined;
        mem.writeIntBig(u64, final_block[0..8], 5 * 8); // RecordHeader is always 5 bytes.
        mem.writeIntBig(u64, final_block[8..16], message_length * 8); // message length we have decrypted til this point.
        self.mac.update(&final_block);
        var computed_tag: [Ghash.mac_length]u8 = undefined;
        self.mac.final(&computed_tag);
        var t: [16]u8 = undefined;
        mem.writeIntBig(u128, &t, self.t);
        for (t) |x, i| {
            computed_tag[i] ^= x;
        }

        var acc: u8 = 0;
        for (computed_tag) |_, i| {
            acc |= (computed_tag[i] ^ auth_tag[i]);
        }
        if (acc != 0) {
            return error.AuthenticationFailed;
        }
    }

    /// Sets the instance of `Aes128` to undefined, to prevent usage after finishing.
    pub fn deinit(self: *Aes128) void {
        self.* = undefined;
    }

    /// xor's the sequence with a key_iv.
    fn xorIv(iv: *[nonce_length]u8, sequence: u64) void {
        var i: u5 = 0;
        while (i < 8) : (i += 1) {
            iv[nonce_length - 1 - i] ^= @intCast(u8, (sequence >> (i *% 8)) & 0xFF);
        }
    }
};

/// Counter mode.
///
/// This mode creates a key stream by encrypting an incrementing counter using a block cipher, and adding it to the source material.
///
/// Important: the counter mode doesn't provide authenticated encryption: the ciphertext can be trivially modified without this being detected.
/// As a result, applications should generally never use it directly, but only in a construction that includes a MAC.
///
/// NOTE: Original at: https://github.com/alexnask/iguanaTLS/blob/master/src/crypto.zig#L159
pub fn ctr(
    comptime BlockCipher: anytype,
    block_cipher: BlockCipher,
    dst: []u8,
    src: []const u8,
    counterInt: *u128,
    idx: *usize,
    endian: std.builtin.Endian,
) void {
    std.debug.assert(dst.len >= src.len);
    const block_length = BlockCipher.block_length;
    var cur_idx: usize = 0;

    const offset = idx.* % block_length;
    if (offset != 0) {
        const part_len = std.math.min(block_length - offset, src.len);

        var counter: [BlockCipher.block_length]u8 = undefined;
        mem.writeInt(u128, &counter, counterInt.*, endian);
        var pad = [_]u8{0} ** block_length;
        mem.copy(u8, pad[offset..], src[0..part_len]);
        block_cipher.xor(&pad, &pad, counter);
        mem.copy(u8, dst[0..part_len], pad[offset..][0..part_len]);
        cur_idx += part_len;
        idx.* += part_len;
        if (idx.* % block_length == 0)
            counterInt.* += 1;
    }

    const start_idx = cur_idx;
    const remaining = src.len - cur_idx;
    cur_idx = 0;

    const parallel_count = BlockCipher.block.parallel.optimal_parallel_blocks;
    const wide_block_length = parallel_count * 16;
    if (remaining >= wide_block_length) {
        var counters: [parallel_count * 16]u8 = undefined;
        while (cur_idx + wide_block_length <= remaining) : (cur_idx += wide_block_length) {
            comptime var j = 0;
            inline while (j < parallel_count) : (j += 1) {
                mem.writeInt(u128, counters[j * 16 .. j * 16 + 16], counterInt.*, endian);
                counterInt.* +%= 1;
            }
            block_cipher.xorWide(parallel_count, dst[start_idx..][cur_idx .. cur_idx + wide_block_length][0..wide_block_length], src[start_idx..][cur_idx .. cur_idx + wide_block_length][0..wide_block_length], counters);
            idx.* += wide_block_length;
        }
    }
    while (cur_idx + block_length <= remaining) : (cur_idx += block_length) {
        var counter: [BlockCipher.block_length]u8 = undefined;
        mem.writeInt(u128, &counter, counterInt.*, endian);
        counterInt.* +%= 1;
        block_cipher.xor(dst[start_idx..][cur_idx .. cur_idx + block_length][0..block_length], src[start_idx..][cur_idx .. cur_idx + block_length][0..block_length], counter);
        idx.* += block_length;
    }
    if (cur_idx < remaining) {
        std.debug.assert(idx.* % block_length == 0);
        var counter: [BlockCipher.block_length]u8 = undefined;
        mem.writeInt(u128, &counter, counterInt.*, endian);

        var pad = [_]u8{0} ** block_length;
        mem.copy(u8, &pad, src[start_idx..][cur_idx..]);
        block_cipher.xor(&pad, &pad, counter);
        mem.copy(u8, dst[start_idx..][cur_idx..], pad[0 .. remaining - cur_idx]);

        idx.* += remaining - cur_idx;
        if (idx.* % block_length == 0)
            counterInt.* +%= 1;
    }
}

test "Aes128 - single message" {
    const key: [Aes128.key_length]u8 = [_]u8{0x69} ** Aes128.key_length;
    const nonce: [Aes128.nonce_length]u8 = [_]u8{0x42} ** Aes128.nonce_length;
    const m = "Test with message only";
    const record: tls.Record = .{ .record_type = .application_data, .len = m.len };
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aes128.tag_length]u8 = undefined;

    crypto.aead.aes_gcm.Aes128Gcm.encrypt(&c, &tag, m, &record.toBytes(), nonce, key);
    var state = Aes128.init(key, nonce, 0, &record.toBytes());
    var idx: usize = 0;
    state.decryptPartial(&m2, &c, &idx);
    try state.verify(tag, m.len);
    try std.testing.expectEqualSlices(u8, m[0..], m2[0..]);
    try std.testing.expectEqual(m.len, idx);
}

test "Aes128 - multiple messages" {
    const key: [Aes128.key_length]u8 = [_]u8{0x69} ** Aes128.key_length;
    const nonce: [Aes128.nonce_length]u8 = [_]u8{0x42} ** Aes128.nonce_length;
    const m = "Test with message only";
    const half_length = m.len / 2;
    var idx: usize = 0;
    const record: tls.Record = .{ .record_type = .application_data, .len = m.len };
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aes128.tag_length]u8 = undefined;

    crypto.aead.aes_gcm.Aes128Gcm.encrypt(&c, &tag, m, &record.toBytes(), nonce, key);
    var state = Aes128.init(key, nonce, 0, &record.toBytes());
    state.decryptPartial(m2[0..half_length], c[0..half_length], &idx);
    try std.testing.expectEqual(half_length, idx);
    state.decryptPartial(m2[half_length..], c[half_length..], &idx);
    try std.testing.expectEqual(m.len, idx);
    // try state.verify(tag, m.len);
    try std.testing.expectEqualSlices(u8, m[0..], m2[0..]);
}
