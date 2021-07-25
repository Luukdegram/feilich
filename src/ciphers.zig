//! Contains imlementations of cipher suites, required (or supported)
//! for TLS 1.3
//! All implementations are done, with 'streaming' support, required
//! to be able to read in parts from a connection as users may not always
//! provide a buffer large enough that entails the entire payload.

const std = @import("std");
const tls = @import("tls.zig");
const crypto = std.crypto;
const mem = std.mem;
const Ghash = crypto.onetimeauth.Ghash;

pub const Aes128 = struct {
    ctx: ReturnType(@TypeOf(StdAes128.initEnc)),
    mac: crypto.onetimeauth.Ghash,

    const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
    const StdAes128 = crypto.core.aes.Aes128;

    pub const suite: tls.CipherSuite = .tls_aes_128_gcm_sha256;
    pub const tag_length = Aes128Gcm.tag_length;
    pub const nonce_length = Aes128Gcm.nonce_length;
    pub const key_length = Aes128Gcm.key_length;

    fn init(key: [key_length]u8, iv: [nonce_length]u8, sequence: u64, ad: []const u8) Aes128 {
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
        };
    }

    fn xorIv(iv: [nonce_length]u8, sequence: u64) void {
        var i: u5 = 0;
        while (i < 8) : (i += 1) {
            iv[nonce_length - 1 - i] ^= ((sequence >> (i * 8)) & 0xFF);
        }
    }
};
