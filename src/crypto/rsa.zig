const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const bigInt = std.math.big.int;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub const Rsa = struct {
    pub const Pss = _Pss;
};

const _Pss = struct {
    salt_length: usize,
    hash: Sha256,

    const Error = error{
        MessageTooLong,
        Encoding,
    };

    const Key = struct {
        modulus: []const usize,
        exponent: []const usize,
    };

    pub const PublicKey = Key;
    pub const PrivateKey = Key;

    /// Verifies a rsa pss signature
    pub fn verify(gpa: *Allocator, pub_key: Key, message: []const u8, signature: []const u8) !bool {
        const modulus = bigInt.Const{ .limbs = pub_key.modulus, .positive = true };
        const exponent = bigInt.Const{ .limbs = pub_key.exponent, .positive = true };

        if (modulus.bitCountAbs() != (signature.len + 7) / 8) return false;

        const limb_len = std.math.divCeil(usize, signature.len, @sizeOf(usize)) catch unreachable;
        const mutable: bigInt.Mutable = .{
            .limbs = try gpa.alloc(usize, limb_len),
            .positive = true,
            .len = limb_len,
        };
        // we copy the bytes and reverse each individual byte,
        // therefore ptrcast to a many-ptr of T u8.
        mem.copy(u8, @ptrCast([*]u8, mutable.limbs.ptr), signature);
        mem.reverse(u8, @ptrCast([*]u8, mutable.limbs.ptr));
        var managed = mutable.toManaged(gpa);
        defer managed.deinit();
    }
};
