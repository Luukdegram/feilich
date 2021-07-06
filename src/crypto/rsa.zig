const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const big_int = std.math.big.int;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const BigInt = big_int.Const;

pub const Rsa = struct {
    pub const Pss = _Pss;
};

pub const PublicKey = struct {
    modulus: big_int.Const,
    exponent: usize,

    pub fn size(self: PublicKey) usize {
        return (self.modulus.bitCountAbs() + 7) / 8;
    }
};

pub const PrivateKey = struct {
    public_key: PublicKey,
    exponent: big_int.Const,
    primes: []big_int.Const,

    pub fn size(self: PrivateKey) usize {
        return self.public_key.size();
    }

    pub fn bitCount(self: PrivateKey) usize {
        return self.public_key.modulus.bitCountAbs();
    }

    fn decryptAndCheck(self: PrivateKey, c: big_int.Managed) !big_int.Managed {}
};

/// Generates a multi-prime RSA keypair of the given of the given bit size
pub fn generateKeyPair(bits: usize) !PrivateKey {
    var private_key: PrivateKey = undefined;
    private_key.public_key.exponent = (1 << 16) + 1;

    if (bits < 64) {
        const prime_limit = @intToFloat(f64, @as(u64, 1) << bits / 2);
        // pi approximates the number of primes less than prime_limit
        var pi = prime_limit / (std.math.log(f64, prime_limit) - 1);
        // Generated primes start with 11 (in binary) so we can only
        // use a quarter of them.
        pi /= 4;
        // Use a factor of two to ensure that key generation
        // terminates within reasonable time.
        pi /= 2;
        if (pi <= @as(f64, 2)) {
            return error.TooFewPrimes;
        }
    }

    var primes: [2]big_int.Const = undefined;

    prime_calc: while (true) {
        var todo = bits;

        for (primes) |*prime| {
            // prime.* = std.math.prime
        }
    }
}

const _Pss = struct {
    salt_length: usize,
    hash: Sha256,

    const Error = error{
        MessageTooLong,
        Encoding,
    };

    /// Calculates the signature of digest using PSS.
    ///
    /// Digest must be the result of hashing the input message using Sha256.
    pub fn sign(gpa: *Allocator, private_key: PrivateKey, digest: []const u8) ![]const u8 {
        const salt_length = private_key.size() - 2 - Sha256.digest_length;
        const salt = try gpa.alloc(u8, salt_length);
        defer gpa.free(salt);
        std.crypto.random.bytes(salt);

        const em_bits = private_key.bitCount() - 1;
        const em = try emsaPssEncode(digest, em_bits, salt);

        const mutable: big_int.Mutable = .{
            .limbs = try gpa.alloc(usize, em.len),
            .positive = true,
            .len = em.len,
        };
        // we copy the bytes and reverse each individual byte,
        // therefore ptrcast to a many-ptr of T u8.
        mem.copy(u8, @ptrCast([*]u8, mutable.limbs.ptr), signature);
        mem.reverse(u8, @ptrCast([*]u8, mutable.limbs.ptr));
        var managed = mutable.toManaged(gpa);
        defer managed.deinit();

        const checked = try private_key.decryptAndCheck(managed);
        const s = gpa.alloc(u8, private_key.size());
    }

    fn emsaPssEncode(hashed: []const u8, em_bit_count: usize, salt: []const u8) ![]const u8 {}

    /// Verifies a PSS signature.
    ///
    /// Digest must be the result of hashing the input message using Sha256.
    pub fn verify(gpa: *Allocator, pub_key: PublicKey, digest: []const u8, signature: []const u8) !bool {
        if (pub_key.size() != signature.len) return false;

        const limb_len = std.math.divCeil(usize, signature.len, @sizeOf(usize)) catch unreachable;
        const mutable: big_int.Mutable = .{
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

/// Returns a number of the given bits size, such that the returned
/// value is prime with high probability.
///
/// Asserts `bits` is 2 or more.
fn calculatePrime(gpa: *Allocator, comptime bits: usize, random: *std.rand.Random) !BigInt {
    std.debug.assert(bits.len > 2);

    const b = blk: {
        var b = bits % 8;
        if (b == 0) b = 8;
        break :blk b;
    };

    var bytes: [@divFloor(bits + 7, 8)]u8 = undefined;
    var prime = try big_int.Managed.init(gpa);

    var big_mod = try big_int.Managed.initSet(gpa, 0);

    while (true) {
        random.bytes(&bytes);

        bytes[0] &= @intCast(u8, (1 << b) - 1);

        if (b >= 2) {
            bytes[0] |= 3 << (b - 2);
        } else {
            bytes[0] |= 1;
            bytes[1] |= 0x80;
        }

        bytes[bytes.len - 1] |= 1;

        const limb_len = std.math.divCeil(usize, bytes.len, @sizeOf(usize)) catch unreachable;
        prime.limbs = @ptrCast([]usize, bytes[0..limb_len]);

        mod(big_mod, small_primes_product);

        const mod = try big_mod.to(u64);

        var delta: u64 = 0;
        next_data: while (delta < 1 << 20) {
            const m = mod + delta;
            for (small_primes) |small_p| {
                if (m % small_p == 0 and (bits > 6 or m != small_p)) {
                    delta = 0;
                    continue :next_data;
                }

                if (delta > 0) {
                    big_mod.set(delta);
                    prime.add(prime.toConst(), big_mod.toConst());
                }
                break;
            }

            if (probablyPrime(prime, 20) and prime.bitCountAbs() == bits) {
                return prime.toConst();
            }
        }
    }
}

const small_primes_product: BigInt = blk: {
    const val: u64 = 16294579238595022365;
    var limbs_buf: [big_int.calcLimbLen(val)]usize = undefined;
    var product = big_int.Mutable.init(limbs_buf, val);
    break :blk product.toConst();
};

const small_primes = [_]u8{
    3, 5, 7, 11, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
};

fn mod(result: *big_int.Managed, other: BigInt) !void {
    var tmp = try big_int.Managed.init(result.allocator);
    defer tmp.deinit();

    try tmp.divTrunc(result, result.toConst(), other);
}

/// Checks if a given big integer, is probably a prime number.
/// A higher `n` will be more accurate but may take more time.
///
fn isProbablyPrime(prime: *big_int.Managed, n: usize) bool {
    if (!prime.isPositive() or prime.limbs[0] == 0) return false;

    const prime_bit_mask: u64 = 1 << 2 | 1 << 3 | 1 << 5 | 1 << 7 |
        1 << 11 | 1 << 13 | 1 << 17 | 1 << 19 | 1 << 23 | 1 << 29 | 1 << 31 |
        1 << 37 | 1 << 41 | 1 << 43 | 1 << 47 | 1 << 53 | 1 << 59 | 1 << 61;

    const w = prime.limbs[0];
    if (prime.len() == 1 and w < 64) {
        return prime_bit_mask & (1 << w) != 0;
    }

    if (prime.isEven()) return false;

    const primes_a = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 37;
    const primes_b = 29 * 31 * 41 * 43 * 47 * 53;

    var r_a: u32 = 0;
    var r_b: u32 = 0;

    switch (@bitSizeOf(usize)) {
        32 => {
            r_a = std.math.mod(u32, primes_a, try prime.to(u32));
            r_b = std.math.mod(u32, primes_b, try prime.to(u32));
        },
        64 => {
            const r = try std.math.mod(u64, (primes_a * primes_b) & std.math.maxInt(u64), try prime.to(u64));
            r_a = @intCast(u32, r) % primes_a;
            r_b = @intCast(u32, r) % primes_b;
        },
        else => unreachable,
    }
}
