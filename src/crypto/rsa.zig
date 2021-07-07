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
        return (self.bitCount() + 7) / 8;
    }

    pub fn bitCount(self: PublicKey) usize {
        return self.modulus.bitCountAbs();
    }
};

pub const PrivateKey = struct {
    public_key: PublicKey,
    exponent: big_int.Const,
    primes: []big_int.Const,

    pre_computed: Precomputed,

    const Precomputed = struct {};

    pub fn size(self: PrivateKey) usize {
        return self.public_key.size();
    }

    pub fn bitCount(self: PrivateKey) usize {
        return self.public_key.bitCount();
    }

    fn decryptAndCheck(self: PrivateKey, message: big_int.Managed) !big_int.Managed {
        const decrypted = try self.decrypt(message);
        _ = decrypted;
    }

    fn decrypt(self: PrivateKey, message: big_int.Managed) !big_int.Managed {
        if (self.public_key.modulus[0] == 0) return error.EmptyKey;
        _ = message;
    }
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
    _ = primes;

    // prime_calc: while (true) {
    //     var todo = bits;
    //     _ = todo;

    //     for (primes) |*prime| {
    //         _ = prime;
    //         // prime.* = std.math.prime
    //     }
    // }
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
    /// Memory is owned by the
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

        const buf = @ptrCast([*]u8, checked.limbs.ptr)[0..private_key.size()];
        mem.reverse(u8, buf);

        return try gpa.resize(buf.ptr[0 .. checked.len() * @sizeOf(usize)], private_key.size());
    }

    // fn emsaPssEncode(hashed: []const u8, em_bit_count: usize, salt: []const u8) ![]const u8 {}

    /// Verifies a PSS signature.
    ///
    /// Digest must be the result of hashing the input message using Sha256.
    pub fn verify(gpa: *Allocator, pub_key: PublicKey, digest: []const u8, signature: []const u8) !bool {
        _ = digest;
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
        next_delta: while (delta < 1 << 20) {
            const m = mod + delta;
            for (small_primes) |small_p| {
                if (m % small_p == 0 and (bits > 6 or m != small_p)) {
                    delta = 0;
                    continue :next_delta;
                }

                if (delta > 0) {
                    big_mod.set(delta);
                    prime.add(prime.toConst(), big_mod.toConst());
                }
                break;
            }

            if (isProbablyPrime(prime, 20) and prime.bitCountAbs() == bits) {
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

    if (r_a % 3 == 0 or r_a % 5 == 0 or r_a % 7 == 0 or r_a % 11 == 0 or r_a % 13 == 0 or
        r_a % 17 == 0 or r_a % 19 == 0 or r_a % 23 == 0 or r_a % 37 == 0 or r_b % 29 == 0 or
        r_b % 31 == 0 or r_b % 41 == 0 or r_b % 43 == 0 or r_b % 47 == 0 or r_b % 53 == 0)
    {
        return false;
    }

    return probablyPrimeMillerRabin(n + 1, true);
}

/// Reports whether `n` passes `reps` rounds of the
/// Miller-Rabin primality test, using pseudo-randomly chosen bases.
/// If force2 is `true`, one of the rounds is forced to use base 2.
///
/// Source: Handbook of Applied Cryptography, p. 139, Algorithm 4.24.
fn probablyPrimeMillerRabin(num: *big_int.Managed, reps: usize, force2: bool) bool {
    _ = force2;
    _ = reps;
    var nm1 = try big_int.Managed.init(num.allocator);
    defer nm1.deinit();

    try nm1.sub(num.toConst(), constants.one);
    // determine q, k such that nm1 = q << k
    const k = trailingZeroBits(nm1);
    var q = try big_int.Managed.init(num.allocator);
    defer q.deinit();
    try q.shiftRight(nm1, k);

    var nm3 = try big_int.Managed.init(num.allocator);
    defer nm3.deinit();
    try nm3.sub(nm1, constants.two);

    // var random = std.rand.DefaultPrng.init(num.limbs[0]);

    var x = try big_int.Managed.init(num.allocator);
    defer x.deinit();
    var y = try big_int.Managed.init(num.allocator);
    defer y.deinit();
    var quotient = try big_int.Managed.init(num.allocator);
    defer quotient.deinit();

    // next_random: {
    //     var i: usize = 0;
    //     while (i < reps) : (i += 1) {
    //         if (i == reps - 1 and force2) {
    //             x.copy(nat_two);
    //         } else {
    //             random.random.bytes(&x.limbs);
    //             x.add(x.toConst(), nat_two);
    //         }
    //     }
    // }
}

fn expNN(z: *big_int.Managed, x: big_int.Managed, y: big_int.Managed, m: big_int.Managed) !void {
    if (m.len() == 1 and m.limbs[0] == 1) {
        z.set(@as(usize, 0));
        return;
    }

    if (y.len() == 0) {
        z.set(@as(usize, 1));
        return;
    }

    if (y.len() == 1 and y.limbs[0] == 1 and m.len() != 0) {
        var r = try big_int.Managed.init(z.allocator);
        defer r.deinit();
        z.divFloor(&r, x.toConst(), m.toConst());
        return;
    }

    z.copy(x.toConst());

    if (x.toConst().orderAbs(constants.one) == .gt and y.len() > 1 and m.len() > 0) {
        if (m.limbs[0] & 1 == 1) {}
    }

    var v = y.limbs[y.len() - 1];
    const shift = leadingZeros(v) + 1;
    v <<= shift;

    var q = try big_int.Managed.init(z.allocator);
    defer q.deinit();

    const mask = 1 << (@bitSizeOf(usize) - 1);
    const w = @bitSizeOf(usize) - shift;

    var zz = try big_int.Managed.init(z.allocator);
    defer zz.deinit();
    var r = try big_int.Managed.init(z.allocator);
    defer r.deinit();

    {
        var i: usize = 0;
        while (i < w) : (i += 1) {
            zz.sqr(z.toConst());

            // swap zz and z
            for (zz.limbs) |*limb, i| {
                std.mem.swap(usize, limb, &z.limbs[i]);
            }

            if (v & mask != 0) {
                zz.mul(zz.toConst(), x.toConst());
            }
        }
    }
}

fn trailingZeroBits(value: big_int.Managed) usize {
    if (value.len() == 0) return 0;

    var i: usize = 0;
    while (value.limbs[i] == 0) {
        i += 1;
    }

    return i * @bitSizeOf(usize) + trailingZeros(value.limbs[i]);
}

fn trailingZeros(value: usize) usize {
    return switch (@bitSizeOf(value)) {
        32 => trailingZeros32(@intCast(u32, value)),
        64 => trailingZeros64(@intCast(u64, value)),
        else => unreachable,
    };
}

fn leadingZeros(value: usize) usize {
    return @bitSizeOf(usize) - switch (@bitSizeOf(value)) {
        32 => leadingZeros32(@intCast(u32, value)),
        64 => leadingZeros64(@intCast(u64, value)),
        else => unreachable,
    };
}

fn trailingZeros32(value: u32) usize {
    if (value == 0) return 32;
    const de_bruijn_32: u32 = 0x077CB531;
    const de_bruijn_32_tab = [32]u8{
        0,  1,  28, 2,  29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4,  8,
        31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6,  11, 5,  10, 9,
    };
    const temp = @intCast(u32, @intCast(i33, value) & -@intCast(i33, value));
    return de_bruijn_32_tab[temp *% de_bruijn_32 >> (32 - 5)];
}
fn trailingZeros64(value: u64) usize {
    if (value == 0) return 64;
    const de_bruijn_64 = 0x03f79d71b4ca8b09;
    const de_bruijn_64_tab = [64]u8{
        0,  1,  56, 2,  57, 49, 28, 3,  61, 58, 42, 50, 38, 29, 17, 4,
        62, 47, 59, 36, 45, 43, 51, 22, 53, 39, 33, 30, 24, 18, 12, 5,
        63, 55, 48, 27, 60, 41, 37, 16, 46, 35, 44, 21, 52, 32, 23, 11,
        54, 26, 40, 15, 34, 20, 31, 10, 25, 14, 19, 9,  13, 8,  7,  6,
    };
    const temp = @intCast(u64, @intCast(i65, value) & -@intCast(i65, value));
    return de_bruijn_64_tab[temp *% de_bruijn_64 >> (64 - 6)];
}

fn leadingZeros32(value: u32) usize {
    var result: usize = 0;
    var copy = value;
    if (copy >= 1 << 16) {
        copy >>= 16;
        result = 16;
    }
    if (copy >= 1 << 8) {
        copy >>= 8;
        result += 8;
    }
    return result + len_8_tab[copy];
}

fn leadingZeros64(value: u64) usize {
    var result: usize = 0;
    var copy = value;
    if (copy >= 1 << 32) {
        copy >>= 32;
        result = 32;
    }
    if (copy >= 1 << 16) {
        copy >>= 16;
        result = 16;
    }
    if (copy >= 1 << 8) {
        copy >>= 8;
        result += 8;
    }
    return result + len_8_tab[copy];
}

const len_8_tab = [256]u8{
    0x00, 0x01, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
};

test "TrailingZeros" {
    var tabs: [256]usize = undefined;
    tabs[0] = 8;
    for (tabs) |*tab, i| {
        if (i == 0) continue;

        var x = i;
        var n: usize = 0;
        while (x & 1 == 0) {
            n += 1;
            x >>= 1;
        }
        tab.* = n;
    }

    for (tabs) |tab, i| {
        var k: usize = 0;
        while (k < 64 - 8) : (k += 1) {
            const x = i << @intCast(u6, k);
            const expected = tab + k;

            if (x <= 1 << 32 - 1) {
                var result = trailingZeros32(@intCast(u32, x));
                if (x == 0) {
                    try std.testing.expectEqual(@as(usize, 32), result);
                } else {
                    try std.testing.expectEqual(expected, result);
                }
            }

            if (x <= 1 << 64 - 1) {
                var result = trailingZeros64(x);
                if (x == 0) {
                    try std.testing.expectEqual(@as(usize, 64), result);
                } else {
                    try std.testing.expectEqual(expected, result);
                }
            }
        }
    }
}

const constants = struct {
    const one: BigInt = blk: {
        var buf: [1]usize = undefined;
        const tmp = big_int.Mutable.init(&buf, 1);
        break :blk tmp.toConst();
    };
    const two: BigInt = blk: {
        var buf: [1]usize = undefined;
        const tmp = big_int.Mutable.init(&buf, 2);
        break :blk tmp.toConst();
    };
    const five: BigInt = blk: {
        var buf: [1]usize = undefined;
        const tmp = big_int.Mutable.init(&buf, 5);
        break :blk tmp.toConst();
    };
    const ten: BigInt = blk: {
        var buf: [1]usize = undefined;
        const tmp = big_int.Mutable.init(&buf, 10);
        break :blk tmp.toConst();
    };
};
