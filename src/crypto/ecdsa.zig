const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

const Sha256 = crypto.hash.sha2.Sha256;

/// Elliptic Curve Digital Signature Algorithm (ECDSA) as specified
/// in [FIPS 186-4] (Digital Signature Standard).
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
///
/// Also known as secp256r1 under SEC2.
/// https://www.secg.org/sec2-v2.pdf (page 9)
///
/// NOTE: This implementation uses the P256 Curve and is not interchangable.
pub const Ecdsa = struct {
    /// The underlying elliptic curve.
    pub const Curve = crypto.ecc.P256;
    /// Length in bytes of a secret key.
    pub const secret_length = 32;
    /// The length in bytes of a public key.
    pub const public_length = 32;
    /// The length in bytes for the seed.
    pub const seed_length = 32;

    pub const KeyPair = struct {
        /// Public key component.
        public_key: [public_length]u8,
        /// Private key component.
        private_key: [secret_length]u8,

        /// Creates a new key pair using a provided seed or else
        /// generates a seed.
        pub fn init(maybe_seed: ?[seed_length]u8) !KeyPair {
            const seed = maybe_seed orelse blk: {
                var random_seed: [seed_length]u8 = undefined;
                crypto.random.bytes(&random_seed);
                break :blk random_seed;
            };

            var pair: KeyPair = undefined;
            mem.copy(u8, &pair.secret_key, &seed);
            pair.public_key = try recoverPublicKey(seed);
            return pair;
        }
    };

    pub fn recoverPublicKey(secret_key: [secret_length]u8) ![public_length]u8 {
        // const res = try Curve.basePoint.fromSec1
    }

    /// Signs a message, using the public key of the given `key_pair`.
    pub fn sign(key_pair: KeyPair, msg: []const u8) ![]const u8 {
        // const k = crypto.random.int(usize);

        const entropy = blk: {
            var buf: [seed_length]u8 = undefined;
            crypto.random.bytes(&buf);
            break :blk buf;
        };

        var out: [Sha256.digest_length]u8 = undefined;
        const hash = Sha256.hash(msg, &out, .{});

        const N = Curve.basePoint.z.field_order;
        const H = Curve.scalar.Scalar.fromBytes(hash, .Little);
        const k = Curve.scalar.random();

        // const R = Curve.basePoint.random

        const R = Curve.random();

        //       var hash = Sha256.init(.{});
        //       hash.update(&key_pair.private_key);
        //       hash.update(&entropy);
        //       hash.update(hash);

        //       var out: [public_length]u8 = undefined;
        //       const key = hash.final(&out);

        //       const N = Curve.basePoint.z.field_order;
        // var k: usize = undefind;

    }
};
