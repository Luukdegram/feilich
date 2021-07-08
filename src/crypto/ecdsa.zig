const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

const Sha521 = crypto.hash.sha2.Sha512;
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
        /// Private key component.
        d: Curve.Fe,

        /// Public key component x-coordinate.
        x: Curve.Fe,
        /// Public key component y-coordinate.
        y: Curve.Fe,

        /// Creates a new key pair using a provided seed or else
        /// generates a new seed and uses that instead.
        pub fn init(maybe_seed: ?[seed_length]u8) !KeyPair {
            const seed = maybe_seed orelse blk: {
                var random_seed: [seed_length]u8 = undefined;
                crypto.random.bytes(&random_seed);
                break :blk random_seed;
            };

            var pair: KeyPair = undefined;
            pair.d = Curve.Fe.fromBytes(seed, .Big);
            // TODO: Verify 'secret_key' does not surpass 'N' (basepoint.z)

            const q = try Curve.basePoint.mul(seed, .Big);
            pair.x = q.x;
            pair.y = q.y;
            return pair;
        }
    };

    /// Represents the signature of a message, that was signed using the private key
    /// of ECDSA using the P256-curve.
    pub const Signature = struct {
        /// The r-component of a signature.
        r: Curve.Fe,
        /// The s-component of a signature.
        s: Curve.Fe,
    };

    // /// Generates a public key using a given `secret_key`.
    //    pub fn recoverPublicKey(secret_key: [secret_length]u8) ![public_length]u8 {
    //        const q = try Curve.basePoint.mul(secret_key, .Big);
    //        return q.toCompressedSec1();
    //    }

    /// Signs a message, using the public key of the given `key_pair`.
    pub fn sign(key_pair: KeyPair, msg: []const u8) !Signature {
        const entropy = blk: {
            var buf: [seed_length]u8 = undefined;
            crypto.random.bytes(&buf);
            break :blk buf;
        };

        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(msg, &digest, .{});

        var md = Sha521.init(.{});
        md.update(&key_pair.d.toBytes(.Big));
        md.update(&entropy);
        md.update(&digest);

        var key: [Sha521.digest_length]u8 = undefined;
        md.final(&key);

        var k: Curve.scalar.CompressedScalar = undefined;
        var k_inverse: Curve.Fe = undefined;
        var r: Curve.Fe = undefined;

        while (true) {
            while (true) {
                k = Curve.scalar.random(.Big);

                k_inverse = k.invert();

                r = (try Curve.basePoint.mul(k)).x;
                if (!r.isZero()) {
                    break;
                }
            }

            const e = Curve.scalar.Scalar.fromBytes(key[0..32], .Big);
            var s = key_pair.d.mul(r);
            s = s.add(e);
            s = s.mul(k_inverse);
            if (!s.isZero()) {
                break;
            }
        }

        return Signature{
            .r = r,
            .s = s,
        };
    }
};
