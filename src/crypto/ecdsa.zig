//! Elliptic Curve Digital Signature Algorithm (ECDSA) as specified
//! in [FIPS 186-4] (Digital Signature Standard).
//! https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
//!
//! Also known as secp256r1 under SEC2.
//! https://www.secg.org/sec2-v2.pdf (page 9)
//!
//! NOTE: This implementation uses the P256 Curve and is not interchangable.

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

/// The underlying elliptic curve.
pub const Curve = crypto.ecc.P256;
/// The length in bytes for the seed.
pub const seed_length = 32;

const Scalar = Curve.scalar.Scalar;
const Sha256 = crypto.hash.sha2.Sha256;

pub const KeyPair = struct {
    /// Private key component.
    d: Scalar,
    /// Public key belonging to this KeyPair
    public_key: PublicKey,

    pub const PublicKey = struct {
        /// Public key component x-coordinate.
        x: Curve.Fe,
        /// Public key component y-coordinate.
        y: Curve.Fe,

        /// Verifies if the given public keys are equivalent.
        pub fn eql(self: PublicKey, other: PublicKey) bool {
            return self.x.equivalent(other.x) and
                self.y.equivalent(other.y);
        }
    };

    /// Creates a new key pair using a provided seed or else
    /// generates a new seed and uses that instead.
    pub fn init(maybe_seed: ?[seed_length]u8) !KeyPair {
        const seed = maybe_seed orelse blk: {
            var random_seed: [seed_length]u8 = undefined;
            crypto.random.bytes(&random_seed);
            break :blk random_seed;
        };

        const q = try Curve.basePoint.mul(seed, .Little);
        const affine = q.affineCoordinates();

        return KeyPair{
            .d = try Scalar.fromBytes(seed, .Little),
            .public_key = .{ .x = affine.x, .y = affine.y },
        };
    }

    /// Verifies the given keypairs are equal
    pub fn eql(self: KeyPair, other: KeyPair) bool {
        return self.public_key.eql(other) and self.d.equivalent(other.d);
    }
};

/// Represents the signature of a message, that was signed using the private key
/// of ECDSA using the P256-curve.
pub const Signature = struct {
    /// The r-component of a signature.
    r: [32]u8,
    /// The s-component of a signature.
    s: [32]u8,
};

/// Signs a message, using the public key of the given `key_pair`.
/// Uses Sha256 to create the digest for the input `msg`.
pub fn sign(key_pair: KeyPair, msg: []const u8) !Signature {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(msg, &digest, .{});
    const e = try Scalar.fromBytes(digest, .Little);

    var k: Scalar = undefined;
    var k_inverse: Scalar = undefined;
    var r: Curve.Fe = undefined;
    var s: Scalar = undefined;

    while (true) {
        while (true) {
            k = Scalar.random();

            k_inverse = k.invert();

            const q = try Curve.basePoint.mul(k.toBytes(), .Little);
            r = q.affineCoordinates().x;

            if (!r.isZero()) {
                break;
            }
        }

        const r_scalar = try Scalar.fromBytes(r.toBytes(.Little), .Little);
        s = key_pair.d.mul(r_scalar).add(e).mul(k_inverse);
        if (!s.isZero()) {
            break;
        }
    }

    return Signature{
        .r = try Curve.Fe.fromBytes(r.toBytes(.Little), .Little),
        .s = try Curve.Fe.fromBytes(s.toBytes(.Little), .Little),
    };
}

/// Verifies a signature of the hash using a given `public_key`
pub fn verify(public_key: KeyPair.PublicKey, hash: [Sha256.digest_length]u8, signature: Signature) !bool {
    const s = try Curve.Fe.fromBytes(signature.s, .Big);
    const r = try Curve.Fe.fromBytes(signature.r, .Big);
    const z = try Curve.Fe.fromBytes(hash, .Big);

    const s_inv = s.invert();
    const u_1 = z.mul(s_inv);
    const u_2 = r.mul(s_inv);

    const Q = try Curve.fromAffineCoordinates(.{ .x = public_key.x, .y = public_key.y });
    const x = (try Curve.basePoint.mulDoubleBasePublic(
        u_1.toBytes(.Big),
        Q,
        u_2.toBytes(.Big),
        .Big,
    )).affineCoordinates().x;

    return x.equivalent(r);
}

test "KeyPair - eql" {
    var key_pair = try KeyPair.init(null);
    var public_key = (&key_pair.public_key).*; // ensure a copy

    try std.testing.expect(key_pair.public_key.eql(public_key));
}

test "verify" {
    const msg = [_]u8{
        0xe1, 0x13, 0x0a, 0xf6, 0xa3, 0x8c, 0xcb, 0x41, 0x2a, 0x9c, 0x8d, 0x13, 0xe1, 0x5d, 0xbf, 0xc9,
        0xe6, 0x9a, 0x16, 0x38, 0x5a, 0xf3, 0xc3, 0xf1, 0xe5, 0xda, 0x95, 0x4f, 0xd5, 0xe7, 0xc4, 0x5f,
        0xd7, 0x5e, 0x2b, 0x8c, 0x36, 0x69, 0x92, 0x28, 0xe9, 0x28, 0x40, 0xc0, 0x56, 0x2f, 0xbf, 0x37,
        0x72, 0xf0, 0x7e, 0x17, 0xf1, 0xad, 0xd5, 0x65, 0x88, 0xdd, 0x45, 0xf7, 0x45, 0x0e, 0x12, 0x17,
        0xad, 0x23, 0x99, 0x22, 0xdd, 0x9c, 0x32, 0x69, 0x5d, 0xc7, 0x1f, 0xf2, 0x42, 0x4c, 0xa0, 0xde,
        0xc1, 0x32, 0x1a, 0xa4, 0x70, 0x64, 0xa0, 0x44, 0xb7, 0xfe, 0x3c, 0x2b, 0x97, 0xd0, 0x3c, 0xe4,
        0x70, 0xa5, 0x92, 0x30, 0x4c, 0x5e, 0xf2, 0x1e, 0xed, 0x9f, 0x93, 0xda, 0x56, 0xbb, 0x23, 0x2d,
        0x1e, 0xeb, 0x00, 0x35, 0xf9, 0xbf, 0x0d, 0xfa, 0xfd, 0xcc, 0x46, 0x06, 0x27, 0x2b, 0x20, 0xa3,
    };

    const Qx = [_]u8{
        0xe4, 0x24, 0xdc, 0x61, 0xd4, 0xbb, 0x3c, 0xb7, 0xef, 0x43, 0x44, 0xa7, 0xf8, 0x95, 0x7a, 0x0c,
        0x51, 0x34, 0xe1, 0x6f, 0x7a, 0x67, 0xc0, 0x74, 0xf8, 0x2e, 0x6e, 0x12, 0xf4, 0x9a, 0xbf, 0x3c,
    };
    const Qy = [_]u8{
        0x97, 0x0e, 0xed, 0x7a, 0xa2, 0xbc, 0x48, 0x65, 0x15, 0x45, 0x94, 0x9d, 0xe1, 0xdd, 0xda, 0xf0,
        0x12, 0x7e, 0x59, 0x65, 0xac, 0x85, 0xd1, 0x24, 0x3d, 0x6f, 0x60, 0xe7, 0xdf, 0xae, 0xe9, 0x27,
    };

    const R = [_]u8{
        0xbf, 0x96, 0xb9, 0x9a, 0xa4, 0x9c, 0x70, 0x5c, 0x91, 0x0b, 0xe3, 0x31, 0x42, 0x01, 0x7c, 0x64,
        0x2f, 0xf5, 0x40, 0xc7, 0x63, 0x49, 0xb9, 0xda, 0xb7, 0x2f, 0x98, 0x1f, 0xd9, 0x34, 0x7f, 0x4f,
    };
    const S = [_]u8{
        0x17, 0xc5, 0x50, 0x95, 0x81, 0x90, 0x89, 0xc2, 0xe0, 0x3b, 0x9c, 0xd4, 0x15, 0xab, 0xdf, 0x12,
        0x44, 0x4e, 0x32, 0x30, 0x75, 0xd9, 0x8f, 0x31, 0x92, 0x0b, 0x9e, 0x0f, 0x57, 0xec, 0x87, 0x1c,
    };

    var pub_key = KeyPair.PublicKey{
        .x = try Curve.Fe.fromBytes(Qx, .Big),
        .y = try Curve.Fe.fromBytes(Qy, .Big),
    };

    var hashed: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&msg, &hashed, .{});
    try std.testing.expect(try verify(pub_key, hashed, .{ .r = R, .s = S }));
}
