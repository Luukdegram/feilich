//! Contains data constructs related to the TLS protocol.

/// Record header. TLS sessions are broken into the sending
/// and receiving of records, which are blocks of data with a type,
/// protocol version and a length.
pub const Record = extern struct {
    /// The type of record we're receiving or sending
    record_type: RecordType,
    /// The (legacy) protocol version.
    /// This is *always* 0x0303 (TLS 1.2) even for TLS 1.3
    /// as the supported versions are part of an extension in TLS 1.3,
    /// rather than the `Record` header.
    protocol_version: u16 = 0x0303,
    /// The length of the bytes that are left for reading.
    /// The length MUST not exceed 2^14 bytes.
    len: u16,

    /// Supported record types by TLS 1.3
    pub const RecordType = enum(u8) {
        change_cipher_spec = 20,
        alert = 21,
        handshake = 22,
        application_data = 23,
    };

    /// Initializes a new `Record` that always has its `protocol_version` set to 0x0303.
    pub fn init(record_type: RecordType, len: usize) Record {
        return .{ .record_type = record_type, .len = len };
    }

    /// Writes a `Record` to a given `writer`.
    pub fn write(self: Record, writer: anytype) !void {
        try writer.writeByte(@enumToInt(self.record_type));
        try writer.writeIntBig(u16, self.protocol_version);
        try writer.writeIntBig(u16, self.len);
    }

    /// Reads from a given `reader` to initialize a new `Record`.
    /// It's up to the user to verify correctness of the data (such as protocol version).
    pub fn read(reader: anytype) !Record {
        return Record{
            .record_type = @intToEnum(RecordType, try reader.readByte()),
            .protocol_version = try reader.readIntBig(u16),
            .len = try reader.readIntBig(u16),
        };
    }
};

/// Represents the key exchange that is supported by the client or server
/// Prior to TLS 1.3 this was called 'elliptic_curves' and only contained elliptic curve groups.
pub const NamedGroup = enum(u16) {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe_private_use_start = 0x01FC,
    ffdhe_private_use_end = 0x01FF,
    ecdhe_private_use_start = 0xFE00,
    ecdhe_private_use_end = 0xFEFF,
    /// reserved and unsupported values
    /// as they're part of earlier TLS version.
    _,

    pub fn int(self: NamedGroup) u16 {
        return @enumToInt(self);
    }
};

pub const SignatureAlgorithm = enum(u16) {
    // RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    // ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    // RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    // EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,

    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    // Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,

    /// Reserved Code Points
    _,
};

/// Supported cipher suites by TLS 1.3
pub const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,
    tls_aes_128_ccm_sha256 = 0x1304,
    tls_aes_128_ccm_8_sha256 = 0x1305,

    pub fn int(self: CipherSuite) u16 {
        return @enumToInt(self);
    }
};

/// Keyshare represents the key exchange used to generate
/// its public key, and the actual public key.
pub const KeyShare = struct {
    /// The key exchange (i.e. curve25519)
    named_group: NamedGroup,
    /// The public key of the client
    key_exchange: []const u8,

    /// Ensures the correct bytes are written to the writer
    /// based on a given `KeyShare`.
    fn write(self: KeyShare, writer: anytype) !void {
        try writer.writeIntBig(u16, Extension.Tag.key_share.int());
        try writer.writeIntBig(u16, 0x0024); // length (36 bytes)
        try writer.writeIntBig(u16, self.named_group.int());
        try writer.writeIntBig(u16, 0x0020); // public key length (32 bytes)
        try writer.writeAll(self.key_exchange);
    }
};
