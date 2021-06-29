//! Contains the data and logic to perform
//! a TLS 1.3 handshake
const std = @import("std");
const Allocator = std.mem.Allocator;

/// Target cpu's endianness. Use this to check if byte swapping is required.
const target_endianness = std.builtin.target.cpu.arch.endian();

/// Represents the possible handshake types
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,
};

pub const ReadError = error{
    /// For TLS 1.3, the legacy version must be 0x0303 (TLS 1.2)
    MismatchingLegacyVersion,
    /// Reached end of stream, perhaps the client disconnected.
    EndOfStream,
    /// The client requested for an extension the server does not support.
    UnsupportedExtension,
};

/// Initializes a new reader that decodes and performs a handshake
pub fn handshakeReader(gpa: *Allocator, reader: anytype) HandshakeReader(@TypeOf(reader)) {
    return HandshakeReader(@TypeOf(reader)).init(gpa, reader);
}

/// Generic handshake reader that will perform a handshake and decode all
/// handshake types
pub fn HandshakeReader(comptime ReaderType: type) type {
    return struct {
        const Self = @This();
        /// Reader we're reading from
        reader: ReaderType,
        /// Allocater used to construct our data
        gpa: *Allocator,

        pub const Error = ReadError || ReaderType.Error || Allocator.Error;

        /// Initializes a new instance of `HandshakeReader` of a given reader that must be of
        /// `ReaderType`.
        pub fn init(gpa: *Allocator, reader: ReaderType) Self {
            return .{ .gpa = gpa, .reader = reader };
        }

        /// Starts reading from the reader and will try to perform a handshake.
        pub fn decode(self: *Self) Error!void {
            const handshake_type = try self.reader.readByte();
            const remaining_length = try self.reader.readIntBig(u24);

            switch (@intToEnum(HandshakeType, handshake_type)) {
                .client_hello => try self.decodeClientHello(remaining_length),
                else => @panic("TODO"),
            }
        }

        /// Decodes a 'client hello' message received from the client.
        fn decodeClientHello(self: *Self, message_length: usize) Error!void {
            // maximum length of client hello
            var buf: [2 + 32 + 32 + (std.math.pow(u32, 2, 16) - 2) + (std.math.pow(u32, 2, 8) - 1) + (std.math.pow(u32, 2, 16) - 1)]u8 = undefined;
            try self.reader.readNoEof(buf[0..message_length]);
            const content = buf[0..message_length];
            // current index into `contents`
            if (std.mem.readIntBig(u16, content[0..2]) != 0x0303) return error.MismatchingLegacyVersion;
            var index: usize = 2;

            const random = content[index..34];
            _ = random; // TODO, check this
            index += 32;

            const session_len = content[index];
            if (session_len != 0) {
                index += 1;
                const session_id = content[index .. index + 32];
                index += 32;
                // TLS version 1.3 ignores session_id
                _ = session_id;
            }

            const cipher_suites_len = std.mem.readIntBig(u16, content[index..][0..2]);
            index += 2;
            const cipher_suites = content[index .. index + cipher_suites_len];
            _ = cipher_suites; //TODO, check this
            index += cipher_suites_len;

            const compression_methods_len = content[index];
            index += 1;
            const compression_methods = content[index .. index + compression_methods_len];
            index += compression_methods_len;

            // TLS version 1.3 ignores compression as well
            _ = compression_methods;

            const extensions_length = std.mem.readIntBig(u16, content[index..][0..2]);
            index += 2;

            var it: ExtensionIterator = .{ .data = content[index .. index + extensions_length], .index = 0 };
            index += extensions_length;

            loop: while (true) {
                while (it.next(self.gpa)) |maybe_extension| {
                    _ = maybe_extension orelse break :loop; // extension == null so stop loop
                } else |err| switch (err) {
                    error.UnsupportedExtension => continue :loop,
                    else => |e| return e,
                }
            }
        }

        /// Constructs extensions as they are parsed.
        /// Allowing to to reduce the need for allocations.
        const ExtensionIterator = struct {
            /// Mutable slice as we may require
            /// to byteswap elements to ensure correct endianness
            data: []u8,
            /// Current index into `data`
            index: usize,

            fn next(self: *ExtensionIterator, gpa: *Allocator) error{ OutOfMemory, UnsupportedExtension }!?Extension {
                if (self.index >= self.data.len) return null;

                const tag_byte = std.mem.readIntBig(u16, self.data[self.index..][0..2]);
                self.index += 2;
                const extension_length = std.mem.readIntBig(u16, self.data[self.index..][0..2]);
                self.index += 2;
                const extension_data = self.data[self.index .. self.index + extension_length];
                self.index += extension_data.len;

                switch (@intToEnum(Extension.Tag, tag_byte)) {
                    .supported_versions => {
                        const versions = blk: {
                            var versions = std.mem.bytesAsSlice(u16, extension_data[1..]);
                            if (target_endianness == .Little) for (versions) |*v| {
                                v.* = @byteSwap(u16, v.*);
                            };

                            break :blk versions;
                        };

                        return Extension{ .supported_versions = @bitCast([]const u16, versions) };
                    },
                    .psk_key_exchange_modes => return Extension{ .psk_key_exchange_modes = extension_data[1..] },
                    .key_share => {
                        const len = std.mem.readIntBig(u16, extension_data[0..2]);
                        var keys = std.ArrayList(KeyShare).init(gpa);
                        defer keys.deinit();

                        var i: usize = 0;
                        while (i < len) {
                            // allocate memory for a new key
                            const key = try keys.addOne();

                            // get the slice for current data
                            const data = extension_data[i + 2 ..];

                            // read named_group and the amount of bytes of public key
                            const named_group = std.mem.readIntBig(u16, data[0..2]);
                            const key_len = std.mem.readIntBig(u16, data[2..4]);

                            // update pointer's value
                            key.* = .{
                                .named_group = @intToEnum(NamedGroup, named_group),
                                .key_exchange = data[4..][0..key_len],
                            };
                            i += key_len + 4;
                        }

                        return Extension{ .key_share = keys.toOwnedSlice() };
                    },
                    // For TLS 1.3 only 1 hostname can be provided which is always
                    // of type DNS hostname. This means the hostname is the remaining
                    // bytes after the 5th element.
                    .server_name => return Extension{ .server_name = extension_data[5..] },
                    .supported_groups => {
                        var groups = std.mem.bytesAsSlice(u16, extension_data[2..]);
                        if (target_endianness == .Little) for (groups) |*group| {
                            group.* = @byteSwap(u16, group.*);
                        };
                        return Extension{ .supported_groups = @bitCast([]const NamedGroup, groups) };
                    },
                    .signature_algorithms => {
                        var algs = std.mem.bytesAsSlice(u16, extension_data[2..]);
                        if (target_endianness == .Little) for (algs) |*alg| {
                            alg.* = @byteSwap(u16, alg.*);
                        };
                        return Extension{ .signature_algorithms = @bitCast([]const SignatureAlgorithm, algs) };
                    },
                    else => return error.UnsupportedExtension,
                }
            }
        };

        /// Extension define what the client requests for extended functionality from servers.
        /// Note that some extensions are required for TLS 1.3 itself,
        /// while others are optional.
        const Extension = union(Tag) {
            /// The supported TLS versions of the client.
            supported_versions: []const u16,
            /// The PSK key exchange modes the client supports
            psk_key_exchange_modes: []const u8,
            /// List of public keys and the key exchange required for them.
            key_share: []const KeyShare,
            /// A list of signature algorithms the client supports
            signature_algorithms: []const SignatureAlgorithm,
            /// The groups of curve types the client supports
            supported_groups: []const NamedGroup,
            /// Hostname of the server the client wants to connect to
            /// TLS uses this to determine which server certificate to use,
            /// rather than requiring multiple servers.
            server_name: []const u8,

            // TODO: Implement the other types. Currently,
            // they're just void types.
            max_gragment_length,
            status_request,
            use_srtp,
            heartbeat,
            application_layer_protocol_negotation,
            signed_certificate_timestamp,
            client_certificate_type,
            server_certificate_type,
            pre_shared_key,
            early_data,
            cookie,
            certificate_authorities,
            oid_filters,
            post_handshake_auth,
            signature_algorithms_cert,

            /// All extensions that are compatible with TLS 1.3
            /// Some may be specified as an external rfc.
            const Tag = enum(u16) {
                server_name = 0,
                max_gragment_length = 1,
                status_request = 5,
                supported_groups = 10,
                signature_algorithms = 13,
                use_srtp = 14,
                heartbeat = 15,
                application_layer_protocol_negotation = 16,
                signed_certificate_timestamp = 18,
                client_certificate_type = 19,
                server_certificate_type = 20,
                pre_shared_key = 41,
                early_data = 42,
                supported_versions = 43,
                cookie = 44,
                psk_key_exchange_modes = 45,
                certificate_authorities = 47,
                oid_filters = 48,
                post_handshake_auth = 49,
                signature_algorithms_cert = 50,
                key_share = 51,
            };
        };
    };
}

/// Represents the key exchange that is supported by the client or server
/// Prior to TLS 1.3 this was called 'elliptic_curves' and only contained elliptic curve groups.
const NamedGroup = enum(u16) {
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
};

const SignatureAlgorithm = enum(u16) {
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

/// Keyshare represents the key exchange used to generate
/// its public key, and the actual public key.
const KeyShare = struct {
    /// The key exchange (i.e. curve25519)
    named_group: NamedGroup,
    /// The public key of the client
    key_exchange: []const u8,
};

test "Client Hello" {
    // Client hello bytes taken from:
    // https://tls13.ulfheim.net/

    // zig fmt: off
    var data = [_]u8{
        // Handshake header
        0x01, 0x00, 0x00, 0xc6,
        // client version
        0x03, 0x03,
        // random
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        // Session id
        0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
        0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee,
        0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
        0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        // Cipher suites
        0xff, 0x00, 0x06, 0x13, 0x01,
        0x13, 0x02, 0x13, 0x03,
        // Compression methods
        0x01, 0x00,
        // Extension length
        0x00, 0x77,
        // Extension - Server name
        0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00,
        0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d,
        0x2e, 0x6e, 0x65, 0x74,
        // Extension - Support groups
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d,
        0x00, 0x17, 0x00, 0x18,
        // Extension - Signature Algorithms
        0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03,
        0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
        0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
        // Extensions - Key Share
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d,
        0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58,
        0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91,
        0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e,
        0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16,
        0x62, 0x54,
        // Extension - PSK Key Exchange modes
        0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
        // Extension - Supported versions
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
    };
    // zig-fmt: on

    var fb_reader = std.io.fixedBufferStream(&data).reader();
    var hs_reader = handshakeReader(std.testing.allocator, fb_reader);
    try hs_reader.decode();
}

/// Initializes a new `HandshakeWriter`, deducing the type of a given
/// instance of a `writer`. The handshake writer will construct all
/// required messages for a succesful handshake.
pub fn handshakeWriter(writer: anytype) HandshakeWriter(@TypeOf(writer)) {
    return HandshakeWriter(@TypeOf(HandshakeWriter)).init(writer);
}

/// Creates a new HandshakeWriter using a given writer type.
/// The handshakewriter builds all messages required to construct a succesful handshake.
pub fn HandshakeWriter(comptime WriterType: type) type {
    return struct{
        const Self = @This();

        writer: WriterType,

        const Error = WriteError || WriterType.Error;

        /// Constructs and sends a 'Server Hello' message to the client.
        /// This must be called, after a succesful 'Client Hello' message was received.
        pub fn serverHello(self: *writer) Error!void {
            _ = self;
        }
    };
}
