//! Contains the data and logic to perform
//! a TLS 1.3 handshake
const std = @import("std");
const tls = @import("tls.zig");
const Allocator = mem.Allocator;
const mem = std.mem;

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
            // maximum length of an entire record (record header + message)
            var buf: [1 << 14]u8 = undefined;
            try self.reader.readNoEof(buf[0..message_length]);
            const content = buf[0..message_length];
            // current index into `contents`
            if (mem.readIntBig(u16, content[0..2]) != 0x0303) return error.MismatchingLegacyVersion;
            var index: usize = 2;

            const random = content[index..34];
            _ = random; // TODO, check this
            index += 32; // random

            // TLS version 1.3 ignores session_id
            // but we will return it to echo it in the server hello.
            const session_len = content[index];
            index += 1;
            if (session_len != 0) {
                const session_id = content[index..][0..32];
                index += session_id.len;
            }

            const cipher_suites_len = mem.readIntBig(u16, content[index..][0..2]);
            index += 2;

            const cipher_suites = blk: {
                const cipher_bytes = content[index..][0..cipher_suites_len];
                index += cipher_suites_len;
                var ciphers = mem.bytesAsSlice(u16, cipher_bytes);
                if (target_endianness == .Little) for (ciphers) |*cipher| {
                    cipher.* = @byteSwap(u16, cipher.*);
                };
                break :blk @bitCast([]const tls.CipherSuite, ciphers);
            };
            _ = cipher_suites;

            // TLS version 1.3 ignores compression as well
            const compression_methods_len = content[index];
            index += compression_methods_len + 1;

            const extensions_length = mem.readIntBig(u16, content[index..][0..2]);
            index += 2;
            var it: ExtensionIterator = .{
                .data = content[index..][0..extensions_length],
                .index = 0,
            };
            index += extensions_length;

            loop: while (true) {
                while (it.next(self.gpa)) |maybe_extension| {
                    _ = maybe_extension orelse break :loop; // extension == null so stop loop
                } else |err| switch (err) {
                    error.UnsupportedExtension => continue :loop,
                    else => |e| return e,
                }
            }

            std.debug.assert(index == message_length);
        }

        /// Constructs extensions as they are parsed.
        /// Allowing to to reduce the need for allocations.
        const ExtensionIterator = struct {
            /// Mutable slice as we may require
            /// to byteswap elements to ensure correct endianness
            data: []u8,
            /// Current index into `data`
            index: usize,

            /// Parses the next extension, returning `null` when all extensions have been parsed.
            /// Will return `UnsupportedExtension` when an extension is not supported by TLS 1.3,
            /// or simply isn't implemented yet.
            fn next(self: *ExtensionIterator, gpa: *Allocator) error{ OutOfMemory, UnsupportedExtension }!?Extension {
                if (self.index >= self.data.len) return null;

                const tag_byte = mem.readIntBig(u16, self.data[self.index..][0..2]);
                self.index += 2;
                const extension_length = mem.readIntBig(u16, self.data[self.index..][0..2]);
                self.index += 2;
                const extension_data = self.data[self.index .. self.index + extension_length];
                self.index += extension_data.len;

                switch (@intToEnum(Extension.Tag, tag_byte)) {
                    .supported_versions => {
                        const versions = blk: {
                            var versions = mem.bytesAsSlice(u16, extension_data[1..]);
                            if (target_endianness == .Little) for (versions) |*v| {
                                v.* = @byteSwap(u16, v.*);
                            };

                            break :blk versions;
                        };

                        return Extension{ .supported_versions = @bitCast([]const u16, versions) };
                    },
                    .psk_key_exchange_modes => return Extension{ .psk_key_exchange_modes = extension_data[1..] },
                    .key_share => {
                        const len = mem.readIntBig(u16, extension_data[0..2]);
                        var keys = std.ArrayList(tls.KeyShare).init(gpa);
                        defer keys.deinit();

                        var i: usize = 0;
                        while (i < len) {
                            // allocate memory for a new key
                            const key = try keys.addOne();

                            // get the slice for current data
                            const data = extension_data[i + 2 ..];

                            // read named_group and the amount of bytes of public key
                            const named_group = mem.readIntBig(u16, data[0..2]);
                            const key_len = mem.readIntBig(u16, data[2..4]);

                            // update pointer's value
                            key.* = .{
                                .named_group = @intToEnum(tls.NamedGroup, named_group),
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
                        var groups = mem.bytesAsSlice(u16, extension_data[2..]);
                        if (target_endianness == .Little) for (groups) |*group| {
                            group.* = @byteSwap(u16, group.*);
                        };
                        return Extension{ .supported_groups = @bitCast([]const tls.NamedGroup, groups) };
                    },
                    .signature_algorithms => {
                        var algs = mem.bytesAsSlice(u16, extension_data[2..]);
                        if (target_endianness == .Little) for (algs) |*alg| {
                            alg.* = @byteSwap(u16, alg.*);
                        };
                        return Extension{ .signature_algorithms = @bitCast([]const tls.SignatureAlgorithm, algs) };
                    },
                    else => return error.UnsupportedExtension,
                }
            }
        };
    };
}

/// Extension define what the client requests for extended functionality from servers.
/// Note that some extensions are required for TLS 1.3 itself,
/// while others are optional.
const Extension = union(Tag) {
    /// The supported TLS versions of the client.
    supported_versions: []const u16,
    /// The PSK key exchange modes the client supports
    psk_key_exchange_modes: []const u8,
    /// List of public keys and the key exchange required for them.
    key_share: []const tls.KeyShare,
    /// A list of signature algorithms the client supports
    signature_algorithms: []const tls.SignatureAlgorithm,
    /// The groups of curve types the client supports
    supported_groups: []const tls.NamedGroup,
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

        fn int(self: Tag) u16 {
            return @enumToInt(self);
        }
    };
};

/// Initializes a new `HandshakeWriter`, deducing the type of a given
/// instance of a `writer`. The handshake writer will construct all
/// required messages for a succesful handshake.
pub fn handshakeWriter(writer: anytype) HandshakeWriter(@TypeOf(writer)) {
    return HandshakeWriter(@TypeOf(HandshakeWriter)).init(writer);
}

/// Creates a new HandshakeWriter using a given writer type.
/// The handshakewriter builds all messages required to construct a succesful handshake.
pub fn HandshakeWriter(comptime WriterType: type) type {
    return struct {
        const Self = @This();

        writer: WriterType,

        const Error = WriteError || WriterType.Error;

        /// Constructs and sends a 'Server Hello' message to the client.
        /// This must be called, after a succesful 'Client Hello' message was received.
        pub fn serverHello(
            self: *Self,
            // Legacy session_id to emit.
            // In TLS 1.3 we can simply echo client's session id.
            session_id: [32]u8,
            // The cipher_suite we support as a server and that was provided
            // by the client.
            cipher_suite: tls.CipherSuite,
            /// The `KeyShare` that was generated, based
            /// on the client's Key Share.
            key_share: tls.KeyShare,
        ) Error!void {
            try self.writer.writeByte(@enumToInt(HandshakeType.server_hello));

            // The total amount of bytes the client must read to decode the
            // entire 'server hello' message.
            const total_length: u16 = 118;
            try self.writer.writeIntBig(u16, total_length);

            // Means TLS 1.2, this is legacy and actual version is sent through extensions
            try self.writer.writeIntBig(u16, 0x303);

            const server_random = blk: {
                var seed: [32]u8 = undefined;
                std.crypto.random.bytes(&seed);
                break :blk;
            };
            try self.writer.writeAll(server_random);

            // session_id is legacy and no longer used. In TLS 1.3 we
            // can just 'echo' client's session id.
            try self.writer.writeAll(session_id);

            // cipher suite
            try self.writer.writeIntBig(u16, cipher_suite.int());

            // Compression methods, which is no longer allowed for TLS 1.3 so assign "null"
            const compression_methods = &[_]u8{ 0x1, 0x00 };
            try self.writer.writeAll(compression_methods);

            // write the extension length (46 bytes)
            try self.writer.writeIntBig(u16, 0x002E);
            total_data += 2;

            // Extension -- Key Share
            try key_share.write(self.writer);

            // Extension -- Supported versions
            const supported_versions = &[_]u8{
                // Extension type
                0x0,  0x2b,
                // byte length (2) remaining
                0x0,  0x02,
                // actual version (TLS 1.3)
                0x03, 0x04,
            };
            try self.writer.writeAll(supported_versions);
        }
    };
}

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
    // zig fmt: on

    var fb_reader = std.io.fixedBufferStream(&data).reader();
    var hs_reader = handshakeReader(std.testing.allocator, fb_reader);
    try hs_reader.decode();
}
