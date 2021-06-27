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

pub const DecodeError = error{
    /// For TLS 1.3, the legacy version must be 0x0303 (TLS 1.2)
    MismatchingLegacyVersion,
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

        pub const Error = DecodeError || ReaderType.Error || Allocator.Error;

        /// Initializes a new instance of `HandshakeReader` of a given reader that must be of
        /// `ReaderType`.
        pub fn init(gpa: *Allocator, reader: ReaderType) Self {
            return .{ .gpa = gpa, .handshake = undefined, .reader = reader };
        }

        /// Starts reading from the reader and will try to perform a handshake.
        pub fn decode(self: *Self) Error!void {
            const handshake_type = try self.reader.readByte();
            const remaining_length = try self.reader.ReadIntBig(u24);

            switch (@intToEnum(HandshakeType, handshake_type)) {
                .client_hello => try self.decodeClientHello(reader, remaining_length),
                else => @panic("TODO"),
            }
        }

        /// Decodes a 'client hello' message received from the client.
        fn decodeClientHello(self: *Self, message_length: usize) Error!void {
            // maximum length of client hello
            var buf: [2 + 32 + 32 + (2 ^ 16 - 2) + (2 ^ 8 - 1) + (2 ^ 16 - 1)]u8 = undefined;
            try reader.readNoEof(buf[0..message_length]);
            const content = buf[0..self.length];
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

            const cipher_suites_len = std.mem.readIntBig(u16, content[index .. index + 2]);
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
            std.debug.assert(index == message_length);

            while (try it.next(self.gpa)) |extension| {
                _ = extension;
            }
        }

        const ExtensionIterator = struct {
            data: []const u8,
            index: usize,

            fn next(self: *ExtensionIterator, gpa: *Allocator) error{OutOfMemory}!?Extension {
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
                            if (target_endianness == .Little) @byteSwap(u16, &versions);
                            break :blk versions;
                        };

                        return Extension{ .supported_versions = versions };
                    },
                    .exchange_modes => return Extension{ .exchange_modes = extension_data[1..] },
                    .key_share => {
                        const len = extension_data[0];
                        var keys = std.ArrayList(KeyShare).init(gpa);
                        defer keys.deinit();

                        var i: usize = 0;
                        while (i < len) {
                            const data = extension_data[i + 1 ..];
                            const key = try keys.addOne();
                            i += 2;
                            key.* = .{
                                .named_group = @intToEnum(NamedGroup, std.mem.readIntBig(u16, data[0..2])),
                                .key_exchange = data[2..],
                            };
                            i += key.key_exchange.len;
                        }

                        return Extension{ .key_share = keys.toOwnedSlice() };
                    },
                }
            }
        };

        const Extension = union(Tag) {
            supported_versions: []const u16,
            /// The PSK key exchange modes the client supports
            exchange_modes: []const u8,
            key_share: []const KeyShare,
            /// A list of signature algorithms the client supports
            signature_alg: []const u16,
            /// The groups of curve types the client supports
            supported_groups: []const NamedGroup,
            server_name: []const u8,

            const KeyShare = struct {
                /// The key exchange (i.e. curve25519)
                named_group: NamedGroup,
                /// The public key of the client
                key_exchange: []const u8,
            };

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
                _padding = 21,
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
