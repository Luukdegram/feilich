//! Handles the connection between the server (this)
//! and its peer (client). Initially, it performs a handshake,
//! which if succesful will send all data encrypted to the client.
const std = @import("std");
const tls = @import("tls.zig");
const handshake = @import("handshake.zig");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;
const Sha256 = crypto.hash.sha2.Sha256;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

/// Server is a data object, containing the
/// private and public key for the TLS 1.3 connection.
///
/// This construct can then be used to connect to new clients.
pub const Server = struct {
    private_key: []const u8,
    public_key: []const u8,
    gpa: *Allocator,

    const Error = error{
        /// We expected a certain message from the client,
        /// but instead received a different one.
        UnexpectedMessage,
        /// The client does not support TLS 1.3
        UnsupportedVersion,
        /// When the named groups supported by the client,
        /// or part of the given key_share are not supported by
        /// the server.
        UnsupportedNamedGroup,
        /// None of the cipher suites provided by the client are
        /// currently supported by the server.
        UnsupportedCipherSuite,
        /// The signate algorithms provided by the client
        /// are not supported by the server.
        UnsupportedSignatureAlgorithm,
    };

    /// Initializes a new `Server` instance for a given public/private key pair.
    pub fn init(gpa: *Allocator, private_key: []const u8, public_key: []const u8) Server {
        return .{ .gpa = gpa, .private_key = private_key, .public_key = public_key };
    }

    /// Connects the server with a new client and performs its handshake.
    /// After succesfull handshake, a new reader and writer are returned which
    /// automatically decrypt, and encrypt the data before reading/writing.
    pub fn connect(
        self: *Server,
        /// Reader 'interface' to the client's connection
        reader: anytype,
        /// Writer 'interface' to the client's connection
        writer: anytype,
    ) (handshake.ReadWriteError(reader, writer) || Error)!void {
        var hasher = Sha256.init(.{});
        var handshake_reader = handshake.handshakeReader(reader, hasher);
        var handshake_writer = handshake.handshakeWriter(writer, hasher);

        var client_key_share: tls.KeyShare = undefined;
        var server_key_share: tls.KeyShare = undefined;
        var signature: tls.SignatureAlgorithm = undefined;
        var server_exchange: tls.KeyExchange = undefined;

        // A client requested to connect with the server,
        // verify a client hello message.
        //
        // We're using a while loop here as we may send a HelloRetryRequest
        // in which the client will send a new helloClient.
        // When a succesful hello reply was sent, we continue the regular path.
        while (true) {
            const hello_result = try handshake_reader.decode();
            switch (hello_result) {
                .client_hello => |client_result| {
                    const suite = for (client_result.cipher_suites) |suite| {
                        if (tls.supported_cipher_suites.isSupported(suite)) {
                            break suite;
                        }
                    } else {
                        try writeAlert(.fatal, .handshake_failure, writer);
                        return error.UnsupportedCipherSuite;
                    };

                    var version_verified = false;
                    var chosen_signature: ?tls.SignatureAlgorithm = null;
                    var chosen_group: ?tls.NamedGroup = null;
                    var key_share: ?tls.KeyShare = null;

                    var it = tls.Extension.Iterator.init(client_result.extensions);
                    loop: while (true) {
                        it_loop: while (it.next(self.gpa)) |maybe_extension| {
                            const extension = maybe_extension orelse break :loop; // reached end of iterator so break out of outer loop
                            switch (extension) {
                                .supported_versions => |versions| for (versions) |version| {
                                    // Check for TLS 1.3, when found continue
                                    // else we return an error.
                                    if (version == 0x0304) {
                                        version_verified = true;
                                        continue :it_loop;
                                    }
                                } else return error.UnsupportedVersion,
                                .supported_groups => |groups| for (groups) |group| {
                                    if (tls.supported_named_groups.isSupported(group)) {
                                        chosen_group = group;
                                        continue :it_loop;
                                    }
                                },
                                .signature_algorithms => |algs| for (algs) |alg| {
                                    if (tls.supported_signature_algorithms.isSupported(alg)) {
                                        chosen_signature = alg;
                                        continue :it_loop;
                                    }
                                },
                                .key_share => |keys| {
                                    defer self.gpa.free(keys);
                                    for (keys) |key| {
                                        if (tls.supported_named_groups.isSupported(key.named_group)) {
                                            key_share = .{
                                                .named_group = key.named_group,
                                                .key_exchange = key.key_exchange,
                                            };
                                            continue :it_loop;
                                        }
                                    }
                                },
                                else => {},
                            }
                        } else |err| switch (err) {
                            error.UnsupportedExtension => {
                                try writeAlert(.warning, .unsupported_extension, writer);
                                // unsupported extensions are a warning, we do not need to support
                                // them all. Simply continue the loop when we find one.
                                continue :loop;
                            },
                            else => return err,
                        }
                    }

                    if (!version_verified) {
                        try writeAlert(.fatal, .protocol_version, writer);
                        return error.UnsupportedVersion;
                    }

                    client_key_share = key_share orelse {
                        try writeAlert(.fatal, .handshake_failure, writer);
                        return error.UnsupportedNamedGroup;
                    };

                    signature = chosen_signature orelse {
                        try writeAlert(.fatal, .handshake_failure, writer);
                        return error.UnsupportedSignatureAlgorithm;
                    };

                    server_key_share = blk: {
                        const group = chosen_group orelse {
                            try writeAlert(.fatal, .handshake_failure, writer);
                            return error.UnsupportedNamedGroup;
                        };

                        server_exchange = try tls.KeyExchange.fromCurve(tls.curves.x25519);
                        break :blk tls.KeyShare{
                            .named_group = group,
                            .key_exchange = server_exchange.public_key,
                        };
                    };

                    try handshake_writer.serverHello(
                        .server_hello,
                        client_result.session_id,
                        suite,
                        server_key,
                    );

                    // We sent our hello server, meaning we can continue
                    // the regular path.
                    break;
                },
                else => return error.UnexpectedMessage,
            }
        }

        // generate handshake key, which is constructed by multiplying
        // the client's public key with the server's private key using the negotiated
        // named group.
        const curve = std.crypto.ecc.Curve25519.fromBytes(client_key_share.key_exchange);
        const shared_key = curve.mul(server_exchange.private_key) catch |err| switch (err) {
            error.WeakPublicKeyError => |e| {
                try writeAlert(.fatal, .insufficient_security, writer);
                return e;
            },
            else => |e| return e,
        };

        var derived_secret: [32]u8 = undefined;
        const early_secret = HkdfSha256.extract("", &[_]u8{0} ** 32);
        HkdfSha256.expand(&derived_secret, "tls13derived", early_secret);
        const handshake_secret = HkdfSha256.extract(&derived_secret, &shared_key.toBytes());
        _ = handshake_secret;
        _ = early_secret;
        _ = shared_key;
    }

    /// Constructs an alert record and writes it to the client's connection.
    /// When an alert is fatal, it is illegal to write any more data to the `writer`.
    fn writeAlert(severity: tls.AlertLevel, alert: tls.Alert, writer: anytype) @TypeOf(writer).Error!void {
        const record = tls.Record.init(.alert, 2); // 2 bytes for level and description.
        try record.writeTo(writer);
        try writer.writeAll(&.{ severity.int(), alert.int() });
    }
};

// Uses example data from https://tls13.ulfheim.net/ to verify
// its output
test "Handshake keys calculation" {
    const hello_hash: [32]u8 = [_]u8{
        0xda, 0x75, 0xce, 0x11, 0x39, 0xac, 0x80, 0xda,
        0xe4, 0x04, 0x4d, 0xa9, 0x32, 0x35, 0x0c, 0xf6,
        0x5c, 0x97, 0xcc, 0xc9, 0xe3, 0x3f, 0x1e, 0x6f,
        0x7d, 0x2d, 0x4b, 0x18, 0xb7, 0x36, 0xff, 0xd5,
    };
    const shared_secret: [32]u8 = [_]u8{
        0xdf, 0x4a, 0x29, 0x1b, 0xaa, 0x1e, 0xb7, 0xcf,
        0xa6, 0x93, 0x4b, 0x29, 0xb4, 0x74, 0xba, 0xad,
        0x26, 0x97, 0xe2, 0x9f, 0x1f, 0x92, 0x0d, 0xcc,
        0x77, 0xc8, 0xa0, 0xa0, 0x88, 0x44, 0x76, 0x24,
    };
    const early_secret = HkdfSha256.extract(&.{}, &[_]u8{0} ** 32);
    var empty_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &empty_hash, .{});
    const derived_secret = tls.hkdfExpandLabel(early_secret, "derived", &empty_hash, 32);
    try std.testing.expectEqualSlices(u8, &.{
        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02,
        0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba,
        0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c,
        0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57,
        0x6c, 0x36, 0x11, 0xba,
    }, &derived_secret);

    const handshake_secret = HkdfSha256.extract(&derived_secret, &shared_secret);
    try std.testing.expectEqualSlices(u8, &.{
        0xfb, 0x9f, 0xc8, 0x06, 0x89, 0xb3, 0xa5, 0xd0,
        0x2c, 0x33, 0x24, 0x3b, 0xf6, 0x9a, 0x1b, 0x1b,
        0x20, 0x70, 0x55, 0x88, 0xa7, 0x94, 0x30, 0x4a,
        0x6e, 0x71, 0x20, 0x15, 0x5e, 0xdf, 0x14, 0x9a,
    }, &handshake_secret);

    const client_secret = tls.hkdfExpandLabel(handshake_secret, "c hs traffic", &hello_hash, 32);
    const server_secret = tls.hkdfExpandLabel(handshake_secret, "s hs traffic", &hello_hash, 32);

    try std.testing.expectEqualSlices(u8, &.{
        0xff, 0x0e, 0x5b, 0x96, 0x52, 0x91, 0xc6, 0x08,
        0xc1, 0xe8, 0xcd, 0x26, 0x7e, 0xef, 0xc0, 0xaf,
        0xcc, 0x5e, 0x98, 0xa2, 0x78, 0x63, 0x73, 0xf0,
        0xdb, 0x47, 0xb0, 0x47, 0x86, 0xd7, 0x2a, 0xea,
    }, &client_secret);
    try std.testing.expectEqualSlices(u8, &.{
        0xa2, 0x06, 0x72, 0x65, 0xe7, 0xf0, 0x65, 0x2a,
        0x92, 0x3d, 0x5d, 0x72, 0xab, 0x04, 0x67, 0xc4,
        0x61, 0x32, 0xee, 0xb9, 0x68, 0xb6, 0xa3, 0x2d,
        0x31, 0x1c, 0x80, 0x58, 0x68, 0x54, 0x88, 0x14,
    }, &server_secret);

    const client_handshake_key = tls.hkdfExpandLabel(client_secret, "key", "", 16);
    const server_handshake_key = tls.hkdfExpandLabel(server_secret, "key", "", 16);

    try std.testing.expectEqualSlices(u8, &.{
        0x71, 0x54, 0xf3, 0x14, 0xe6, 0xbe, 0x7d, 0xc0,
        0x08, 0xdf, 0x2c, 0x83, 0x2b, 0xaa, 0x1d, 0x39,
    }, &client_handshake_key);
    try std.testing.expectEqualSlices(u8, &.{
        0x84, 0x47, 0x80, 0xa7, 0xac, 0xad, 0x9f, 0x98,
        0x0f, 0xa2, 0x5c, 0x11, 0x4e, 0x43, 0x40, 0x2a,
    }, &server_handshake_key);

    var temp: [32]u8 = undefined;
    std.mem.copy(u8, &temp, &client_secret);
    const client_handshake_iv = tls.hkdfExpandLabel(temp, "iv", "", 12);

    try std.testing.expectEqualSlices(u8, &.{
        0x71, 0xab, 0xc2, 0xca, 0xe4, 0xc6, 0x99, 0xd4, 0x7c, 0x60, 0x02, 0x68,
    }, &client_handshake_iv);

    std.mem.copy(u8, &temp, &server_secret);
    const server_handshake_iv = tls.hkdfExpandLabel(temp, "iv", "", 12);

    try std.testing.expectEqualSlices(u8, &.{
        0x4c, 0x04, 0x2d, 0xdc, 0x12, 0x0a, 0x38, 0xd1, 0x41, 0x7f, 0xc8, 0x15,
    }, &server_handshake_iv);
}
