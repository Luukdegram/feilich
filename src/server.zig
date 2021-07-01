//! Handles the connection between the server (this)
//! and its peer (client). Initially, it performs a handshake,
//! which if succesful will send all data encrypted to the client.
const std = @import("std");
const tls = @import("tls.zig");
const handshake = @import("handshake.zig");
const mem = std.mem;
const Allocator = mem.Allocator;

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
        var handshake_reader = handshake.handshakeReader(reader);
        var handshake_writer = handshake.handshakeWriter(writer);

        // A client requested to connect with the server,
        // verify a client hello message.
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
                            error.UnsupportedExtension => continue :loop,
                            else => return err,
                        }
                    }

                    if (!version_verified) {
                        try writeAlert(.fatal, .protocol_version, writer);
                        return error.UnsupportedVersion;
                    }

                    const client_exchange = key_share orelse {
                        try writeAlert(.fatal, .handshake_failure, writer);
                        return error.UnsupportedNamedGroup;
                    };

                    // TODO: Save this information as we require it
                    // to decrypt client messages.
                    _ = client_exchange;

                    var server_exchange: tls.KeyExchange = undefined;
                    const server_key = blk: {
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
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    /// Constructs an alert record and writes it to the client's connection.
    /// When an alert is fatal, it is illegal to write any more data to the `writer`.
    fn writeAlert(severity: tls.AlertLevel, alert: tls.Alert, writer: anytype) @TypeOf(writer).Error!void {
        const record = tls.Record.init(.alert, 2); // 2 bytes for level and description.
        try record.writeTo(writer);
        try writer.writeAll(&.{ severity.int(), alert.int() });
    }
};
