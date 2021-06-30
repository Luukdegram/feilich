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
        UnexpectedMessage,
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
                    var it = tls.Extension.Iterator.init(client_result.extensions);
                    loop: while (true) {
                        it_loop: while (it.next(self.gpa)) |maybe_extension| {
                            const extension = maybe_extension orelse break :loop; // reached end of iterator so break out of outer loop
                            switch (extension) {
                                .supported_versions => |versions| for (versions) |version| {
                                    // Check for TLS 1.3, when found continue
                                    // else we return an error.
                                    if (version == 0x0304) continue :it_loop;
                                } else return error.UnsupportedVersion,
                                .supported_groups => |groups| {
                                    //i TODO
                                    _ = groups;
                                },
                                .signature_algorithms => |algs| {
                                    // TODO
                                    _ = algs;
                                },
                                .key_share => |keys| {
                                    // TODO
                                    _ = keys;
                                },
                                else => {},
                            }
                        } else |err| switch (err) {
                            error.UnsupportedExtension => continue :loop,
                            else => return err,
                        }
                    }

                    try handshake_writer.serverHello(
                        .server_hello,
                        client_result.session_id,
                        client_result.cipher_suites[0],
                    );
                },
                else => return error.UnexpectedMessage,
            }
        }
    }
};
