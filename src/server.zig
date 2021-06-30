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

    /// Initializes a new `Server` instance for a given public/private key pair.
    pub fn init(gpa: *Allocator, private_key: []const u8, public_key: []const u8) Server {
        return .{ .gpa = gpa, .private_key = private_key, .public_key = public_key };
    }

    /// Connects the server with a new client and performs its handshake.
    /// After succesfull handshake, a new reader and writer are returned which
    /// automatically decrypt, and encrypt the data before reading/writing.
    pub fn connect(self: *Server, reader: anytype, writer: anytype) !void {
        var handshake_reader = handshake.handshakeReader(reader);
        var handshake_writer = handshake.handshakeWriter(writer);

        _ = handshake_reader;
        _ = handshake_writer;
        _ = self;
    }
};
