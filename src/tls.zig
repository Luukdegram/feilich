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
