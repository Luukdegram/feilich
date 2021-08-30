//! Decoder for the ASN.1 DER encoding rules.
//! DER encoding contains a tag, length and value for each element.
//! Note: This means it only supports DER encoding rules, not BER and CER
//! as the only use case is for X.509 support.

const std = @import("std");
const mem = std.mem;
const BigInt = std.math.big.int.Const;

/// Represents the current context of the asn1 decoder,
/// which is used to track its state.
pub const AsnIterator = struct {
    /// the data being decoded
    /// This is not owned by `Context` itself.
    data: []const u8,
    /// The current index into `data`.
    index: usize,

    /// Attempts to iterate over the next asn.1 element.
    /// Returns null when not found, or reached end of data.
    pub fn next(self: *AsnIterator) !?Value {
        return nextValue(self);
    }
};

/// Initializes an `AsnIterator` which is used to decode the ASN.1 content.
/// Looping over `next` will allow the user to iterate over asn.1 elements, representing
/// a tag, length and value.
pub fn iterator(data: []const u8) AsnIterator {
    return .{ .data = data, .index = 0 };
}

/// A subset of ASN.1 tag types as specified by the spec.
/// We only define the tags that are required for https.
/// Read more at:
/// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
pub const Tag = enum(u8) {
    integer = 0x02,
    bit_string = 0x03,
    octet_string = 0x04,
    object_identifier = 0x06,
    utf8_string = 0x0C,
    printable_string = 0x13,
    ia5_string = 0x16,
    utc_time = 0x17,
    generalized_time = 0x18,
    sequence = 0x30,
    set = 0x31,
};

/// Represents the value of an element that was encoded using ASN.1 DER encoding rules.
pub const Value = union(Tag) {
    integer: BigInt, // can represent integers up to 126 bytes.
};

inline fn nextValue(self: *AsnIterator) !?Value {
    if (self.index >= self.data.len) return null; // reached end of data.

    // Represents the Tag class
    const Class = enum(u2) {
        universal,
        application,
        context_specific,
        private,
    };

    const tag_byte = self.data[self.index];
    self.index += 1;

    const tag_class = @intToEnum(Class, @intCast(u2, tag_byte >> 6));
    const tag = @intToEnum(Tag, tag_byte);
    const length = try findLength(self);
}

/// Returns the length of element
fn findLength(self: *AsnIterator) error{InvalidLength}!usize {
    const first_byte = self.data[self.index];
    self.index += 1;
    if (first_byte & 0x80 == 0) {
        return first_byte; // single byte length
    }

    // The first 7 bits of the first byte contain the total
    // amount of bytes that represent the length.
    const byte_length = @truncate(u7, first_byte);
    if (byte_length > self.data[self.index..].len) return error.InvalidLength;
    if (byte_length > @sizeOf(usize)) @panic("TODO: Implement lengths larger than @sizeOf(usize))");
    const length = mem.readIntBig(usize, self.data[self.index..][0..@sizeOf(usize)]);
    self.index += byte_length;
    return length;
}
