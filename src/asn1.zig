//! Decoder for the ASN.1 DER encoding rules.
//! DER encoding contains a tag, length and value for each element.
//! Note: This means it only supports DER encoding rules, not BER and CER
//! as the only use case is for X.509 support.

const std = @import("std");
const mem = std.mem;
const BigInt = std.math.big.int.Const;

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
    bit_string: struct {
        data: [*]const u8,
        len: usize,
    },
    octet_string: []const u8,
    object_identifier: struct {
        data: [16]u32,
        len: u5,
    },
    utf8_string: []const u8,
    printable_string: []const u8,
    ia5_string: []const u8,
    utc_time: []const u8,
    generalized_time: []const u8,
    sequence: []const Value,
    set: []const Value,
};

/// Represents a string which may contain unused bits
pub const BitString = struct {
    /// Contains the string as well as the unused bits
    data: []const u8,
    /// The total amount of bits of the string
    bit_length: u8,
};

/// Decodes ans.1 binary data into Zig types
pub const Decoder = struct {
    /// Internal index into the data.
    /// Should not be tempered with outside the Decoder.
    index: usize,
    /// The ans.1 binary data that is being decoded by the current instance.
    data: []const u8,

    /// Initializes a new decoder instance for the given binary data.
    pub fn init(data: []const u8) Decoder {
        return .{ .index = 0, .data = data };
    }

    /// Decodes the binary data into given type `T`.
    /// Will call the `decode` declaration on the given type, and therefore
    /// requires the struct type to have a `decode` method with a pointer
    /// to itself and a pointer to a `Decode` instance like e.g.
    ///
    /// fn (self: *T, decoder: *Decoder) !void
    pub fn decode(self: Decoder, comptime T: type) !T {
        if (@typeInfo(T) != .Struct) {
            @compileError("Type " ++ @typeName(T) ++ " must be a struct type.");
        }
        if (!comptime std.meta.trait.hasFn("decode")(T)) {
            @compileError("Type " ++ @typeName(T) ++ " has no 'decode' declaration.");
        }
        var value: T = undefined;

        const tag_byte = try self.nextByte();
        if (tag_byte != @enumToInt(Tag.sequence)) {
            return error.UnexpectedTag;
        }
        const expected_length = try self.findLength();
        const current_index = self.index;
        try value.decode(self);

        if (expected_length != self.index - current_index) {
            return error.MismatchingLength;
        }
    }

    /// Reads the next byte from the data and increments the index.
    /// Returns error.EndOfData if reached the end of the data.
    fn nextByte(self: *Decoder) error{EndOfData}!u8 {
        if (self.index >= self.data.len) return error.EndOfData;
        defer self.index += 1;
        return self.data[self.index];
    }

    fn decodeTag(self: *Decoder) error{ EndOfData, InvalidTag, ContextSpecific }!Tag {
        const tag_byte = try self.nextByte();
        return std.meta.intToEnum(Tag, tag_byte) catch blk: {
            if (tag_byte & 0xC0 == 0x80) {
                self.index -= 1;
                break :blk error.ContextSpecific;
            }
            break :blk error.InvalidTag;
        };
    }

    /// Returns the length of the current element being decoded.
    fn findLength(self: *Decoder) error{InvalidLength}!usize {
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

    /// Decodes the data into a `BitString`
    pub fn decodeBitString(self: *Decoder) error{ InvalidTag, InvalidLength, EndOfData }!BitString {
        const tag_byte = try self.nextByte();
        if (tag_byte != @enumToInt(Tag.bit_string)) {
            return error.InvalidTag;
        }
        const length = try self.findLength();
        const extra_bits = try self.nextByte();
        const total_bit_length = (length - 1) * 8 - extra_bits;
        const string_length = std.math.divCeil(usize, total_bit_length, 8) catch unreachable;
        const string = self.data[self.index..][0..string_length];
        self.index += length;
        return BitString{ .data = string, .bit_length = total_bit_length };
    }

    /// Decodes the data into the given string tag.
    /// If the expected data contains a bit string, use `decodeBitString`.
    pub fn decodeString(self: *Decoder, tag: Tag) error{ InvalidTag, InvalidLength, EndOfData }![]const u8 {
        std.debug.assert(switch (tag) {
            .octet_string, .ia5_string, .utf8_string, .printable_string => false,
            else => true,
        }); // Given `Tag` is not a valid string tag
        const tag_byte = try self.nextByte();
        if (tag_byte != @enumToInt(tag)) {
            return error.InvalidTag;
        }
        const length = try self.findLength();
        defer self.index += length;
        return self.data[self.index..][0..length];
    }

    pub fn decodeInt(self: *Decoder) !BigInt {
        const tag = try self.decodeTag();
        if (tag != .integer) return error.InvalidTag;
    }

    const ContextSpecificOptions = struct {
        specificity: enum { optional },
        decodeFn: anytype,
    };

    pub fn decodeContextSpecific(
        self: *Decoder,
        comptime options: ContextSpecificOptions,
    ) !ReturnType(@TypeOf(options.decodeFn)) {
        _ = self;
    }
};

fn ReturnType(comptime T: type) type {
    return @typeInfo(T).Fn.ReturnType;
}

test "Decode DER asn.1" {
    const AlgorithmIdentifier = struct {
        algorithm: u32,
        parameters: ?[]const u8,
    };
    const Extension = struct {
        extn_id: []const u8,
        critical: bool,
        extn_value: []const u8,
    };
    const Validity = struct {
        not_before: i64,
        not_after: i64,
    };
    const SubjectPublicKeyInfo = struct {
        algorithm: AlgorithmIdentifier,
        subject_public_key: []const u8,
    };
    const TBSCertificate = struct {
        version: u2,
        serial_number: u32,
        signature: AlgorithmIdentifier,
        issuer: []const u8,
        validity: Validity,
        subject: []const u8,
        subject_public_key_info: SubjectPublicKeyInfo,
        issuer_unique_id: ?[]const u8,
        subject_unique_id: ?[]const u8,
        extensions: []const Extension,
    };
    const Certificate = struct {
        tbs_certificate: TBSCertificate,
        signature_algorithm: AlgorithmIdentifier,
        signature_value: BitString,

        const Cert = @This();

        fn decode(self: *Cert, decoder: *Decoder) !void {
            self.tbs_certificate = try decoder.decode(TBSCertificate);
            self.signature_algorithm = try decoder.decode(AlgorithmIdentifier);
            self.signature_value = try decoder.decodeBitString();
        }
    };

    var decoder = Decoder.init("");
    const certificate = try decoder.decode(Certificate);
    _ = certificate;
}
