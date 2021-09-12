//! Decoder for the ASN.1 DER encoding rules.
//! DER encoding contains a tag, length and value for each element.
//! Note: This means it only supports DER encoding rules, not BER and CER
//! as the only use case is for X.509 support.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const BigInt = std.math.big.int.Const;
const testing = std.testing;

/// A subset of ASN.1 tag types as specified by the spec.
/// We only define the tags that are required for PEM certificates.
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
    sequence = 0x30,
    set = 0x31,
    context = 255, // Used by decoder, but is not a valid Tag.
    _,
};

/// Represents the value of an element that was encoded using ASN.1 DER encoding rules.
pub const Value = union(Tag) {
    integer: BigInt, // can represent integers up to 126 bytes.
    bit_string: BitString,
    octet_string: []const u8,
    object_identifier: struct {
        data: [16]u32,
        len: u5,
    },
    utf8_string: []const u8,
    printable_string: []const u8,
    ia5_string: []const u8,
    utc_time: []const u8,
    sequence: []const Value,
    set: []const Value,
    context: struct {
        value: *const Value,
        id: u8,
    },

    /// Frees any memory that was allocated while constructed
    /// a given `Value`
    pub fn deinit(self: Value, gpa: *Allocator) void {
        switch (self) {
            .integer => |int| gpa.free(int.limbs),
            .sequence => |seq| for (seq) |val| {
                val.deinit(gpa);
            } else gpa.free(seq),
            .set => |set| for (set) |val| {
                val.deinit(gpa);
            } else gpa.free(set),
            .context => |ctx| {
                ctx.value.deinit(gpa);
                gpa.destroy(ctx.value);
            },
            else => {},
        }
    }
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
    /// Allocator is used to allocate memory for limbs (as we must swap them due to endianness),
    /// as well as allocate a Value for sets and sequences.
    /// Memory can be freed easily by calling `deinit` on a `Value`.
    gpa: *Allocator,

    pub const Error = error{
        /// Tag found is either not supported or incorrect
        InvalidTag,
        OutOfMemory,
        /// Index has reached the end of `data`'s size
        EndOfData,
        /// The length could not be decoded and is malformed
        InvalidLength,
    };

    /// Initializes a new decoder instance for the given binary data.
    pub fn init(gpa: *Allocator, data: []const u8) Decoder {
        return .{ .index = 0, .data = data, .gpa = gpa };
    }

    /// Decodes from the current index into `data` and returns
    /// a `Value`
    pub fn decode(self: *Decoder) Error!Value {
        const tag = self.decodeTag() catch |err| switch (err) {
            error.ContextSpecific => {
                const tag_byte = try self.nextByte();
                const length = try self.findLength();
                const current_index = self.index;
                const context = try self.gpa.create(Value);
                errdefer self.gpa.destroy(context);

                context.* = try self.decode();
                if (self.index - current_index != length) {
                    return error.InvalidLength;
                }
                return Value{ .context = .{ .value = context, .id = tag_byte - 0xa0 } };
            },
            else => |e| return e,
        };
        return switch (tag) {
            .bit_string => Value{ .bit_string = try self.decodeBitString() },
            .integer => Value{ .integer = try self.decodeInt() },
            .octet_string, .ia5_string, .utf8_string, .printable_string => {
                const string_value = try self.decodeString();
                return @as(Value, switch (tag) {
                    .octet_string => .{ .octet_string = string_value },
                    .ia5_string => .{ .ia5_string = string_value },
                    .utf8_string => .{ .utf8_string = string_value },
                    .printable_string => .{ .printable_string = string_value },
                    .utc_time => .{ .utc_time = string_value },
                    else => unreachable,
                });
            },
            .object_identifier => try self.decodeObjectIdentifier(),
            .sequence, .set => try self.decodeSequence(tag),
            else => unreachable, // unsupported tags are caught by decodeTag()
        };
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
    pub fn decodeBitString(self: *Decoder) !BitString {
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
        return BitString{ .data = string, .bit_length = @intCast(u8, total_bit_length) };
    }

    /// Decodes the data into the given string tag.
    /// If the expected data contains a bit string, use `decodeBitString`.
    pub fn decodeString(self: *Decoder) ![]const u8 {
        const length = try self.findLength();
        defer self.index += length;
        return self.data[self.index..][0..length];
    }

    /// Decodes an integer value, while allocating the memory for the limbs
    /// as we must ensure the endianness is correct.
    /// BigInt expects LE bytes, whereas certificates are BE.
    pub fn decodeInt(self: *Decoder) !BigInt {
        const length = try self.findLength();

        const byte = try self.nextByte();
        const is_positive = byte == 0x00 and length > 1;
        const actual_length = length - @boolToInt(is_positive);

        const limb_count = std.math.divCeil(usize, actual_length, @sizeOf(usize)) catch unreachable;
        const limb_bytes = try self.gpa.dupe(u8, self.data[self.index..][0..actual_length]);
        mem.reverse(u8, limb_bytes);
        self.index += length;

        if (!is_positive) {
            limb_bytes[0] = byte & ~@as(u8, 0x80);
        }

        return BigInt{
            .limbs = @ptrCast([*]usize, @alignCast(@alignOf([*]usize), limb_bytes.ptr))[0..limb_count],
            .positive = is_positive or (byte & 0x80) == 0x00,
        };
    }

    /// Decodes data into an object identifier
    pub fn decodeObjectIdentifier(self: *Decoder) !Value {
        const length = try self.findLength();
        const initial_byte = try self.nextByte();
        var identifier = Value{ .object_identifier = .{ .data = undefined, .len = 0 } };
        identifier.object_identifier.data[0] = initial_byte / 40;
        identifier.object_identifier.data[0] = initial_byte % 40;

        var out_idx: u5 = 2;
        var index: usize = 0;
        while (index < length - 1) {
            var current: u32 = 0;
            var current_byte = try self.nextByte();
            index += 1;
            while (current_byte & 0x80 == 0x80) : (index += 1) {
                current *= 128;
                current += @as(u32, current_byte & ~@as(u8, 0x80)) * 128;
                current_byte += current_byte;
            } else {
                current += current_byte;
            }
            identifier.object_identifier.data[out_idx] = current;
            out_idx += 1;
        }
        identifier.object_identifier.len = out_idx;
        self.index += length;
        return identifier;
    }

    pub fn decodeSequence(self: *Decoder, tag: Tag) !Value {
        const length = try self.findLength();
        var value_list = std.ArrayList(Value).init(self.gpa);
        errdefer for (value_list.items) |val| {
            val.deinit(self.gpa);
        } else value_list.deinit();

        while (self.index < length) {
            const value = try value_list.addOne();
            value.* = try self.decode();
        }

        const final_list = value_list.toOwnedSlice();
        return switch (tag) {
            .sequence => Value{ .sequence = final_list },
            .set => Value{ .sequence = final_list },
            else => unreachable,
        };
    }
};

test "Decode int" {}

test "Octet string" {
    var bytes: []const u8 = &.{ 0x04, 0x04, 0x03, 0x02, 0x06, 0xA0 };
    var decoder = Decoder.init(testing.allocator, bytes);
    const value = try decoder.decode();
    defer value.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, bytes[2..], value.octet_string);
}
