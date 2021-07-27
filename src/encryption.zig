//! Contains a reader and writer that will encrypt
//! or decrypt tls records before sending to the peer
//! or providing it to the caller. Meaning callers will get
//! access to actual data from the peer, without having to deal with
//! decryption based on what was agreed upon during handshake.

const std = @import("std");
const tls = @import("tls.zig");
const ciphers = @import("ciphers.zig");
const io = std.io;
const math = std.math;
const assert = std.debug.assert;

pub fn EncryptedReadWriter(comptime ReaderType: type, comptime WriterType: type) type {
    return struct {
        const Self = @This();

        /// Writer we write to after encrypting the user's data.
        inner_writer: WriterType,
        /// Reader we read from containing the encrypted data, and decrypt
        /// before passing the data to the user.
        inner_reader: ReaderType,
        /// Cipher used to encrypt and decrypt our data.
        cipher: tls.CipherSuite,
        /// The state of the reader, to ensure we decrypt data correctly as the user
        /// may provide a buffer that is not large enough to read the entire payload message,
        /// before we can decrypt it.
        reader_state: State = .start,
        /// Storage of our server and client keys, accessible in a generic way where a given
        /// cipher type is used to construct the lengths correctly.
        key_storage: ciphers.KeyStorage,
        /// Sequences of encrypted data we have received from the client. This will be xor'd
        /// with the client nonce when decrypting the data.
        client_seq: u64 = 1,
        /// Sequences of data we have encrypted and set to the client. This will be xor'd
        /// with the server nonce when encrypting the data.
        server_seq: u64 = 1,

        const State = union(enum) {
            start: void,
            reading: struct {
                length: u16,
                index: usize,
                context: Context(ciphers.supported),
            },
        };

        /// Represents the type of the reader that will be returned when `reader()` is called.
        pub const Reader = io.Reader(*Self, ReadError, read);
        /// Represents the type of the writer that will be returned when `writer()` is called.
        pub const Writer = io.Writer(*Self, WriteError, write);

        /// Error set containing the possible errors when performing reads.
        pub const ReadError = ReaderType.Error || tls.Alert.Error || error{ AuthenticationFailed, EndOfStream };
        /// Error set containing the possible errors when performing writes.
        pub const WriteError = WriterType.Error;

        /// Initializes a new `EncryptedReadWriter` generic, from a given
        /// `ReaderType` and `WriterType`. This construct allows a user to read decrypted
        /// data and send encrypted data.
        /// The `KeyStorage` must be filled with all key data to ensure the keys can be accessed
        /// when data is being decrypted or encrypted.
        pub fn init(reader: ReaderType, writer: WriterType, key_storage: ciphers.KeyStorage) Self {
            return .{ .inner_writer = writer, .inner_reader = reader, .key_storage = key_storage };
        }

        /// Returns a generic `Reader`
        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        /// Returns a generic `Writer`
        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        /// Returns a pointer to the context of the currently used cipher.
        ///
        /// User must ensure `reader_state` is `reading`.
        /// User must ensure given `suite` is a supported cipher suite as found
        /// in `tls.supported`.
        fn context(self: *Self, comptime suite: tls.CipherSuite) *ciphers.TypeFromSuite(cipher) {
            return for (supported) |cipher| {
                if (cipher.suite == suite) {
                    break &@field(self.reader_state.reading.context, @tagName(suite));
                }
            } else unreachable; // User must provide supported cipher suite
        }

        /// Returns the index of the current context as a mutable pointer.
        ///
        /// NOTE: User must ensure current state is `reader_state`
        inline fn index(self: *Self) *usize {
            return &self.reader_state.reading.index;
        }

        /// Returns the length of the current record.
        ///
        /// NOTE: User must ensure current state is `reader_state`
        inline fn recordLength(self: Self) u16 {
            return self.reader_state.reading.length;
        }

        /// performs a single read, attempts to decrypt the data if required
        /// and returns the length that was read from the connection.
        pub fn read(self: *Self, buf: []u8) ReadError!usize {
            if (self.reader_state == .start) {
                const record_header = try tls.Record.readFrom(self.inner_reader);

                if (record_header.record_type != .application_data and
                    record_header.record_type != .alert)
                {
                    const alert = tls.Alert.init(.unexpected_message, .fatal);
                    try alert.writeTo(self.writer());
                    return error.UnexpectedMessage;
                }

                inline for (ciphers.supported) |cipher| {
                    if (cipher.suite == self.cipher) {
                        self.reader_state = .{
                            .length = record_header.len - 16, // minus auth tag
                            .index = 0,
                            .context = cipher.init(
                                self.key_storage,
                                self.client_seq,
                                &record_header.toBytes(),
                            ),
                        };
                    }
                }

                if (record_header.record_type == .alert) {
                    var encrypted: [2]u8 = undefined;
                    var auth_tag: [16]u8 = undefined;
                    try self.inner_reader.readNoEof(&encrypted);
                    try self.inner_reader.readNoEof(&auth_tag);

                    var alert_buf: [2]u8 = undefined;
                    inline for (tls.ciphers) |cipher| {
                        if (cipher.suite == self.cipher) {
                            cipher.decryptPartial(
                                self.context(cipher.suite),
                                &alert_buf,
                                &encrypted,
                                self.index(),
                            );

                            assert(self.index().* == self.recordLength());
                            try cipher.verify(
                                self.context(cipher.suite),
                                auth_tag,
                                self.recordLength(),
                            );
                        }
                    }
                    self.reader_state = .start;
                    self.client_seq += 1;

                    const alert = tls.Alert.fromBytes(encrypted);
                    if (alert.tag == .close_notify) {
                        return error.EndOfStream;
                    }
                    return alert.toError();
                }

                // decrypt in max sizes of 1024 bytes
                // TODO: Check if we increase this.
                // The reason we do this is because we need double buffers,
                // one to store encrypted data, and the user provided buffer
                // to write the decrypted data to.
                // This will never read more than record length.
                const max_length = math.min(math.min(self.recordLength(), 1024), buf.len);
                var encrypted: [1024]u8 = undefined;

                const read_len = try self.inner_reader.read(encrypted[0..max_length]);
                inline for (ciphers.supported) |cipher| {
                    if (cipher.suite == self.cipher) {
                        cipher.decryptPartial(
                            self.context(cipher.suite),
                            buffer[0..read_len],
                            encrypted[0..read_len],
                            self.index(),
                        );

                        // If we read all data, verify its authentication
                        if (self.index().* == self.recordLength()) {
                            const auth_tag = try self.readAuthTag();
                            try cipher.verify(
                                self.context(cipher.suite),
                                auth_tag,
                                self.recordLength(),
                            );

                            self.client_seq += 1;
                            self.reader_state = .start;
                        }
                    }
                }
                return read_len;
            }
            // state is `reading`
            const state = &self.reader_state.reading;
            const max_len = math.min(math.min(buf.len, 1024), state.length - state.index);

            var encrypted: [1024]u8 = undefined;
            const read_len = try self.inner_reader.read(encrypted[0..max_len]);

            inline for (ciphers.supported) |cipher| {
                if (cipher.suite == self.suite) {
                    cipher.decryptPartial(
                        &state.context,
                        buffer[0..read_len],
                        encrypted[0..read_len],
                        &state.index,
                    );

                    if (state.index == state.length) {
                        const auth_tag = try self.readAuthTag();
                        try cipher.verify(
                            &state.context,
                            auth_tag,
                            state.length,
                        );

                        self.client_seq += 1;
                        self.reader_state = .start;
                    }
                }
            }
        }

        /// Reads an authentication tag from the inner reader.
        /// Returns `EndOfStream` if stream is not long enough.
        fn readAuthTag(self: *Self) ReadError![16]u8 {
            var buf: [16]u8 = undefined;
            try self.inner_reader.readNoEof(&buf);
            return buf;
        }
    };
}

/// Creates a union where each tag is a type corresponding
/// to a given list of ciphers.
fn Context(comptime cipher_suites: []const type) type {
    var fields: [cipher_suites.len]std.builtin.TypeInfo.UnionField = undefined;
    for (cipher_suites) |cipher, index| {
        fields[index] = .{
            .name = @tagName(cipher.suite),
            .field_type = cipher.Context,
            .alignment = @alignOf(cipher.Context),
        };
    }

    return @Type(.{
        .Union = .{
            .layout = .Extern,
            .tag_type = null,
            .fields = &fields,
            .decls = &.{},
        },
    });
}
