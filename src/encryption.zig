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

        /// performs a single read, attempts to decrypt the data if required
        /// and returns the length that was read from the connection.
        pub fn read(self: *Self, buf: []u8) ReadError!usize {
            if (self.reader_state == .start) {
                const record_header = try tls.Record.readFrom(self.inner_reader);

                if (record_header.record_type != .application_data and
                    record_header.record_type != .alert)
                {
                    return error.TODOWriteAlert;
                }

                inline for (ciphers.supported) |cipher| {
                    if (cipher.suite == self.cipher) {
                        self.reader_state = .{
                            .length = record_header.len,
                            .index = 0,
                        };
                        const blub = cipher.init(self.key_storage, self.server_seq, &record_header.toBytes());
                        _ = blub;
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
                                &@field(self.reader_state.reading.context, @tagName(cipher.suite)),
                                &alert_buf,
                                &encrypted,
                                &self.reader_state.reading.index,
                            );

                            assert(self.reader_state.reading.index == record_header.len);
                            try cipher.verify(
                                &@field(self.reader_state.reading.context, @tagName(cipher.suite)),
                                auth_tag,
                                record_header.len,
                            );
                        }
                    }
                    self.reader_state = .start;
                    self.server_seq += 1;

                    const alert = tls.Alert.fromBytes(encrypted);
                    if (alert.tag == .close_notify) {
                        return error.EndOfStream;
                    }
                    return alert.toError();
                }

                const min_length = math.min(record_header.len, buf.len);
            }
        }
    };
}
