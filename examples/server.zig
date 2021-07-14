const tls = @import("feilich");
const std = @import("std");
const net = std.net;

pub fn main() !void {
    var server = net.StreamServer.init(.{ .reuse_address = true });
    defer server.close();
    try server.listen(net.Address.initIp4(.{ 0, 0, 0, 0 }, 8080));

    const tls_server = tls.Server.init(std.heap.page_allocator, "", "");

    while (true) {
        const connection = try server.accept();
        const stream = connection.stream;

        tls_server.connect(stream.reader(), stream.writer()) catch |err| {
            std.log.debug("Error: {s}\n", .{@errorName(err)});
            return;
        };
    }
}
