"""GBK request lines and little-endian response frames.

SPDX-License-Identifier: CC-BY-SA-4.0
"""

import struct
from typing import Callable

MAX_FRAME_SIZE = 64 * 1024 * 1024
MAX_FIELD_UNITS = 512


class ProtocolError(Exception):
    """Invalid framing, encoding, or command response."""


def encode_request(*fields: str) -> bytes:
    """Encode fields without silently replacing unsupported characters.

    This is an envelope codec, not a command allowlist. Packet.encode()
    separately restricts the reference client's supported commands.
    """
    if not fields:
        raise ValueError("A request needs at least one field")
    for value in fields:
        if not isinstance(value, str) or not value:
            raise ValueError("Fields must be nonempty strings")
        units = len(value.encode("utf-16-le", errors="surrogatepass")) // 2
        if units > MAX_FIELD_UNITS:
            raise ValueError("A field exceeds the client limit")
        if any(c == "&" or ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("A field contains a delimiter or control character")
    line = "&".join(fields) + "\r\n"
    try:
        encoded = line.encode("gbk", errors="strict")
        if encoded.decode("gbk") != line:
            raise UnicodeError("GBK round trip changed the request")
        return encoded
    except UnicodeError:
        raise ValueError("A field cannot be represented exactly in GBK") from None


def decode_text(body: bytes) -> str:
    try:
        return body.decode("gb18030", errors="strict").rstrip("\0")
    except UnicodeError:
        raise ProtocolError("Response text is not valid GB18030") from None


def decode_length(header: bytes, maximum: int = MAX_FRAME_SIZE) -> int:
    if len(header) != 4:
        raise ProtocolError("The response length prefix must contain four octets")
    length = struct.unpack("<I", header)[0]
    if not 1 <= length <= maximum:
        raise ProtocolError("Response length is outside the client limit")
    return length


def read_frame(read_exact: Callable[[int], bytes]) -> bytes:
    """Read one frame; the caller provides an exact-read transport function."""
    size = decode_length(read_exact(4))
    body = read_exact(size)
    if len(body) != size:
        raise ProtocolError("Truncated response body")
    return body


class FrameDecoder:
    """Incremental framing example for fragmented or coalesced TCP data.

    feed() returns complete bodies and retains incomplete data. A decoder
    that raises ProtocolError must be discarded along with its connection.
    """

    def __init__(self, maximum: int = MAX_FRAME_SIZE):
        if not 1 <= maximum <= MAX_FRAME_SIZE:
            raise ValueError("Invalid frame limit")
        self.maximum = maximum
        self._buffer = bytearray()
        self._expected: int | None = None

    def feed(self, data: bytes) -> list[bytes]:
        self._buffer.extend(data)
        result = []
        while True:
            if self._expected is None:
                if len(self._buffer) < 4:
                    break
                self._expected = decode_length(self._buffer[:4], self.maximum)
                del self._buffer[:4]
            if len(self._buffer) < self._expected:
                break
            result.append(bytes(self._buffer[:self._expected]))
            del self._buffer[:self._expected]
            self._expected = None
        return result

    def finish(self) -> None:
        """Validate EOF; a partial prefix or body is a framing error."""
        if self._buffer or self._expected is not None:
            raise ProtocolError("Connection ended during a response frame")
