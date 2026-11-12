"""A serialized TCP transport for the packet examples.

SPDX-License-Identifier: CC-BY-SA-4.0
"""

import ipaddress
import socket
import threading
import time
from contextlib import contextmanager
from typing import Callable, TypeVar

from . import packets
from .codec import ProtocolError, read_frame

T = TypeVar("T")


class Client:
    """One authenticated connection, shared by serialized read-only calls.

    Use as a context manager so both success and failure close the session.
    There is no automatic reconnect or native logout/heartbeat command.
    """

    def __init__(self, host: str, port: int, *, timeout: float = 8,
                 operation_timeout: float = 25):
        if not host or not 1 <= port <= 65535:
            raise ValueError("A server host and valid port are required")
        if timeout <= 0 or operation_timeout <= 0:
            raise ValueError("Timeouts must be positive")
        self.host = host
        self.port = port
        self.timeout = timeout
        self.operation_timeout = operation_timeout
        self._socket: socket.socket | None = None
        self._authenticated = False
        self._lock = threading.RLock()
        self._deadline: float | None = None

    def __enter__(self):
        with self._lock:
            if self._socket is not None:
                raise RuntimeError("The client is already connected")
            self._socket = socket.create_connection((self.host, self.port), self.timeout)
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        with self._lock:
            connection, self._socket = self._socket, None
            self._authenticated = False
            if connection is not None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                finally:
                    connection.close()

    @contextmanager
    def transaction(self):
        """Keep a cursor workflow together, with one bounded execution time."""
        with self._lock:
            previous = self._deadline
            if previous is None:
                self._deadline = time.monotonic() + self.operation_timeout
            try:
                yield
            finally:
                self._deadline = previous

    def _apply_timeout(self) -> socket.socket:
        if self._socket is None:
            raise RuntimeError("Use the client inside a with block")
        remaining = (self._deadline or time.monotonic()) - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("The LeHua query deadline expired")
        self._socket.settimeout(min(self.timeout, remaining))
        return self._socket

    def _read_exact(self, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            part = self._apply_timeout().recv(min(65536, size - len(result)))
            if not part:
                raise ProtocolError("Connection ended during a response frame")
            result.extend(part)
        return bytes(result)

    def send(self, packet: packets.Packet[T]) -> T:
        wire = packet.encode()  # Validate before writing any bytes.
        is_login = packet.fields[0] == "teacherlogin"
        with self.transaction():
            if is_login and self._authenticated:
                raise RuntimeError("The connection is already authenticated")
            if not is_login and not self._authenticated:
                raise RuntimeError("Authenticate this connection first")
            try:
                self._apply_timeout().sendall(wire)
                result = packet.parse(read_frame(self._read_exact))
                if is_login:
                    self._authenticated = True
                return result
            except (OSError, ProtocolError):
                # Invalid/uncertain responses are never reused for another query.
                self.close()
                raise

    def login(self, user: str, password: str) -> None:
        try:
            ipv4 = ipaddress.ip_address(self.host).version == 4
        except ValueError:
            ipv4 = False
        self.send(packets.login(user, password, None if ipv4 else self.host))

    @staticmethod
    def _check_page(page: packets.Page, expected: int, total: int,
                    size: int) -> None:
        expected_size = min(size, total - (expected - 1) * size)
        if (page.page != expected or page.total != total
                or len(page.rows) != expected_size):
            raise ProtocolError("List contents changed during pagination")

    def page(self, factory: Callable[[bool], packets.Packet[packets.Page[T]]],
             number: int = 1) -> packets.Page[T]:
        """Replay first/next commands to a requested one-based page.

        Example: client.page(packets.teachers, 2), or a factory wrapping
        packets.students(roster, next_page).
        """
        if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 1000:
            raise ValueError("Page number must be between 1 and 1000")
        with self.transaction():
            first = self.send(factory(False))
            size = len(first.rows) or 1
            pages = max(1, (first.total + size - 1) // size)
            if number > pages:
                raise ValueError("The requested page does not exist")
            self._check_page(first, 1, first.total, size)
            result = first
            for current in range(2, number + 1):
                result = self.send(factory(True))
                self._check_page(result, current, first.total, size)
            return result

    def all_students(self, roster: str) -> tuple[packets.Student, ...]:
        """Read a whole roster; preserve numbers as strings and ignore end_raw."""
        with self.transaction():
            first = self.send(packets.students(roster))
            size = len(first.rows) or 1
            self._check_page(first, 1, first.total, size)
            rows = list(first.rows)
            page = 1
            while len(rows) < first.total:
                page += 1
                following = self.send(packets.students(roster, True))
                self._check_page(following, page, first.total, size)
                rows.extend(following.rows)
            return tuple(rows)
