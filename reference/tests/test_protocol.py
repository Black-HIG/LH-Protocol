"""Offline wire-format and local-loopback tests; never contact LeHua.

SPDX-License-Identifier: CC-BY-SA-4.0
"""

import contextlib
import re
import socket
import struct
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from lehua import Client, ProtocolError, packets
from lehua.codec import FrameDecoder, MAX_FRAME_SIZE, decode_length, decode_text, encode_request, read_frame


def frame(body: bytes) -> bytes:
    return struct.pack("<I", len(body)) + body


def student_page(page: int, numbers: list[str], total: int = 3) -> bytes:
    rows = "".join(f"<kh>{number}</kh><st>Example</st><sc>DemoSchool</sc>"
                   "<cs>Class 1</cs><tp></tp>" for number in numbers)
    return (f"GetStudentListSuccess<a_c>{total}</a_c><c_p>{page}</c_p>"
            f"<end>unspecified</end>{rows}").encode("gb18030")


@contextlib.contextmanager
def server(script):
    """One local connection with a fixed request/response script."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    errors = []
    observed = []
    eof = threading.Event()

    def run():
        try:
            with listener.accept()[0] as connection:
                connection.settimeout(3)
                reader = connection.makefile("rb")
                try:
                    for expected, body in script:
                        actual = reader.readline()
                        observed.append(actual)
                        if actual != expected:
                            raise AssertionError("Unexpected request in local fixture")
                        if body is None:
                            continue  # Wait for client timeout/closure without a response.
                        data = frame(body)
                        # Deliberately fragment the length prefix and body.
                        for chunk in (data[:1], data[1:3], data[3:6], data[6:]):
                            if chunk:
                                connection.sendall(chunk)
                    if reader.read(1) == b"":
                        eof.set()
                    else:
                        raise AssertionError("Unexpected extra request")
                finally:
                    reader.close()
        except BaseException as error:
            errors.append(error)
        finally:
            listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], observed, eof
    finally:
        thread.join(4)
        listener.close()
        if thread.is_alive():
            raise AssertionError("Local fixture server failed to terminate")
        if errors:
            raise errors[0]


class CodecTests(unittest.TestCase):
    def test_request_vector_and_chinese_round_trip(self):
        self.assertEqual(encode_request("setting", "getXmList").hex(),
                         "73657474696e6726676574586d4c6973740d0a")
        self.assertEqual(encode_request("setting", "示例考试", "数学").decode("gbk"),
                         "setting&示例考试&数学\r\n")

    def test_invalid_fields_never_silently_encode(self):
        for value in ("", "a&b", "a\r\nb", "a\0b", "a\x7fb", "😀", "x" * 513):
            with self.subTest(value_type=repr(value[:5])):
                with self.assertRaises(ValueError):
                    encode_request("setting", value)
        self.assertTrue(encode_request("x" * 512).endswith(b"\r\n"))
        with self.assertRaises(ValueError):
            encode_request()

    def test_text_nuls_and_invalid_encoding(self):
        self.assertEqual(decode_text("示例".encode("gb18030") + b"\0\0"), "示例")
        with self.assertRaises(ProtocolError):
            decode_text(b"\x81")

    def test_fragmentation_and_coalesced_frames(self):
        wire = bytes.fromhex("03000000414243010000005a")
        for split in range(len(wire) + 1):
            with self.subTest(split=split):
                decoder = FrameDecoder()
                self.assertEqual(decoder.feed(wire[:split]) + decoder.feed(wire[split:]),
                                 [b"ABC", b"Z"])
                decoder.finish()
        decoder = FrameDecoder()
        result = []
        for octet in wire:
            result.extend(decoder.feed(bytes([octet])))
        self.assertEqual(result, [b"ABC", b"Z"])
        decoder.finish()

    def test_length_bounds_before_body_allocation(self):
        self.assertEqual(decode_length(struct.pack("<I", MAX_FRAME_SIZE)), MAX_FRAME_SIZE)
        for size in (0, MAX_FRAME_SIZE + 1):
            with self.assertRaises(ProtocolError):
                FrameDecoder().feed(struct.pack("<I", size))
        with self.assertRaises(ProtocolError):
            decode_length(b"\x01")

    def test_partial_eof(self):
        for wire in (b"\x01", frame(b"ABC")[:-1]):
            decoder = FrameDecoder()
            decoder.feed(wire)
            with self.assertRaises(ProtocolError):
                decoder.finish()
        parts = iter((struct.pack("<I", 3), b"AB"))
        with self.assertRaises(ProtocolError):
            read_frame(lambda _: next(parts))


class PacketTests(unittest.TestCase):
    def test_confirmed_request_forms_and_selectors(self):
        forms = [
            (packets.login("demo-user", "demo-password"), "teacherlogin&demo-user&demo-password"),
            (packets.login("demo-user", "demo-password", "server.example.invalid"),
             "teacherlogin&demo-user&demo-password&server.example.invalid"),
            (packets.projects(), "setting&getXmList"),
            (packets.progress("Demo", "Math"), "setting&getAllProgressDetail&Demo&Math"),
            (packets.score_files("Demo"), "setting&getScoreFileList&Demo"),
            (packets.score_archive("Demo", "Math.zip"), "setting&downScoreFile&Demo&Math.zip"),
            (packets.rosters(), "setting&GetGradeList"),
            (packets.subjects(), "setting&GetSubjectList"),
            (packets.teachers(), "setting&GetTeacherList"),
            (packets.teachers(True), "setting&GetTeacherListNext"),
            (packets.students("DemoRoster"), "setting&GetStudentList&DemoRoster"),
            (packets.students("DemoRoster", True), "setting&GetStudentListNext&DemoRoster"),
            (packets.paper_summary("Demo", "Math", "00012345"), "getsudentSj&Demo&Math&00012345&head"),
        ]
        for side in ("front", "back"):
            forms.append((packets.paper_image("Demo", "Math", "00012345", side),
                          f"getsudentSj&Demo&Math&00012345&{side}"))
        for packet, expected in forms:
            self.assertEqual(packet.encode(), (expected + "\r\n").encode("gbk"))

    def test_unverified_or_mutating_commands_rejected(self):
        for fields in (("setting", "GetStudentListSearch", "Demo", "prefix"),
                       ("setting", "deleteTeacher", "demo"),
                       ("setting", "getXmList", "extra")):
            with self.assertRaises(ValueError):
                packets.Packet("unsupported", fields, lambda body: body).encode()

    def test_login_repr_and_error_do_not_echo_credentials(self):
        packet = packets.login("fictional-user", "fictional-password")
        self.assertNotIn("fictional-user", repr(packet))
        self.assertNotIn("fictional-password", repr(packet))
        self.assertIsNone(packet.parse(b"LoginSuccess&unused"))
        with self.assertRaises(ProtocolError) as error:
            packet.parse(b"failure&fictional-password")
        self.assertNotIn("fictional-password", str(error.exception))

    def test_document_exchange_fixtures(self):
        document = Path(__file__).resolve().parents[2] / "protocol.md"
        text = document.read_text(encoding="utf-8")
        bodies = re.findall(r"^S -> C body: ([^\r\n]+)", text, re.M)
        def body(prefix):
            return next(value for value in bodies if value.startswith(prefix)).encode("gb18030")
        projects = packets.projects().parse(body("getXmList&"))
        self.assertEqual(projects[0].name, "DemoExam(DemoRoster)")
        self.assertEqual(projects[0].subjects, ("Math",))
        progress = packets.progress("Demo", "Math").parse(body("getYjProgress&"))
        self.assertEqual(progress.groups[0].reviewed, progress.groups[0].total)
        self.assertEqual(progress.groups[0].unreviewed, 0)
        self.assertEqual(progress.schools[0].assigned, 0)
        self.assertGreater(progress.schools[0].reviewed, 0)
        self.assertEqual(packets.score_files("Demo").parse(body("getScoreFileListSuccess")), ("Math.zip",))
        for line in re.findall(r"^C -> S: ([^\r\n]+)\\r\\n$", text, re.M):
            self.assertEqual(encode_request(*line.split("&")), (line + "\r\n").encode("gbk"))

    def test_zip_and_jpeg_offsets(self):
        zip_bytes = b"PK\x03\x04example"
        self.assertEqual(packets.score_archive("Demo", "Math.zip").parse(
            b"downScoreFileSuccess" + zip_bytes), zip_bytes)
        jpeg = b"\xff\xd8\xffexample"
        # Non-text padding is intentional: its layout is not established.
        header = b"getsudentSjok".ljust(40, b"\xff")
        self.assertEqual(packets.paper_image("Demo", "Math", "00012345", "front").parse(header + jpeg), jpeg)
        with self.assertRaises(ProtocolError):
            packets.score_archive("Demo", "Math.zip").parse(b"downScoreFileSuccessBAD")
        with self.assertRaises(ProtocolError):
            packets.paper_image("Demo", "Math", "00012345", "front").parse(header + b"BAD")

    def test_absence_and_zero_score_are_distinct(self):
        packet = packets.paper_summary("Demo", "Math", "00012345")
        header = b"getsudentSjHeadOk".ljust(40, b"\0")
        self.assertEqual(packet.parse(header + b"<zf>0</zf>"), 0)
        self.assertEqual(packet.parse(header + b"<zf>93.5</zf>"), 93.5)
        for body in (b"getsudentSjno", header, header + b"<zf>NaN</zf>", header + b"<zf>unknown</zf>"):
            self.assertIsNone(packet.parse(body))
        self.assertIsNone(packets.paper_image("Demo", "Math", "00012345", "back").parse(b"getsudentSjno"))

    def test_directory_parsers_preserve_strings_and_unknown_fields(self):
        students = packets.students("Demo").parse(student_page(1, ["00012345", "00012346"]))
        self.assertEqual(students.rows[0].number, "00012345")
        self.assertEqual(students.end_raw, "unspecified")
        self.assertEqual(students.rows[0].tp_raw, "")
        teacher = (b"<a_c>1</a_c><c_p>1</c_p><end>unknown</end>"
                   b"<teacher><nm>demo</nm><rlnm>Example</rlnm><js>role</js>"
                   b"<kemu>Math</kemu><sc>DemoSchool</sc><gd>Demo</gd></teacher>")
        self.assertEqual(packets.teachers().parse(teacher).rows[0].username, "demo")
        for malformed in (teacher.replace(b"</gd>", b""), teacher.replace(b"<c_p>1</c_p>", b"")):
            with self.assertRaises(ProtocolError):
                packets.teachers().parse(malformed)
        self.assertEqual(packets.rosters().parse(b"GetGradeListSuccess<grade> Demo </grade><grade>Demo</grade>"), ("Demo",))
        self.assertEqual(packets.subjects().parse(b"GetSubjectListSuccess<subject>Math</subject>"), ("Math",))


class ClientTests(unittest.TestCase):
    def test_login_once_pagination_and_cleanup(self):
        script = [
            (encode_request("teacherlogin", "demo-user", "demo-password"), b"loginsuccess&"),
            (packets.projects().encode(), b'getXmList&success&<xm name="Demo"><subject>Math</subject></xm>'),
            (packets.students("Demo").encode(), student_page(1, ["00012345", "00012346"])),
            (packets.students("Demo", True).encode(), student_page(2, ["00022345"])),
        ]
        with server(script) as (port, observed, eof):
            with Client("127.0.0.1", port) as client:
                client.login("demo-user", "demo-password")
                self.assertEqual(client.send(packets.projects())[0].name, "Demo")
                numbers = [row.number for row in client.all_students("Demo")]
                self.assertEqual(numbers, ["00012345", "00012346", "00022345"])
            self.assertTrue(eof.wait(1))
            self.assertEqual(sum(line.startswith(b"teacherlogin&") for line in observed), 1)

    def test_page_replay_and_changed_total(self):
        login = (encode_request("teacherlogin", "demo-user", "demo-password"), b"loginsuccess&")
        first = (packets.students("Demo").encode(), student_page(1, ["00012345", "00012346"]))
        second = (packets.students("Demo", True).encode(), student_page(2, ["00022345"]))
        with server([login, first, second]) as (port, _, eof):
            with Client("127.0.0.1", port) as client:
                client.login("demo-user", "demo-password")
                page = client.page(lambda next_page: packets.students("Demo", next_page), 2)
                self.assertEqual(page.page, 2)
                self.assertEqual(page.rows[0].number, "00022345")
            self.assertTrue(eof.wait(1))
        changed = (second[0], student_page(2, ["00022345"], total=4))
        with server([login, first, changed]) as (port, _, eof):
            with self.assertRaises(ProtocolError):
                with Client("127.0.0.1", port) as client:
                    client.login("demo-user", "demo-password")
                    client.all_students("Demo")
            self.assertTrue(eof.wait(1))

    def test_login_failure_closes_connection(self):
        script = [(encode_request("teacherlogin", "demo-user", "demo-password"), b"loginfailed")]
        with server(script) as (port, _, eof):
            with self.assertRaises(ProtocolError):
                with Client("127.0.0.1", port) as client:
                    client.login("demo-user", "demo-password")
            self.assertTrue(eof.wait(1))

    def test_invalid_response_closes_without_relogin(self):
        script = [
            (encode_request("teacherlogin", "demo-user", "demo-password"), b"loginsuccess&"),
            (packets.projects().encode(), b"unexpected"),
        ]
        with server(script) as (port, observed, eof):
            with self.assertRaises(ProtocolError):
                with Client("127.0.0.1", port) as client:
                    client.login("demo-user", "demo-password")
                    client.send(packets.projects())
            self.assertTrue(eof.wait(1))
            self.assertEqual(len(observed), 2)

    def test_timeout_closes_connection(self):
        script = [
            (encode_request("teacherlogin", "demo-user", "demo-password"), b"loginsuccess&"),
            (packets.projects().encode(), None),
        ]
        with server(script) as (port, _, eof):
            with self.assertRaises(TimeoutError):
                with Client("127.0.0.1", port, timeout=0.1) as client:
                    client.login("demo-user", "demo-password")
                    client.send(packets.projects())
            self.assertTrue(eof.wait(1))

    def test_hostname_login_includes_configured_host(self):
        connection = Mock()
        body = b"loginsuccess&"
        connection.recv.side_effect = [struct.pack("<I", len(body)), body]
        with patch("lehua.client.socket.create_connection", return_value=connection):
            with Client("server.example.invalid", 12345) as client:
                client.login("demo-user", "demo-password")
        connection.sendall.assert_called_once_with(encode_request(
            "teacherlogin", "demo-user", "demo-password", "server.example.invalid"))
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
