"""Typed requests and parsers for the twelve confirmed command forms.

All response parsers receive a body with its four-octet prefix removed.
SPDX-License-Identifier: CC-BY-SA-4.0
"""

import math
import re
from dataclasses import dataclass, field
from typing import Callable, Generic, TypeVar

from .codec import ProtocolError, decode_text, encode_request

T = TypeVar("T")


@dataclass(frozen=True)
class Packet(Generic[T]):
    name: str
    fields: tuple[str, ...] = field(repr=False)
    parse: Callable[[bytes], T] = field(repr=False, compare=False)

    def encode(self) -> bytes:
        """Keep statically observed and mutating commands off the wire."""
        allowed = {
            "getXmList": 2, "getAllProgressDetail": 4,
            "getScoreFileList": 3, "downScoreFile": 4,
            "GetGradeList": 2, "GetSubjectList": 2,
            "GetTeacherList": 2, "GetTeacherListNext": 2,
            "GetStudentList": 3, "GetStudentListNext": 3,
        }
        f = self.fields
        valid = bool(f) and (
            (f[0] == "teacherlogin" and len(f) in (3, 4))
            or (f[0] == "setting" and len(f) >= 2
                and allowed.get(f[1]) == len(f))
            or (f[0] == "getsudentSj" and len(f) == 5
                and f[4] in ("head", "front", "back"))
        )
        if not valid:
            raise ValueError("Unsupported command or argument count")
        return encode_request(*f)


@dataclass(frozen=True)
class Project:
    name: str
    subjects: tuple[str, ...]


@dataclass(frozen=True)
class GroupProgress:
    group: str
    reviewed: int
    unreviewed: int

    @property
    def total(self) -> int:
        return self.reviewed + self.unreviewed


@dataclass(frozen=True)
class SchoolProgress:
    school: str
    group: str
    reviewed: int
    assigned: int


@dataclass(frozen=True)
class Progress:
    groups: tuple[GroupProgress, ...]
    schools: tuple[SchoolProgress, ...]


@dataclass(frozen=True)
class Teacher:
    username: str
    name: str
    role: str
    subject: str
    school: str
    grade: str


@dataclass(frozen=True)
class Student:
    number: str
    name: str
    school: str
    class_name: str
    tp_raw: str  # Preserved without assigning meaning to the native tp tag.


@dataclass(frozen=True)
class Page(Generic[T]):
    rows: tuple[T, ...]
    total: int
    page: int
    end_raw: str  # Presence is known; end-of-list semantics are not.


def _packet(fields: tuple[str, ...], parse: Callable[[bytes], T]) -> Packet[T]:
    name = fields[1] if fields[0] == "setting" else fields[0]
    return Packet(name, fields, parse)


def _text(body: bytes, prefix: str) -> str:
    text = decode_text(body)
    if not text.startswith(prefix):
        raise ProtocolError("The response has an unexpected success marker")
    return text[len(prefix):]


def _unique(values) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _values(body: bytes, prefix: str, tag: str) -> tuple[str, ...]:
    text = _text(body, prefix)
    return _unique(value.strip() for value in re.findall(
        rf"<{tag}>([^<>]+)</{tag}>", text) if value.strip())


def login(user: str, password: str, host: str | None = None) -> Packet[None]:
    """host is supplied for the non-IPv4 login form; see the specification."""
    def parse(body: bytes) -> None:
        if not decode_text(body).lower().startswith("loginsuccess&"):
            # Do not echo a possibly sensitive native response or credentials.
            raise ProtocolError("LeHua authentication failed")

    fields = ("teacherlogin", user, password)
    if host is not None:
        fields += (host,)
    return _packet(fields, parse)


def projects() -> Packet[tuple[Project, ...]]:
    def parse(body: bytes) -> tuple[Project, ...]:
        text = _text(body, "getXmList&success&")
        matches = re.findall(r'<xm name="([^"]+)">(.*?)</xm>', text, re.S)
        if len(matches) != text.count('<xm name="'):
            raise ProtocolError("Malformed examination record")
        return tuple(Project(name, tuple(re.findall(
            r"<subject>([^<]+)</subject>", inner))) for name, inner in matches)

    return _packet(("setting", "getXmList"), parse)


def progress(project: str, subject: str) -> Packet[Progress]:
    def parse(body: bytes) -> Progress:
        text = _text(body, "getYjProgress&success&")
        groups = re.findall(r"<tizu name=([^<>]+)><yj_count>(\d+)</yj_count>"
                            r"<no_count>(\d+)</no_count></tizu>", text)
        schools = re.findall(r"<school name=([^<>]+)><tz>([^<>]*)</tz>"
                             r"<yj_count>(\d+)</yj_count></school>", text)
        tasks = re.findall(r"<school_renwu name=([^<>]+)><tz>([^<>]*)</tz>"
                           r"<yj_count>(\d+)</yj_count></school_renwu>", text)
        if (len(groups) != text.count("<tizu name=")
                or len(schools) != text.count("<school name=")
                or len(tasks) != text.count("<school_renwu name=")):
            raise ProtocolError("Malformed progress record")
        assigned = {(school, group): int(count) for school, group, count in tasks}
        return Progress(
            tuple(GroupProgress(group, int(done), int(todo))
                  for group, done, todo in groups),
            tuple(SchoolProgress(school, group, int(count),
                                 assigned.get((school, group), 0))
                  for school, group, count in schools),
        )

    return _packet(("setting", "getAllProgressDetail", project, subject), parse)


def score_files(project: str) -> Packet[tuple[str, ...]]:
    def parse(body: bytes) -> tuple[str, ...]:
        return _unique(re.findall(r"<([^<>]+\.zip)>",
                                 _text(body, "getScoreFileListSuccess"), re.I))

    return _packet(("setting", "getScoreFileList", project), parse)


def score_archive(project: str, filename: str) -> Packet[bytes]:
    def parse(body: bytes) -> bytes:
        if (body[:20] != b"downScoreFileSuccess"
                or body[20:24] != b"PK\x03\x04"):
            raise ProtocolError("Invalid score archive marker or ZIP signature")
        return body[20:]

    return _packet(("setting", "downScoreFile", project, filename), parse)


def _number(value: str) -> str:
    if not isinstance(value, str) or not 3 <= len(value) <= 64:
        raise ValueError("A complete examination number must have 3 to 64 characters")
    return value


def paper_summary(project: str, subject: str, number: str) -> Packet[float | None]:
    def parse(body: bytes) -> float | None:
        if body.startswith(b"getsudentSjno"):
            return None
        if len(body) < 40 or not body.startswith(b"getsudentSjHeadOk"):
            raise ProtocolError("Unexpected paper summary header")
        # Inspect the ASCII score element without decoding unknown header bytes
        # or a possibly truncated GB18030 sequence at the end of the search range.
        match = re.search(rb"<zf>([^<]+)</zf>", body[40:1000])
        if not match:
            return None
        try:
            value = float(match[1].decode("ascii"))
        except (UnicodeError, ValueError):
            return None
        return value if math.isfinite(value) else None

    return _packet(("getsudentSj", project, subject, _number(number), "head"), parse)


def paper_image(project: str, subject: str, number: str, side: str) -> Packet[bytes | None]:
    if side not in ("front", "back"):
        raise ValueError("An image side must be front or back")

    def parse(body: bytes) -> bytes | None:
        if body.startswith(b"getsudentSjno"):
            return None
        if (not body.startswith(b"getsudentSjok")
                or body[40:43] != b"\xff\xd8\xff"):
            raise ProtocolError("Invalid paper image header or JPEG signature")
        return body[40:]

    return _packet(("getsudentSj", project, subject, _number(number), side), parse)


def rosters() -> Packet[tuple[str, ...]]:
    return _packet(("setting", "GetGradeList"),
                   lambda body: _values(body, "GetGradeListSuccess", "grade"))


def subjects() -> Packet[tuple[str, ...]]:
    return _packet(("setting", "GetSubjectList"),
                   lambda body: _values(body, "GetSubjectListSuccess", "subject"))


def _page(text: str, rows: tuple[T, ...]) -> Page[T]:
    metadata = re.search(r"<a_c>(\d+)</a_c><c_p>(\d+)</c_p><end>([^<]*)</end>", text)
    if not metadata:
        raise ProtocolError("Missing pagination metadata")
    total, page = int(metadata[1]), int(metadata[2])
    if total == 0 and not rows:
        return Page(rows, 0, 1, metadata[3])
    if page < 1 or not rows or len(rows) > total:
        raise ProtocolError("Inconsistent pagination metadata")
    return Page(rows, total, page, metadata[3])


def teachers(next_page: bool = False) -> Packet[Page[Teacher]]:
    def parse(body: bytes) -> Page[Teacher]:
        # A dedicated teacher success prefix is not established.
        text = decode_text(body)
        records = re.findall(r"<teacher><nm>([^<]*)</nm><rlnm>([^<]*)</rlnm>"
                             r"<js>([^<]*)</js><kemu>([^<]*)</kemu>"
                             r"<sc>([^<]*)</sc><gd>([^<]*)</gd></teacher>", text)
        if len(records) != text.count("<teacher>"):
            raise ProtocolError("Malformed teacher record")
        return _page(text, tuple(Teacher(*row) for row in records))

    command = "GetTeacherListNext" if next_page else "GetTeacherList"
    return _packet(("setting", command), parse)


def students(roster: str, next_page: bool = False) -> Packet[Page[Student]]:
    def parse(body: bytes) -> Page[Student]:
        text = _text(body, "GetStudentListSuccess")
        records = re.findall(r"<kh>([^<]*)</kh><st>([^<]*)</st><sc>([^<]*)</sc>"
                             r"<cs>([^<]*)</cs><tp>([^<]*)</tp>", text)
        if len(records) != text.count("<kh>"):
            raise ProtocolError("Malformed student record")
        return _page(text, tuple(Student(number.strip(), *rest)
                                 for number, *rest in records))

    command = "GetStudentListNext" if next_page else "GetStudentList"
    return _packet(("setting", command, roster), parse)
