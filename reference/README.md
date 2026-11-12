# Reference Implementation

This small Python implementation makes the [native protocol specification](../protocol.md) executable. It focuses on wire encoding, packet shapes, and readable query examples. It uses Python 3.10 or later and has no third-party dependencies.

## Reading order

1. [lehua/codec.py](lehua/codec.py) encodes ampersand-delimited GBK lines and reads four-octet little-endian response lengths. `FrameDecoder` separately demonstrates incremental decoding across fragmented and coalesced TCP reads.
2. [lehua/packets.py](lehua/packets.py) pairs each request with a typed response parser. `Packet.encode()` validates the confirmed command allowlist and argument counts; `Packet.parse()` receives a response body after the outer frame prefix has been removed.
3. [lehua/client.py](lehua/client.py) connects the packets to a synchronous socket. It serializes exchanges and keeps complete cursor workflows under one lock and deadline.
4. [examples.py](examples.py) shows short, explicit query workflows and a command-line entry point.
5. [tests/test_protocol.py](tests/test_protocol.py) exercises the codecs, packets, documentation transcripts, and connection lifecycle without contacting a LeHua server.

## Offline checks

From this directory:

```sh
python -m unittest discover -s tests -v
python examples.py --help
```

Tests create a temporary server bound to `127.0.0.1` and exchange synthetic responses. They cover frame fragmentation/coalescing, invalid lengths, partial EOF, GBK rejection, command restrictions, native binary offsets, score absence versus zero, pagination consistency, one-login connection reuse, and cleanup after failures.

No network request runs merely by importing the package or asking for CLI help.

## Configuration

The CLI reads these environment variables:

| Variable | Meaning |
| --- | --- |
| `LEHUA_HOST` | Your configured server's hostname or IPv4 address |
| `LEHUA_PORT` | Your configured server's TCP port |
| `LEHUA_USER` | Account name |
| `LEHUA_PASSWORD` | Account password |

No real service address, default port, or working credentials are included. Set the variables in your local environment; do not commit them. The original transport sends login credentials over plain TCP, as described in the specification.

For example, in PowerShell, replace the placeholders and read the password interactively:

```powershell
$env:LEHUA_HOST = 'server.example.invalid'
$env:LEHUA_PORT = '<your-server-port>'
$env:LEHUA_USER = '<your-account>'
$password = Read-Host 'LeHua password' -AsSecureString
$env:LEHUA_PASSWORD = [System.Net.NetworkCredential]::new('', $password).Password
python examples.py projects
Remove-Item Env:LEHUA_PASSWORD
```

## API call examples

After setting the environment variables, run these from `reference/`. The examination and roster names below are fictional; choose exact names from the corresponding list query.

```sh
python examples.py projects
python examples.py subjects
python examples.py rosters
python examples.py progress "DemoExam(DemoRoster)" Math
python examples.py score-files "DemoExam(DemoRoster)"
python examples.py download-score "DemoExam(DemoRoster)" Math.zip Math.zip
python examples.py paper "DemoExam(DemoRoster)" Math 00012345
python examples.py teachers --page 2
python examples.py students DemoRoster --page 2
python examples.py numbers DemoRoster --prefix 0001
python examples.py numbers DemoRoster --contains 2345
```

`numbers` reads the complete roster before deduplicating and filtering its examination-number strings. `--prefix` uses `str.startswith`; `--contains` uses substring matching. When both are supplied, both conditions apply. These are local filters rather than unverified native search requests.

`download-score` first checks the archive list and writes the returned ZIP to a new file. It does not unpack the archive or overwrite an existing file. `paper` queries the summary, front, and back independently, displaying the score and available image sizes. The underlying image packets return raw JPEG bytes.

### Calling the library

The same workflow can be expressed directly:

```python
import os
from lehua import Client, packets

with Client(os.environ["LEHUA_HOST"], int(os.environ["LEHUA_PORT"])) as client:
    client.login(os.environ["LEHUA_USER"], os.environ["LEHUA_PASSWORD"])

    examinations = client.send(packets.projects())
    if examinations and examinations[0].subjects:
        project = examinations[0]
        subject = project.subjects[0]
        progress = client.send(packets.progress(project.name, subject))
        for group in progress.groups:
            print(group.group, group.reviewed, group.unreviewed, group.total)

# The context manager closes the authenticated connection, also on failure.
```

To read a particular directory page, replay the native cursor commands within one transaction:

```python
teacher_page = client.page(packets.teachers, 2)
student_page = client.page(
    lambda next_page: packets.students("DemoRoster", next_page), 2
)
```

These two calls belong inside the authenticated `with` block above. `client.page` starts from the first page for each traversal, validates totals and page sizes, and does not interpret the unknown `end` field as a boolean. `client.all_students(roster)` traverses an entire roster under the same connection lock.

### Packet/result map

| Packet factory | Native operation | Parsed result |
| --- | --- | --- |
| `login(user, password, host=None)` | `teacherlogin` | `None` on success; exception on failure |
| `projects()` | `setting&getXmList` | Tuple of `Project` records |
| `progress(project, subject)` | `setting&getAllProgressDetail` | `Progress` with group and school records |
| `score_files(project)` | `setting&getScoreFileList` | Tuple of archive filenames |
| `score_archive(project, filename)` | `setting&downScoreFile` | ZIP bytes |
| `paper_summary(project, subject, number)` | `getsudentSj`, `head` | Finite score or `None` |
| `paper_image(project, subject, number, side)` | `getsudentSj`, `front`/`back` | JPEG bytes or `None` |
| `rosters()` | `setting&GetGradeList` | Tuple of roster names |
| `subjects()` | `setting&GetSubjectList` | Tuple of subject names |
| `teachers(next_page=False)` | `GetTeacherList` / `GetTeacherListNext` | `Page[Teacher]` |
| `students(roster, next_page=False)` | `GetStudentList` / `GetStudentListNext` | `Page[Student]` |

The thin client chooses the documented login host-field variant automatically: it omits the host for an IPv4 literal and appends the configured host otherwise. The packet-level `login` builder keeps that distinction explicit for inspecting wire bytes.

## Boundaries

Only the confirmed authentication and read-only command forms are allowed. Static candidate commands are not callable through these packets. There are no marking, password-change, administration-write, archive-extraction, or website functions.

The client has an eight-second per-I/O timeout, a 25-second outer workflow deadline, and a 64 MiB response-body limit. These are client limits, not proven server capabilities. A `transaction()` groups several calls under one lock and deadline. Examples authenticate once per invocation and close on completion or failure; they do not repeatedly log in for each API call.

No automatic reconnect, heartbeat, native logout command, or background inactivity timer is implemented. A long-lived application built on this example must add its own consumer/inactivity lifecycle and call `close()` when appropriate. The CLI examples are short-lived and use a context manager for dependable session release.

Response parsing follows the known fragment shapes rather than treating the bodies as generic XML. `tp_raw` and `end_raw` preserve unknown values without inventing semantics. Binary header padding is not decoded or interpreted.

## Validation

The 19 offline tests establish consistency with the documented exchanges and cover the connection lifecycle using a local fixture server.

On 2026-11-12, a read-only smoke test also succeeded against the configured LeHua server using one authenticated connection. It exercised examination, global-subject and roster discovery; teacher and student second-page traversal; group and school progress; score-archive discovery and retrieval; complete roster traversal; and paper summary/front/back requests. A downloaded archive had a valid ZIP directory containing spreadsheets, and a present JPEG image was parsed successfully.

No score was available in the tested summary responses; finite-score parsing is covered by the offline fixtures. The test connection was closed on completion. No service address, credentials, or real person records are included in this repository. These checks establish compatibility with the tested deployment, not every LeHua server.

## License

Copyright (c) 2026 Black-HIG. This reference implementation is covered by the repository's [CC BY-SA 4.0 license](../LICENSE).
