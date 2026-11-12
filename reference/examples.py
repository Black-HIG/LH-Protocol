"""Small read-only API examples. No network request runs during import.

Run `python examples.py --help` from reference/. The server and credentials
come from environment variables; every example closes its session on exit.
SPDX-License-Identifier: CC-BY-SA-4.0
"""

import argparse
import json
import os
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path

from lehua import Client, ProtocolError, packets


def list_projects(client: Client):
    return client.send(packets.projects())


def show_progress(client: Client, project: str, subject: str):
    result = client.send(packets.progress(project, subject))
    return {
        "groups": [{**asdict(row), "total": row.total} for row in result.groups],
        "schools": result.schools,
    }


def download_score(client: Client, project: str, filename: str, output: str):
    # One connection and lock for discovery followed by download.
    with client.transaction():
        if filename not in client.send(packets.score_files(project)):
            raise ValueError("Select a filename returned by score_files")
        archive = client.send(packets.score_archive(project, filename))
    with Path(output).open("xb") as file:  # Do not overwrite an existing file.
        file.write(archive)
    return {"saved": output, "bytes": len(archive)}


def read_paper(client: Client, project: str, subject: str, number: str):
    with client.transaction():
        score = client.send(packets.paper_summary(project, subject, number))
        front = client.send(packets.paper_image(project, subject, number, "front"))
        back = client.send(packets.paper_image(project, subject, number, "back"))
    # Images are raw JPEG bytes; do not print student images into logs.
    return {"score": score, "front_bytes": len(front) if front is not None else None,
            "back_bytes": len(back) if back is not None else None}


def examination_numbers(client: Client, roster: str, prefix: str, contains: str):
    rows = client.all_students(roster)
    numbers = dict.fromkeys(row.number for row in rows if row.number)
    return [number for number in numbers
            if number.startswith(prefix) and contains in number]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only LeHua protocol examples")
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("projects", "rosters", "subjects"):
        commands.add_parser(name)
    progress = commands.add_parser("progress")
    progress.add_argument("project")
    progress.add_argument("subject")
    scores = commands.add_parser("score-files")
    scores.add_argument("project")
    download = commands.add_parser("download-score")
    for name in ("project", "filename", "output"):
        download.add_argument(name)
    paper = commands.add_parser("paper")
    for name in ("project", "subject", "number"):
        paper.add_argument(name)
    teachers = commands.add_parser("teachers")
    teachers.add_argument("--page", type=int, default=1)
    students = commands.add_parser("students")
    students.add_argument("roster")
    students.add_argument("--page", type=int, default=1)
    numbers = commands.add_parser("numbers")
    numbers.add_argument("roster")
    numbers.add_argument("--prefix", default="")
    numbers.add_argument("--contains", default="")
    return parser


def main() -> int:
    parser = _parser()
    args = parser.parse_args()  # --help never opens a connection.
    names = ("LEHUA_HOST", "LEHUA_PORT", "LEHUA_USER", "LEHUA_PASSWORD")
    if any(not os.environ.get(name) for name in names):
        parser.error("Set LEHUA_HOST, LEHUA_PORT, LEHUA_USER and LEHUA_PASSWORD")
    try:
        port = int(os.environ["LEHUA_PORT"])
        # One login for the selected workflow, including any first/next requests.
        with Client(os.environ["LEHUA_HOST"], port) as client:
            client.login(os.environ["LEHUA_USER"], os.environ["LEHUA_PASSWORD"])
            if args.action in ("projects", "rosters", "subjects"):
                result = client.send(getattr(packets, args.action)())
            elif args.action == "progress":
                result = show_progress(client, args.project, args.subject)
            elif args.action == "score-files":
                result = client.send(packets.score_files(args.project))
            elif args.action == "download-score":
                result = download_score(client, args.project, args.filename, args.output)
            elif args.action == "paper":
                result = read_paper(client, args.project, args.subject, args.number)
            elif args.action == "teachers":
                result = client.page(packets.teachers, args.page)
            elif args.action == "students":
                result = client.page(lambda next_page: packets.students(args.roster, next_page), args.page)
            else:
                result = examination_numbers(client, args.roster, args.prefix, args.contains)
        print(json.dumps(result, default=lambda obj: asdict(obj) if is_dataclass(obj) else str(obj),
                         ensure_ascii=True, indent=2))
        return 0
    except (OSError, ProtocolError, ValueError, RuntimeError):
        # Exception chaining/native response bytes can contain private data.
        print("The example could not complete. Check configuration, inputs and connectivity.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
