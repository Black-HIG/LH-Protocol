# LeHua Server Read-Only Query Protocol

| Document property | Value |
| --- | --- |
| Revision | 1.0.0 |
| Category | Project protocol specification |
| Status | Implemented interoperability profile; reverse-engineered |
| Published | 2026-11-11 |
| Language | English |
| Scope | Native LeHua TCP authentication and read-only queries |
| License | CC BY-SA 4.0 International |
| Attribution | Copyright (c) 2026 Black-HIG |

## Abstract

This document specifies the native TCP exchanges currently understood for the LeHua examination and marking server. It covers authentication, examination discovery, marking progress, score archive retrieval, student paper retrieval, teacher records, student rosters, and subject discovery. It defines the request syntax, response framing, character encodings, binary offsets, connection state, pagination behavior, and field mappings needed to implement an independent query client.

The specification separates commands exercised by the reference implementation from additional command strings found in the original executable. It records the limits of the available evidence and provides synthetic examples and transport test vectors. All account names, passwords, examination names, and person records in examples are fictional.

## Status of This Memo

This is a project-internal RFC-style specification. It documents an observed interoperability profile, with no claim of vendor endorsement or IETF publication. Requirements in this memo apply to clients implementing this profile. Statements about server behavior are limited to the evidence described in Section 2.

Business-data mutation, marking submission, password changes, and server configuration are outside this profile. Authentication and connection closure change session state only. The document defines the native server protocol independently of any website, HTTP adapter, hosting platform, or cache service.

## Contents

1. Introduction
2. Conventions and Evidence Levels
3. Protocol Overview
4. Transport, Encoding, and Framing
5. Authentication and Connection Lifecycle
6. Identifiers and Data Semantics
7. Implemented Command Registry
8. Command Specifications
9. Pagination and Query Workflows
10. Error Handling and Recovery
11. Security Considerations
12. Compatibility and Open Questions
13. IANA Considerations
14. References

- Appendix A. Complete Example Exchanges
- Appendix B. Transport Test Vectors
- Appendix C. Statically Observed Command Candidates
- Appendix D. Validation Notes

## 1. Introduction

The LeHua client communicates with its server through a persistent TCP connection. Requests are ampersand-delimited text lines. Responses use a binary length prefix and contain either text fragments or a command-specific binary payload. A connection is authenticated once and reused for subsequent queries.

This memo consolidates the currently implemented read-only protocol into a single specification. A conforming client can use the confirmed command set without exposing a generic command execution interface or calling unverified commands.

The server host and TCP port are deployment parameters. The original client's configuration supplies these values. This memo does not assign a default port, a public service address, or a protocol version negotiation mechanism.

## 2. Conventions and Evidence Levels

### 2.1. Requirement Language

The uppercase terms MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL express requirement levels as defined by BCP 14, consisting of [RFC2119] and [RFC8174]. Lowercase uses have their ordinary English meaning.

ABNF follows [RFC5234], with case-sensitive string literals from [RFC7405]. The `%s` prefix denotes an exact, case-sensitive ASCII literal. ABNF in this memo describes octets on the wire; additional GBK encoding and parameter constraints apply as stated in Section 4.

### 2.2. Evidence Levels

| Level | Meaning | Use in this memo |
| --- | --- | --- |
| V: Verified integration | Implemented in the reference client and exercised against the configured server during earlier integration work | The commands in Sections 7 and 8 |
| S: Static observation | A literal command string was extracted from the original executable | Appendix C only |
| P: Client profile | A defensive rule, timeout, or operational choice of the reference client | Explicitly identified as a client rule; not a proven server limit |
| U: Unknown | The available implementation and observations do not establish the behavior | Recorded as an open question; no wire format is invented |

The exact teacher-list success prefix is an example of level U: teacher rows and pagination are consumed successfully, but the reference parser does not validate a dedicated prefix. Appendix C candidates remain level S regardless of how descriptive their names appear.

### 2.3. Notation

`C -> S` denotes client-to-server data; `S -> C` denotes server-to-client data. In transcript blocks, `\r\n` represents exactly the octets `0D 0A`; it is not four literal printable characters. Braces such as `{project}` denote substituted parameters and are not transmitted.

Unless a block explicitly shows the entire response frame, response examples show the body after the four-octet length prefix has been removed. Newlines used to display separate response fragments are illustrative; field sequences within a record retain the order and adjacency shown.

Offsets and lengths are measured in octets. Integers described as counts use nonnegative decimal text unless specified otherwise. A field marked unknown MUST NOT be assigned an application meaning solely from its tag name.

## 3. Protocol Overview

The normal exchange is:

```text
Client                              Server
  | -------- TCP connect -----------> |
  | -------- teacherlogin ----------> |
  | <------ framed login result ----- |
  | -------- query request ---------> |
  | <------ framed query result ----- |
  | -------- next request ----------> |
  | <------ framed query result ----- |
  | -------- TCP close -------------> |
```

An authenticated connection carries the session. The confirmed queries do not carry a separate session token, request ID, or correlation ID. A client MUST serialize exchanges on each connection: it sends one request, consumes that request's entire response frame, then sends the next request.

Multi-command workflows, including cursor pagination, SHOULD hold the connection's query lock for the whole workflow. This prevents unrelated commands from interfering with connection-local state.

## 4. Transport, Encoding, and Framing

### 4.1. TCP and Character Encodings

The observed transport is plain TCP. The confirmed connection procedure does not negotiate TLS or an application protocol version.

Requests MUST be encoded as GBK. A client implementing this profile MUST reject a parameter when a GBK encode/decode round trip changes its value. Silent substitution with `?` is not permitted. Responses containing text are decoded using GB18030 by the reference implementation. Trailing NUL characters are removed from decoded text; binary bodies MUST retain their original octets.

UTF-8, URL percent encoding, HTML entity escaping, and JSON escaping are not native parameter encodings. A client MUST NOT apply them as an assumed way of transmitting a literal ampersand or a character outside the supported GBK repertoire.

### 4.2. Request Envelope

```abnf
request-line = field *(amp field) CRLF
amp          = %x26
field        = 1*field-octet
field-octet  = %x20-25 / %x27-7E / %x80-FF
CRLF         = %x0D.0A
```

The octet grammar is necessary but not sufficient: the complete request MUST also be valid GBK. Each field MUST be nonempty and MUST NOT contain an ampersand, an ASCII control character in `00` through `1F`, or `7F`. There is no confirmed delimiter-escaping mechanism.

The reference client limits each decoded field to 512 UTF-16 code units before encoding. This is a client-profile limit; the server's actual maximum field length is unknown. Clients SHOULD preserve identifiers exactly rather than normalizing their spelling, punctuation, or case.

There is no request-side binary length prefix. The final CRLF terminates the request. For example:

```text
setting&getXmList\r\n
```

### 4.3. Response Envelope

Every confirmed response uses the following envelope:

```text
Offset       Size          Meaning
0            4             Unsigned body length N, little-endian
4            N             Response body
```

If the prefix octets are `b0`, `b1`, `b2`, and `b3`, then:

```text
N = b0 + 256*b1 + 65536*b2 + 16777216*b3
```

The length covers the body only. The client MUST read exactly four prefix octets, decode `N`, and then read exactly `N` body octets. A single TCP read may contain a partial prefix, a partial body, or bytes belonging to a subsequent frame. TCP packet boundaries have no application meaning; surplus octets MUST be retained for subsequent reads.

This profile accepts `1 <= N <= 67,108,864` (64 MiB). Zero or larger lengths are rejected and the connection is closed. This bound is a defensive client limit, not a discovered server capability. A response body is not terminated by an additional CRLF in the framing model.

### 4.4. Text Bodies

Text success markers and tags are case-sensitive unless explicitly stated otherwise. Several bodies contain XML-like fragments with multiple top-level records, unquoted attributes, or filename-only angle-bracket entries. Clients MUST NOT assume the body is a well-formed XML document.

For example, the following is an observed record shape:

```text
<tizu name=15><yj_count>885</yj_count><no_count>0</no_count></tizu>
```

The examination list uses a different attribute form:

```text
<xm name="DemoExam(DemoRoster)"><subject>Math</subject></xm>
```

The exact record structures consumed by the reference parser are specified in Section 8. The treatment of literal `<`, `>`, and quote characters inside server-generated field values is unknown.

### 4.5. Binary Bodies

Binary responses retain the same four-octet outer envelope. They then use a command-specific body header. Offsets below are relative to the start of the body, excluding the outer length prefix.

| Response | Body header | Content offset | Content validation |
| --- | --- | --- | --- |
| Score archive | Exact 20-octet ASCII `downScoreFileSuccess` | 20 | Starts with ZIP local-file signature `50 4B 03 04` |
| Paper image | First 40 octets decode to a string starting with `getsudentSjok` | 40 | Starts with JPEG signature `FF D8 FF` |
| Paper summary | First 40 octets decode to a string starting with `getsudentSjHeadOk` | 40 | Text metadata; the reference client searches body offsets 40 through 999 for `<zf>` |
| Missing paper/summary | Header text starts with `getsudentSjno` | None | Treat as an absent item |

The complete layout of the 40-octet paper header is unknown. The known marker prefix does not establish the meaning or padding of its remaining octets. Clients MUST NOT infer that the entire header is a NUL-padded string or move the content offset based on the marker's printed length.

## 5. Authentication and Connection Lifecycle

### 5.1. Login Request

```abnf
login-line = %s"teacherlogin" amp user amp password [amp host] CRLF
user       = field
password   = field
host       = field
```

The reference client sends three fields, including the command, when the configured server address is an IPv4 literal:

```text
teacherlogin&demo-user&demo-password\r\n
```

When the configured address is not an IPv4 literal, it appends that configured address:

```text
teacherlogin&demo-user&demo-password&server.example.invalid\r\n
```

This conditional host field is confirmed client behavior. Its server-side purpose, necessity across deployments, and behavior with IPv6 addresses have not been established.

### 5.2. Login Response

The response body is text. The reference implementation recognizes a case-insensitive prefix `loginsuccess&` as success. Any data following that prefix is not currently interpreted.

A different body is treated as login failure. No stable taxonomy of native authentication failure markers or numeric error codes has been established. Implementations MUST NOT manufacture distinctions such as “wrong password” versus “account already connected” from an unspecified response.

A simultaneous connection using the same account has caused login conflicts during integration. The exact server policy is unknown. Clients SHOULD reuse an existing authenticated connection and avoid repeated login attempts while another client may hold the account.

### 5.3. Session States

```text
DISCONNECTED --connect--> CONNECTED --successful login--> AUTHENTICATED
      ^                       |                              |
      |                       | login failure                | close, EOF,
      |                       | or transport failure         | timeout, error
      +-----------------------+------------------------------+
```

Queries in Section 8 require an authenticated connection, except for login itself. Reconnection creates a new connection and requires a new login. Query cursors MUST be considered invalid after a disconnect.

### 5.4. Reuse, Inactivity, and Logout

A client SHOULD retain one authenticated connection throughout an active user session. It SHOULD close that connection when the user explicitly exits, when the last consumer leaves, or when its inactivity deadline expires.

The reference client uses a five-minute inactivity deadline. It distinguishes user activity from consumer-presence heartbeats; a presence heartbeat alone does not extend the activity deadline. These are client policies, not server wire-protocol messages or confirmed server timeouts.

No explicit native logout command has been confirmed. Logout in the reference implementation closes the authenticated TCP connection. Closure is attempted gracefully, with forced destruction after 750 milliseconds if needed. Integrations SHOULD arrange connection cleanup in a `finally`-equivalent path after a bounded task, login failure, or shutdown.

### 5.5. Timeouts

The reference profile applies an eight-second socket inactivity timeout during an exchange and a 25-second deadline while executing a queued query workflow. The workflow deadline starts after the workflow obtains the connection queue slot. These values are implementation safeguards and are not advertised by the server.

A framing error, unexpected EOF, or response timeout MUST invalidate the affected connection. A client MUST NOT continue using a byte stream whose frame alignment is uncertain.

## 6. Identifiers and Data Semantics

| Name | Meaning | Source and constraints |
| --- | --- | --- |
| `project` | Examination/project identifier | Exact `name` attribute of an `<xm>` record |
| `subject` | Subject within a project | Exact `<subject>` value nested under that project |
| `roster` | Student roster name | `<grade>` value returned by `GetGradeList` |
| `number` | Student examination number | `<kh>` value; preserve as a string, including leading zeros |
| `file` | Score archive filename | Exact filename returned by `getScoreFileList` |
| `group` | Marking question-group label | `tizu` name or `<tz>` text; may be a range such as `12-14` |
| `school` | School label | Exact label in the relevant response record |
| `side` | Paper representation selector | Exact lowercase `head`, `front`, or `back` |

A project's displayed name is its identifier in the confirmed protocol. No independent numeric project ID, creation timestamp, or examination date is returned by `getXmList`.

The reference client derives a roster key from the last nonempty, nonnested, ASCII-parenthesized substring of the project name. For example, `DemoExam(DemoRoster)` gives `DemoRoster`. This is a naming convention used for roster lookup, not an explicit foreign-key field supplied by `getXmList`. A project without such a suffix cannot be resolved by this convention.

Dates inferred from names are presentation heuristics. They MUST NOT be represented as authoritative server dates. Likewise, list order MUST NOT be interpreted as chronological order.

The reference client constrains a full examination number to 3 through 64 characters and applies the common field restrictions. This length rule is a client-profile constraint. Prefix and substring searches can be performed over retrieved examination numbers; no verified server-side prefix or substring search command is specified here.

## 7. Implemented Command Registry

All entries below have evidence level V. There are twelve distinct command forms when first-page and next-page operations are counted separately; `getsudentSj` has three selector variants.

| Section | Command form, excluding final CRLF | Result |
| --- | --- | --- |
| 8.1 | `teacherlogin&{user}&{password}[&{host}]` | Authenticated connection |
| 8.2 | `setting&getXmList` | Examinations and their subjects |
| 8.3 | `setting&getAllProgressDetail&{project}&{subject}` | Question-group and school progress |
| 8.4 | `setting&getScoreFileList&{project}` | Score archive filenames |
| 8.5 | `setting&downScoreFile&{project}&{file}` | ZIP archive bytes |
| 8.6 | `getsudentSj&{project}&{subject}&{number}&{side}` | Summary, front image, or back image |
| 8.7 | `setting&GetGradeList` | Student roster names |
| 8.8 | `setting&GetSubjectList` | Global subject names |
| 8.9 | `setting&GetTeacherList` | First teacher page |
| 8.9 | `setting&GetTeacherListNext` | Next teacher page |
| 8.10 | `setting&GetStudentList&{roster}` | First student page |
| 8.10 | `setting&GetStudentListNext&{roster}` | Next student page |

Command spelling and capitalization MUST be preserved. In particular, `getsudentSj` retains the original spelling, and the verified `GetGradeList` command uses an uppercase `G`.

## 8. Command Specifications

### 8.1. `teacherlogin`

The syntax, conditional host field, success recognition, and lifecycle are specified in Section 5. Login MUST precede the other commands on the same TCP connection. Credentials are transmitted as GBK text fields without a confirmed challenge-response exchange.

### 8.2. `setting&getXmList`

**Request**

```abnf
project-list-line = %s"setting&getXmList" CRLF
```

**Response**

The text body MUST start with the exact prefix `getXmList&success&`. The remaining text contains zero or more project records:

```text
<xm name="DemoExam(DemoRoster)"><subject>Math</subject><subject>English</subject></xm>
```

| Element/attribute | Meaning |
| --- | --- |
| `xm/@name` | Project name and identifier |
| Nested `subject` | A subject available within that project |

The reference representation uses `{ id: name, name, subjects: [...] }`, where `id` is an alias for the original name. That alias does not introduce a new server identifier. A global subject list from Section 8.8 MUST NOT be substituted for the subjects associated with a particular project.

### 8.3. `setting&getAllProgressDetail`

**Request**

```abnf
progress-line = %s"setting&getAllProgressDetail" amp project amp subject CRLF
project       = field
subject       = field
```

**Response**

The text body MUST start with `getYjProgress&success&`. The consumed record forms are:

```text
<tizu name=12-14><yj_count>885</yj_count><no_count>0</no_count></tizu>
<school name=DemoSchool><tz>12-14</tz><yj_count>885</yj_count></school>
<school_renwu name=DemoSchool><tz>12-14</tz><yj_count>0</yj_count></school_renwu>
```

| Record | Field | Interpretation |
| --- | --- | --- |
| `tizu` | `name` | Question-group label |
| `tizu` | `yj_count` | Reviewed count for the group |
| `tizu` | `no_count` | Unreviewed count for the group |
| `school` | `name` | School label |
| `school` | `tz` | Question-group label |
| `school` | `yj_count` | Reviewed count attributable to that school and group |
| `school_renwu` | `name`, `tz` | School/group key for the assignment record |
| `school_renwu` | `yj_count` | Assignment count shown by the original client |

For a question group:

```text
reviewed = tizu.yj_count
unreviewed = tizu.no_count
total = reviewed + unreviewed
progress = reviewed / total     ; when total > 0
```

An empty group has no defined percentage in the native response. A client MUST choose and label its own zero-total presentation.

School rows and question-group rows are separate dimensions. A client MUST join assignment records by the pair `(school name, group label)` and MUST NOT use an arbitrary school name for a group summary. The reference client substitutes zero when the corresponding assignment record is absent; that zero is a fallback, not a confirmed server assertion of an empty task.

The original client has displayed a completed school task with a positive reviewed count and a zero assignment count. Consequently, a zero assignment count MUST NOT by itself be interpreted as zero reviewed work, an incomplete group, or the total number of papers. Group completion MUST use the `tizu` reviewed/unreviewed counts.

Counts are parsed as nonnegative decimal integers. The reference parser verifies that all recognized `tizu` and `school` record starts yield complete records; a malformed recognized record causes a protocol error instead of silently producing a partial progress report.

### 8.4. `setting&getScoreFileList`

**Request**

```abnf
score-list-line = %s"setting&getScoreFileList" amp project CRLF
```

**Response**

The text body MUST start with `getScoreFileListSuccess`. ZIP filenames are carried as angle-bracket entries:

```text
getScoreFileListSuccess<Math.zip><English.zip>
```

The reference parser recognizes filenames ending in `.zip`, case-insensitively, and removes duplicate filenames while preserving first occurrence order. These entries are not XML start/end element pairs. A client SHOULD obtain filenames from this list before downloading an archive and MUST preserve the listed filename when constructing the download request.

### 8.5. `setting&downScoreFile`

**Request**

```abnf
score-download-line = %s"setting&downScoreFile" amp project amp file CRLF
file                = field
```

**Response**

The body starts with the exact 20-octet ASCII marker `downScoreFileSuccess`. The remainder is the ZIP archive:

```text
Body offset    Length       Value
0              20           ASCII "downScoreFileSuccess"
20             N - 20       ZIP bytes, beginning 50 4B 03 04
```

The marker and ZIP signature MUST both be validated before exposing the archive. The first ZIP byte is at body offset 20, or TCP-frame offset 24.

ZIP contents are not typed by this command. Integration has encountered spreadsheet files, including XLS, XLSX, and CSV, but neither the filename list nor the download marker guarantees an archive's internal file types, count, structure, or decompressed size. Archive extraction and spreadsheet rendering are client-side concerns.

### 8.6. `getsudentSj`

**Request**

```abnf
paper-line = %s"getsudentSj" amp project amp subject amp number amp side CRLF
number     = field
side       = %s"head" / %s"front" / %s"back"
```

The request identifies a complete examination number, not a prefix. The subject SHOULD first be verified against the selected project's subject list.

**Summary: `side = head`**

A present summary has a 40-octet body header beginning with `getsudentSjHeadOk`. The reference client decodes the next available metadata bytes in body range `[40, 1000)` and searches for:

```text
<zf>93.5</zf>
```

`zf` is the reported score. The reference client accepts nonempty text convertible to a finite number. An absent, empty, or unparseable `zf` leaves the score unavailable; it MUST NOT be converted into a zero score. The rest of the summary layout, including metadata beyond this search range, is unspecified.

**Images: `side = front` or `side = back`**

A present image has a 40-octet body header beginning with `getsudentSjok`, followed by JPEG bytes beginning `FF D8 FF`. The first JPEG byte is at body offset 40, or TCP-frame offset 44. Each side is retrieved separately.

**Absence**

A header beginning with `getsudentSjno` means that the requested representation is absent. This is a valid negative query result, not a framing error. A student can have a summary, one image, both images, or none of these. Roster membership does not establish image availability.

A header that matches none of the expected markers, or an image response without the expected JPEG signature, is a protocol error. The exact bytes following the known marker prefixes remain unspecified.

### 8.7. `setting&GetGradeList`

**Request**

```abnf
roster-list-line = %s"setting&GetGradeList" CRLF
```

**Response**

The text body MUST start with `GetGradeListSuccess`. The consumed values are:

```text
GetGradeListSuccess<grade>DemoRoster</grade><grade>AnotherRoster</grade>
```

In this operation, `grade` values are student roster identifiers. A client MUST NOT assume they form a fixed enumeration of school grade levels. The reference client trims leading/trailing whitespace, removes empty values, and deduplicates the list.

### 8.8. `setting&GetSubjectList`

**Request**

```abnf
subject-list-line = %s"setting&GetSubjectList" CRLF
```

**Response**

The text body MUST start with `GetSubjectListSuccess`. Values use `subject` elements:

```text
GetSubjectListSuccess<subject>Math</subject><subject>English</subject>
```

This is a global subject list. The reference client trims, removes empty values, and deduplicates it. It supplies subject-management queries but does not establish the subjects assigned to any particular examination.

### 8.9. `setting&GetTeacherList` and `setting&GetTeacherListNext`

**Requests**

```abnf
teacher-first-line = %s"setting&GetTeacherList" CRLF
teacher-next-line  = %s"setting&GetTeacherListNext" CRLF
```

The first command starts a list traversal. The second advances the connection-local traversal. The confirmed request forms have no teacher-name, role, school, search, page-number, or page-size parameter.

**Response**

The body contains the pagination envelope from Section 9 and zero or more teacher records with the following ordered field sequence:

```text
<teacher><nm>demo.teacher</nm><rlnm>Example Teacher</rlnm><js>ExampleRole</js><kemu>Math</kemu><sc>DemoSchool</sc><gd>DemoRoster</gd></teacher>
```

| Native tag | Interpretation | Reference field name |
| --- | --- | --- |
| `nm` | Username | `username` |
| `rlnm` | Display/real name | `name` |
| `js` | Role text | `role` |
| `kemu` | Subject text | `subject` |
| `sc` | School text | `school` |
| `gd` | Grade/roster text reported for the teacher | `grade` |

The vocabulary of `js`, and the multiplicity or delimiter conventions inside `kemu` and `gd`, are unknown. Clients SHOULD preserve these values as strings. Passwords are not fields in the consumed teacher record shape.

A dedicated teacher-list success prefix has not been established by the reference parser. It decodes the body, validates pagination, and extracts the ordered teacher records. This memo therefore specifies no invented `GetTeacherListSuccess` marker.

The number of parsed records MUST match the number of recognized `<teacher>` starts. Partial recognized records are a protocol error.

### 8.10. `setting&GetStudentList` and `setting&GetStudentListNext`

**Requests**

```abnf
student-first-line = %s"setting&GetStudentList" amp roster CRLF
student-next-line  = %s"setting&GetStudentListNext" amp roster CRLF
roster             = field
```

The roster SHOULD first be selected from `GetGradeList`. The next-page command repeats the same roster. Neither confirmed request form accepts a page number, a page size, or a search predicate.

**Response**

The text body MUST start with `GetStudentListSuccess`. It contains the pagination envelope from Section 9, followed by records having this ordered field sequence:

```text
<kh>00012345</kh><st>Example Student</st><sc>DemoSchool</sc><cs>Class 1</cs><tp>unknown</tp>
```

| Native tag | Interpretation | Reference field name |
| --- | --- | --- |
| `kh` | Examination number, retained as text | `number` |
| `st` | Student name | `name` |
| `sc` | School text | `school` |
| `cs` | Class text | `className` |
| `tp` | Meaning unknown | Not exposed by the reference data model |

The reference implementation trims `kh` but preserves the other mapped strings. It requires the `tp` element to recognize the complete record shape, while assigning no meaning to its contents. The number of parsed records MUST match the number of recognized `<kh>` starts.

## 9. Pagination and Query Workflows

### 9.1. Pagination Envelope

Teacher and student list responses contain this ordered metadata sequence:

```text
<a_c>3</a_c><c_p>1</c_p><end>0</end>
```

| Tag | Established interpretation |
| --- | --- |
| `a_c` | Total record count for the list traversal |
| `c_p` | Current one-based page number |
| `end` | Present in the consumed envelope; value semantics are unknown |

The example value `0` for `end` is illustrative and conveys no last-page meaning. A client MUST NOT rely on `end` as an established end-of-list flag.

No client-selected page size is transmitted in the confirmed commands. For a nonempty directory, the reference client infers the page size from the first page's row count:

```text
pageSize = number of records on page 1
pageCount = ceil(total / pageSize)
```

An empty list is represented internally as one empty page. The reference client accepts a zero total with no records without requiring a particular reported `c_p` value in that case.

### 9.2. Directory Page Traversal

To obtain page `P`, the reference client performs the following sequence within one connection lock:

1. Issue the first-page command and consume the response.
2. Derive the total, first-page size, and page count.
3. Reject a requested page beyond the derived page count.
4. Issue the next-page command repeatedly until page `P` is reached.
5. On every nonempty page, verify the expected one-based page number.
6. Verify an unchanged total and the expected number of records on each later page.

This sequence restarts from page one for each independent page request. The confirmed protocol offers a cursor interface; arbitrary page jumps are not established.

For a list with `T` records and inferred page size `S`, page `p` is expected to contain `min(S, T - (p - 1) * S)` records. If the total or page contents change incompatibly during traversal, the client SHOULD abort the traversal and ask the caller to reload.

### 9.3. Retrieving All Examination Numbers

To enumerate numbers for a project:

1. Read `getXmList` and resolve the exact project name.
2. Resolve the roster naming convention described in Section 6.
3. Send `GetStudentList` for that roster.
4. Collect nonempty `kh` values, trimming surrounding whitespace.
5. Send `GetStudentListNext` until the accumulated record count equals `a_c`.
6. Validate a stable total, consecutive page numbers, nonempty intermediate pages, and no count overflow.
7. Deduplicate the collected examination numbers while preserving first occurrence order.

The accumulation count before deduplication determines completion. The returned unique-number count may therefore be lower than `a_c` if the source roster contains duplicates. A zero total produces an empty result.

Clients can apply `startsWith` or `contains` filtering to the collected strings while retaining leading zeros. Static search-command names in Appendix C do not establish server-side prefix-search semantics.

### 9.4. Reading a Paper

For a selected project, subject, and complete examination number, the reference workflow queries `head`, `front`, and `back` separately. It reports a paper record when at least one score or image is available. All three absence responses produce no paper record.

The image queries return the image bytes themselves. A later download may issue another image query on the same authenticated connection. There is no confirmed server-issued download URL or image token in this workflow.

### 9.5. Reading Score Archives and Progress

A score workflow first calls `getScoreFileList`, selects a listed filename, and then calls `downScoreFile`. A progress workflow first obtains the project's subjects from `getXmList`, then calls `getAllProgressDetail` once for each distinct subject.

The server returns each subject's progress separately. Summing work across question groups measures marking tasks, which can count the same physical paper more than once. A client SHOULD label any aggregate accordingly.

## 10. Error Handling and Recovery

The native protocol has no established universal error envelope or stable numeric error-code registry. The reference client's application exceptions and HTTP status codes are outside the native protocol.

| Condition | Required or recommended handling |
| --- | --- |
| Invalid local parameter or failed GBK round trip | Reject before writing request bytes |
| Login body without recognized success prefix | Treat login as failed and close the connection |
| Text query without its required success prefix | Treat as an unexpected response; do not substitute an empty successful result |
| `getsudentSjno` for a paper representation | Return an absent-item result; the response frame is valid |
| Missing or malformed recognized pagination/record data | Abort the query; do not return silently truncated records |
| Wrong ZIP/JPEG marker or file signature | Reject the binary result |
| Zero/oversized frame, unexpected EOF, or response timeout | Invalidate and close the connection |
| Total or page sequence changes during traversal | Abort the traversal and restart from the first page if the caller retries |

Clients SHOULD bound retries and avoid automatic login loops. After reconnection, they MUST authenticate again and restart cursor-dependent work from its first-page command. A failed request MUST NOT be retried on a stream with uncertain frame alignment.

An empty parsed project or filename list alone is not evidence that every possible server error was understood: the reference parsers recognize the specific record shapes in this memo. Implementers SHOULD retain sanitized diagnostic metadata, such as command name, frame length, and expected marker, when investigating compatibility failures.

## 11. Security Considerations

### 11.1. Credentials and Transport

The observed plain-TCP login carries the account name and password directly. The confirmed wire procedure provides no transport encryption or message authentication. Deployments SHOULD restrict network access and use an appropriately secured network path. This memo does not define a new TLS mode that the server is known to accept.

Credentials and complete login request lines MUST NOT be written to ordinary logs, examples, or error reports. Student and teacher records are sensitive data; diagnostic output SHOULD redact or omit them.

### 11.2. Command and Parameter Boundaries

Clients implementing this read-only profile MUST allow only the confirmed commands and argument counts in Section 7. They MUST validate parameters before serializing them. In particular, an ampersand or CRLF MUST NOT be accepted inside a field.

A generic raw-command relay would bypass the command boundary and SHOULD NOT be exposed. Getter-like names in the executable are insufficient evidence of read-only server behavior; Appendix C candidates MUST remain outside the implemented allowlist until separately verified.

### 11.3. Resource and Parser Limits

Frame lengths MUST be validated before allocating body buffers. Text counts SHOULD be checked for range and internal consistency. Binary headers MUST be removed by their specified offsets, and binary content MUST NOT be passed through text decoding.

Downloaded archives and spreadsheets remain untrusted input. Consumers SHOULD apply independent decompression, file-count, parser, and rendering limits. Those local limits do not change the native ZIP response format or establish a server-side archive quota.

### 11.4. Connection Cleanup

Clients SHOULD release authenticated connections promptly after explicit logout, inactivity, loss of all consumers, or fatal transport failure. Connection reuse during activity and dependable cleanup afterward reduce account contention without repeated authentication for every query.

No native heartbeat, lease-renewal, explicit logout, or server-enforced idle duration has been confirmed in this profile.

## 12. Compatibility and Open Questions

The following are intentionally unresolved:

| Topic | Established boundary |
| --- | --- |
| Protocol negotiation | No version/capability negotiation is implemented |
| Account concurrency | Conflicts have occurred; exact server policy is unknown |
| Host field in login | Conditional field is used by the reference client; server interpretation is unknown |
| Native logout and heartbeat | No confirmed commands |
| Teacher success prefix | No dedicated prefix is validated |
| `end` pagination tag | Presence is required by the parser; value semantics are unknown |
| `tp` student tag | Parsed as part of the record shape; meaning is unknown |
| Paper header bytes | Content offsets and marker prefixes are known; remaining header layout is unknown |
| Native error messages | No complete marker/code registry |
| Maximum server field/frame size | Client limits are known; server maxima are unknown |
| Text escaping | No confirmed mechanism for delimiters or markup inside values |
| Search and cursor navigation variants | Literal candidates exist; arguments and behavior are unverified |
| Global/project subject relationship | Distinct lists are available; no broader relational schema is established |
| Administrative writes | Outside the read-only profile |

A future revision SHOULD promote a static candidate to a specified command only after its complete request form, successful response, absence/error behavior, side-effect classification, and session requirements have been checked. New evidence SHOULD identify the executable/server context and avoid embedding private records.

## 13. IANA Considerations

This memo requests no IANA actions and defines no Internet-wide port, media type, or protocol registry.

## 14. References

### 14.1. Normative References

- [RFC2119] Bradner, S., *Key words for use in RFCs to Indicate Requirement Levels*, BCP 14, RFC 2119, March 1997. <https://www.rfc-editor.org/rfc/rfc2119>
- [RFC8174] Leiba, B., *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words*, BCP 14, RFC 8174, May 2017. <https://www.rfc-editor.org/rfc/rfc8174>
- [RFC5234] Crocker, D., Ed., and P. Overell, *Augmented BNF for Syntax Specifications: ABNF*, STD 68, RFC 5234, January 2008. <https://www.rfc-editor.org/rfc/rfc5234>
- [RFC7405] Kyzivat, P., *Case-Sensitive String Support in ABNF*, RFC 7405, December 2014. <https://www.rfc-editor.org/rfc/rfc7405>

### 14.2. Informative References

- [Reference Implementation](https://github.com/Black-HIG/LH-Protocol/tree/main/reference): a Python implementation of the codec, confirmed packet forms, and illustrative query workflows.
- Earlier integration observations: comparison with the original client's progress display and successful directory, pagination, score-archive, and paper-query integration. These observations establish compatibility with the configured server, not every LeHua deployment.
- Offline inspection of command literals in the original client, used solely to identify the unverified candidates in Appendix C.

## Appendix A. Complete Example Exchanges (Informative)

### A.1. Login, Discovery, Progress, and Archive Download

The following is a synthetic exchange. Each `S -> C body` is independently preceded by `uint32le(body.length)`. Chinese and other supported non-ASCII text would be encoded according to Section 4.

```text
C -> S: teacherlogin&demo-user&demo-password&server.example.invalid\r\n
S -> C body: loginsuccess&

C -> S: setting&getXmList\r\n
S -> C body: getXmList&success&<xm name="DemoExam(DemoRoster)"><subject>Math</subject></xm>

C -> S: setting&getAllProgressDetail&DemoExam(DemoRoster)&Math\r\n
S -> C body: getYjProgress&success&<tizu name=15><yj_count>885</yj_count><no_count>0</no_count></tizu><school name=DemoSchool><tz>15</tz><yj_count>885</yj_count></school><school_renwu name=DemoSchool><tz>15</tz><yj_count>0</yj_count></school_renwu>

C -> S: setting&getScoreFileList&DemoExam(DemoRoster)\r\n
S -> C body: getScoreFileListSuccess<Math.zip>

C -> S: setting&downScoreFile&DemoExam(DemoRoster)&Math.zip\r\n
S -> C body: [20 octets: downScoreFileSuccess][ZIP bytes starting 50 4B 03 04]

C -> S: TCP connection closure when the consumer finishes or logs out
```

The progress result represents 885 reviewed and zero unreviewed group tasks, hence 100% group completion. The school's zero assignment count does not erase its 885 reviewed tasks.

### A.2. Two-Page Student Traversal

This synthetic list has three records and a first-page size of two. `end` is shown solely to satisfy the envelope shape, with no asserted value semantics.

```text
C -> S: setting&GetGradeList\r\n
S -> C body: GetGradeListSuccess<grade>DemoRoster</grade>

C -> S: setting&GetStudentList&DemoRoster\r\n
S -> C body: GetStudentListSuccess<a_c>3</a_c><c_p>1</c_p><end>0</end><kh>00012345</kh><st>Example One</st><sc>DemoSchool</sc><cs>Class 1</cs><tp></tp><kh>00012346</kh><st>Example Two</st><sc>DemoSchool</sc><cs>Class 1</cs><tp></tp>

C -> S: setting&GetStudentListNext&DemoRoster\r\n
S -> C body: GetStudentListSuccess<a_c>3</a_c><c_p>2</c_p><end>0</end><kh>00022345</kh><st>Example Three</st><sc>DemoSchool</sc><cs>Class 2</cs><tp></tp>
```

The resulting examination-number list is `00012345`, `00012346`, `00022345`. Prefix `0001` selects the first two strings; substring `2345` selects the first and third. These filters do not require an additional native request.

### A.3. Paper Summary and Images

```text
C -> S: getsudentSj&DemoExam(DemoRoster)&Math&00012345&head\r\n
S -> C body: [40-octet header beginning getsudentSjHeadOk][metadata containing <zf>93.5</zf>]

C -> S: getsudentSj&DemoExam(DemoRoster)&Math&00012345&front\r\n
S -> C body: [40-octet header beginning getsudentSjok][JPEG starting FF D8 FF]

C -> S: getsudentSj&DemoExam(DemoRoster)&Math&00012345&back\r\n
S -> C body: [header beginning getsudentSjno]
```

The student has an available score and front image, with an absent back image. Bracketed annotations are descriptive placeholders, not literal bytes or an assertion about unknown padding.

## Appendix B. Transport Test Vectors (Informative)

### B.1. ASCII Request

The exact request `setting&getXmList\r\n` has 19 octets:

```text
73 65 74 74 69 6E 67 26 67 65 74 58 6D 4C 69 73 74 0D 0A
```

### B.2. Framing Only

The following seven octets encode a three-octet body `ABC`:

```text
03 00 00 00 41 42 43
```

`ABC` is a transport test body, not a valid success result for a command in Section 8. A framing reader must produce the same body when these octets arrive in one read or in arbitrary fragments such as:

```text
Read 1: 03
Read 2: 00 00
Read 3: 00 41
Read 4: 42 43
```

A coalesced pair of transport frames is:

```text
03 00 00 00 41 42 43 01 00 00 00 5A
```

It yields `ABC`, then `Z`. This vector checks buffering only; it does not authorize request pipelining.

### B.3. Length Boundary Checks

| Prefix | Decoded length | Profile result |
| --- | --- | --- |
| `00 00 00 00` | 0 | Reject |
| `01 00 00 00` | 1 | Accept framing length |
| `00 00 00 04` | 67,108,864 | Accept framing length, subject to complete body arrival |
| `01 00 00 04` | 67,108,865 | Reject |

Accepting a framing length does not establish that the enclosed body is a valid command response.

## Appendix C. Statically Observed Command Candidates (Informative)

The following literals were extracted offline from the original client. They are additional query/download-shaped candidates, excluding the verified commands in Section 7. A trailing `&` is preserved exactly as found and indicates only that the literal includes a delimiter; it does not establish argument count, argument order, or field semantics.

Every entry has evidence level S. No request format, response schema, permissions, absence semantics, cursor behavior, or side-effect guarantee is specified for these candidates. They MUST NOT be called merely because their names start with `get`, `Get`, or `down`. No network probing of these candidates was performed while preparing this revision.

| Literal command candidate | Evidence |
| --- | --- |
| `setting&GetFenkeList` | S; unverified |
| `setting&GetStudentListLast&` | S; unverified |
| `setting&GetStudentListPre&` | S; unverified |
| `setting&GetStudentListSearch&` | S; unverified |
| `setting&GetTeacherListLast` | S; unverified |
| `setting&GetTeacherListPre` | S; unverified |
| `setting&GetTeacherListSearch&` | S; unverified |
| `setting&GetkemuFenkeList&` | S; unverified |
| `setting&downTeacherXls` | S; unverified |
| `setting&downTeacherXls&` | S; unverified |
| `setting&getAllStudentXls&` | S; unverified |
| `setting&getDankeNotAll&` | S; unverified |
| `setting&getGradeList` | S; unverified |
| `setting&getJiaoyanRenwuList&` | S; unverified |
| `setting&getNewXm` | S; unverified |
| `setting&getOneSchoolSjUploadProgress&` | S; unverified |
| `setting&getOnlineStatus&` | S; unverified |
| `setting&getQksjTjProgress&` | S; unverified |
| `setting&getRenwuList&` | S; unverified |
| `setting&getSchoolSubjectList&` | S; unverified |
| `setting&getSchoolSubjectUserList&` | S; unverified |
| `setting&getSchoolTizuDetail&` | S; unverified |
| `setting&getShuapingTizuList&` | S; unverified |
| `setting&getSingleSubjectCount&` | S; unverified |
| `setting&getSjNotUploadProgress&` | S; unverified |
| `setting&getSjQuekaoHaveScore&` | S; unverified |
| `setting&getSjUploadProgress&` | S; unverified |
| `setting&getSjUploadProgressX&` | S; unverified |
| `setting&getSjUploadTjProgress&` | S; unverified |
| `setting&getSubjectDetail&` | S; unverified |
| `setting&getSubjectUserList&` | S; unverified |
| `setting&getTeacherUserList` | S; unverified |
| `setting&getTeacherUserList&` | S; unverified |
| `setting&getTemplateImage_back&` | S; unverified |
| `setting&getTemplateImage_front&` | S; unverified |
| `setting&getTizuScoreList&` | S; unverified |
| `setting&getTizuUserList&` | S; unverified |
| `setting&getTizuUserListDetail&` | S; unverified |
| `setting&getXmFsxBySchool&` | S; unverified |
| `setting&getXmSchool&` | S; unverified |
| `setting&getXmSchoolList&` | S; unverified |
| `setting&getXmSubjectList&` | S; unverified |
| `setting&getXmSubjectTizu&` | S; unverified |
| `setting&getXuanzuoDetailList&` | S; unverified |
| `setting&getXuanzuoList&` | S; unverified |
| `setting&getXuanzuoNameList&` | S; unverified |
| `setting&getYjProgress&` | S; unverified |
| `setting&getYjScoreIdList&` | S; unverified |
| `setting&getYjSingleProgress&` | S; unverified |
| `setting&getYjTeacherDetail&` | S; unverified |
| `setting&getYjTizuDetail&` | S; unverified |
| `setting&getYjTizuMoreDetail&` | S; unverified |

Case variants and literals with and without a trailing delimiter are listed separately when both occur in the executable. Mutating, generation, deletion, configuration, password, and marking-control strings are outside this read-only inventory.

## Appendix D. Validation Notes (Informative)

Earlier integration exercised examination and subject discovery, teacher and student pagination, progress comparison with the original client, score ZIP retrieval, and paper representations. The command descriptions were cross-checked against the reference query implementation. Statically observed candidates remain unverified, as explained in Appendix C.

Document validation uses offline fixtures and source inspection. Preparing this revision does not require signing in to the server or changing any server records. Examples remain synthetic and do not disclose the configured account, its password, or actual student/teacher records.

Offline checks validated eleven synthetic request lines through the reference GBK encoder; parsed the examination, progress, score-list, teacher, and two-page student examples with the corresponding reference helpers; resolved references among all 26 ABNF rules; checked transport vectors and binary marker length; and checked the 52-entry static candidate inventory. These checks establish example consistency without claiming independent validation of undocumented server behavior.

## License

Copyright (c) 2026 Black-HIG. This document is licensed under the [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/). Attribute the work as *LeHua Server Read-Only Query Protocol* by Black-HIG, link to the license, and indicate any changes. The license applies to this documentation; it grants no rights to the original LeHua executable, server software, trademarks, or private records mentioned in the text.
