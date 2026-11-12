# LH-Protocol

RFC-style documentation for the LeHua server's native TCP query protocol.

Read [LeHua Server Read-Only Query Protocol](protocol.md).

The specification documents twelve implemented command forms, including authentication, examination and subject discovery, marking progress, score archive downloads, paper summaries and images, teacher records, and student rosters. It includes ABNF, response framing, binary layouts, pagination workflows, synthetic transcripts, and transport test vectors. A separate appendix lists 52 command candidates found by static inspection, with their unverified status made explicit.

Examples use fictional credentials and records. The specification is an independent interoperability document based on the reference implementation and earlier integration observations.

## Reference Implementation

The [Python reference implementation](reference/README.md) demonstrates the protocol using only the Python 3.10+ standard library:

- [codec](reference/lehua/codec.py): GBK request encoding, response lengths, exact reads, and incremental frame decoding.
- [packets](reference/lehua/packets.py): typed request builders and response parsers for the twelve confirmed command forms.
- [client](reference/lehua/client.py): a serialized authenticated TCP connection, bounded workflows, cursor traversal, and connection cleanup.
- [examples](reference/examples.py): examination discovery, progress, score downloads, paper queries, directory pagination, and examination-number filtering.

Run the offline tests from `reference/` with `python -m unittest discover -s tests -v`. Tests use synthetic fixtures and a loopback server. Read the [usage guide](reference/README.md) before supplying a server address or credentials.

## License and attribution

Copyright (c) 2026 Black-HIG.

The documentation and reference implementation are licensed under the [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/) (SPDX: `CC-BY-SA-4.0`). The complete legal text is in [LICENSE](LICENSE).

Suggested attribution: *LeHua Server Read-Only Query Protocol*, Black-HIG, [LH-Protocol](https://github.com/Black-HIG/LH-Protocol), CC BY-SA 4.0. Indicate changes when sharing an adaptation.

The license covers the original documentation and reference code in this repository. It does not grant rights to the original LeHua executable, server software, trademarks, or private records referenced in it.
