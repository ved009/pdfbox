# PDFParser DoS Risks and Secure Parsing Profile

## Observed High-Cost Parsing Paths

- **Lenient trailer repair triggers full-file brute-force scan.** When trailer retrieval fails in lenient mode, the parser clears the xref table and `BruteForceParser.rebuildTrailer()` scans from offset 6 to EOF for `obj`/`endobj` patterns. A crafted PDF without a valid `startxref` (or with trailing garbage) forces an O(file size) scan with repeated seeking. **Cap:** disable brute-force recovery in production or gate it behind strict file/object-size ceilings; impose a maximum scanned-byte budget before aborting.

- **Streams without valid `/Length` fall back to unlimited keyword search.** In lenient mode `parseCOSStream()` accepts missing or invalid `Length` and uses `readUntilEndStream()` to hunt for `endstream`, consuming data until the sentinel appears and buffering it. A malicious stream can omit the terminator or place it after huge data, causing linear-time reads and unbounded memory use. **Cap:** require `/Length`, validate against a maximum stream size, and disable the lenient fallback or enforce a global stream-byte quota with early aborts.

- **Object scanning tolerates overlapping/malformed objects.** During brute-force search, candidate object IDs are tracked until a later `endobj`; missing `endobj` keeps the scanner moving and can rescan overlapping offsets, especially in files filled with repeated `obj` fragments. **Cap:** enforce limits on discovered objects and maximum search distance after a missing `endobj`, then abort to avoid quadratic overlap.

## Crafted PDF Patterns

- Files omitting `%%EOF`/`startxref` or appending long garbage trailers to force brute-force reconstruction.
- Streams missing `/Length` or lying about it, with late or absent `endstream` markers.
- PDFs packed with repeated `obj` substrings but malformed generation/object IDs to keep the brute-force search looping.

## Recommended Secure Parsing Profile (e-sign SaaS)

- **Strict mode by default:** disable lenient parsing for customer uploads; reject files lacking `startxref`/trailer unless in a controlled repair workflow.
- **Size and resource ceilings:** set limits on file size, bytes scanned during trailer/object recovery, object count, stream length, and total decompressed bytes; abort when any threshold is exceeded.
- **Stream requirements:** require `/Length`, verify declared length ≤ configured cap and matches actual data; forbid `readUntilEndStream` fallback in production.
- **Resource accounting:** track bytes read, seeks in brute-force mode, and objects parsed; stop when counters exceed thresholds to prevent quadratic rescans.
- **Feature gating:** disable brute-force trailer reconstruction and object-stream recovery except in offline repair tooling.
- **Monitoring:** log early-abort reasons (length mismatch, missing markers, counter limits) to flag hostile uploads and tune limits.
