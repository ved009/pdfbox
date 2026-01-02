# Lenient parsing fail-open and DoS hotspots

This document summarizes places in the PDFBox parser where `lenient = true` causes malformed input to be accepted or auto-repaired instead of failing fast.

## Findings

1. **Trailer and cross-reference recovery**  
   * **Location**: `COSParser.retrieveTrailer`  
   * **Lenient condition**: When `startxref`/xref parsing fails, or the trailer lacks `Root`, lenient mode sets `rebuildTrailer` to `true`.  
   * **Malformed input**: Missing/invalid `startxref`, damaged xref table, or trailer without a `Root` entry.  
   * **Recovery behavior**: Clears existing xref table and runs `BruteForceParser.rebuildTrailer`, auto-populating offsets and trailer entries.  
   * **Risk**: Accepts attacker-controlled object graphs whose offsets/types were not validated, enabling gadgets to be reached even when cross-reference data is corrupt. In e-signature/SaaS contexts this bypasses structural integrity checks that should abort parsing.  
   * **Subsystems reachable**: Full document object model including rendering, annotations, forms, and signatures once a synthetic trailer/root is built.  
   
2. **Missing EOF marker**  
   * **Location**: `COSParser.getStartxrefOffset`  
   * **Lenient condition**: If no `%%EOF` is found in the tail of the file, lenient mode treats the buffer end as EOF instead of throwing.  
   * **Malformed input**: PDFs without a proper end-of-file marker.  
   * **Recovery behavior**: Continues searching for `startxref` and proceeds with parsing.  
   * **Risk**: Allows truncated/concatenated files to be processed; untrusted data may smuggle extra bytes after the logical end or omit EOF entirely, undermining file boundary checks.  
   * **Subsystems reachable**: Entire parsing pipeline (xref, objects, rendering) despite missing terminator.  

3. **Missing xref entry lookups**  
   * **Location**: `COSParser.getObjectOffset`  
   * **Lenient condition**: When an object offset is absent from the xref table, lenient mode queries the brute-force offset map and inserts it into the xref table.  
   * **Malformed input**: Corrupt or intentionally pruned xref tables that omit object references.  
   * **Recovery behavior**: Auto-fills offsets from brute-force search and continues dereferencing objects.  
   * **Risk**: Attacker-controlled objects that were not declared in xref become reachable, bypassing structural validation and enabling hidden content/streams to execute downstream processing.  
   * **Subsystems reachable**: Any feature that dereferences objects—page trees, embedded files, forms, annotations.  

4. **Missing `endobj` terminators**  
   * **Location**: `COSParser.parseFileObject`  
   * **Lenient condition**: If an object ends with anything other than `endobj`, lenient mode logs a warning and accepts the object.  
   * **Malformed input**: Objects missing proper `endobj` markers.  
   * **Recovery behavior**: Suppresses exception, leaving parsed object in the document.  
   * **Risk**: Parser may merge object boundaries or skip validation, allowing crafted streams/objects to bleed into subsequent content; downstream consumers process partially parsed attacker data.  
   * **Subsystems reachable**: Rendering and higher-level model objects corresponding to the malformed indirect object.  

5. **Object stream parse failures**  
   * **Location**: `COSParser.parseObjectStreamObject`  
   * **Lenient condition**: Exceptions while parsing an object stream are logged but ignored when lenient.  
   * **Malformed input**: Corrupt object stream bodies.  
   * **Recovery behavior**: Continues without throwing, returning `null` for problematic entries while leaving other objects cached.  
   * **Risk**: Downstream code may treat missing objects as `null`/default, potentially skipping checks or mis-associating resources; attacker-crafted streams can evade detection.  
   * **Subsystems reachable**: Any consumer of compressed objects (page resources, forms, annotations) continues execution.  

6. **Missing stream length**  
   * **Location**: `COSParser.parseCOSStream`  
   * **Lenient condition**: If a stream lacks a `Length` entry, lenient mode warns and falls back to scanning for `endstream`.  
   * **Malformed input**: Streams without declared length.  
   * **Recovery behavior**: Reads until `endstream`/`endobj`, sets computed length into the dictionary, and proceeds.  
   * **Risk**: Allows ambiguous stream boundaries; attackers can append hidden data or rely on early `endstream` tokens to truncate validation.  
   * **Subsystems reachable**: Stream consumers (images, content streams, embedded files, form XObjects) run with inferred lengths.  

7. **Malformed stream terminators**  
   * **Location**: `COSParser.parseCOSStream`  
   * **Lenient condition**: Accepts `endobj` in place of `endstream`, or `endstream...` with trailing garbage, by logging and rewinding instead of failing.  
   * **Malformed input**: Streams ending with wrong keywords or extra bytes after `endstream`.  
   * **Recovery behavior**: Continues parsing and rewinds to align subsequent parsing.  
   * **Risk**: Lets truncated/misaligned streams be treated as valid, potentially enabling injection of extra tokens or hiding data beyond expected boundaries.  
   * **Subsystems reachable**: Same as above—rendering and resource consumers operate on streams despite malformed endings.  

8. **Header version fallback**  
   * **Location**: `COSParser.parseHeader` (invoked via `parsePDFHeader`/`parseFDFHeader`)  
   * **Lenient condition**: If the version string cannot be parsed, lenient mode defaults the document version to 1.7 instead of throwing.  
   * **Malformed input**: Headers missing a numeric version or containing garbage.  
   * **Recovery behavior**: Assumes version 1.7 and rewinds to continue parsing.  
   * **Risk**: Processes files without a valid PDF signature/version line, enabling non-PDF blobs or polyglots to be ingested.  
   * **Subsystems reachable**: Entire document processing path under an assumed version.  

9. **Missing header version info**  
   * **Location**: `PDFParser.parse(boolean)`  
   * **Lenient condition**: If both PDF and FDF header parsing fail, lenient mode emits a warning instead of throwing.  
   * **Malformed input**: Files without recognizable `%PDF-`/`%FDF-` headers.  
   * **Recovery behavior**: Continues into `initialParse()` and builds document structures anyway.  
   * **Risk**: Non-PDF data can be interpreted as PDF objects, increasing attack surface in services that rely on header validation.  
   * **Subsystems reachable**: Full parsing (xref, objects, rendering) proceeds despite missing magic header.  

10. **Missing catalog type auto-insertion**  
    * **Location**: `PDFParser.initialParse`  
    * **Lenient condition**: When the root dictionary lacks `/Type /Catalog`, lenient mode inserts it automatically.  
    * **Malformed input**: Root object without the required type.  
    * **Recovery behavior**: Adds `/Type /Catalog` and continues.  
    * **Risk**: Accepts non-catalog roots, which could mask malicious root objects or bypass schema validation; downstream consumers trust the auto-tagged catalog.  
    * **Subsystems reachable**: Document catalog and page tree become usable even if attacker supplied an improperly typed root.  

## Summary table

| # | File & method | Lenient-only behavior | Should be strict by default for untrusted PDFs? |
|---|---------------|-----------------------|-----------------------------------------------|
| 1 | `COSParser.retrieveTrailer` | Rebuilds trailer/xref when parsing fails or `Root` missing | Yes |
| 2 | `COSParser.getStartxrefOffset` | Allows missing `%%EOF` | Yes |
| 3 | `COSParser.getObjectOffset` | Brute-force inserts missing xref entries | Yes |
| 4 | `COSParser.parseFileObject` | Accepts objects without `endobj` | Yes |
| 5 | `COSParser.parseObjectStreamObject` | Swallows object stream parse exceptions | Yes |
| 6 | `COSParser.parseCOSStream` | Infers length when missing | Yes |
| 7 | `COSParser.parseCOSStream` | Accepts malformed stream terminators | Yes |
| 8 | `COSParser.parseHeader` | Defaults version when header invalid | Yes |
| 9 | `PDFParser.parse` | Continues without PDF/FDF header | Yes |
| 10 | `PDFParser.initialParse` | Auto-inserts `/Type /Catalog` | Yes |

## Denial-of-service hotspots (lenient-only)

The following behaviors are the most likely to create CPU- or memory-heavy parsing when `lenient = true`.

| Rank | File & method | Unbounded work in lenient path | Minimal malicious pattern | Suggested regression test | Smallest safe fix |
| ---- | ------------- | ----------------------------- | ------------------------- | ------------------------- | ------------------ |
| 1 (highest) | `BruteForceParser.bfSearchForObjects` invoked via `COSParser.retrieveTrailer` rebuild path | `do { … } while (currentOffset < lastEOFMarker && !parser.isEOF())` scans from byte 6 until `lastEOFMarker`, which is set to `Long.MAX_VALUE` when no `%%EOF` exists, causing a full-file walk with repeated seeks and digit checks | Large (10–100 MB) file with `%PDF-1.7` header, no `startxref`/`%%EOF`, and filler bytes containing many `obj` substrings forces trailer rebuild and endless brute-force scan | Add an integration test that opens such a file in lenient mode and asserts parsing exceeds a reasonable time budget or trips a guard counter; the same file should fail fast when strict | Cap brute-force search span (e.g., stop after N MB/objects) and abort rebuild when no EOF is found; optionally gate on system property for backwards compatibility |
| 2 | `COSParser.getObjectOffset` fallback to `BruteForceParser.getBFCOSObjectOffsets` | First missing xref entry triggers the same full brute-force search as above, potentially on-demand for crafted references; repeated missing objects can re-enter the search logic | Xref table that omits many referenced objects plus large padding with `obj` tokens makes offset recovery traverse the whole file to satisfy each dereference | Unit test that dereferences a missing object in a large, malformed file and asserts the lookup is limited (e.g., throws after hitting a maximum search byte count) | Share the same search cap as above and short-circuit repeated brute-force calls once the cap is hit; reject unresolved objects instead of retrying |
| 3 | `COSParser.parseCOSStream` when `/Length` is absent or invalid | `readUntilEndStream()` loops over the stream buffer until it matches `endstream`/`endobj`; with no length and no terminator it streams until EOF, counting bytes | Stream dictionary without `/Length`, followed by megabytes of data and **no** `endstream` token; lenient parsing scans the rest of the file | Regression test that parses such a stream and expects an early abort or bounded byte count rather than full-file traversal | Enforce a maximum fallback scan length (e.g., configurable MB limit) and throw if `endstream` is not found within that bound |
| 4 (lower) | `COSParser.parseCOSStream` accepting `endobj`/extra bytes as terminators | Extra characters after `endstream` cause rewind-based re-parsing; malformed `endobj` terminators can misalign parsing but do not inherently force large scans | Stream ending with `endobj` plus trailing noise; lenient mode rewinds and continues | Unit test verifying the parser caps rewind/realignment attempts and fails after a small number of unexpected terminators | Add a small cap on rewind distance or terminator corrections before throwing; reject oversized trailing garbage |

**Ranking rationale:** Items 1–3 perform unbounded scanning over attacker-controlled file sizes; the brute-force search is the most CVE-prone because it runs over the entire file when `%%EOF`/xref are absent, while missing stream lengths can still consume the remaining file. Malformed terminators (rank 4) are primarily correctness issues with limited incremental work.
