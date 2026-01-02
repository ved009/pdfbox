# Lenient brute-force rebuild blueprints and reachability

This note provides minimal and DoS-scale PDF layouts that trigger PDFBox's lenient brute-force trailer rebuild path via the default `Loader.loadPDF(...)` APIs. It also restates the call chain and trigger conditions so the behavior is easily reproducible.

## Default API reachability

* **Lenient defaults**: `Loader.loadPDF(...)` creates `PDFParser` and calls `parse()` with `lenient = true` by default.
* **Call chain**: `Loader.loadPDF(...)` → `PDFParser.parse()` → `initialParse()` → `retrieveTrailer()` → `BruteForceParser.rebuildTrailer()` → `bfSearchForObjects()`.
* **Trigger**: If `retrieveTrailer()` cannot find `%%EOF`/`startxref`, xref parsing throws, or the trailer lacks `/Root`, lenient mode flips `rebuildTrailer = true`, clears xref data, and starts the brute-force scan over the entire file to synthesize object offsets.

## Trigger condition summary

* **Entry point**: Any default `Loader.loadPDF(...)` overload (no explicit lenient toggle needed).
* **Minimal malformation**: Omit both `startxref` and `%%EOF` so `retrieveTrailer()` cannot locate an EOF marker and sets `rebuildTrailer = true` in lenient mode.
* **Fallback path**: `rebuildTrailer = true` causes `BruteForceParser.bfSearchForObjects()` to scan from byte 6 onward, treating every `obj` substring as a candidate offset until the end of the file.

## Variant A: smallest reproducible brute-force trigger

Goal: prove reachability with minimal size while still causing a full brute-force scan.

**Blueprint (line/byte oriented)**
1. Header: `%PDF-1.7\n` (valid header keeps parsing alive).
2. Object: `1 0 obj\n<< /Type /Catalog >>\nendobj\n` (ensures at least one object exists).
3. Filler: A short line containing the substring `obj` (e.g., `garbage obj token\n`) to provide a candidate during scanning.
4. Omissions: **No** `xref`, `startxref`, or `%%EOF`.

**Result**: Lenient parsing reaches `retrieveTrailer()`, fails to find terminators, sets `rebuildTrailer = true`, and `bfSearchForObjects()` walks the entire file looking for `obj` tokens.

## Variant B: DoS amplifier pattern

Goal: maximize CPU by increasing candidate offsets and scan length while remaining parseable enough to reach rebuild.

**Blueprint (scalable)**
1. Header: `%PDF-1.7\n`.
2. Seed objects: Minimal catalog/page pair: `1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n`.
3. Filler strategy: Repeat a dense block such as `"000 0 obj\n<<>>\nendobj\n"` (or any byte sequence containing `obj`) many times to inflate file size and candidate offsets. Add whitespace between blocks to avoid accidental `startxref` tokens.
4. Termination: Omit `xref`, `startxref`, and `%%EOF` so the scan runs to end-of-file.
5. Scaling knobs: Choose repetition counts to hit target sizes (e.g., ~1 MB ≈ 20k repetitions of a 50-byte block; 10 MB ≈ 200k; 50 MB ≈ 1M). CPU grows with both file length and `obj` density.

**Result**: Parser accepts the header and seed objects, then brute-force scanning iterates over nearly every byte, evaluating each `obj` substring as a potential object start. Larger files proportionally increase CPU consumption.

## Regression test plan (JUnit-style)

* **Fixtures**: Store variant A and a 1–5 MB variant B under `src/test/resources/malformed/` to avoid large inline arrays.
* **Invocation**: In a test method, load the fixture as bytes, wrap in `RandomAccessReadBuffer`, construct `PDFParser` (or call `Loader.loadPDF`), and invoke `parse()` (lenient default). Use try-with-resources to close the parser.
* **Assertions**:
  * **Timeout/guard**: Wrap parsing in a time-limited executor or guard counter; assert parsing completes within a small budget once a fix is applied (e.g., <500 ms for variant A) or throws a guard exception if a scan cap is exceeded.
  * **Behavioral**: After applying limits, expect `IOException` or guard failure when `startxref`/`%%EOF` are missing rather than unbounded brute-force scanning.
* **Stability**: Prefer byte-scan counters over absolute timing to avoid platform flakiness. If timing is used, include generous margins.

## Notes on avoiding false negatives

* Ensure fixtures never contain `startxref`, `xref`, `trailer`, or `%%EOF` substrings—even in filler—to keep the rebuild path active.
* Keep filler ASCII-only with obvious `obj` tokens to maximize candidate offsets while avoiding accidental binary structure.
* When timing is necessary, calibrate against a known-good baseline or use ample timeout headroom to accommodate CI variance.
