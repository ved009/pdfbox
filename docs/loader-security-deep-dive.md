# Loader and PDFParser security deep dive

This document captures a threat and hardening analysis for the `Loader` API family and the downstream
`PDFParser` that ingests untrusted PDFs. It focuses on attacker-controlled inputs, missing constraints,
and safer defaults for consumers such as e-signature platforms.

## Attacker-controlled inputs flowing into PDFParser
- **Byte-array entry points** (`Loader.loadPDF(byte[])`, `loadPDF(byte[], String, InputStream, String, StreamCacheCreateFunction)`) wrap attacker-supplied buffers in `RandomAccessReadBuffer` before constructing a `PDFParser`. Passwords, keystore streams, aliases, and stream cache factory are also caller-provided and passed directly to the parser without validation.【F:pdfbox/src/main/java/org/apache/pdfbox/Loader.java†L168-L242】
- **File entry points** (`Loader.loadPDF(File, ...)`) open `RandomAccessReadBufferedFile` handles over attacker-controlled files and forward caller-provided passwords/keystore/aliases/stream-cache factories into `PDFParser`. `RandomAccessRead` handles are intentionally left open for signing and never capped for size or lifetime.【F:pdfbox/src/main/java/org/apache/pdfbox/Loader.java†L245-L366】
- **RandomAccessRead entry points** allow callers to feed arbitrary custom I/O sources (including unbounded in-memory buffers or network-backed streams) plus optional password/keystore/alias and stream-cache factory to `PDFParser` without preflight checks.【F:pdfbox/src/main/java/org/apache/pdfbox/Loader.java†L368-L484】
- **Lenient parsing default**: `PDFParser.parse()` calls `parse(true)`, enabling lenient parsing on untrusted input unless callers explicitly disable it. Header validation falls back to warnings when lenient, and missing catalog `/Type` values are auto-inserted, smoothing over malformed structures provided by attackers.【F:pdfbox/src/main/java/org/apache/pdfbox/pdfparser/PDFParser.java†L125-L185】

## Missing constraints and risky defaults
- **Unbounded resource use**: All constructors advertise “Unrestricted main memory” for buffering PDF streams and use memory-only caches by default (e.g., `IOUtils.createMemoryOnlyStreamCache()`), exposing callers to memory exhaustion on large or adversarial PDFs.【F:pdfbox/src/main/java/org/apache/pdfbox/Loader.java†L168-L479】【F:pdfbox/src/main/java/org/apache/pdfbox/pdfparser/PDFParser.java†L38-L95】
- **No file size or object count limits**: Loader methods accept any file, buffer, or `RandomAccessRead` length, and `PDFParser` does not enforce maximum xref entries, object counts, or page tree depth before `initialParse`, allowing oversized or deeply nested documents to consume CPU/memory.
- **Lenient error handling by default**: Parsing continues when headers are missing or malformed and auto-corrects root dictionaries in lenient mode, making crafted structures more likely to reach deeper logic instead of failing fast.【F:pdfbox/src/main/java/org/apache/pdfbox/pdfparser/PDFParser.java†L105-L185】
- **Unbounded stream and recursion depth**: Stream lengths, nested objects, and recursive structures are not capped before or during `initialParse`, so intentionally malformed xref tables, page trees, or object graphs can trigger stack/memory exhaustion.
- **Open-ended caller-provided streams**: Password and keystore `InputStream` arguments are consumed without size checks; hostile or extremely large keystore payloads could tie up parser threads or memory.

## Recommended mitigations

### API-level hardening
- **Add limit parameters** (or security profiles) to `Loader` overloads so callers can specify maximum file size, maximum objects/xref entries, maximum page tree depth, and maximum stream length; default to secure presets for untrusted input.
- **Default to bounded caching** by replacing memory-only stream caches with configurable hybrid/disk-backed caches and offering strict presets for server-side use.
- **Expose strict-mode parsing** that defaults `lenient=false` for all `Loader` entry points (or add a "strict" variant) to make header and structure failures fatal by default in e-sign contexts.
- **Preflight inputs**: reject zero/negative stream lengths and cap keystore/password stream sizes before constructing `PDFParser`.

### Internal parser guards
- **Fail fast on header issues**: treat missing or invalid headers as fatal unless a caller explicitly opts into leniency; avoid auto-setting catalog `/Type` in strict mode.
- **Enforce structural caps**: in `PDFParser.initialParse`, bound the number of xref entries, maximum object number, page tree depth, and recursion depth while parsing trailers and page hierarchies; reject documents exceeding limits before allocating large structures.
- **Limit stream lengths and buffering strategy**: respect a maximum stream length when constructing COS streams and ensure stream caches spill to disk once thresholds are crossed to prevent OOM.
- **Close unused resources**: ensure `RandomAccessRead` and keystore streams are closed on parse failures to reduce resource leaks during attack attempts.

### Dangerous defaults for e-sign platforms
E-signature and document-processing services that call `Loader.loadPDF(...)` without explicit limits inherit lenient parsing, unbounded in-memory buffering, and no structural caps. Such defaults should be overridden with strict parsing, conservative resource limits, and disk-backed caches before accepting untrusted uploads.
