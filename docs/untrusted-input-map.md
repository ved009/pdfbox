# PDFBox untrusted PDF input entry points

This document summarizes the public APIs and main code paths that ingest or process untrusted PDF content. It highlights the areas most relevant to parsing, rendering, signature handling, forms, annotations, embedded files, JavaScript actions, and incremental updates.

## Parsing and document loading
- **Loader.loadPDF(...)** provides byte-array, file, and `RandomAccessRead` entry points that construct a `PDFParser` and return a `PDDocument`. These methods accept passwords and optional key stores, meaning they are the first boundary for untrusted input and decryption context.【F:pdfbox/src/main/java/org/apache/pdfbox/Loader.java†L168-L242】【F:pdfbox/src/main/java/org/apache/pdfbox/Loader.java†L255-L259】 See the companion [Loader/PDFParser security deep dive](./loader-security-deep-dive.md) for attacker-controlled inputs, missing constraints, and mitigation guidance.
- **PDFParser.load(...)** legacy static helpers delegate to `Loader` but still expose parsing for external callers, ultimately creating a `PDDocument` from the parsed COS structures.【F:pdfbox/src/main/java/org/apache/pdfbox/pdfparser/PDFParser.java†L199-L236】

## Rendering and page content processing
- **PDFRenderer** consumes a loaded `PDDocument` and walks pages/annotations to paint into an AWT `BufferedImage`. The renderer exposes annotation filtering (`setAnnotationsFilter`) and rendering hints, making it the main API path that interprets graphics, fonts, images, and appearance streams from untrusted PDFs during display or rasterization.【F:pdfbox/src/main/java/org/apache/pdfbox/rendering/PDFRenderer.java†L40-L160】

## Digital signature capture and verification surfaces
- **PDSignature** models signature dictionaries and exposes metadata setters/getters (`setName`, `setLocation`, `setReason`, etc.) used when creating or inspecting signatures. It is the primary object representing signature fields that may have been populated by untrusted signers and later verified by consumers.【F:pdfbox/src/main/java/org/apache/pdfbox/pdmodel/interactive/digitalsignature/PDSignature.java†L150-L217】
- **PDDocument.saveIncremental(...)** pathways append revisions for signing or post-sign changes against an originally loaded file via `COSWriter`. Because incremental saves rely on the prior loaded content and signature byte ranges, they are the main APIs for manipulating and preserving untrusted signed PDFs without rewriting the full document.【F:pdfbox/src/main/java/org/apache/pdfbox/pdmodel/PDDocument.java†L1054-L1132】
- **PDDocument.saveIncrementalForExternalSigning(...)** prepares data to be signed externally and then embeds the CMS signature, combining untrusted original content with new signature bytes.【F:pdfbox/src/main/java/org/apache/pdfbox/pdmodel/PDDocument.java†L1134-L1168】

## Forms and user input fields
- **PDAcroForm** encapsulates interactive form data, importing FDF payloads (`importFDF`) and exporting filled data (`exportFDF`). These methods ingest or serialize field values coming from untrusted sources and link them into the document’s field tree.【F:pdfbox/src/main/java/org/apache/pdfbox/pdmodel/interactive/form/PDAcroForm.java†L60-L172】

## Annotations and appearance handling
- **PDAnnotation.createAnnotation(...)** instantiates concrete annotation types (links, file attachments, widgets, markup, etc.) based on the `/Subtype` in the annotation dictionary. Rendering and form workflows rely on these objects to interpret annotation content supplied by the PDF author, including widget annotations tied to form fields.【F:pdfbox/src/main/java/org/apache/pdfbox/pdmodel/interactive/annotation/PDAnnotation.java†L42-L160】

## Embedded file access
- **PDComplexFileSpecification** represents file attachment specifications and resolves embedded file streams through the `/EF` dictionary. It is the core API for accessing filenames and embedded payloads that originate from untrusted documents (e.g., attachments or file annotations).【F:pdfbox/src/main/java/org/apache/pdfbox/pdmodel/common/filespecification/PDComplexFileSpecification.java†L44-L140】

## JavaScript actions
- **PDActionJavaScript** wraps `/JavaScript` actions, exposing getters/setters for script code stored as strings or streams in action dictionaries. This is the main API surface for discovering or manipulating JavaScript embedded in PDFs, which may need to be sandboxed or disabled when processing untrusted input.【F:pdfbox/src/main/java/org/apache/pdfbox/pdmodel/interactive/action/PDActionJavaScript.java†L25-L92】

## Incremental update and mutation considerations
- **PDDocument.saveIncremental(...)** requires a loaded source stream (`pdfSource`) and writes only updated objects via `COSWriter`, ensuring modifications are appended instead of replacing the original file. This logic governs how untrusted PDFs are mutated while preserving prior revisions, which is critical for signature preservation and forensic traceability.【F:pdfbox/src/main/java/org/apache/pdfbox/pdmodel/PDDocument.java†L1054-L1132】
- **PDDocument.importPage(...)** copies page dictionaries and content streams from another `PDDocument`, reassigning object keys and warning about inherited resources. This path brings external page content—including annotations and resources—into a new document and thus handles untrusted data during merging or assembly operations.【F:pdfbox/src/main/java/org/apache/pdfbox/pdmodel/PDDocument.java†L667-L712】
