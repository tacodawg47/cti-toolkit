# Report Extension References and Wrapped PDF Acceptance

Date: 2026-11-24. Phase 2 stays open. This is a feature and acceptance pass,
not a fresh-data import. The operator explicitly prioritized feature delivery
over bulk NVD/CVE List catch-up. No dependency or git operation was performed.

## Delivered

Report Extraction now separates explicit software extension references from
ordinary IOCs. Chrome IDs use the Chromium 32-character a-p alphabet. VS Code
uses publisher.extension identifiers. Firefox uses explicitly labelled add-on
IDs, including email-shaped strings, @names and braced GUIDs. Recognize
official Chrome and VS Code marketplace URLs, including hidden report hrefs.
Chrome extension resource URLs also establish the Chrome ID.

Copy individual IDs or a list with ecosystem labels. Listing links are
constructed on fixed official hosts and opened only by the analyst. A source
mention is not a maliciousness judgment or proof of a live listing. Do not
infer a Firefox listing slug from its stable ID or treat a moz-extension
runtime UUID as that ID. Recognized references are masked before ordinary
hash/email/domain extraction. A bare MD5 or dotted word retains its original
handling. Code artifacts, including YARA rules, stay outside this prose pass.
The display cap is 200 unique references; masking continues beyond it.

Feeds has an independent Fetch New CVE Records POST. GET is read-only. The
control calls the existing CVE List incremental importer only, captures local
review changes, then returns to feed status. It does not call NVD, unrelated
feeds or the large full snapshot loader. Existing delta age/size limits apply.
No live refresh was run in this pass. No commit hook or automatic refresh was
added. A stale checkpoint is reported for an explicit full-load decision.

## Original PDF Check

Source: [Trend Micro Research, New MuddyWater Activities Uncovered](https://documents.trendmicro.com/assets/white_papers/wp_new_muddywater_findings_uncovered.pdf).
The original is 28 PDF pages, 1,617,194 bytes. It remains under ignored data,
with extracted text and rendered appendix images. It is not a redistributable
test fixture. SHA-256:
`0d52f31709ecb0f005712987abba4a7703314395795aa1b190fcc5b397735cac`.

Defender custom scan completed, exit 0, explicit output found no threats.
Product 4.18.26100.4, engine 1.1.26100.4, signatures 1.463.453.0, last updated
2026-11-24 07:10:05 Eastern. This records the scan, not a safety guarantee.
No protection settings were changed. Only this public project artifact was
selected. Read signature metadata with the permitted elevated read because
the sandbox returned access denied.

The baseline found 8 hash-shaped strings, including four fragments classified
as MD5s. The earlier repair found 107, including those four fragments. The
publisher's plural SHA-256s heading was not recognized, leaving two 32+32
rows ambiguous. Recognizing plural hash headings now returns 105 complete
SHA-256 values and no fragment MD5s. Standalone detection names now belong
to their own row. Previous detection names and previous hash-section headings
are not carried into the next row. Legacy underscore detection labels are
also retained.

An independent row-terminator scan of the default extracted appendix found
106 reported rows: 105 complete concatenated values and one 41-character
head. All 105 complete values exactly match extractor output. The remaining
23-character tail is visible at the top of printed page 20, continuing the
last row on printed page 19. The default PDF text stream places that tail
after other tables on page 20. The existing bounded adjacent-line algorithm
correctly refuses that association, leaving one complete source hash missed.

Rendered printed pages 19-21 were checked. A trial using pypdf layout mode
did not provide a trustworthy alternative reference list; it changed fragment
grouping and ordering. The bundled Poppler has pdfinfo/pdftoppm, not pdftotext.
Do not describe the unsuccessful layout trial as an independent pass.
The row-terminator comparison shares pypdf's text layer, so visual review of
the unusual boundary is still necessary. This is not a universal PDF claim.
All 105 recovered rows retain the source detection label after the fix.

The initial suspicion of incomplete publisher digests was incorrect. The
41-character head plus its 23-character continuation is a complete value.
Keep this correction in the handoff. The remaining work is reading-order
recovery using defensible page/column positions, not guessing digest bytes.

## Verification and Limits

Full offline suite: 483 tests, 482 passed and one existing skip. New synthetic
checks cover typed references, ID/hash ambiguity, stable versus runtime IDs,
hidden hrefs, fake store hosts, credential-bearing links, rule exclusion,
caps, passive escaped UI, copy controls, isolated POST and cross-site guards.
PDF tests cover plural headings, next-line detection names and row isolation.
The local app was restarted for feed GET and synthetic extraction smoke
checks. Original downloaded material and captures stay in ignored data.
After the final nearby-URL-context refinement, all 17 focused extension/PDF
tests passed again. A final verified hidden restart and loopback check
confirmed that the source context is retained and the URL query token is
absent from the rendered extraction result. No provider request was made.

The missing cross-page row is a documented PDF limitation. It does not justify
holding unrelated feature delivery on another data refresh. Phase 2 closeout
still needs an explicit disposition for HTMX partial loads and optional
GreyNoise/CVEDB lookups. Scheduling stays in the Phase 5 foundation slice.

## Format References

Reviewed primary documentation and wrote our own small stdlib parser. No
extension package or upstream executable code was installed or copied.

- [Chromium ID implementation](https://chromium.googlesource.com/chromium/src/+/main/components/crx_file/id_util.cc): length/alphabet validation.
- [Chrome extension key](https://developer.chrome.com/docs/extensions/reference/manifest/key): stable extension identity.
- [VS Code Extension Marketplace](https://code.visualstudio.com/docs/configure/extensions/extension-marketplace): publisher.extension identifiers.
- [Mozilla add-on identity](https://extensionworkshop.com/documentation/develop/extensions-and-the-add-on-id/): stable add-on identity versus development IDs.
- [Mozilla browser-specific settings](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/browser_specific_settings): accepted ID forms.
