"""Synthetic layout regressions, not a claim to cover every publisher page."""

import unittest
from unittest.mock import patch

from app.modules.extract import attack, html, markdown, pdf


CATALOG = {"objects": {
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactics": ["execution"]},
    "T1059.003": {"name": "Command and Scripting Interpreter: Windows Command Shell", "tactics": ["execution"]},
    "T1105": {"name": "Ingress Tool Transfer", "tactics": ["command-and-control"]},
}, "tactics": {"TA0002": {"name": "Execution", "slug": "execution"},
               "TA0011": {"name": "Command and Control", "slug": "command-and-control"}}}


def findings(document):
    return {row["id"]: row for row in attack.extract(document, CATALOG)}


def evidence(document, ident="T1059.001"):
    return findings(document)[ident]["evidence"]


class AttackLayoutTests(unittest.TestCase):
    def test_heading_supplies_table_tactic_and_content_overrides_wrong_headers(self):
        document = html.parse_document("""<h2>Execution</h2><table>
          <tr><td><b>Tactic</b></td><td>Technique</td><td>Annotation</td></tr>
          <tr><td>PowerShell</td><td>T1059.001</td><td>Ran encoded PowerShell commands.</td></tr>
          <tr><td>Windows Command Shell</td><td>T1059.003</td><td>Launched cmd.exe.</td></tr></table>""")
        first = evidence(document)[0]
        self.assertEqual(first["procedure"], "Ran encoded PowerShell commands.")
        self.assertEqual(first["tactic"], "Execution")
        self.assertFalse(first["name_mismatch"])

    def test_lists_split_catalog_label_with_colon(self):
        document = html.parse_document("""<p><b>Execution</b></p><ul>
          <li>T1059.001 Command and Scripting Interpreter: PowerShell: Ran encoded commands.</li>
          <li>Windows Command Shell (T1059.003) - Launched cmd.exe.</li></ul>""")
        first = evidence(document)[0]
        self.assertEqual(first["procedure"], "Ran encoded commands.")
        self.assertEqual(first["kind"], "HTML List")
        self.assertEqual(first["tactic"], "Execution")
        self.assertEqual(evidence(document, "T1059.003")[0]["procedure"], "Launched cmd.exe.")

    def test_grid_preserves_row_alignment(self):
        document = html.parse_document("""<h2>Execution</h2><div>
          <div><span>T1059.001</span><span>PowerShell</span><span>Ran encoded commands.</span></div>
          <div><span>T1059.003</span><span>Windows Command Shell</span><span>Launched cmd.exe.</span></div>
          </div>""")
        self.assertEqual(evidence(document)[0]["kind"], "HTML Grid")
        self.assertEqual(evidence(document, "T1059.003")[0]["procedure"], "Launched cmd.exe.")

    def test_article_sections_do_not_become_grid_rows(self):
        document = html.parse_document("""<div>
          <div><h2>Execution</h2><p>Background description.</p></div>
          <div><table><tr><th>ID</th><th>Use</th></tr>
          <tr><td>T1059.001</td><td>Ran encoded commands.</td></tr></table><p>Figure one.</p></div>
          <div><table><tr><th>ID</th><th>Use</th></tr>
          <tr><td>T1059.003</td><td>Launched cmd.exe.</td></tr></table><p>Figure two.</p></div>
          </div>""")
        for ident, expected in [("T1059.001", "Ran encoded commands."), ("T1059.003", "Launched cmd.exe.")]:
            rows = evidence(document, ident)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["kind"], "HTML Table")
            self.assertEqual(rows[0]["procedure"], expected)
        self.assertFalse(any(table.kind == "HTML Grid" for table in document.tables))

    def test_combined_tactic_and_technique_grid_has_no_invented_procedure(self):
        document = html.parse_document("""<div>
          <div><span>Tactic: Technique</span><span>ATT&amp;CK Code</span></div>
          <div><span>Execution: PowerShell</span><span>T1059.001</span></div>
          <div><span>Execution: Windows Command Shell</span><span>T1059.003</span></div>
          </div>""")
        for row in findings(document).values():
            self.assertEqual(row["evidence"][0]["procedure"], "")
            self.assertEqual(row["evidence"][0]["tactic"], "Execution")
            self.assertFalse(row["evidence"][0]["name_mismatch"])

    def test_heading_block_attaches_only_following_paragraph(self):
        document = html.parse_document("""<h3>T1059.001 PowerShell</h3><p>Ran encoded commands.</p>
          <h3>T1059.003 Windows Command Shell</h3><p>Launched cmd.exe.</p>""")
        self.assertEqual(evidence(document)[0]["procedure"], "Ran encoded commands.")
        self.assertEqual(evidence(document, "T1059.003")[0]["procedure"], "Launched cmd.exe.")

    def test_pre_and_br_blocks_keep_lines(self):
        body = "T1059.001 PowerShell - Ran encoded commands.\nT1059.003 Windows Command Shell - Launched cmd.exe."
        for tag, content, kind in [("pre", body, "Preformatted Lines"), ("p", body.replace("\n", "<br>"), "HTML Line Block")]:
            with self.subTest(tag=tag):
                rows = evidence(html.parse_document("<h2>Execution</h2><" + tag + ">" + content + "</" + tag + ">"))
                self.assertEqual(rows[0]["procedure"], "Ran encoded commands.")
                self.assertEqual(rows[0]["kind"], kind)
                self.assertEqual(rows[0]["tactic"], "Execution")

    def test_names_only_list_does_not_invent_procedure(self):
        document = html.parse_document("<ul><li>T1059.001 PowerShell</li><li>T1059.003 Windows Command Shell</li></ul>")
        self.assertTrue(all(not item["procedure"] for row in findings(document).values() for item in row["evidence"]))

    def test_parent_subtechnique_prefix_and_ids_only_shared_label(self):
        document = html.parse_document("<ul><li>Command and Scripting Interpreter::PowerShell [T1059.001] - Ran encoded commands.</li></ul>")
        self.assertEqual(evidence(document)[0]["procedure"], "Ran encoded commands.")
        labels = html.parse_document("<ul><li>T1059.001 PowerShell and T1059.003 Windows Command Shell</li></ul>")
        self.assertTrue(all(not item["procedure"] for row in findings(labels).values() for item in row["evidence"]))

    def test_shared_row_and_tactic_mismatch_are_retained(self):
        document = html.parse_document("""<table><tr><th>ID</th><th>Use</th><th>Tactic</th></tr>
          <tr><td>T1059.001, T1059.003</td><td>Ran shared command scripts.</td><td>Command and Control</td></tr></table>""")
        for row in findings(document).values():
            self.assertTrue(row["evidence"][0]["shared"])
            self.assertTrue(row["evidence"][0]["tactic_mismatch"])

    def test_tactic_separator_carries_to_next_row(self):
        document = html.parse_document("""<table><tr><th>ID</th><th>Use</th><th>Tactic</th></tr>
          <tr><td colspan="3">Execution</td></tr>
          <tr><td>T1059.001</td><td>Ran encoded commands.</td><td></td></tr>
          <tr><td>T1059.003</td><td>Launched cmd.exe.</td><td></td></tr></table>""")
        self.assertEqual(evidence(document)[0]["tactic"], "Execution")

    def test_prose_is_labelled_low_for_three_ids(self):
        document = html.parse_document("<p>The actor combined T1059.001, T1059.003 and T1105 to transfer and run scripts.</p>")
        for row in findings(document).values():
            item = row["evidence"][0]
            self.assertEqual(item["kind"], "Prose Fallback")
            self.assertEqual(item["confidence"], "Low")
            self.assertTrue(item["shared"])

    def test_markdown_heading_and_body(self):
        document = markdown.parse_document("### T1059.001 PowerShell\n\nRan encoded commands.\n\n### T1059.003\nLaunched cmd.exe.")
        self.assertEqual(evidence(document)[0]["kind"], "Markdown Heading Block")
        self.assertEqual(evidence(document, "T1059.003")[0]["procedure"], "Launched cmd.exe.")

    def test_pdf_aligned_paragraphs_and_page_boundaries(self):
        document = pdf.hash_document("T1059.001 PowerShell\nRan encoded commands.\n\nT1059.003\nLaunched cmd.exe.")
        self.assertEqual(evidence(document)[0]["procedure"], "Ran encoded commands.")
        self.assertEqual(evidence(document, "T1059.003")[0]["kind"], "PDF Paragraph")
        # A heading at the end of a page cannot borrow the next page's prose.
        separated = pdf.hash_document("T1059.001 PowerShell\fRan encoded commands.")
        self.assertEqual(evidence(separated), [])

    def test_pdf_flattened_columns_are_ids_only(self):
        document = pdf.hash_document("T1059.001 PowerShell\nT1059.003 Windows Command Shell\nRan encoded commands.\nLaunched cmd.exe.")
        self.assertTrue(all(not row["evidence"] for row in findings(document).values()))

    def test_pdf_multiple_ids_in_one_paragraph_not_assigned(self):
        document = pdf.hash_document("T1059.001 and T1059.003\nRan shared command scripts.")
        self.assertTrue(all(not row["evidence"] for row in findings(document).values()))

    def test_script_and_atlas_ids_do_not_become_attack_evidence(self):
        document = html.parse_document('<script>T1059.001</script><p>AML.T0040</p><p>T9999</p>')
        self.assertEqual(list(findings(document)), ["T9999"])
        self.assertEqual(findings(document)["T9999"]["status"], "Absent From Catalog")

    def test_structure_limit_keeps_reference_with_notice(self):
        with patch("app.modules.extract.layouts.MAX_NODES", 3):
            document = html.parse_document("<div><div><div><p>T1059.001</p></div></div></div>")
        self.assertTrue(document.layout_limited)
        self.assertIn("T1059.001", findings(document))

    def test_parsing_never_fetches_linked_resources(self):
        with patch("socket.socket", side_effect=AssertionError("unexpected network")):
            document = html.parse_document('<img src="https://example.test/x"><iframe src="https://example.test/y"></iframe><p>T1059.001 PowerShell</p>')
            self.assertIn("T1059.001", findings(document))
