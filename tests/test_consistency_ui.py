import json
import re
import unittest
from pathlib import Path

import quickjs

from api.runner_service import SnapshotRunnerResult
from test_consistency_checks import application, check_payload, state_payload


ROOT = Path(__file__).resolve().parents[1]
DOM = """
class Element {
  constructor() {
    this.children = [];
    this.value = '';
    this.classList = { toggle() {}, remove() {}, add() {} };
  }
  append(child) { this.children.push(child); }
  replaceChildren() { this.children = []; this.value = ''; }
  set textContent(value) { this.value = String(value); this.children = []; }
  get textContent() { return [this.value, ...this.children.map(child => child.textContent)].join(' '); }
}
const nodes = {};
const document = {
  createElement() { return new Element(); },
  querySelector(id) { return nodes[id] || (nodes[id] = new Element()); }
};
const $ = id => document.querySelector(id);
const elements = new Proxy({}, { get(target, name) { return $('#'+name); } });
const formatBeijingTime = value => value || '-';
const formatDateTime = value => value || '-';
"""


def function_source(html, name):
    start = re.search(r"^    function " + re.escape(name) + r"\(", html, re.MULTILINE)
    if start is None:
        raise AssertionError("Missing UI function: " + name)
    following = re.search(r"\n    (?:async )?function ", html[start.end():])
    if following is None:
        raise AssertionError("Cannot locate function boundary: " + name)
    return html[start.start():start.end() + following.start()]


class ConsistencyUiTests(unittest.TestCase):
    def render(self, page, report):
        html = (ROOT / "api/static" / page).read_text()
        context = quickjs.Context()
        context.set_time_limit(2)
        context.eval(DOM)
        helpers = (
            ("appendCheckCell", "appendCheckStatus") if page == "admin_ui.html"
            else ("appendTextCell", "appendStatusBadge")
        )
        for name in (*helpers, "formatNodeDifference", "checkStatusLabel", "actionLabel",
                     "actionObject", "actionBasis", "renderConsistencyCheck"):
            context.eval(function_source(html, name))
        context.eval("renderConsistencyCheck(" + json.dumps(report) + ");")
        return json.loads(context.eval("JSON.stringify({summary:$('#consistencySummary').textContent,"
                                       "nodes:$('#consistencyNodeRows').textContent,"
                                       "actions:$('#consistencyActionRows').textContent})"))

    def test_raw_configuration_issues_and_application_details_are_visible_in_both_pages(self):
        report = check_payload(state_payload(application(grouped=False), {"public": {}})).payload
        for page in ("admin_ui.html", "test_ui.html"):
            with self.subTest(page=page):
                rendered = self.render(page, report)
                for issue in report["firewalls"]["TEST-FW"]["config_issues"]:
                    self.assertIn(issue, rendered["nodes"])
                    self.assertIn(issue, rendered["actions"])
                self.assertIn("UD_TServe_203.0.113.10", rendered["actions"])
                self.assertIn("public", rendered["actions"])
                self.assertIn("\u914d\u7f6e\u5f02\u5e38", rendered["summary"])
                self.assertNotIn("repair_ip", rendered["actions"])
                self.assertNotIn("repair_application", rendered["actions"])
                self.assertNotIn("\u5b58\u5728\uff1a\u65e0\uff1b\u7f3a\u5931\uff1a\u65e0", rendered["actions"])

    def test_incomplete_query_still_displays_the_issues_that_were_observed(self):
        report = check_payload(
            state_payload(application(grouped=False)),
            SnapshotRunnerResult("failed", 1, "", error_message="device unavailable"),
        ).payload
        for page in ("admin_ui.html", "test_ui.html"):
            with self.subTest(page=page):
                rendered = self.render(page, report)
                self.assertIn("missing from application group", rendered["nodes"])
                self.assertIn("device unavailable", rendered["nodes"])
                self.assertFalse(rendered["actions"].strip())


if __name__ == "__main__":
    unittest.main()
