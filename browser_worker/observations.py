"""Manifest-defined text views and document-bound navigation references."""
import html
import json
import re
import secrets
from urllib.parse import urlsplit

from shadow_common.secret_guard import SecretGuard, REDACTED
from .auth import exact_https_url
from .errors import BrowserFailure, Code
from .output_gate import Phase


def project_records(records, spec, protected_values):
    guard = SecretGuard(protected_values)
    if type(records) is not list or len(records) > 50:
        raise BrowserFailure(Code.UNSUPPORTED_VIEW)
    result = []
    for record in records:
        if type(record) is not dict or set(record) != {"fields", "actions"}:
            raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        fields, actions = record["fields"], record["actions"]
        if type(fields) is not dict or set(fields) != set(spec["fields"]) or type(actions) is not list or len(actions) > 4:
            raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        projected = []
        for name, text in fields.items():
            if type(text) is not str or len(text) > 256:
                raise BrowserFailure(Code.UNSUPPORTED_VIEW)
            # Never truncate a long secret-bearing field into an unmatched
            # prefix. HTML entities are checked before preserving visible text.
            value = guard.project(text)
            if guard.project(html.unescape(text)) == REDACTED:
                value = REDACTED
            projected.append({"name": name, "value": value})
        for action in actions:
            if (type(action) is not dict or set(action) != {"id", "index"}
                    or action["id"] not in spec["actions"] or type(action["index"]) is not int
                    or not 0 <= action["index"] < 200):
                raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        result.append({"fields": projected, "actions": actions})
    return result


COLLECT = r"""(spec => {
  if (window !== window.top || document.querySelector('iframe,frame,input[type=password]')) return null;
  const roots = document.querySelectorAll(spec.root);
  if (roots.length !== 1) return null;
  const root = roots[0], rows = [...root.querySelectorAll(spec.rows)];
  if (rows.length > 50) return null;
  const snapshot = {document, root, url: location.href, actions: [], checks: []};
  const unique = (scope, selector) => {const matches = scope.querySelectorAll(selector); return matches.length === 1 ? matches[0] : null;};
  const visible = node => node instanceof HTMLElement && node.isConnected && node.getClientRects().length > 0 &&
    getComputedStyle(node).visibility === 'visible' && getComputedStyle(node).display !== 'none';
  const records = [];
  for (const row of rows) {
    if (!visible(row)) return null;
    const fields = {}, actions = [];
    for (const [name, selector] of Object.entries(spec.fields)) {
      const node = unique(row, selector);
      if (!visible(node) || !['SPAN','P','H1','H2','TD','DD'].includes(node.tagName) || node.children.length) return null;
      const value = node.innerText;
      if (value.length > 256) return null;
      fields[name] = value;
      snapshot.checks.push(() => unique(row, selector) === node && visible(node) && node.children.length === 0 && node.innerText === value);
    }
    for (const [name, action] of Object.entries(spec.actions)) {
      const node = unique(row, action.selector);
      if (!(node instanceof HTMLAnchorElement) || !visible(node) || node.download || !['','_self'].includes(node.target)) return null;
      const url = new URL(node.href);
      if (url.origin !== spec.origin || url.search || url.hash || url.username || url.password ||
          !(new RegExp(action.path)).test(url.pathname)) return null;
      const index = snapshot.actions.length;
      snapshot.actions.push({node, row, selector: action.selector, href: node.href, visible, unique});
      const href = node.href;
      snapshot.checks.push(() => unique(row, action.selector) === node && visible(node) && node.href === href &&
        !node.download && ['', '_self'].includes(node.target));
      actions.push({id: name, index});
    }
    records.push({fields, actions});
  }
  snapshot.valid = () => snapshot.document === document && snapshot.url === location.href &&
    document.querySelectorAll(spec.root).length === 1 && document.querySelector(spec.root) === root &&
    !document.querySelector('iframe,frame,input[type=password]') &&
    root.querySelectorAll(spec.rows).length === rows.length &&
    [...root.querySelectorAll(spec.rows)].every((node, index) => node === rows[index] && visible(node)) &&
    snapshot.checks.every(check => check());
  globalThis.__shadowView = snapshot;
  return records;
})"""

TARGET = r"""(index => {
  const snapshot = globalThis.__shadowView, action = snapshot?.actions[index];
  if (!action || !snapshot.valid() || snapshot.document !== document || !snapshot.root.isConnected ||
      !snapshot.root.contains(action.row) || !action.visible(action.node) ||
      action.unique(action.row, action.selector) !== action.node || action.node.href !== action.href ||
      action.node.download || !['','_self'].includes(action.node.target)) return null;
  return action.href;
})"""


class Observations:
    def __init__(self, page, gate, adapter, protected_values):
        self.page, self.gate, self.adapter = page, gate, adapter
        self.protected_values = protected_values
        self.cdp = None
        self.world = None
        self.references = {}
        self.document_ref = None
        self.snapshot = None

    async def document(self):
        self.gate.lease.check()
        if len(self.page.context.pages) != 1:
            raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        if self.cdp is None:
            self.cdp = await self.page.context.new_cdp_session(self.page)
        tree = (await self.cdp.send("Page.getFrameTree"))["frameTree"]
        if tree.get("childFrames"):
            raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        frame = tree["frame"]
        return frame, frame["id"] + ":" + frame["loaderId"]

    def view(self, url):
        origin = exact_https_url(url)
        if origin != self.adapter["origin"]:
            raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        path = urlsplit(url).path
        for spec in self.adapter["views"]:
            if re.fullmatch(spec["path"], path):
                return spec
        raise BrowserFailure(Code.UNSUPPORTED_VIEW)

    async def evaluate(self, expression):
        self.gate.lease.check()
        result = await self.cdp.send("Runtime.evaluate", {"expression": expression, "contextId": self.world, "returnByValue": True})
        self.gate.lease.check()
        if "exceptionDetails" in result:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        return result.get("result", {}).get("value")

    async def observe(self, view_id):
        frame, document = await self.document()
        checkpoint = self.gate.output_checkpoint(document)
        spec = self.view(frame["url"])
        if view_id != spec["id"]:
            raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        self.references.clear()
        self.world = (await self.cdp.send("Page.createIsolatedWorld", {"frameId": frame["id"], "worldName": "shadow-safe-views", "grantUniveralAccess": False}))["executionContextId"]
        raw = await self.evaluate(COLLECT + "(" + json.dumps(spec | {"origin": self.adapter["origin"]}) + ")")
        cookies = await self.page.context.cookies()
        if len(cookies) > 256 or any(len(cookie["value"]) > 8192 for cookie in cookies):
            raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        records = project_records(raw, spec, self.protected_values + [cookie["value"] for cookie in cookies])
        for record in records:
            for action in record["actions"]:
                reference = secrets.token_hex(32)
                self.references[reference] = action.pop("index")
                action["element_ref"] = reference
        _, current = await self.document()
        self.gate.validate_output(checkpoint, current)
        if await self.evaluate("globalThis.__shadowView?.valid() === true") is not True:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        self.snapshot = checkpoint
        self.document_ref = secrets.token_hex(32)
        return {"view_id": spec["id"], "document_ref": self.document_ref, "records": records}

    async def click(self, reference):
        _, current = await self.document()
        if reference not in self.references or self.snapshot is None:
            raise BrowserFailure(Code.INVALID_REQUEST)
        self.gate.validate_output(self.snapshot, current)
        target = await self.evaluate(TARGET + "(" + str(self.references[reference]) + ")")
        if type(target) is not str:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        self.view(target)
        self.gate.validate_output(self.snapshot, (await self.document())[1])
        await self.navigate_url(target)

    async def navigate(self, route_id):
        frame, document = await self.document()
        self.gate.output_checkpoint(document)
        self.view(frame["url"])
        if await self.page.locator('input[type=password],iframe,frame').count():
            raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        target = self.adapter["routes"].get(route_id)
        if target is None:
            raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        await self.navigate_url(target)

    async def navigate_url(self, target):
        self.view(target)
        self.references.clear()
        self.snapshot = None
        self.gate.transition(Phase.NAVIGATING)
        # Manifest links designate read-only navigation. Do not execute a
        # website's arbitrary click handler when following the approved link.
        await self.page.goto(target, wait_until="domcontentloaded", timeout=15000)
        frame, document = await self.document()
        if frame["url"] != target:
            raise BrowserFailure(Code.DOCUMENT_CHANGED)
        self.view(frame["url"])
        if await self.page.locator('input[type=password],iframe,frame').count():
            raise BrowserFailure(Code.UNSUPPORTED_VIEW)
        self.gate.transition(Phase.VERIFYING)
        self.gate.ready(document)
