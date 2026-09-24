"""Strict checks for packaged adapters, also applied by the native generator."""
import re
from browser_worker.auth import LoginSpec, exact_https_url
from browser_worker.errors import BrowserFailure, Code


def validate(value):
    try:
        if type(value) is not dict or set(value) != {"id", "version", "qualification", "origin", "routes", "views", "login"}:
            raise ValueError
        name(value["id"])
        if type(value["version"]) is not int or not 1 <= value["version"] <= 1000000 or value["qualification"] not in {"synthetic-only", "qualified"}:
            raise ValueError
        origin = value["origin"]
        if exact_https_url(origin) != origin:
            raise ValueError
        spec = LoginSpec(**value["login"])
        if exact_https_url(spec.success) != origin:
            raise ValueError
        routes = value["routes"]
        if type(routes) is not dict or not 1 <= len(routes) <= 32:
            raise ValueError
        for route, url in routes.items():
            name(route)
            if exact_https_url(url) != origin:
                raise ValueError
        views = value["views"]
        if type(views) is not list or not 1 <= len(views) <= 32:
            raise ValueError
        ids = set()
        for view in views:
            if type(view) is not dict or set(view) != {"id", "path", "root", "rows", "fields", "actions"}:
                raise ValueError
            name(view["id"])
            if view["id"] in ids:
                raise ValueError
            ids.add(view["id"])
            pattern(view["path"])
            selector(view["root"])
            selector(view["rows"])
            if type(view["fields"]) is not dict or not 1 <= len(view["fields"]) <= 8 or type(view["actions"]) is not dict or len(view["actions"]) > 4:
                raise ValueError
            for field, path in view["fields"].items():
                name(field)
                selector(path)
            for action, rule in view["actions"].items():
                name(action)
                if type(rule) is not dict or set(rule) != {"selector", "path"}:
                    raise ValueError
                selector(rule["selector"])
                pattern(rule["path"])
    except (ValueError, TypeError, KeyError, re.error):
        raise BrowserFailure(Code.UNSUPPORTED_VIEW) from None


def name(value):
    if type(value) is not str or re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", value) is None:
        raise ValueError


def selector(value):
    if type(value) is not str or not 1 <= len(value) <= 256 or not value.isascii():
        raise ValueError


def pattern(value):
    selector(value)
    if not value.startswith("^/") or not value.endswith("$"):
        raise ValueError
    re.compile(value)
