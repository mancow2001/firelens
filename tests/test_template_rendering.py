#!/usr/bin/env python3
"""
Regression tests for the Starlette TemplateResponse calling convention.

Starlette >= 1.0 removed the legacy `TemplateResponse(name, context)`
signature; the request must be passed first:
`TemplateResponse(request, name, context)`. Passing the context dict as
`name` breaks Jinja2's template cache with:
  TypeError: cannot use 'tuple' as a dict key (unhashable type: 'dict')
"""

import re
from pathlib import Path

import pytest
from starlette.requests import Request
from starlette.templating import Jinja2Templates

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = PROJECT_ROOT / "src" / "firelens" / "templates"
ROUTES_DIR = PROJECT_ROOT / "src" / "firelens" / "web_dashboard" / "routes"

# Legacy signature: first positional argument is a string literal
LEGACY_CALL = re.compile(r'TemplateResponse\(\s*(?:\n\s*)?"')


def _make_request() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("testclient", 50000),
    }
    return Request(scope)


def test_no_legacy_templateresponse_calls():
    """Route code must not use the removed TemplateResponse(name, context) form"""
    offenders = []
    for path in ROUTES_DIR.glob("*.py"):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if LEGACY_CALL.search(line):
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders, f"legacy TemplateResponse(name, ...) calls: {offenders}"


@pytest.mark.parametrize(
    "template_name",
    sorted(p.name for p in TEMPLATES_DIR.glob("*.html")),
)
def test_template_compiles(template_name):
    """Every shipped template must compile under the installed Jinja2"""
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    template = templates.get_template(template_name)
    assert template.name == template_name


def test_new_style_templateresponse():
    """New-style call works against the real templates directory"""
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    request = _make_request()
    response = templates.TemplateResponse(request, "dashboard.html", {})
    assert response.status_code == 200
