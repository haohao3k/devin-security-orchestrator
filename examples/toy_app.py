"""Tiny safe fixture for planning a candidate; this is not a benchmark."""
from html import escape


def render_name(name: str) -> str:
    return "<p>" + escape(name, quote=True) + "</p>"
