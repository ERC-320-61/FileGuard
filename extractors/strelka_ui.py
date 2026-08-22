"""Extract a raw Strelka event from the Strelka UI/API response wrapper."""

from __future__ import annotations

from typing import Any


def extract_strelka_event(wrapper: Any) -> dict[str, Any]:
    """Return the first raw event from a Strelka UI/API response wrapper."""
    if not isinstance(wrapper, dict):
        raise ValueError("Strelka wrapper must be an object")
    if "strelka_response" not in wrapper:
        raise ValueError("Strelka wrapper is missing 'strelka_response'")

    response = wrapper["strelka_response"]
    if not isinstance(response, list):
        raise ValueError("'strelka_response' must be a list of events")
    if not response:
        raise ValueError("'strelka_response' contains no events")
    if not isinstance(response[0], dict):
        raise ValueError("'strelka_response[0]' must be an object")

    return response[0]
