"""Minimal FileGuard client for CAPE's REST API.

FileGuard talks to CAPE only through this HTTP boundary:

    file -> POST /apiv2/tasks/create/file/  -> task ID
    task ID -> GET /apiv2/tasks/status/<id>/ -> status string
    task ID -> GET /apiv2/tasks/get/report/<id>/ -> JSON report

This client knows nothing about how or where CAPE runs (Hyper-V, KVM/libvirt,
snapshots, the analysis guest, CAPE's host kernel, or any specific address) --
only CAPE's API surface, configured via CAPE_BASE_URL/CAPE_API_TOKEN/
CAPE_REQUEST_TIMEOUT. That is what keeps this client portable between a local
development lab and a future AWS-hosted CAPE deployment without any code
change here.

This module does not poll, retry, or orchestrate submissions -- it only wraps
the three CAPE operations FileGuard needs, each as a single request.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests

DEFAULT_TIMEOUT = 30.0


class CapeClientError(Exception):
    """Raised when a CAPE API operation fails for any reason."""


class CapeClient:
    """Thin client for the CAPE API operations FileGuard needs."""

    def __init__(
        self,
        base_url: str | None = None,
        api_token: str | None = None,
        timeout: float | None = None,
    ) -> None:
        base_url = base_url or os.environ.get("CAPE_BASE_URL")
        if not base_url:
            raise CapeClientError("CAPE_BASE_URL is not configured")
        self.base_url = base_url.rstrip("/")

        if api_token is None:
            api_token = os.environ.get("CAPE_API_TOKEN") or None
        self.api_token = api_token

        if timeout is None:
            env_timeout = os.environ.get("CAPE_REQUEST_TIMEOUT")
            timeout = float(env_timeout) if env_timeout else DEFAULT_TIMEOUT
        self.timeout = float(timeout)

    def _headers(self) -> dict[str, str]:
        if self.api_token:
            return {"Authorization": f"Token {self.api_token}"}
        return {}

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _parse_json(self, response: Any, *, context: str) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise CapeClientError(f"{context}: CAPE response was not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise CapeClientError(f"{context}: malformed CAPE response (expected a JSON object)")
        return payload

    def submit_file(
        self,
        path: str | Path,
        *,
        package: str | None = None,
        machine: str | None = None,
        timeout: int | None = None,
    ) -> int:
        """Submit a file to CAPE for analysis and return its task ID.

        package/machine/timeout are CAPE's own submission options (which
        analysis package to use, which sandbox machine to target, and how
        long CAPE should let the analysis run) -- not this client's own HTTP
        request timeout, which is always applied separately via self.timeout.
        """
        source = Path(path)
        if not source.exists() or not source.is_file():
            raise CapeClientError(f"submit_file: source is not an existing regular file: {source}")

        data: dict[str, str] = {}
        if package is not None:
            data["package"] = package
        if machine is not None:
            data["machine"] = machine
        if timeout is not None:
            data["timeout"] = str(timeout)

        try:
            with source.open("rb") as handle:
                response = requests.post(
                    self._url("/apiv2/tasks/create/file/"),
                    files={"file": (source.name, handle)},
                    data=data,
                    headers=self._headers(),
                    timeout=self.timeout,
                )
        except requests.RequestException as exc:
            raise CapeClientError(f"submit_file: request to CAPE failed: {exc}") from exc

        if response.status_code != 200:
            raise CapeClientError(
                f"submit_file: CAPE returned HTTP {response.status_code}: {response.text[:500]}"
            )

        payload = self._parse_json(response, context="submit_file")
        if payload.get("error"):
            raise CapeClientError(f"submit_file: CAPE reported an error: {payload.get('error_value') or payload}")

        task_ids = None
        data_field = payload.get("data")
        if isinstance(data_field, dict):
            task_ids = data_field.get("task_ids")
        if not task_ids or not isinstance(task_ids, list):
            raise CapeClientError(f"submit_file: CAPE response did not include a task ID: {payload}")

        try:
            return int(task_ids[0])
        except (TypeError, ValueError) as exc:
            raise CapeClientError(f"submit_file: CAPE returned a non-integer task ID: {task_ids[0]!r}") from exc

    def get_status(self, task_id: int) -> str:
        """Return CAPE's status string for a task (e.g. "reported")."""
        try:
            response = requests.get(
                self._url(f"/apiv2/tasks/status/{int(task_id)}/"),
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise CapeClientError(f"get_status: request to CAPE failed: {exc}") from exc

        if response.status_code != 200:
            raise CapeClientError(
                f"get_status: CAPE returned HTTP {response.status_code}: {response.text[:500]}"
            )

        payload = self._parse_json(response, context="get_status")
        if payload.get("error"):
            raise CapeClientError(f"get_status: CAPE reported an error: {payload.get('error_value') or payload}")

        status = payload.get("data")
        if not isinstance(status, str) or not status:
            raise CapeClientError(f"get_status: CAPE response did not include a status string: {payload}")
        return status

    def get_report(self, task_id: int) -> dict[str, Any]:
        """Return CAPE's JSON report for a task as a Python dict."""
        try:
            response = requests.get(
                self._url(f"/apiv2/tasks/get/report/{int(task_id)}/"),
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise CapeClientError(f"get_report: request to CAPE failed: {exc}") from exc

        if response.status_code != 200:
            raise CapeClientError(
                f"get_report: CAPE returned HTTP {response.status_code}: {response.text[:500]}"
            )

        payload = self._parse_json(response, context="get_report")
        if payload.get("error") is True:
            raise CapeClientError(f"get_report: CAPE reported an error: {payload.get('error_value') or payload}")

        return payload
