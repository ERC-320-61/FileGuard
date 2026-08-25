"""Tests for the FileGuard CAPE API client. No real CAPE instance is used."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cape_client import CapeClient, CapeClientError


class _FakeResponse:
    def __init__(self, status_code: int = 200, json_body=None, text: str = ""):
        self.status_code = status_code
        self._json_body = json_body
        self.text = text or (str(json_body) if json_body is not None else "")

    def json(self):
        if self._json_body is None:
            raise ValueError("no JSON body")
        return self._json_body


class CapeClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.sample_path = Path(self._tmp.name) / "sample.txt"
        self.sample_path.write_bytes(b"harmless cape client test content")
        self.client = CapeClient(base_url="http://cape.example.local:8000", timeout=5)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # -- submit_file -----------------------------------------------------

    def test_submit_file_returns_task_id(self) -> None:
        response = _FakeResponse(200, {"error": False, "data": {"task_ids": [3], "errors": []}})
        with mock.patch("cape_client.requests.post", return_value=response) as post:
            task_id = self.client.submit_file(self.sample_path)

        self.assertEqual(task_id, 3)
        post.assert_called_once()

    def test_submit_file_sends_optional_package_machine_timeout(self) -> None:
        response = _FakeResponse(200, {"error": False, "data": {"task_ids": [7]}})
        with mock.patch("cape_client.requests.post", return_value=response) as post:
            self.client.submit_file(self.sample_path, package="exe", machine="fileguard-win-sandbox", timeout=120)

        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["data"]["package"], "exe")
        self.assertEqual(kwargs["data"]["machine"], "fileguard-win-sandbox")
        self.assertEqual(kwargs["data"]["timeout"], "120")
        # The client's own HTTP timeout is always applied separately from
        # CAPE's submission-level "timeout" option.
        self.assertEqual(kwargs["timeout"], 5)

    def test_submit_file_omits_optional_fields_when_not_provided(self) -> None:
        response = _FakeResponse(200, {"error": False, "data": {"task_ids": [1]}})
        with mock.patch("cape_client.requests.post", return_value=response) as post:
            self.client.submit_file(self.sample_path)

        self.assertEqual(post.call_args.kwargs["data"], {})

    def test_submit_file_rejects_missing_file(self) -> None:
        missing = Path(self._tmp.name) / "does-not-exist.txt"

        with mock.patch("cape_client.requests.post") as post:
            with self.assertRaises(CapeClientError):
                self.client.submit_file(missing)

        post.assert_not_called()

    def test_submit_file_rejects_directory_as_source(self) -> None:
        directory = Path(self._tmp.name) / "a-directory"
        directory.mkdir()

        with self.assertRaises(CapeClientError):
            self.client.submit_file(directory)

    def test_submit_file_raises_on_connection_failure(self) -> None:
        import requests

        with mock.patch("cape_client.requests.post", side_effect=requests.ConnectionError("refused")):
            with self.assertRaises(CapeClientError):
                self.client.submit_file(self.sample_path)

    def test_submit_file_raises_on_malformed_response(self) -> None:
        response = _FakeResponse(200, {"error": False, "data": {}})  # no task_ids
        with mock.patch("cape_client.requests.post", return_value=response):
            with self.assertRaises(CapeClientError):
                self.client.submit_file(self.sample_path)

    def test_submit_file_raises_on_non_json_response(self) -> None:
        response = _FakeResponse(200, json_body=None, text="not json")
        with mock.patch("cape_client.requests.post", return_value=response):
            with self.assertRaises(CapeClientError):
                self.client.submit_file(self.sample_path)

    def test_submit_file_raises_on_cape_error_response(self) -> None:
        response = _FakeResponse(200, {"error": True, "error_value": "Invalid file"})
        with mock.patch("cape_client.requests.post", return_value=response):
            with self.assertRaises(CapeClientError):
                self.client.submit_file(self.sample_path)

    def test_submit_file_raises_on_http_failure_status(self) -> None:
        response = _FakeResponse(500, text="internal server error")
        with mock.patch("cape_client.requests.post", return_value=response):
            with self.assertRaises(CapeClientError):
                self.client.submit_file(self.sample_path)

    # -- get_status --------------------------------------------------------

    def test_get_status_returns_reported(self) -> None:
        response = _FakeResponse(200, {"error": False, "data": "reported"})
        with mock.patch("cape_client.requests.get", return_value=response):
            status = self.client.get_status(3)

        self.assertEqual(status, "reported")

    def test_get_status_raises_on_cape_error(self) -> None:
        response = _FakeResponse(200, {"error": True, "error_value": "Task not found"})
        with mock.patch("cape_client.requests.get", return_value=response):
            with self.assertRaises(CapeClientError):
                self.client.get_status(999)

    def test_get_status_raises_on_connection_failure(self) -> None:
        import requests

        with mock.patch("cape_client.requests.get", side_effect=requests.Timeout("timed out")):
            with self.assertRaises(CapeClientError):
                self.client.get_status(3)

    # -- get_report ----------------------------------------------------

    def test_get_report_returns_dict(self) -> None:
        report = {"info": {"id": 3}, "target": {"file": {"name": "sample.txt"}}}
        response = _FakeResponse(200, report)
        with mock.patch("cape_client.requests.get", return_value=response):
            result = self.client.get_report(3)

        self.assertEqual(result, report)

    def test_get_report_raises_on_non_json_response(self) -> None:
        response = _FakeResponse(200, json_body=None, text="<html>not json</html>")
        with mock.patch("cape_client.requests.get", return_value=response):
            with self.assertRaises(CapeClientError):
                self.client.get_report(3)

    def test_get_report_raises_on_cape_error_response(self) -> None:
        response = _FakeResponse(200, {"error": True, "error_value": "Report not found"})
        with mock.patch("cape_client.requests.get", return_value=response):
            with self.assertRaises(CapeClientError):
                self.client.get_report(3)

    # -- authentication --------------------------------------------------

    def test_authorization_header_sent_when_token_configured(self) -> None:
        client = CapeClient(base_url="http://cape.example.local:8000", api_token="secret-token", timeout=5)
        response = _FakeResponse(200, {"error": False, "data": "reported"})
        with mock.patch("cape_client.requests.get", return_value=response) as get:
            client.get_status(3)

        self.assertEqual(get.call_args.kwargs["headers"].get("Authorization"), "Token secret-token")

    def test_no_authorization_header_when_token_absent(self) -> None:
        response = _FakeResponse(200, {"error": False, "data": "reported"})
        with mock.patch("cape_client.requests.get", return_value=response) as get:
            self.client.get_status(3)

        self.assertNotIn("Authorization", get.call_args.kwargs["headers"])

    # -- configuration -----------------------------------------------------

    def test_missing_base_url_raises(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(CapeClientError):
                CapeClient()

    def test_trailing_slash_in_base_url_is_normalized(self) -> None:
        client = CapeClient(base_url="http://cape.example.local:8000/", timeout=5)
        self.assertEqual(client._url("/apiv2/tasks/status/3/"), "http://cape.example.local:8000/apiv2/tasks/status/3/")


if __name__ == "__main__":
    unittest.main()
