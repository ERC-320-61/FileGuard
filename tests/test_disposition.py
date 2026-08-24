"""Tests for the FileGuard local disposition executor."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import disposition
from disposition import DispositionError, _publish_without_overwrite, execute_disposition


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DispositionExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.intake_dir = self.root / "intake"
        self.clean_dir = self.root / "clean"
        self.quarantine_dir = self.root / "quarantine"
        self.intake_dir.mkdir()
        self.clean_dir.mkdir()
        self.quarantine_dir.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_source(
        self,
        name: str = "sample.txt",
        content: bytes = b"harmless FileGuard disposition test content",
    ) -> Path:
        path = self.intake_dir / name
        path.write_bytes(content)
        return path

    def test_clean_decision_copies_verifies_and_deletes_source(self) -> None:
        source = self._make_source()
        original_hash = _sha256_of(source)
        decision = {"conclusion": "CLEAN", "destination": "clean", "review_required": False, "reasons": []}

        result = execute_disposition(source, decision, self.clean_dir, self.quarantine_dir)

        destination_path = self.clean_dir / "sample.txt"
        self.assertTrue(destination_path.exists())
        self.assertEqual(_sha256_of(destination_path), original_hash)
        self.assertFalse(source.exists())
        self.assertEqual(result["destination"], "clean")
        self.assertEqual(result["destination_path"], destination_path)
        self.assertEqual(result["sha256"], original_hash)
        self.assertTrue(result["source_deleted"])

    def test_suspicious_decision_routes_to_quarantine(self) -> None:
        source = self._make_source()
        decision = {"conclusion": "SUSPICIOUS", "destination": "quarantine", "review_required": True, "reasons": []}

        result = execute_disposition(source, decision, self.clean_dir, self.quarantine_dir)

        self.assertTrue((self.quarantine_dir / "sample.txt").exists())
        self.assertFalse(source.exists())
        self.assertEqual(result["destination"], "quarantine")

    def test_malicious_decision_routes_to_quarantine(self) -> None:
        source = self._make_source()
        decision = {"conclusion": "MALICIOUS", "destination": "quarantine", "review_required": True, "reasons": []}

        result = execute_disposition(source, decision, self.clean_dir, self.quarantine_dir)

        self.assertTrue((self.quarantine_dir / "sample.txt").exists())
        self.assertFalse(source.exists())
        self.assertEqual(result["destination"], "quarantine")

    def test_incomplete_decision_routes_to_quarantine(self) -> None:
        source = self._make_source()
        decision = {"conclusion": "INCOMPLETE", "destination": "quarantine", "review_required": True, "reasons": []}

        result = execute_disposition(source, decision, self.clean_dir, self.quarantine_dir)

        self.assertTrue((self.quarantine_dir / "sample.txt").exists())
        self.assertFalse(source.exists())
        self.assertEqual(result["destination"], "quarantine")

    def test_existing_destination_file_is_not_overwritten(self) -> None:
        source = self._make_source(content=b"new content")
        existing = self.clean_dir / "sample.txt"
        existing.write_bytes(b"pre-existing content, must not be touched")
        decision = {"conclusion": "CLEAN", "destination": "clean"}

        with self.assertRaises(DispositionError) as ctx:
            execute_disposition(source, decision, self.clean_dir, self.quarantine_dir)

        self.assertEqual(ctx.exception.stage, "destination_exists")
        self.assertEqual(existing.read_bytes(), b"pre-existing content, must not be touched")
        self.assertTrue(source.exists())

    def test_publish_without_overwrite_refuses_existing_final_path(self) -> None:
        # Exercises the low-level publish primitive directly, bypassing the
        # caller's upfront exists() check entirely, to prove the no-overwrite
        # guarantee is real (atomic at publish time via os.link) rather than
        # only a check-then-act pre-check that could race.
        final_path = self.clean_dir / "target.txt"
        final_path.write_bytes(b"original")
        temp_path = self.clean_dir / ".tmp-test-target.txt"
        temp_path.write_bytes(b"incoming")

        with self.assertRaises(FileExistsError):
            _publish_without_overwrite(temp_path, final_path)

        self.assertEqual(final_path.read_bytes(), b"original")
        self.assertTrue(temp_path.exists())  # cleanup is the caller's responsibility

    def test_failed_verification_preserves_source(self) -> None:
        source = self._make_source()
        decision = {"conclusion": "CLEAN", "destination": "clean"}
        real_sha256 = disposition._sha256
        calls = {"n": 0}

        def _tampering_sha256(path: Path) -> str:
            calls["n"] += 1
            if calls["n"] == 2:  # second call computes the destination hash
                return "0" * 64
            return real_sha256(path)

        with mock.patch("disposition._sha256", side_effect=_tampering_sha256):
            with self.assertRaises(DispositionError) as ctx:
                execute_disposition(source, decision, self.clean_dir, self.quarantine_dir)

        self.assertEqual(ctx.exception.stage, "verification_failed")
        self.assertTrue(source.exists())
        self.assertFalse((self.clean_dir / "sample.txt").exists())
        self.assertEqual(list(self.clean_dir.iterdir()), [])  # temp file cleaned up

    def test_source_delete_failure_preserves_verified_destination_and_raises(self) -> None:
        source = self._make_source()
        decision = {"conclusion": "CLEAN", "destination": "clean"}
        real_unlink = Path.unlink

        def _flaky_unlink(self_path, *args, **kwargs):
            if self_path == source:
                raise OSError("permission denied")
            return real_unlink(self_path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", _flaky_unlink):
            with self.assertRaises(DispositionError) as ctx:
                execute_disposition(source, decision, self.clean_dir, self.quarantine_dir)

        self.assertEqual(ctx.exception.stage, "source_delete")
        destination_path = self.clean_dir / "sample.txt"
        self.assertTrue(destination_path.exists())
        self.assertEqual(_sha256_of(destination_path), _sha256_of(source))
        self.assertTrue(source.exists())
        self.assertEqual(ctx.exception.destination_path, destination_path)

    def test_malformed_decision_preserves_source(self) -> None:
        source = self._make_source()

        with self.assertRaises(DispositionError) as ctx:
            execute_disposition(source, {"conclusion": "CLEAN"}, self.clean_dir, self.quarantine_dir)

        self.assertEqual(ctx.exception.stage, "decision_malformed")
        self.assertTrue(source.exists())
        self.assertEqual(list(self.clean_dir.iterdir()), [])
        self.assertEqual(list(self.quarantine_dir.iterdir()), [])

    def test_unknown_destination_preserves_source(self) -> None:
        source = self._make_source()
        decision = {"conclusion": "CLEAN", "destination": "archive"}

        with self.assertRaises(DispositionError) as ctx:
            execute_disposition(source, decision, self.clean_dir, self.quarantine_dir)

        self.assertEqual(ctx.exception.stage, "decision_unknown_destination")
        self.assertTrue(source.exists())

    def test_conclusion_destination_mismatch_preserves_source(self) -> None:
        source = self._make_source()
        decision = {"conclusion": "MALICIOUS", "destination": "clean"}

        with self.assertRaises(DispositionError) as ctx:
            execute_disposition(source, decision, self.clean_dir, self.quarantine_dir)

        self.assertEqual(ctx.exception.stage, "decision_conclusion_destination_mismatch")
        self.assertTrue(source.exists())
        self.assertEqual(list(self.clean_dir.iterdir()), [])

    def test_missing_source_fails_safely(self) -> None:
        missing = self.intake_dir / "does-not-exist.txt"
        decision = {"conclusion": "CLEAN", "destination": "clean"}

        with self.assertRaises(DispositionError) as ctx:
            execute_disposition(missing, decision, self.clean_dir, self.quarantine_dir)

        self.assertEqual(ctx.exception.stage, "source_missing")

    def test_source_is_directory_not_a_file(self) -> None:
        directory_source = self.intake_dir / "a-directory"
        directory_source.mkdir()
        decision = {"conclusion": "CLEAN", "destination": "clean"}

        with self.assertRaises(DispositionError) as ctx:
            execute_disposition(directory_source, decision, self.clean_dir, self.quarantine_dir)

        self.assertEqual(ctx.exception.stage, "source_invalid")

    def test_missing_destination_directory_fails_safely(self) -> None:
        source = self._make_source()
        missing_clean_dir = self.root / "does-not-exist-clean"
        decision = {"conclusion": "CLEAN", "destination": "clean"}

        with self.assertRaises(DispositionError) as ctx:
            execute_disposition(source, decision, missing_clean_dir, self.quarantine_dir)

        self.assertEqual(ctx.exception.stage, "destination_dir_missing")
        self.assertTrue(source.exists())


if __name__ == "__main__":
    unittest.main()
