"""Regress publication races, cleanup failure handling, and untrusted test inputs."""

import argparse
import contextlib
import io
import subprocess  # nosec B404
import unittest
from unittest.mock import patch

from container_publish_tags import latest_source, publication_tags, validate_release
from smoke_mcp_container import image_reference, managed_container, remove_container, request


class CleanupTests(unittest.TestCase):
    """Ensure a failed cleanup never hides the original test failure."""

    def test_cleanup_reports_failure_without_replacing_primary_error(self):
        """Preserve the same primary exception for command errors, timeouts, and OS errors."""
        for failure in (subprocess.CalledProcessError(1, ["docker", "rm"]),
                        subprocess.TimeoutExpired(["docker", "rm"], 20), OSError("daemon unavailable")):
            with self.subTest(failure=type(failure).__name__):
                primary = ValueError("certificate validation failed")
                diagnostic = io.StringIO()
                with patch("smoke_mcp_container.subprocess.run", side_effect=failure) as run:
                    with contextlib.redirect_stderr(diagnostic):
                        with self.assertRaises(ValueError) as caught:
                            try:
                                raise primary
                            finally:
                                remove_container("fixture-container", force=True)
                self.assertIs(caught.exception, primary)
                self.assertIn("cleanup also failed", diagnostic.getvalue())
                self.assertEqual(run.call_args.kwargs["timeout"], 20)

    def test_cleanup_failure_is_fatal_after_successful_validation(self):
        """Fail the job if cleanup fails after an otherwise successful test."""
        failure = subprocess.CalledProcessError(1, ["docker", "rm"])
        with patch("smoke_mcp_container.subprocess.run", side_effect=failure):
            with self.assertRaises(subprocess.CalledProcessError):
                remove_container("fixture-container")

    def test_partial_startup_failure_cleans_up_the_preassigned_name(self):
        """Remove a possibly created container even when Docker never returns its ID."""
        for failure in (subprocess.CalledProcessError(1, ["docker", "run"]),
                        subprocess.TimeoutExpired(["docker", "run"], 60)):
            with self.subTest(failure=type(failure).__name__):
                with patch("smoke_mcp_container.subprocess.check_output", side_effect=failure) as start:
                    with patch("smoke_mcp_container.remove_container") as remove:
                        with self.assertRaises(type(failure)) as caught:
                            with managed_container(["docker", "run", "-d", "--", "fixture/image"]):
                                self.fail("failed startup must not enter validation")
                self.assertIs(caught.exception, failure)
                command = start.call_args.args[0]
                name = command[command.index("--name") + 1]
                self.assertTrue(name.startswith("mcp-check-"))
                self.assertLess(command.index("--name"), command.index("--"))
                remove.assert_called_once_with(name, force=True)
                self.assertEqual(start.call_args.kwargs["timeout"], 60)

    def test_managed_container_cleans_up_after_successful_validation(self):
        """Use the same preassigned name for validation and subsequent removal."""
        with patch("smoke_mcp_container.subprocess.check_output", return_value="fixture-id"):
            with patch("smoke_mcp_container.remove_container") as remove:
                with managed_container(["docker", "create", "--", "fixture/image"]) as container:
                    remove.assert_not_called()
                remove.assert_called_once_with(container, force=True)


class PublicationTests(unittest.TestCase):
    """Prevent historical builds and prereleases from moving the current stable image."""

    def test_delayed_main_build_cannot_roll_latest_back(self):
        """An older updater promotes current main instead of its own stale build."""
        self.assertEqual(publication_tags("fixture/image", "old", "branch", "main"),
                         ["fixture/image:old"])
        current = "b" * 40
        self.assertEqual(latest_source("fixture/image", current), f"fixture/image:{current}")
        with self.assertRaises(ValueError):
            latest_source("fixture/image", "old")

    def test_tag_dispatch_publishes_version_independently_of_latest(self):
        """Keep version aliases even when a newer latest update supersedes a queued one."""
        self.assertEqual(publication_tags("fixture/image", "old", "tag", "v1.2.3"),
                         ["fixture/image:old", "fixture/image:v1.2.3", "fixture/image:1.2.3"])
        self.assertNotIn("fixture/image:latest", publication_tags("fixture/image", "new", "tag", "v1.2.3-rc.1"))

    def test_dispatch_tag_must_match_checked_out_package(self):
        """Refuse mismatched and malformed release refs before building or publishing."""
        validate_release("tag", "v1.2.3", "1.2.3")
        for tag in ("v1.2.4", "v1", "v1.2.3;command"):
            with self.assertRaises(ValueError):
                validate_release("tag", tag, "1.2.3")


class InputTests(unittest.TestCase):
    """Prevent test helpers from accepting shell options or arbitrary URL destinations."""

    def test_image_is_a_single_operand(self):
        """Reject option and command-like image input before invoking Docker."""
        self.assertEqual(image_reference("fixture/image:scan"), "fixture/image:scan")
        for image in ("--privileged", "image;command", "$(command)", "image\n--privileged"):
            with self.assertRaises(argparse.ArgumentTypeError):
                image_reference(image)

    def test_http_requests_remain_on_loopback(self):
        """Reject files, remote hosts, and URLs containing authentication information."""
        for url in ("file:///etc/passwd", "http://example.com:80/", "http://user@127.0.0.1:80/"):
            with self.assertRaises(ValueError):
                request(url)


if __name__ == "__main__":
    unittest.main()
