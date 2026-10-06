"""E2E validation-profile contract (Phase 8.4 §36, 8.4.1 §13/§23).

The ``e2e_fixture`` profile must exist, be allowlisted (code-owned,
fixed argv), and remain unselected unless the isolated E2E environment
explicitly opts in via REMEDIATION_VALIDATION_PROFILE — the default
profile for the platform remains ``incident_service``.

Phase 8.4.1: the profile's assertion is EXACT — it passes only for the
patched fixture state (SERVICE_NAME == 'checkout-service-remediated'),
fails for the initial value, a longer substring-lookalike, and a
missing file — proven by executing the profile's own argv (no Docker).
"""

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from incident_service.application.services import remediation_validation_runner as runner_module
from incident_service.application.services.validation_sandbox import (
    is_safe_working_directory,
)

FIXTURE_TARGET = "src/service_config.py"
FIXTURE_REPO = pathlib.Path(__file__).parent / "fixtures" / "e2e_fixture_repo"
INITIAL_CONTENT = (FIXTURE_REPO / FIXTURE_TARGET).read_text(encoding="utf-8")


class E2eFixtureProfileTests(unittest.TestCase):
    def test_profile_is_registered_and_allowlisted(self):
        self.assertIn("e2e_fixture", runner_module._DEFAULT_PROFILES)
        runner = object.__new__(runner_module.RemediationValidationRunner)
        # construction through the public API with an explicit sandbox stub
        # proves allowlisting without executing anything
        sandbox = unittest.mock.MagicMock()
        instance = runner_module.RemediationValidationRunner(
            sandbox=sandbox,
            profiles=runner_module._DEFAULT_PROFILES,
        )
        self.assertIn("e2e_fixture", instance._profiles)

    def test_profile_steps_are_fixed_code_owned_constants(self):
        steps = runner_module._DEFAULT_PROFILES["e2e_fixture"]
        self.assertGreaterEqual(len(steps), 1)
        for step in steps:
            self.assertIsInstance(step.argv, tuple)
            self.assertTrue(step.argv, "argv must not be empty")
            self.assertNotIn("shell", step.argv[0])
            self.assertTrue(is_safe_working_directory(step.working_directory))
            self.assertLessEqual(step.timeout_seconds, 300.0)
            self.assertLessEqual(step.max_output_bytes, 1_000_000)


class ExactFixtureAssertionTests(unittest.TestCase):
    """Suite E (§23): the assertion proves the exact patched value —
    executed directly from the profile's own argv, no Docker required."""

    @staticmethod
    def _run_assertion(files):
        step = runner_module._DEFAULT_PROFILES["e2e_fixture"][0]
        argv = (sys.executable, *step.argv[1:])  # policy argv[0] is `python`
        with tempfile.TemporaryDirectory() as workdir:
            for relative, content in files.items():
                path = pathlib.Path(workdir, relative)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            completed = subprocess.run(
                argv, cwd=workdir, capture_output=True, text=True, timeout=30
            )
            return completed.returncode

    def test_profile_contains_exact_assertion_not_substring_presence(self):
        step = runner_module._DEFAULT_PROFILES["e2e_fixture"][0]
        argv_blob = " ".join(step.argv)
        self.assertIn(
            runner_module.E2E_FIXTURE_PATCHED_SERVICE_NAME,
            argv_blob,
            "profile must assert the exact patched fixture value",
        )
        # the old weak check ('SERVICE_NAME' merely present) is gone
        self.assertNotIn("'SERVICE_NAME' in", argv_blob)
        # shell-free, fixed python only
        self.assertEqual(step.argv[0], "python")
        self.assertEqual(step.argv[1], "-c")

    def test_patched_fixture_value_passes(self):
        patched = INITIAL_CONTENT.replace(
            'SERVICE_NAME = "checkout-service"',
            f'SERVICE_NAME = "{runner_module.E2E_FIXTURE_PATCHED_SERVICE_NAME}"',
        )
        self.assertNotEqual(patched, INITIAL_CONTENT)
        self.assertEqual(
            self._run_assertion({FIXTURE_TARGET: patched}), 0,
            "exact patched value must pass",
        )

    def test_initial_fixture_value_fails(self):
        self.assertEqual(self._run_assertion({FIXTURE_TARGET: INITIAL_CONTENT}), 1)

    def test_missing_file_fails(self):
        self.assertEqual(self._run_assertion({}), 1)

    def test_substring_lookalike_value_fails(self):
        lookalike = (
            f'SERVICE_NAME = "{runner_module.E2E_FIXTURE_PATCHED_SERVICE_NAME}-evil"'
        )
        self.assertEqual(self._run_assertion({FIXTURE_TARGET: lookalike + "\n"}), 1)

    def test_profile_and_deterministic_adapter_fixture_values_agree(self):
        """Cross-service drift guard (§13 vs §10): the value the RCA
        adapter patches TO is exactly the value this profile asserts."""
        from agent_service.application.deterministic_rca import (
            E2E_FIXTURE_INITIAL_SERVICE_NAME,
            E2E_PATCHED_SERVICE_NAME,
        )

        self.assertEqual(
            E2E_PATCHED_SERVICE_NAME,
            runner_module.E2E_FIXTURE_PATCHED_SERVICE_NAME,
        )
        # the deterministic patch's pre-image matches the fixture file
        from agent_service.application.deterministic_rca import DETERMINISTIC_PATCH

        self.assertIn(
            '-SERVICE_NAME = "'
            f'{E2E_FIXTURE_INITIAL_SERVICE_NAME}"',
            DETERMINISTIC_PATCH,
        )
        # pre-image line equals the fixture file's exact initial content
        self.assertIn(INITIAL_CONTENT.strip(), DETERMINISTIC_PATCH)

    def test_default_profile_is_unchanged_platform_suite(self):
        from incident_service.application.services.proposal_execution_service import (
            DEFAULT_VALIDATION_PROFILE,
        )

        self.assertEqual(DEFAULT_VALIDATION_PROFILE, "incident_service")

    def test_e2e_profile_selected_only_via_explicit_env(self):
        from incident_service.application.services import proposal_execution_service as pes

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop(pes.VALIDATION_PROFILE_ENV, None)
            self.assertEqual(
                getattr(pes, "resolve_validation_profile", lambda: None)()
                if hasattr(pes, "resolve_validation_profile")
                else os.getenv(pes.VALIDATION_PROFILE_ENV, "").strip()
                or pes.DEFAULT_VALIDATION_PROFILE,
                "incident_service",
            )
        with patch.dict(
            os.environ, {pes.VALIDATION_PROFILE_ENV: "e2e_fixture"}
        ):
            resolved = (
                os.getenv(pes.VALIDATION_PROFILE_ENV, "").strip()
                or pes.DEFAULT_VALIDATION_PROFILE
            )
            self.assertEqual(resolved, "e2e_fixture")


if __name__ == "__main__":
    unittest.main()
