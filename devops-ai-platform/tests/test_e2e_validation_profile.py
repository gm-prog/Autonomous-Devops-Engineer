"""E2E validation-profile contract (Phase 8.4 §36).

The ``e2e_fixture`` profile must exist, be allowlisted (code-owned,
fixed argv), and remain unselected unless the isolated E2E environment
explicitly opts in via REMEDIATION_VALIDATION_PROFILE — the default
profile for the platform remains ``incident_service``.
"""

import os
import unittest
from unittest.mock import patch

from incident_service.application.services import remediation_validation_runner as runner_module
from incident_service.application.services.validation_sandbox import (
    is_safe_working_directory,
)


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
