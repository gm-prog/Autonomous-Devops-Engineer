"""Phase 8.2 — execution-authority proofs for the application-command layer.

Phase 8.2 retired ``ApplyAutomatedFixCommandHandler`` (Option B: no
legitimate runtime caller existed — repository-wide analysis found only
tests that spy on it to prove non-invocation). This module replaces
``test_apply_automated_fix`` and pins the retired surface:

* the legacy command module is gone (not merely "unused");
* no application command can construct a GitHub client or create a PR;
* the command layer contains no remediation side-effect primitives at all.
"""



import importlib
import pathlib
import unittest


COMMANDS_DIR = pathlib.Path(__file__).resolve().parent

PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""

SOURCE_SHA = "a" * 40

# Side-effect primitives that must never appear in application commands.
FORBIDDEN_COMMAND_PRIMITIVES = (
    "create_pull_request(",
    "create_branch_from_commit(",
    "publish_branch(",
    "reconcile_and_create_pr(",
    "GitHubPRClient",
    "RemediationOrchestrationService",
    "ProposalExecutionService",
    "subprocess.",
    "os.system(",
)


class RetiredLegacyCommandTests(unittest.TestCase):
    """§3.3 Option B: the executable legacy surface is deleted."""

    def test_legacy_command_module_is_retired(self):
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module(
                "incident_service.application.commands.apply_automated_fix"
            )

    def test_no_apply_automated_fix_symbols_remain(self):
        import incident_service.application.commands as commands_pkg

        source = pathlib.Path(commands_pkg.__file__).read_text(encoding="utf-8")
        self.assertNotIn("ApplyAutomatedFix", source)
        self.assertNotIn(
            "ApplyAutomatedFixCommandHandler",
            dir(commands_pkg) or [],
        )

    def test_application_commands_contain_no_side_effect_primitives(self):
        """Static boundary: every non-test module under
        ``application/commands/`` must be free of GitHub/git/orchestration
        primitives (the high-risk incident+patch+repo+github signature is
        gone with the retired handler)."""
        offenders = []
        for path in sorted(COMMANDS_DIR.glob("*.py")):
            if path.name.startswith("test_"):
                continue
            text = path.read_text(encoding="utf-8")
            for primitive in FORBIDDEN_COMMAND_PRIMITIVES:
                if primitive in text:
                    offenders.append(f"{path.name}: {primitive}")
        self.assertEqual(offenders, [])



if __name__ == "__main__":
    unittest.main()
