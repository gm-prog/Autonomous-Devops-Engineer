"""Unit tests for the Phase 8.4.2 E2E harness helper logic (§44).

The live workflow must never be the first test of its own helpers.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from e2e import helpers as H
from e2e.readiness import ReadinessTimeout, wait_until


class ValidatorTests(unittest.TestCase):
    def test_sha40(self):
        self.assertTrue(H.validate_sha40("a" * 40))
        self.assertFalse(H.validate_sha40("A" * 40))
        self.assertFalse(H.validate_sha40("a" * 39))
        self.assertFalse(H.validate_sha40(42))

    def test_repo_slug(self):
        self.assertTrue(H.validate_repo_slug("gm-prog/ares-e2e-fixture"))
        self.assertFalse(H.validate_repo_slug("bare"))
        self.assertFalse(H.validate_repo_slug("a/b/c"))
        self.assertFalse(H.validate_repo_slug("gm-prog/ares-e2e-fixture/extra"))
        self.assertFalse(H.validate_repo_slug(None))

    def test_branch(self):
        self.assertTrue(H.validate_branch("automation/remediation/e2e/12345"))
        self.assertFalse(H.validate_branch("../evil"))
        self.assertFalse(H.validate_branch(""))
        self.assertFalse(H.validate_branch("a..b"))

    def test_digest_ref(self):
        good = "python@sha256:" + "a" * 64
        self.assertTrue(H.validate_digest_ref(good))
        self.assertFalse(H.validate_digest_ref("python:3.11-slim"))
        self.assertFalse(H.validate_digest_ref("python@sha256:zz"))
        self.assertFalse(H.validate_digest_ref("python@sha256:" + "a" * 63))

    def test_digest_ref_accepts_a_registry_host_with_port(self):
        """Phase 8.4.2-D D-1: the run-scoped images live in localhost:5001."""
        self.assertTrue(H.validate_digest_ref(
            "localhost:5001/ares-e2e-sandbox@sha256:" + "b" * 64))
        self.assertTrue(H.validate_digest_ref(
            "localhost:5001/ares-e2e-workload@sha256:" + "c" * 64))
        self.assertFalse(H.validate_digest_ref("localhost:5001/ares-e2e-sandbox:v1"))
        self.assertFalse(H.validate_digest_ref("UNRESOLVED"))
        self.assertFalse(H.validate_digest_ref(
            "localhost:5001/ares-e2e-sandbox@sha256:" + "b" * 63))


class PinnedImageTests(unittest.TestCase):
    """Committed immutable pins (Phase 8.4.2-D §5) — offline contract."""

    PIN_FILE = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "e2e", "pinned-images.txt")

    def test_committed_file_parses_to_six_digest_refs(self):
        with open(self.PIN_FILE, encoding="utf-8") as handle:
            records = H.parse_pinned_images(handle.read())
        self.assertEqual(len(records), 6)
        self.assertEqual(sorted(r["key"] for r in records),
                         sorted(H.PINNED_IMAGE_KEYS))
        for record in records:
            self.assertRegex(record["digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertTrue(H.validate_digest_ref(record["ref"]), record)

    def test_sentinel_and_malformed_pins_raise(self):
        for pin in ("UNRESOLVED", "latest", "sha256:" + "a" * 63):
            with self.subTest(pin=pin):
                with self.assertRaises(ValueError):
                    H.parse_pinned_images(
                        f"python:3.11-slim {pin} E2E_PYTHON_BASE_IMAGE\n")

    def test_provenance_exports_are_deterministic(self):
        with open(self.PIN_FILE, encoding="utf-8") as handle:
            records = H.parse_pinned_images(handle.read())
        first = H.pin_provenance_exports(records)
        self.assertEqual(first, H.pin_provenance_exports(records))
        self.assertEqual(sorted(first), ["E2E_BASE_IMAGES",
                                         "E2E_KIND_NODE_DIGEST",
                                         "E2E_REGISTRY_DIGEST"])
        mapping = H.parse_scalar_mapping(first["E2E_BASE_IMAGES"])
        self.assertEqual(sorted(mapping), sorted(H.BASE_IMAGE_KEYS))


class ExecutionProvenanceTests(unittest.TestCase):
    """A live PASS may never be claimed with empty provenance (§9)."""

    def _complete(self):
        return dict(
            source_sha="a" * 40, fixture_seed_sha="b" * 40,
            workspace_root="/tmp/ares-e2e-workspaces",
            registry_image_digest="registry@sha256:" + "1" * 64,
            kind_node_image_digest="kindest/node@sha256:" + "2" * 64,
            base_images="E2E_PYTHON_BASE_IMAGE=python@sha256:" + "3" * 64,
            built_image_digests="E2E_WORKLOAD_IMAGE=localhost:5001/w@sha256:"
                                + "4" * 64,
            sandbox_image_digest="localhost:5001/s@sha256:" + "5" * 64)

    def test_complete_provenance_passes(self):
        manifest = H.new_manifest(**self._complete())
        self.assertEqual(H.missing_execution_provenance(manifest), [])
        H.finalize_execution_manifest(manifest, H.PASS)
        self.assertEqual(manifest["result"], "PASS")

    def test_each_missing_field_downgrades_a_pass(self):
        for field in H.REQUIRED_EXECUTION_PROVENANCE:
            with self.subTest(field=field):
                fields = self._complete()
                fields[field] = ""
                manifest = H.new_manifest(**fields)
                H.finalize_execution_manifest(manifest, H.PASS)
                self.assertEqual(manifest["result"], "FAIL")
                self.assertIn(field, manifest["provenance_rejection"])

    def test_not_verified_manifests_need_no_provenance(self):
        manifest = H.new_manifest(workflow_run_id="local")
        H.finalize_manifest(manifest, H.NOT_VERIFIED)
        self.assertEqual(manifest["result"], "NOT_VERIFIED")
        blocked = H.new_manifest(workflow_run_id="local")
        H.finalize_execution_manifest(blocked, H.BLOCKED)
        self.assertEqual(blocked["result"], "BLOCKED")
        self.assertNotIn("provenance_rejection", blocked)

    def test_extract_repo_digest_prefers_digest_refs(self):
        refs = ["python:3.11-slim", "python@sha256:" + "b" * 64]
        self.assertEqual(H.extract_repo_digest(refs), refs[1])
        self.assertEqual(H.extract_repo_digest(["python:3.11-slim"]), "")

    def test_image_digest_of(self):
        self.assertEqual(H.image_digest_of("sha256:" + "c" * 64), "c" * 64)
        self.assertEqual(H.image_digest_of("not-a-digest"), "")


class GateTests(unittest.TestCase):
    def test_classify_gate(self):
        self.assertEqual(H.classify_gate([{"result": "PASS"}, {"result": "PASS"}]), "PASS")
        self.assertEqual(H.classify_gate([{"result": "PASS"}, {"result": "FAIL"}]), "FAIL")
        self.assertEqual(H.classify_gate([{"result": "NOT_VERIFIED"}]), "NOT_VERIFIED")
        self.assertEqual(H.classify_gate([{"result": "BLOCKED"}]), "BLOCKED")
        self.assertEqual(H.classify_gate([]), "PASS")

    def test_row(self):
        self.assertEqual(H.row("c", "200", "404", False)["result"], "FAIL")
        self.assertEqual(H.row("c", "200", "200", True)["result"], "PASS")

    def test_execution_outcome_gate(self):
        ok = H.classify_execution_outcomes([200, 409])
        self.assertTrue(ok["acceptable"])
        ok = H.classify_execution_outcomes([502, 409])
        self.assertTrue(ok["acceptable"])
        bad = H.classify_execution_outcomes([500])
        self.assertFalse(bad["acceptable"])
        bad = H.classify_execution_outcomes([404, 404])
        self.assertFalse(bad["acceptable"])
        bad = H.classify_execution_outcomes([409])
        self.assertFalse(bad["acceptable"], "conflict-only race never proves a winner")


class ManifestTests(unittest.TestCase):
    def test_valid_manifest_roundtrip(self):
        manifest = H.new_manifest(workflow_run_id="1", result=H.NOT_VERIFIED)
        self.assertEqual(H.validate_manifest(manifest), [])
        H.finalize_manifest(manifest, H.PASS)
        self.assertEqual(manifest["result"], "PASS")
        self.assertEqual(manifest["schema"], "ares.e2e.golden-path/1")

    def test_manifest_rejects_bad_result_and_shape(self):
        self.assertTrue(H.validate_manifest({"schema": H.SCHEMA, "result": "SUCCESS"}))
        self.assertTrue(H.validate_manifest({"schema": H.SCHEMA, "result": "PASS",
                                             "nested": {"a": 1}}))
        self.assertTrue(H.validate_manifest({"schema": "wrong", "result": "PASS"}))
        self.assertTrue(H.validate_manifest("not-a-dict"))
        with self.assertRaises(ValueError):
            H.finalize_manifest({"schema": H.SCHEMA}, "PASSED")


class SecretScanTests(unittest.TestCase):
    def test_detects_token_classes(self):
        samples = [
            "ghp_" + "A1b2" * 8,
            "github_pat_" + "x" * 30,
            "-----BEGIN RSA PRIVATE KEY-----",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcdefghij",
            "Authorization: Bearer sometoken",
            "E2E_FIXTURE_GITHUB_TOKEN=supersecret",
            "x-access-token:leak@github.com/o/r.git",
        ]
        for sample in samples:
            with self.subTest(sample=sample[:24]):
                self.assertTrue(H.secret_scan_text(sample), sample)

    def test_clean_text_passes(self):
        self.assertEqual(H.secret_scan_text(
            '{"incident_id":"inc-1","proposal_hash":"%s"}' % ("d" * 64)), [])

    def test_redact_masks_findings(self):
        text = "token ghp_%s here" % ("B2c3" * 8)
        self.assertNotIn("ghp_", H.redact(text))


class ReadinessTests(unittest.TestCase):
    def test_wait_until_succeeds_after_retries(self):
        state = {"n": 0}

        def probe():
            state["n"] += 1
            return state["n"] >= 3, f"attempt {state['n']}"

        result = wait_until("probe", probe, timeout=30, interval=0.001)
        self.assertTrue(result["passed"])
        self.assertGreaterEqual(result["attempts"], 3)

    def test_wait_until_times_out_with_history(self):
        with self.assertRaises(ReadinessTimeout) as ctx:
            wait_until("never", lambda: (False, "still down"),
                       timeout=0.01, interval=0.002)
        self.assertIn("still down", str(ctx.exception))

    def test_probe_exceptions_never_crash_the_waiter(self):
        def boom():
            raise RuntimeError("transient")
        with self.assertRaises(ReadinessTimeout) as ctx:
            wait_until("boom", boom, timeout=0.01, interval=0.002)
        self.assertIn("transient", str(ctx.exception))

    def test_invalid_timing_rejected(self):
        with self.assertRaises(ValueError):
            wait_until("x", lambda: (True, ""), timeout=0, interval=1)


class FixtureContractTests(unittest.TestCase):
    """The fixture payloads and the exact file contract stay in lockstep."""

    ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "e2e")

    def _fixture(self, name):
        with open(os.path.join(self.ROOT, "fixtures", name), encoding="utf-8") as fh:
            return fh.read()

    def test_initial_fixture_file_is_exact(self):
        content = open(
            os.path.join(self.ROOT, "fixtures", "..", "..", "tests",
                         "fixtures", "e2e_fixture_repo", "src",
                         "service_config.py"), encoding="utf-8").read()
        self.assertEqual(content, 'SERVICE_NAME = "checkout-service"\n')

    def test_k8s_placeholder_and_iac_validation(self):
        from deployment_service.application.services.iac_validator import IaCValidator
        k8s = self._fixture("k8s-deployment.yaml")
        self.assertIn("WORKLOAD_IMAGE_REF", k8s)
        substituted = k8s.replace(
            "WORKLOAD_IMAGE_REF",
            "localhost:5001/ares-e2e-workload@sha256:" + "e" * 64)
        result = IaCValidator().validate(
            self._fixture("Dockerfile"), substituted,
            self._fixture("main.tf"), self._fixture("pipeline.yaml"))
        self.assertEqual(result["status"], "PASS", result)

    def test_terraform_fixture_is_zero_cloud(self):
        tf = self._fixture("main.tf")
        self.assertIn("terraform_data", tf)
        for banned in ("provider ", "local-exec", "remote-exec", 'data "external"',
                       "aws_", "google_", "azurerm_"):
            self.assertNotIn(banned, tf)

    def test_dockerfile_fixture_has_from_and_user(self):
        content = self._fixture("Dockerfile")
        self.assertRegex(content, r"(?im)^FROM\s+\S+")
        self.assertRegex(content, r"(?im)^USER\s+\S+")


class ContractHashTests(unittest.TestCase):
    def test_reproduction_uses_real_canonical_hash(self):
        from incident_service.application.services.proposal_generation_service import (
            compute_proposal_hash,
        )
        base = dict(incident_id="i", root_cause="r", evidence_refs=["e1"],
                    repository="o/r", source_sha="a" * 40,
                    file_paths=["src/service_config.py"], patch="p",
                    validation_plan=["v"], risk_class="MEDIUM")
        digest = compute_proposal_hash(**base)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        mirrored = H.sha256_hex(json.dumps(
            H.canonical_proposal_hash_inputs(**base),
            sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        self.assertEqual(digest, mirrored)


class ModuleImportTests(unittest.TestCase):
    def test_driver_module_imports(self):
        import e2e.golden_path as driver
        self.assertTrue(hasattr(driver, "main"))
        self.assertEqual(driver.PATCHED_LINE,
                         'SERVICE_NAME = "checkout-service-remediated"')


if __name__ == "__main__":
    unittest.main()
