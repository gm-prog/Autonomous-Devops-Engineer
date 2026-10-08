package com.example

import com.example.data.GeminiClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 8.7-D: the Android client must function without any Gemini provider
 * secret, in BOTH modes:
 *
 *  * OFFLINE: the deterministic, non-secret template engine works with no
 *    network and no credential.
 *  * LIVE: analysis runs through the gateway's typed, JWT-authenticated
 *    endpoint (BackendGatewayClient.requestRepositoryAnalysis). The client
 *    carries only a platform-issued gateway JWT — never a Gemini key — and a
 *    failed live attempt is a typed failure, never a fabricated success.
 *
 * These tests run under `gradle test` (JDK + Android SDK required). The
 * build-time structural guarantees (no BuildConfig.GEMINI_API_KEY, no
 * `?key=` request path, authenticated-and-typed remote path, offline default)
 * are enforced by the CI job `android-secret-guards` over the repository
 * source.
 */
class GeminiClientSecretPolicyTest {

  @Test
  fun offline_template_engine_produces_assets_without_any_credential() {
    val result = GeminiClient.generateSimulatedAssets(
      repoName = "offline-probe",
      technology = "Python 3.12 / FastAPI",
      framework = "FastAPI 3.0"
    )
    // Truthful non-secret fallback: complete asset set, no key involved.
    assertTrue(result.dockerfile.isNotBlank())
    assertTrue(result.k8sYaml.isNotBlank())
    assertTrue(result.terraformTf.isNotBlank())
    assertTrue(result.pipelineYaml.isNotBlank())
    assertTrue(result.report.isNotBlank())
    // The offline templates never embed a provider key.
    val all = listOf(result.dockerfile, result.k8sYaml, result.terraformTf, result.pipelineYaml, result.report)
    for (asset in all) {
      assertFalse(asset.contains("AIza"))
    }
  }

  @Test
  fun analyze_repository_is_offline_and_credential_free() {
    // analyzeRepository must be a plain (non-suspend, network-free) call to
    // the offline engine: the same deterministic result as the engine alone.
    val viaEngine = GeminiClient.generateSimulatedAssets("x", "Node.js", "React")
    val viaAnalyze = GeminiClient.analyzeRepository("x", "url", "React", "Node.js")
    assertEquals(viaEngine, viaAnalyze)
  }

  @Test
  fun offline_templates_are_deterministic_for_the_same_input() {
    val a = GeminiClient.generateSimulatedAssets("x", "Node.js", "React")
    val b = GeminiClient.generateSimulatedAssets("x", "Node.js", "React")
    assertEquals(a, b)
  }
}
