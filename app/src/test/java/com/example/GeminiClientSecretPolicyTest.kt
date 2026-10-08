package com.example

import com.example.data.GeminiClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 8.7-C: the Android client must function without any Gemini provider
 * secret.  These tests run under `gradle test` (JDK + Android SDK required).
 *
 * The build-time structural guarantee (no BuildConfig.GEMINI_API_KEY etc.) is
 * enforced by the CI job `android-secret-guards` over the repository source.
 */
class GeminiClientSecretPolicyTest {

  @Test
  fun no_remote_configured_means_offline_fallback_available() {
    // Without a backend URL the client is in the keyless, offline state.
    assertFalse(GeminiClient.isRemoteAnalysisConfigured(null))
    assertFalse(GeminiClient.isRemoteAnalysisConfigured("   "))
  }

  @Test
  fun remote_configured_state_is_a_non_secret_configuration() {
    // A backend URL (non-secret configuration) switches to server-side AI.
    assertTrue(GeminiClient.isRemoteAnalysisConfigured("http://10.0.2.2:8000"))
  }

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
  fun offline_templates_are_deterministic_for_the_same_input() {
    val a = GeminiClient.generateSimulatedAssets("x", "Node.js", "React")
    val b = GeminiClient.generateSimulatedAssets("x", "Node.js", "React")
    assertEquals(a, b)
  }
}
