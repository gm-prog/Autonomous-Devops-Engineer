package com.example

import com.example.data.BackendGatewayClient
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 8.7-D.1: the authenticated analysis transport is HTTPS-only.
 *
 * The bearer JWT is only ever sent to HTTPS destinations; cleartext HTTP is
 * permitted exclusively for the local emulator/loopback endpoint and only
 * in debug builds (production builds reject even that exception).  These
 * tests exercise the application-level URL policy directly — no network is
 * involved: unsafe URLs are rejected BEFORE a request is constructed, so an
 * arbitrary user-entered `http://host` can never become an authenticated
 * analysis destination.
 *
 * Run under `gradle test` (JDK + Android SDK required).
 */
class AnalysisUrlPolicyTest {

  @Test
  fun https_destination_is_permitted() {
    assertNull(BackendGatewayClient.validateAnalysisUrl("https://gw.example.com"))
    assertNull(BackendGatewayClient.validateAnalysisUrl("https://gw.example.com:8443/base/"))
  }

  @Test
  fun arbitrary_cleartext_http_is_rejected_even_in_debug() {
    val reason =
      BackendGatewayClient.validateAnalysisUrl("http://evil.example.com", debugBuild = true)
    assertNotNull(
      "an arbitrary http host must never become an analysis destination",
      reason
    )
    assertTrue(reason!!.contains("HTTPS"))
  }

  @Test
  fun local_emulator_http_is_permitted_in_debug_builds() {
    assertNull(BackendGatewayClient.validateAnalysisUrl("http://10.0.2.2:8000", debugBuild = true))
    assertNull(BackendGatewayClient.validateAnalysisUrl("http://localhost:8000", debugBuild = true))
    assertNull(BackendGatewayClient.validateAnalysisUrl("http://127.0.0.1:8000", debugBuild = true))
  }

  @Test
  fun production_builds_reject_even_the_local_exception() {
    for (host in listOf("http://10.0.2.2:8000", "http://localhost:8000", "http://127.0.0.1:8000")) {
      val reason = BackendGatewayClient.validateAnalysisUrl(host, debugBuild = false)
      assertNotNull("production build must reject cleartext: $host", reason)
      assertTrue("rejection must cite the production rule: $host", reason!!.contains("production"))
    }
  }

  @Test
  fun malformed_and_unsupported_urls_are_rejected() {
    assertNotNull(BackendGatewayClient.validateAnalysisUrl("not a url"))
    assertNotNull(BackendGatewayClient.validateAnalysisUrl("ftp://gw.example.com"))
    assertNotNull(BackendGatewayClient.validateAnalysisUrl("http://"))
  }

  @Test
  fun unsafe_url_fails_before_any_request_is_sent() = runBlocking {
    val outcome =
      BackendGatewayClient.requestRepositoryAnalysis(
        baseUrlStr = "http://evil.example.com:8000",
        jwtToken = "test-jwt",
        repoName = "x",
        repoUrl = "https://github.com/o/r.git",
        framework = "FastAPI",
        technology = "Python 3.12"
      )
    val failure = outcome as? BackendGatewayClient.AnalysisOutcome.Failure
    assertNotNull("an unsafe URL must yield a typed failure", failure)
    assertTrue(failure!!.reason.contains("HTTPS"))
  }
}
