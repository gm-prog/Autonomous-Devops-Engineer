package com.example

import com.example.data.BackendGatewayClient
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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

  /**
   * Phase 8.7-D.1-CORRECTION (#9): a transport exception must NOT leak raw
   * network/exception detail (URL, host, socket, DNS, connection string)
   * into the user-facing [BackendGatewayClient.AnalysisOutcome.Failure].
   * The failure reason is a stable message; only a safe technical
   * identifier (the exception class simple name) is logged, never returned.
   */
  @Test
  fun transport_exception_detail_never_reaches_the_failure_reason() = runBlocking {
    val previous = BackendGatewayClient.httpClient
    // A hostile transport whose exception message is FULL of the kind of
    // detail the audit forbids from reaching the UI layer.
    val sensitive =
      "connect timed out to https://gw.internal.corp:8443/api via " +
          "proxy http://user:pass@10.20.30.40:3128 (socket 10.20.30.40:54321, " +
          "dns: gw.internal.corp -> 10.20.30.40)"
    val hostile =
      OkHttpClient.Builder()
        .addInterceptor { chain -> throw java.io.IOException(sensitive) }
        .build()
    BackendGatewayClient.httpClient = hostile
    try {
      val outcome =
        BackendGatewayClient.requestRepositoryAnalysis(
          baseUrlStr = "https://gw.internal.corp:8443",
          jwtToken = "test-jwt",
          repoName = "x",
          repoUrl = "https://github.com/o/r.git",
          framework = "FastAPI",
          technology = "Python 3.12"
        )
      val failure = outcome as? BackendGatewayClient.AnalysisOutcome.Failure
      assertNotNull("a transport failure must be a typed failure", failure)
      // Stable, detail-free message:
      assertEquals("Unable to reach the analysis gateway.", failure!!.reason)
      // None of the sensitive fragments may appear in the returned reason:
      for (leak in listOf("gw.internal.corp", "10.20.30.40", "proxy", "socket", "dns", "54321", "8443")) {
        assertFalse(
          "sensitive detail '$leak' leaked into Failure.reason: ${failure.reason}",
          failure.reason.contains(leak)
        )
      }
    } finally {
      BackendGatewayClient.httpClient = previous
    }
  }
}
