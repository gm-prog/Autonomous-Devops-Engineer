package com.example

import com.example.data.BackendGatewayClient
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 8.7-D.1-CORRECTION-3 (Finding F) — the JWT-bearing gateway client
 * must never let a redirect or an unconfirmed origin move the access token
 * somewhere the operator did not explicitly choose.
 *
 * Contract under test:
 *
 *  * the AUTHENTICATED client is a dedicated OkHttp instance with
 *    followRedirects(false) and followSslRedirects(false) — OkHttp's
 *    default (follow) is a defect here because a 3xx would carry the
 *    bearer token to another host/scheme/port/endpoint;
 *  * a 3xx response is a safe, explicit failure — the Location header is
 *    never followed, logged, or surfaced;
 *  * the gateway URL is canonicalized before token handling: no userinfo,
 *    no query, no fragment (legitimate base paths are preserved);
 *  * the exact origin used (normalized scheme, host, port) requires an
 *    explicit in-memory operator trust confirmation BEFORE any
 *    Authorization-bearing request is constructed — untrusted origin
 *    yields a typed failure with ZERO network calls;
 *  * the approval is bound to the normalized origin: any change to any
 *    part of (scheme, host, port) invalidates it, and it is never
 *    persisted (fresh process = untrusted, like the memory-only JWT).
 *
 * All tests are offline: the transport is a seam with a scripted
 * interceptor — no real network I/O.
 */
class GatewayOriginTrustTest {

  private fun analysisJson(): String =
    JSONObject().apply {
      put(
        "analysis",
        JSONObject().apply {
          put("dockerfile", "FROM python")
          put("k8s_yaml", "apiVersion: v1")
          put("terraform_tf", "resource \"null_resource\" {}")
          put("pipeline_yaml", "steps: []")
          put("report", "ok")
        }
      )
    }.toString()

  @After
  fun tearDown() {
    // Static seams: restore defaults and start every test untrusted.
    BackendGatewayClient.authenticatedHttpClient = defaultAuthenticated
    BackendGatewayClient.TrustedGatewayOrigin.clear()
  }

  private val defaultAuthenticated =
    OkHttpClient.Builder()
      .followRedirects(false)
      .followSslRedirects(false)
      .build()

  // ------------------------------------------------------------------
  // Client isolation + redirect policy
  // ------------------------------------------------------------------

  @Test
  fun authenticated_client_never_follows_redirects() {
    // The dedicated JWT-bearing client has BOTH redirect followings off —
    // including the http->https "safe" SSL redirects.
    val client = BackendGatewayClient.authenticatedHttpClient
    assertFalse(
      "the authenticated client must set followRedirects(false)",
      client.followRedirects
    )
    assertFalse(
      "the authenticated client must set followSslRedirects(false)",
      client.followSslRedirects
    )
    // The credential-free diagnostics client is a SEPARATE instance —
    // its (default) redirect behavior can never carry a token because it
    // is only used by the credential-free probe.
    val diagnostic = BackendGatewayClient.httpClient
    assertTrue(
      "diagnostics and authenticated clients must be separate instances",
      diagnostic !== client
    )
  }

  @Test
  fun redirect_response_is_explicit_safe_failure_never_followed() = runBlocking {
    // A gateway that answers the authenticated call with a 302 to another
    // host: the client must fail explicitly, make exactly ONE call (no
    // follow), and the Location value must never reach the UI reason.
    val location = "https://evil.example.com/steal?token=leak"
    val calls = intArrayOf(0)
    val redirectClient =
      OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .addInterceptor { chain ->
          calls[0]++
          Response.Builder()
            .protocol(Protocol.HTTP_1_1)
            .code(302)
            .message("Found")
            .url(chain.request().url)
            .header("Location", location)
            .build()
        }
        .build()
    BackendGatewayClient.authenticatedHttpClient = redirectClient
    BackendGatewayClient.TrustedGatewayOrigin.approve(
      BackendGatewayClient.parseGatewayOrigin("https://gw.example.com:8443")!!
    )

    val outcome =
      BackendGatewayClient.requestRepositoryAnalysis(
        baseUrlStr = "https://gw.example.com:8443",
        jwtToken = "test-jwt-must-not-leak",
        repoName = "x",
        repoUrl = "https://github.com/o/r.git",
        framework = "FastAPI",
        technology = "Python 3.12"
      )
    val failure = outcome as? BackendGatewayClient.AnalysisOutcome.Failure
    assertNotNull("a 3xx on the authenticated path must be a typed failure", failure)
    assertEquals("exactly one call — the redirect must NOT be followed", 1, calls[0])
    assertEquals(302, failure!!.httpCode)
    assertTrue(
      "the failure must say redirects are never followed: ${failure.reason}",
      failure.reason.contains("redirect", ignoreCase = true) &&
        failure.reason.contains("never followed")
    )
    // The Location target (host or marker) must never be surfaced:
    assertFalse("Location host leaked: ${failure.reason}", failure.reason.contains("evil.example.com"))
    assertFalse("Location marker leaked: ${failure.reason}", failure.reason.contains("steal"))
  }

  // ------------------------------------------------------------------
  // URL canonicalization: userinfo / query / fragment
  // ------------------------------------------------------------------

  @Test
  fun userinfo_query_and_fragment_are_rejected() {
    assertNotNull(
      "userinfo (user:pass@host) must be rejected",
      BackendGatewayClient.validateAnalysisUrl("https://user:pass@gw.example.com")
    )
    assertNotNull(
      "username-only userinfo must be rejected",
      BackendGatewayClient.validateAnalysisUrl("https://user@gw.example.com")
    )
    assertNotNull(
      "a query string must be rejected",
      BackendGatewayClient.validateAnalysisUrl("https://gw.example.com?x=1")
    )
    assertNotNull(
      "a fragment must be rejected",
      BackendGatewayClient.validateAnalysisUrl("https://gw.example.com#frag")
    )
    // Legitimate base paths remain permitted (preserved contract):
    assertNull(BackendGatewayClient.validateAnalysisUrl("https://gw.example.com/base/path/"))
    assertNull(BackendGatewayClient.validateAnalysisUrl("https://gw.example.com:8443/gw"))
  }

  // ------------------------------------------------------------------
  // Origin normalization + trust binding
  // ------------------------------------------------------------------

  @Test
  fun origin_normalization_rules() {
    // Host case + default-port elision + trailing slash all normalize to
    // the SAME origin:
    val a = BackendGatewayClient.parseGatewayOrigin("https://GW.example.com:443/base/")
    val b = BackendGatewayClient.parseGatewayOrigin("https://gw.example.com")
    assertEquals(a, b)
    assertEquals("https://gw.example.com:443", a!!.canonical)

    // Any part of the (scheme, host, port) triple changing is a DIFFERENT
    // origin:
    val https443 = BackendGatewayClient.parseGatewayOrigin("https://gw.example.com")!!
    val http80 = BackendGatewayClient.parseGatewayOrigin("http://gw.example.com")!!
    val port8443 = BackendGatewayClient.parseGatewayOrigin("https://gw.example.com:8443")!!
    val otherHost = BackendGatewayClient.parseGatewayOrigin("https://other.example.com")!!
    assertFalse(https443.canonical == http80.canonical)
    assertFalse(https443.canonical == port8443.canonical)
    assertFalse(https443.canonical == otherHost.canonical)

    // Unparseable input:
    assertNull(BackendGatewayClient.parseGatewayOrigin("not a url"))
    assertNull(BackendGatewayClient.parseGatewayOrigin(""))
  }

  @Test
  fun approval_is_bound_to_normalized_origin_and_cleared_on_change() {
    val origin = BackendGatewayClient.parseGatewayOrigin("https://gw.example.com:8443")!!
    BackendGatewayClient.TrustedGatewayOrigin.approve(origin)
    assertTrue(BackendGatewayClient.TrustedGatewayOrigin.hasApproval)

    // The same origin, written differently, is still approved:
    assertTrue(
      BackendGatewayClient.TrustedGatewayOrigin.isApproved(
        BackendGatewayClient.parseGatewayOrigin("https://GW.example.com:8443/base/")!!
      )
    )

    // ANY part of the triple changing invalidates the approval:
    assertFalse(
      BackendGatewayClient.TrustedGatewayOrigin.isApproved(
        BackendGatewayClient.parseGatewayOrigin("https://gw.example.com:8444")!!
      )
    )
    assertFalse(
      BackendGatewayClient.TrustedGatewayOrigin.isApproved(
        BackendGatewayClient.parseGatewayOrigin("https://other.example.com:8443")!!
      )
    )
    assertFalse(
      BackendGatewayClient.TrustedGatewayOrigin.isApproved(
        BackendGatewayClient.parseGatewayOrigin("http://gw.example.com:8443")!!
      )
    )

    // Explicit revocation:
    BackendGatewayClient.TrustedGatewayOrigin.clear()
    assertFalse(BackendGatewayClient.TrustedGatewayOrigin.hasApproval)
    assertFalse(BackendGatewayClient.TrustedGatewayOrigin.isApproved(origin))
  }

  // ------------------------------------------------------------------
  // Trust gate: no confirmation => zero network calls, no bearer header
  // ------------------------------------------------------------------

  @Test
  fun untrusted_origin_sends_zero_network_calls() = runBlocking {
    var networkCalls = 0
    val countingClient =
      OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .addInterceptor { chain ->
          networkCalls++
          throw AssertionError("no request may leave the process for an untrusted origin")
        }
        .build()
    BackendGatewayClient.authenticatedHttpClient = countingClient
    // Registry starts clean in tearDown; assert the gate holds BEFORE any
    // approval exists:
    assertFalse(BackendGatewayClient.TrustedGatewayOrigin.hasApproval)

    val outcome =
      BackendGatewayClient.requestRepositoryAnalysis(
        baseUrlStr = "https://gw.example.com:8443",
        jwtToken = "test-jwt-must-not-leak",
        repoName = "x",
        repoUrl = "https://github.com/o/r.git",
        framework = "FastAPI",
        technology = "Python 3.12"
      )
    val failure = outcome as? BackendGatewayClient.AnalysisOutcome.Failure
    assertNotNull("an untrusted origin must yield a typed failure", failure)
    assertTrue(
      "the failure must cite the trust confirmation: ${failure.reason}",
      failure.reason.contains("not trusted")
    )
    assertEquals("zero network calls for an untrusted origin", 0, networkCalls)
  }

  @Test
  fun trusted_origin_allows_the_authenticated_request() = runBlocking {
    var bearerSeen: String? = null
    val calls = intArrayOf(0)
    val okClient =
      OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .addInterceptor { chain ->
          calls[0]++
          bearerSeen = chain.request().header("Authorization")
          Response.Builder()
            .protocol(Protocol.HTTP_1_1)
            .code(200)
            .message("OK")
            .url(chain.request().url)
            .header("Content-Type", "application/json")
            .body(analysisJson().toResponseBody("application/json".toMediaType()))
            .build()
        }
        .build()
    BackendGatewayClient.authenticatedHttpClient = okClient
    // Confirmation FIRST, then the request:
    BackendGatewayClient.TrustedGatewayOrigin.approve(
      BackendGatewayClient.parseGatewayOrigin("https://gw.example.com:8443")!!
    )

    val outcome =
      BackendGatewayClient.requestRepositoryAnalysis(
        baseUrlStr = "https://gw.example.com:8443",
        jwtToken = "test-jwt-must-not-leak",
        repoName = "x",
        repoUrl = "https://github.com/o/r.git",
        framework = "FastAPI",
        technology = "Python 3.12"
      )
    val success = outcome as? BackendGatewayClient.AnalysisOutcome.Success
    assertNotNull("a trusted origin + 200 must yield a parsed success", success)
    assertEquals("exactly one call", 1, calls[0])
    assertEquals("the bearer header must carry the configured token",
      "Bearer test-jwt-must-not-leak", bearerSeen)
    assertEquals("ok", success!!.analysis.report)
  }

  @Test
  fun same_origin_redirect_and_cross_origin_redirect_are_identical_failures() = runBlocking {
    // Same-origin redirect (path change) and cross-origin redirect are BOTH
    // explicit failures — the policy never "trusts" same-origin moves
    // either: the approved URL was the analysis endpoint itself.
    for (location in listOf(
      "https://gw.example.com:8443/elsewhere",
      "https://other.example.com/steal"
    )) {
      val calls = intArrayOf(0)
      val redirectClient =
        OkHttpClient.Builder()
          .followRedirects(false)
          .followSslRedirects(false)
          .addInterceptor { chain ->
            calls[0]++
            Response.Builder()
              .protocol(Protocol.HTTP_1_1)
              .code(307)
              .message("Temporary Redirect")
              .url(chain.request().url)
              .header("Location", location)
              .build()
          }
          .build()
      BackendGatewayClient.authenticatedHttpClient = redirectClient
      BackendGatewayClient.TrustedGatewayOrigin.approve(
        BackendGatewayClient.parseGatewayOrigin("https://gw.example.com:8443")!!
      )
      val outcome =
        BackendGatewayClient.requestRepositoryAnalysis(
          baseUrlStr = "https://gw.example.com:8443",
          jwtToken = "test-jwt",
          repoName = "x",
          repoUrl = "https://github.com/o/r.git",
          framework = "FastAPI",
          technology = "Python 3.12"
        )
      val failure = outcome as? BackendGatewayClient.AnalysisOutcome.Failure
      assertNotNull("a redirect must be a typed failure ($location)", failure)
      assertEquals("exactly one call ($location)", 1, calls[0])
      assertEquals(307, failure!!.httpCode)
      BackendGatewayClient.TrustedGatewayOrigin.clear()
    }
  }
}

