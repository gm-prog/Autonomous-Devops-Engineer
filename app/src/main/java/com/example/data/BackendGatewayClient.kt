package com.example.data

import android.util.Log
import com.example.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Platform gateway client (Phase 8.7-D).
 *
 * SECURITY MODEL:
 *
 * This client contains NO provider credential. It can do two things:
 *
 * 1. `testConnection` — a diagnostics-only reachability probe against the
 *    user-configured gateway URL (Settings "Ping Endpoint"). It is not an
 *    analysis or execution transport.
 *
 * 2. `requestRepositoryAnalysis` — the typed, AUTHENTICATED repository
 *    analysis call introduced in Phase 8.7-D. It POSTs non-secret repository
 *    metadata to the gateway's typed endpoint
 *    `POST {baseUrl}/api/v1/repository/analyze` with an
 *    `Authorization: Bearer <JWT>` header (a platform-issued JWT supplied by
 *    the operator in Settings — never a Gemini key). The server validates
 *    the JWT, enforces role authorization, and calls Gemini with its own
 *    SERVER-SIDE GEMINI_API_KEY.
 *
 * TRANSPORT POLICY (Phase 8.7-D.1, hardened in 8.7-D.1-CORRECTION-3):
 * the JWT is only ever sent to HTTPS destinations; cleartext HTTP is
 * permitted exclusively for the local emulator endpoint and only in debug
 * builds. Unsafe URLs are rejected before the request is constructed (see
 * [validateAnalysisUrl]).
 *
 * REDIRECT + TRUST POLICY (Phase 8.7-D.1-CORRECTION-3, Finding F): the
 * JWT-bearing call runs on a dedicated client with followRedirects(false)
 * and followSslRedirects(false) — a 3xx is a safe explicit failure and a
 * redirect can NEVER move the token to another host/scheme/port/endpoint.
 * The gateway URL is canonicalized before any token handling (no userinfo,
 * query, or fragment). The exact origin used is bound to an explicit,
 * in-memory operator trust confirmation ([TrustedGatewayOrigin]),
 * invalidated whenever any part of the (scheme, host, port) changes and
 * never persisted. The confirmation is endpoint-choice protection, NOT
 * cryptographic server identity — TLS certificate validation still
 * governs the connection.
 *
 * HONEST FAILURE: every non-success outcome is surfaced as a typed
 * [AnalysisFailure] with a truthful reason. This client NEVER fabricates an
 * analysis result — there is no silent fallback to simulated content.
 */
object BackendGatewayClient {
    private const val TAG = "BackendGatewayClient"

    private val defaultClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    /**
     * The DIAGNOSTICS client — credential-free only ([testConnection]).
     * Production code always uses the default instance; the setter is a
     * documented TEST seam (@VisibleForTesting) so the transport-failure
     * contract (stable, detail-free failure messages) can be verified
     * offline.
     */
    @androidx.annotation.VisibleForTesting
    var httpClient: OkHttpClient = defaultClient

    // Phase 8.7-D.1-CORRECTION-3 (Finding F): the JWT-BEARING client is a
    // SEPARATE, dedicated OkHttp instance whose redirect policy is
    // explicitly off — including the "safe" http->https SSL redirects.
    // OkHttp's default is followRedirects(true), which would let a
    // misconfigured or hostile gateway move the bearer token to another
    // host/scheme/port/endpoint via a 3xx.  With the policy off, a 3xx is
    // answered as a safe explicit failure (see requestRepositoryAnalysis);
    // the Location header is never followed, logged, or surfaced.
    private val defaultAuthenticatedClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    /**
     * The HTTP client used EXCLUSIVELY for the authenticated analysis call
     * ([requestRepositoryAnalysis]) — never for diagnostics.  Documented
     * TEST seam (@VisibleForTesting) for the redirect/trust contract.
     */
    @androidx.annotation.VisibleForTesting
    var authenticatedHttpClient: OkHttpClient = defaultAuthenticatedClient

    /**
     * Analysis URL policy (Phase 8.7-D.1).
     *
     * The authenticated analysis transport must NEVER carry a bearer JWT
     * over arbitrary cleartext HTTP:
     *  * live backend URLs must be HTTPS;
     *  * `http://` is permitted ONLY for the local emulator/loopback
     *    endpoints (10.0.2.2, localhost, 127.0.0.1) and ONLY in debug
     *    builds (BuildConfig.DEBUG — production builds reject even the
     *    local exception);
     *  * anything else is rejected BEFORE the request is constructed, so
     *    a user-entered `http://host` can never become an authenticated
     *    analysis destination.
     *
     * The diagnostics probe ([testConnection]) is a separate,
     * credential-free path and stays governed by the Network Security
     * Configuration (no cleartext in production builds at the platform
     * level either).
     */
    private val LOCAL_EMULATOR_HOSTS = setOf("10.0.2.2", "localhost", "127.0.0.1")

    /**
     * @param debugBuild the build-type gate for the local cleartext
     *   exception — defaults to the real [BuildConfig.DEBUG] of the
     *   compiled variant (production builds therefore reject even the
     *   local exception).
     * @return a truthful rejection reason, or null when the URL is permitted.
     */
    fun validateAnalysisUrl(rawUrl: String, debugBuild: Boolean = BuildConfig.DEBUG): String? {
        val clean = rawUrl.trim().removeSuffix("/")
        if (clean.isEmpty()) return "Gateway URL is not configured."
        val url: HttpUrl = try {
            // OkHttp 4.x: HttpUrl.parse() is an error-level deprecation;
            // the supported form is the String.toHttpUrl() extension.
            clean.toHttpUrl() ?: return "Gateway URL is malformed."
        } catch (e: Exception) {
            // Defensive only: log a safe technical identifier, never the raw
            // message (it may embed the raw URL/host) in the returned reason.
            Log.w(TAG, "Gateway URL parse failure: ${e.javaClass.simpleName}")
            return "Gateway URL is malformed."
        }
        return policyRejection(url, debugBuild)
    }

    /**
     * The SHARED analysis-URL policy (Phase 8.7-D.1-CORRECTION-3 closeout).
     *
     * Both [validateAnalysisUrl] (the authenticated request path) and
     * [parseGatewayOrigin] (the trust UI) apply EXACTLY this check, so a
     * URL the request path would reject can never yield a confirmable
     * origin in the trust UI, and vice versa.  The explicit debug-only
     * local cleartext HTTP exception is part of this shared policy.
     *
     * @return a truthful rejection reason, or null when the parsed URL is
     *   permitted.
     */
    private fun policyRejection(url: HttpUrl, debugBuild: Boolean): String? {
        // Phase 8.7-D.1-CORRECTION-3 (Finding F): canonicalize the gateway
        // URL BEFORE any token handling.  The analysis destination is
        // exactly scheme://host[:port][/base-path] + the fixed analysis
        // route — userinfo (user:pass@host), a query string, and a fragment
        // are all rejected: they make the "exact URL used" ambiguous and
        // can smuggle credentials or alter the destination the operator
        // approved.  Legitimate base paths are preserved.
        // OkHttp 4.10: the *() function forms are ERROR-level
        // deprecations ("moved to val") — use the property forms.
        if (url.username.isNotEmpty() || url.encodedPassword.isNotEmpty()) {
            return "Gateway URLs must not contain user info (user:pass@host) — " +
                "configure scheme://host[:port] with an optional base path only."
        }
        if (url.encodedQuery != null || url.encodedFragment != null) {
            return "Gateway URLs must not contain a query string or fragment — " +
                "configure scheme://host[:port] with an optional base path only."
        }
        return when (url.scheme) {
            "https" -> null
            "http" -> when {
                !debugBuild ->
                    "Cleartext HTTP is not permitted for authenticated analysis in " +
                        "production builds. Configure an HTTPS gateway URL."
                url.host.lowercase() in LOCAL_EMULATOR_HOSTS -> null
                else ->
                    "Cleartext HTTP is permitted only for the local emulator endpoint " +
                        "($LOCAL_EMULATOR_HOSTS) in debug builds. Configure an HTTPS " +
                        "gateway URL."
            }
            else ->
                "Only HTTPS is permitted for authenticated analysis (the local " +
                    "emulator endpoint is allowed over HTTP in debug builds only)."
        }
    }

    /**
     * The normalized gateway origin: exactly (scheme, host, port) — the
     * unit an explicit operator trust confirmation is bound to (Finding F).
     *
     * The host is lower-cased and the port is OkHttp's EFFECTIVE port
     * (443 for https, 80 for http when omitted), so
     * `https://GW.example.com:443/base/` and `https://gw.example.com`
     * normalize to the SAME origin.  Any change to any part of the
     * (scheme, host, port) triple is a different origin.
     */
    data class GatewayOrigin(val scheme: String, val host: String, val port: Int) {
        val canonical: String get() = "$scheme://${host.lowercase()}:$port"
    }

    /**
     * Parses the normalized origin of a gateway URL, or null when the URL
     * cannot be parsed OR fails the shared analysis URL policy
     * ([policyRejection] — the exact check [validateAnalysisUrl] applies).
     *
     * Phase 8.7-D.1-CORRECTION-3 closeout: the trust UI derives the
     * confirmable origin from this function, so malformed,
     * userinfo/query/fragment-bearing, or unsupported-scheme URLs can
     * never appear trusted/confirmable.  The explicit debug-only local
     * HTTP exception is preserved through the shared policy.
     * Pure function — no network, no state.
     */
    fun parseGatewayOrigin(rawUrl: String, debugBuild: Boolean = BuildConfig.DEBUG): GatewayOrigin? {
        val clean = rawUrl.trim().removeSuffix("/")
        if (clean.isEmpty()) return null
        val url: HttpUrl = try {
            clean.toHttpUrl() ?: return null
        } catch (e: Exception) {
            return null
        }
        if (policyRejection(url, debugBuild) != null) return null
        return GatewayOrigin(url.scheme, url.host.lowercase(), url.port)
    }

    /**
     * In-memory trusted-origin registry (Phase 8.7-D.1-CORRECTION-3,
     * Finding F).
     *
     * An EXPLICIT operator confirmation (the trust control in Settings) is
     * required before the platform JWT is ever attached to a request for a
     * gateway origin.  The approval is bound to the NORMALIZED
     * (scheme, host, port): changing ANY part of the origin invalidates it
     * (isApproved returns false again), and the approval is NEVER
     * persisted — a fresh process starts untrusted, exactly like the
     * memory-only gateway JWT (which is likewise cleared on restart).
     *
     * SCOPE, STATED HONESTLY: this confirmation protects against a wrong
     * or accidental endpoint choice (operator confirms exactly where the
     * token will be sent). It is NOT cryptographic server identity: TLS
     * certificate validation still governs the connection — this client
     * installs no permissive trust managers and never disables
     * certificate checks.
     */
    object TrustedGatewayOrigin {
        @Volatile
        private var approvedCanonical: String? = null

        fun approve(origin: GatewayOrigin) {
            approvedCanonical = origin.canonical
        }

        fun isApproved(origin: GatewayOrigin): Boolean = origin.canonical == approvedCanonical

        fun clear() {
            approvedCanonical = null
        }

        val hasApproval: Boolean
            get() = approvedCanonical != null

        @androidx.annotation.VisibleForTesting
        fun approvedCanonicalForTests(): String? = approvedCanonical
    }

    /** Outcome of a typed, authenticated remote analysis request. */
    sealed class AnalysisOutcome {
        data class Success(val analysis: DevOpsAnalysisResult) : AnalysisOutcome()
        data class Failure(val reason: String, val httpCode: Int? = null) : AnalysisOutcome()
    }

    /**
     * Checks if the user-specified API Gateway URL is responsive.
     * Diagnostics only — never an analysis transport.
     */
    suspend fun testConnection(baseUrlStr: String): Boolean = withContext(Dispatchers.IO) {
        val cleanUrl = baseUrlStr.trim().removeSuffix("/")
        if (cleanUrl.isEmpty()) return@withContext false

        val request = Request.Builder()
            .url("$cleanUrl/")
            .get()
            .build()

        try {
            httpClient.newCall(request).execute().use { response ->
                Log.d(TAG, "Connection check: code ${response.code}")
                return@withContext response.isSuccessful || response.code == 404
            }
        } catch (e: Exception) {
            Log.w(TAG, "Gateway connection probe failed: ${e.javaClass.simpleName}")
            try {
                val healthRequest = Request.Builder()
                    .url("$cleanUrl/api/v1/health")
                    .get()
                    .build()
                httpClient.newCall(healthRequest).execute().use { res ->
                    return@withContext res.isSuccessful
                }
            } catch (ex: Exception) {
                return@withContext false
            }
        }
    }

    /**
     * Typed, authenticated repository-analysis request (Phase 8.7-D).
     *
     * @param jwtToken a platform-issued gateway JWT (operator-supplied in
     *   Settings). This is the ONLY credential this client carries — and it
     *   is never a Gemini key.
     *
     * @return [AnalysisOutcome.Success] with validated server-generated
     *   assets, or [AnalysisOutcome.Failure] with a truthful reason. Never
     *   fabricates a success.
     */
    suspend fun requestRepositoryAnalysis(
        baseUrlStr: String,
        jwtToken: String,
        repoName: String,
        repoUrl: String,
        framework: String,
        technology: String
    ): AnalysisOutcome = withContext(Dispatchers.IO) {
        val cleanUrl = baseUrlStr.trim().removeSuffix("/")
        if (cleanUrl.isEmpty()) {
            return@withContext AnalysisOutcome.Failure("Gateway URL is not configured.")
        }
        if (jwtToken.isBlank()) {
            // Fail closed on the client side too: no token, no live call.
            return@withContext AnalysisOutcome.Failure("No gateway access token (JWT) configured — live analysis requires one.")
        }

        // Phase 8.7-D.1: reject unsafe URLs BEFORE constructing/sending the
        // authenticated request (HTTPS-only, with a debug-local exception).
        val urlPolicyError = validateAnalysisUrl(cleanUrl)
        if (urlPolicyError != null) {
            Log.w(TAG, "Analysis URL rejected by policy")
            return@withContext AnalysisOutcome.Failure(urlPolicyError)
        }

        // Phase 8.7-D.1-CORRECTION-3 (Finding F): the EXACT origin used by
        // the request must be explicitly trusted by the operator BEFORE
        // any bearer token is attached.  Untrusted origin => typed failure
        // with ZERO network calls.  The approval is bound to the
        // normalized (scheme, host, port), so a URL change that alters any
        // part of the origin automatically invalidates it.
        val origin = parseGatewayOrigin(cleanUrl)
        if (origin == null) {
            return@withContext AnalysisOutcome.Failure("Gateway URL is malformed.")
        }
        if (!TrustedGatewayOrigin.isApproved(origin)) {
            Log.w(TAG, "Analysis origin not explicitly trusted; no request constructed")
            return@withContext AnalysisOutcome.Failure(
                "Gateway origin is not trusted. Confirm the gateway origin in " +
                    "Settings before the access token can be sent."
            )
        }

        val endpoint = "$cleanUrl/api/v1/repository/analyze"
        val payload = JSONObject().apply {
            put("repo_name", repoName)
            put("repo_url", repoUrl)
            put("framework", framework)
            put("technology", technology)
        }

        val request = Request.Builder()
            .url(endpoint)
            .post(payload.toString().toRequestBody("application/json".toMediaType()))
            .addHeader("Authorization", "Bearer $jwtToken")
            .build()

        try {
            // The JWT-bearing request goes ONLY through the dedicated
            // authenticated client (redirects never followed).
            authenticatedHttpClient.newCall(request).execute().use { response ->
                // Finding F: the authenticated client never follows
                // redirects.  A 3xx means the configured gateway URL is not
                // the analysis endpoint (misconfiguration, or a hostile
                // redirector trying to move the bearer token): fail
                // explicitly and safely.  The Location header is NEVER
                // followed, logged, or surfaced — it must not steer the
                // operator or the token anywhere.
                if (response.code in 300..399) {
                    Log.w(TAG, "Live analysis redirected: HTTP ${response.code} (redirects are never followed)")
                    return@withContext AnalysisOutcome.Failure(
                        "Gateway redirected the authenticated analysis request; " +
                            "redirects are never followed. Check the configured gateway URL.",
                        response.code
                    )
                }
                val body = response.body?.string().orEmpty()
                if (!response.isSuccessful) {
                    Log.w(TAG, "Live analysis failed: HTTP ${response.code}")
                    return@withContext when (response.code) {
                        in 401..403 -> AnalysisOutcome.Failure(
                            "Gateway rejected the access token (unauthorized). Re-issue the gateway JWT.",
                            response.code
                        )
                        429 -> AnalysisOutcome.Failure("Live analysis is rate limited on the server.", response.code)
                        in 500..599 -> AnalysisOutcome.Failure(
                            "Server-side analysis failed (the provider may be unconfigured or unavailable).",
                            response.code
                        )
                        else -> AnalysisOutcome.Failure("Gateway error (HTTP ${response.code}).", response.code)
                    }
                }
                return@withContext parseAnalysisResponse(body)
            }
        } catch (e: Exception) {
            // Stable, detail-free user-facing message. Raw exception text can
            // embed the URL, host, proxy, socket or DNS details — none of
            // that may reach the UI layer or a crash log. Only a safe
            // technical identifier is logged.
            Log.w(TAG, "Live analysis network failure: ${e.javaClass.simpleName}")
            return@withContext AnalysisOutcome.Failure("Unable to reach the analysis gateway.")
        }
    }

    /**
     * Strictly parses the typed server response. Any structural surprise is
     * a typed failure — never a fabricated asset.
     */
    private fun parseAnalysisResponse(body: String): AnalysisOutcome {
        val json = try {
            JSONObject(body)
        } catch (e: Exception) {
            return AnalysisOutcome.Failure("Server response was not valid JSON.")
        }
        val analysis = json.optJSONObject("analysis") ?: run {
            return AnalysisOutcome.Failure("Server response was missing the analysis payload.")
        }
        val fields = listOf("dockerfile", "k8s_yaml", "terraform_tf", "pipeline_yaml", "report")
        for (field in fields) {
            val value = analysis.optString(field, "")
            if (value.isBlank()) {
                return AnalysisOutcome.Failure("Server response was incomplete (missing $field).")
            }
        }
        return AnalysisOutcome.Success(
            DevOpsAnalysisResult(
                dockerfile = analysis.getString("dockerfile"),
                k8sYaml = analysis.getString("k8s_yaml"),
                terraformTf = analysis.getString("terraform_tf"),
                pipelineYaml = analysis.getString("pipeline_yaml"),
                report = analysis.getString("report")
            )
        )
    }
}
