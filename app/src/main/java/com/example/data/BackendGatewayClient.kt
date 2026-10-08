package com.example.data

import android.util.Log
import com.example.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
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
 * TRANSPORT POLICY (Phase 8.7-D.1): the JWT is only ever sent to HTTPS
 * destinations; cleartext HTTP is permitted exclusively for the local
 * emulator endpoint and only in debug builds. Unsafe URLs are rejected
 * before the request is constructed (see [validateAnalysisUrl]).
 *
 * HONEST FAILURE: every non-success outcome is surfaced as a typed
 * [AnalysisFailure] with a truthful reason. This client NEVER fabricates an
 * analysis result — there is no silent fallback to simulated content.
 */
object BackendGatewayClient {
    private const val TAG = "BackendGatewayClient"
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

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
            HttpUrl.parse(clean) ?: return "Gateway URL is malformed."
        } catch (e: Exception) {
            return "Gateway URL is malformed: ${e.message}"
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
            client.newCall(request).execute().use { response ->
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
                client.newCall(healthRequest).execute().use { res ->
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
            client.newCall(request).execute().use { response ->
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
            Log.w(TAG, "Live analysis network failure: ${e.javaClass.simpleName}")
            return@withContext AnalysisOutcome.Failure("Gateway unreachable: ${e.message}")
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
