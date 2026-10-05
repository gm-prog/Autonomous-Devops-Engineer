package com.example.data

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

object BackendGatewayClient {
    private const val TAG = "BackendGatewayClient"
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .build()

    /**
     * Checks if the user-specified API Gateway URL is responsive.
     * Probes the gateway's liveness endpoints in order:
     *   GET {base}/health          (root backend canonical)
     *   GET {base}/api/v1/health   (client-compatibility alias)
     * Only an HTTP 2xx counts as "connected" — a 404 means the URL is
     * reachable but not the DevOps gateway, so it must NOT be reported as
     * success (the previous implementation treated 404 as connected, which
     * let the status pill lie).
     */
    suspend fun testConnection(baseUrlStr: String): Boolean = withContext(Dispatchers.IO) {
        val cleanUrl = baseUrlStr.trim().removeSuffix("/")
        if (cleanUrl.isEmpty()) return@withContext false

        for (path in listOf("/health", "/api/v1/health")) {
            val request = Request.Builder()
                .url("$cleanUrl$path")
                .get()
                .build()
            try {
                client.newCall(request).execute().use { response ->
                    Log.d(TAG, "Connection check $cleanUrl$path: code ${response.code}")
                    if (response.isSuccessful) return@withContext true
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed connection test to $cleanUrl$path: ${e.message}")
            }
        }
        false
    }

    /**
     * Optional: Calls the FastAPI backend repo analysis endpoint to generate
     * DevOps blueprints (Dockerfile, K8s, Terraform, pipelines) if remote integrations are active.
     */
    suspend fun queryRemoteAnalysis(
        baseUrlStr: String,
        repoName: String,
        repoUrl: String,
        framework: String,
        technology: String
    ): DevOpsAnalysisResult? = withContext(Dispatchers.IO) {
        val cleanUrl = baseUrlStr.trim().removeSuffix("/")
        val endpoint = "$cleanUrl/api/v1/repository/analyze"

        val jsonPayload = JSONObject().apply {
            put("name", repoName)
            put("url", repoUrl)
            put("framework", framework)
            put("technology", technology)
        }

        val requestBody = jsonPayload.toString().toRequestBody("application/json".toMediaType())
        val request = Request.Builder()
            .url(endpoint)
            .post(requestBody)
            .build()

        try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.w(TAG, "Remote analysis request returned code ${response.code}")
                    return@withContext null
                }
                val bodyStr = response.body?.string() ?: return@withContext null
                val json = JSONObject(bodyStr)
                
                // Assuming the fastapi gateway responds with generated structure or reports
                return@withContext DevOpsAnalysisResult(
                    dockerfile = json.optString("dockerfile", "").ifEmpty { "## Generated remotely via API Gateway" },
                    k8sYaml = json.optString("k8s_yaml", "").ifEmpty { "## Kubernetes remote description config" },
                    terraformTf = json.optString("terraform_tf", "").ifEmpty { "## Terraform remote resource modules" },
                    pipelineYaml = json.optString("pipeline_yaml", "").ifEmpty { "## Remote GitHub actions workflow configuration" },
                    report = json.optString("analysis_report", "").ifEmpty { "Successfully generated via remote FastAPI microservices." }
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Remote analysis failed: ${e.message}")
            return@withContext null
        }
    }
}
