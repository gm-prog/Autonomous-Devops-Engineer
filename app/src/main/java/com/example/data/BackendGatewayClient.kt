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
     * Hits either the root '/' or the '/api/v1/health' endpoint.
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
            Log.w(TAG, "Failed connection test to $cleanUrl: ${e.message}")
            // Let's also check if they provide a '/health' subpath
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
