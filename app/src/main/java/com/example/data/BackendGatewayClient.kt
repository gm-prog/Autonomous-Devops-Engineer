package com.example.data

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
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
        if (cleanUrl.isEmpty()) return@withContext null

        try {
            val createPayload = JSONObject().apply {
                put("name", repoName)
                put("url", repoUrl)
                put("framework", framework)
                put("technology", technology)
            }
            val createRequest = Request.Builder()
                .url(cleanUrl + "/api/repositories")
                .post(createPayload.toString().toRequestBody("application/json".toMediaType()))
                .build()

            val repositoryId = client.newCall(createRequest).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.w(TAG, "Repository registration returned code ${response.code}")
                    return@withContext null
                }
                val json = JSONObject(response.body?.string() ?: return@withContext null)
                json.optInt("id", 0).takeIf { it > 0 } ?: return@withContext null
            }

            val analyzeRequest = Request.Builder()
                .url(cleanUrl + "/api/repositories/" + repositoryId + "/analyze")
                .post("{}".toRequestBody("application/json".toMediaType()))
                .build()
            client.newCall(analyzeRequest).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.w(TAG, "Remote analysis dispatch returned code ${response.code}")
                    return@withContext null
                }
            }

            repeat(30) {
                delay(1000)
                val statusRequest = Request.Builder()
                    .url(cleanUrl + "/api/repositories/" + repositoryId)
                    .get()
                    .build()
                client.newCall(statusRequest).execute().use { response ->
                    if (!response.isSuccessful) return@use
                    val json = JSONObject(response.body?.string() ?: return@use)
                    when (json.optString("status")) {
                        "Generated" -> throw RemoteAnalysisComplete(
                            DevOpsAnalysisResult(
                                dockerfile = json.optString("dockerfile"),
                                k8sYaml = json.optString("k8s_yaml"),
                                terraformTf = json.optString("terraform_tf"),
                                pipelineYaml = json.optString("pipeline_yaml"),
                                report = json.optString("analysis_report").ifEmpty {
                                    "Repository analysis completed by the remote backend."
                                }
                            )
                        )
                        "Failed" -> throw RemoteAnalysisFailed("Remote repository analysis failed")
                    }
                }
            }
            null
        } catch (e: RemoteAnalysisComplete) {
            e.result
        } catch (e: RemoteAnalysisFailed) {
            Log.w(TAG, e.message.orEmpty())
            null
        } catch (e: Exception) {
            Log.e(TAG, "Remote analysis failed: ${e.message}")
            null
        }
    }

    private class RemoteAnalysisComplete(val result: DevOpsAnalysisResult) : Exception()
    private class RemoteAnalysisFailed(message: String) : Exception(message)
}
