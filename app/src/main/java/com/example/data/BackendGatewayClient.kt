package com.example.data

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * Platform gateway connectivity diagnostic (Phase 8.7-C.1 scope note).
 *
 * This client only performs a reachability probe against a user-configured
 * gateway URL (settings "Ping Endpoint" diagnostics). It is NOT an AI or
 * analysis client: this branch contains no implemented, authenticated
 * server-side analysis backend for the app, so there is deliberately no
 * remote repository-analysis call in the app. Repository analysis always
 * runs the offline engine in [GeminiClient]. See devops-ai-platform/SECURITY.md.
 */
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
}
