package com.example

import com.example.data.GeminiClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM unit tests for the 5-tag AI output protocol parser
 * (GeminiClient.parseTag). This is the most fragile contract in the app:
 * any model-output change that breaks tag extraction silently degrades
 * the analysis to empty artifacts.
 */
class GeminiClientParseTest {

    @Test
    fun `extracts content between tags`() {
        val text = "preamble <DOCKERFILE>FROM python:3.12-alpine</DOCKERFILE> trailing"
        assertEquals("FROM python:3.12-alpine", GeminiClient.parseTag(text, "DOCKERFILE"))
    }

    @Test
    fun `multi-line content is preserved`() {
        val text = "<KUBERNETES>apiVersion: apps/v1\nkind: Deployment</KUBERNETES>"
        assertEquals("apiVersion: apps/v1\nkind: Deployment", GeminiClient.parseTag(text, "KUBERNETES"))
    }

    @Test
    fun `missing tag yields empty string, not an exception`() {
        assertEquals("", GeminiClient.parseTag("no tags at all", "CICD"))
    }

    @Test
    fun `unterminated tag yields empty string`() {
        assertEquals("", GeminiClient.parseTag("<TERRAFORM>resource \"aws\" \"x\" {", "TERRAFORM"))
    }

    @Test
    fun `close tag before open tag yields empty string`() {
        assertEquals("", GeminiClient.parseTag("</REPORT>text<REPORT>", "REPORT"))
    }

    @Test
    fun `strips markdown code fences from payload`() {
        val text = "<CICD>\n```yaml\nname: ci\n```\n</CICD>"
        assertEquals("name: ci", GeminiClient.parseTag(text, "CICD"))
    }

    @Test
    fun `strips language-tagged fences`() {
        val text = "<DOCKERFILE>\n```dockerfile\nFROM alpine\n```\n</DOCKERFILE>"
        assertEquals("FROM alpine", GeminiClient.parseTag(text, "DOCKERFILE"))
    }

    @Test
    fun `all five protocol tags parse from a realistic model response`() {
        val text = """
            <DOCKERFILE>FROM alpine</DOCKERFILE>
            <KUBERNETES>kind: Service</KUBERNETES>
            <TERRAFORM>provider "aws" { region = "us-east-1" }</TERRAFORM>
            <CICD>name: pipeline</CICD>
            <REPORT>It works.</REPORT>
        """.trimIndent()
        assertEquals("FROM alpine", GeminiClient.parseTag(text, "DOCKERFILE"))
        assertEquals("kind: Service", GeminiClient.parseTag(text, "KUBERNETES"))
        assertEquals("provider \"aws\" { region = \"us-east-1\" }", GeminiClient.parseTag(text, "TERRAFORM"))
        assertEquals("name: pipeline", GeminiClient.parseTag(text, "CICD"))
        assertEquals("It works.", GeminiClient.parseTag(text, "REPORT"))
    }
}
