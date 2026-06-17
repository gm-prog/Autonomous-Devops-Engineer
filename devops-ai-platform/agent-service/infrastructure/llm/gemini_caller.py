import os
import requests
import logging
from typing import Dict, Any
from ...domain.remote_llm_interface import RemoteLLMInterface

logger = logging.getLogger("GeminiCallerAdapter")

class GeminiCallerAdapter(RemoteLLMInterface):
    """
    Adapter implementing RemoteLLMInterface.
    Connects to the official Google Gemini API using REST.
    """
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"

    def generate_remediation(self, prompt: str, system_instruction: str) -> str:
        if not self.api_key:
            logger.warning("[OFFLINE_BYPASS] No valid Gemini API Key detected. Engaging simulator fallback...")
            return "SIMULATED remediations: Scale connection pool capacity configurations in application-prod.yaml to 100 threads."

        # Target basic/complex model according to guidelines: gemini-3.5-flash
        model_name = "gemini-3.5-flash"
        endpoint = f"{self.base_url}/{model_name}:generateContent?key={self.api_key}"
        
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": system_instruction}]}
        }

        try:
            response = requests.post(endpoint, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            logger.error(f"Gemini API handshake failed: {e}")
            return f"Bypassed on error: {str(e)}"

    def generate_iac_blueprint(self, tech_metadata: Dict[str, Any]) -> Dict[str, str]:
        # Target high quality reasoning model: gemini-3.1-pro-preview
        model_name = "gemini-3.1-pro-preview"
        if not self.api_key:
            return {
                "Dockerfile": "FROM python:3.11-alpine\nCMD ['uvicorn', 'app.main:app']",
                "Deployment.yaml": "apiVersion: apps/v1\nkind: Deployment..."
            }

        endpoint = f"{self.base_url}/{model_name}:generateContent?key={self.api_key}"
        # Request blueprint payload logic...
        return {}
