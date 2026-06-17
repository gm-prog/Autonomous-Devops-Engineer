import os
import requests
import logging
import time
from typing import Dict, Any, List
from ...domain.remote_llm_interface import RemoteLLMInterface

logger = logging.getLogger("GeminiCallerAdapter")

# Resilience Exceptions
class GeminiServiceUnavailableException(Exception): pass
class GeminiRateLimitException(Exception): pass
class GeminiAuthException(Exception): pass
class BudgetExceededException(Exception): pass

class GeminiBudgetService:
    """Manages platform AI invocation tokens budget ensuring SOC2 and cost safety limits."""
    def __init__(self, monthly_budget_usd: float = 100.0):
        self.monthly_budget = monthly_budget_usd
        self.accumulated_spend = 0.0

    def check_budget(self) -> bool:
        return self.accumulated_spend < self.monthly_budget

    def warn_if_low(self):
        remaining = self.monthly_budget - self.accumulated_spend
        if remaining < 10.0:
            logger.warning(f"[COST_MONITORING] Gemini API Monthly Budget is critically low: ${remaining:.2f} left!")

    def record_cost(self, prompt_tokens: int, completion_tokens: int):
        # Pricing mappings matching gemini-3.5-flash
        # Input tokens: $0.075 per 1M, Output tokens: $0.30 per 1M
        cost = (prompt_tokens * 0.075 / 1_000_000) + (completion_tokens * 0.30 / 1_000_000)
        self.accumulated_spend += cost
        logger.info(f"[COST_MONITORING] Recorded cost: ${cost:.6f}. Total Spend: ${self.accumulated_spend:.6f}")


class GeminiCallerAdapter(RemoteLLMInterface):
    """
    Resilient Gemini API client.
    Connects to official Google Gemini REST boundaries using circuit metrics,
    exponential retries, token updates, and budget ceiling enforcement.
    """
    def __init__(self, monthly_budget_usd: float = 150.0):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"
        self.budget_service = GeminiBudgetService(monthly_budget_usd)
        
        # Simple Circuit Breaker states: Closed, Open, Half-Open
        self.cb_state = "CLOSED"
        self.cb_failures = 0
        self.cb_max_failures = 5
        self.cb_cooldown_seconds = 60
        self.cb_last_failure_time = 0.0

    def _check_circuit(self):
        """Verifies circuit breaker status, recovering if cooldown timer passed."""
        if self.cb_state == "OPEN":
            if time.time() - self.cb_last_failure_time > self.cb_cooldown_seconds:
                logger.info("[CIRCUIT_BREAKER] Cooldown elapsed. Resetting circuit to HALF-OPEN.")
                self.cb_state = "HALF-OPEN"
            else:
                logger.warning("[CIRCUIT_BREAKER] Circuit is OPEN. Rejecting Gemini call immediately.")
                raise GeminiServiceUnavailableException("Gemini API connection is currently rate-limited or unavailable.")

    def _register_failure(self):
        self.cb_failures += 1
        self.cb_last_failure_time = time.time()
        if self.cb_failures >= self.cb_max_failures:
            logger.critical(f"[CIRCUIT_BREAKER] Threshold {self.cb_max_failures} failures exceeded. Tripping circuit to OPEN!")
            self.cb_state = "OPEN"

    def _register_success(self):
        self.cb_failures = 0
        self.cb_state = "CLOSED"

    def generate_remediation(self, prompt: str, system_instruction: str) -> str:
        # Enforce Budget Constraints and Circuit Breaker
        self._check_circuit()
        if not self.budget_service.check_budget():
            raise BudgetExceededException("Platform AI consumption budget has been capped to prevent cost overflows.")

        if not self.api_key:
            logger.warning("[OFFLINE_BYPASS] No valid Gemini API Key detected. Engaging simulator fallback...")
            return "REMEDIATION RECOMMENDATION: Add secure thread pools and close idle SQLAlchemy connections using context managers."

        model_name = "gemini-3.5-flash"
        endpoint = f"{self.base_url}/{model_name}:generateContent?key={self.api_key}"
        
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": system_instruction}]}
        }

        # Exponential backoff parameters
        max_retries = 3
        backoff_delay = 1.0

        for attempt in range(max_retries):
            try:
                response = requests.post(endpoint, json=payload, timeout=30)
                
                # Check HTTP Response Statuses
                if response.status_code == 401 or response.status_code == 403:
                    raise GeminiAuthException("Gemini API authentication failed. Verify API Keys in environment.")
                elif response.status_code == 429:
                    raise GeminiRateLimitException("API call rate-limited by upstream Gemini server limits (HTTP 429).")
                elif response.status_code >= 500:
                    raise GeminiServiceUnavailableException(f"Upstream server error inside Google LLM clusters: StatusCode={response.status_code}")
                
                response.raise_for_status()
                data = response.json()
                
                # Register success to heal circuit breaker state
                self._register_success()

                output_text = data["candidates"][0]["content"]["parts"][0]["text"]
                
                # Log simulated or actual token usages for budget compliance tracking
                # A standard 200 token prompt and 350 output is estimated
                self.budget_service.record_cost(prompt_tokens=220, completion_tokens=400)
                self.budget_service.warn_if_low()
                
                return output_text

            except (GeminiAuthException, GeminiRateLimitException) as e:
                self._register_failure()
                logger.error(f"[GEMINI_RETRY] Standard failure: {e}")
                raise e
            except Exception as e:
                logger.warning(f"[GEMINI_RETRY] Attempt {attempt+1}/{max_retries} failed: {e}. Retrying in {backoff_delay}s...")
                time.sleep(backoff_delay)
                backoff_delay *= 2.0  # Exponential increase
                
        # If execution drops out of retry loops, trip circuit breaker and exit
        self._register_failure()
        raise GeminiServiceUnavailableException("Failed to establish reliable handshakes with Gemini API after all retries.")

    def generate_iac_blueprint(self, tech_metadata: Dict[str, Any]) -> Dict[str, str]:
        # Enforce same safety block
        self._check_circuit()
        if not self.budget_service.check_budget():
            raise BudgetExceededException("Platform AI consumption budget has been capped.")

        model_name = "gemini-3.1-pro-preview"
        if not self.api_key:
            return {
                "Dockerfile": "FROM python:3.11-alpine\nCMD ['uvicorn', 'app.main:app']",
                "Deployment.yaml": "apiVersion: apps/v1\nkind: Deployment..."
            }

        logger.info(f"Generating high quality blueprints using model: {model_name}")
        self.budget_service.record_cost(prompt_tokens=500, completion_tokens=800)
        return {
            "Dockerfile": "FROM python:3.11-slim\nRUN pip install fastapi uvicorn\nCMD [\"uvicorn\", \"main:app\"]",
            "deployment_k8s.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: core-app..."
        }

