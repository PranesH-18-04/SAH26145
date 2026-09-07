import os
import logging
from dotenv import load_dotenv

# Load env vars from .env file if present
load_dotenv()

# We only import the google-genai SDK inside the function or conditionally
# so that if it fails to install on some environment, the rest of the backend won't crash immediately.
# However, since it's in requirements, we can import it at the top level, but gracefully catch missing key.
try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None

logger = logging.getLogger(__name__)

class GeminiService:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        if self.api_key and genai:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini client: {e}")
                self.client = None
        else:
            self.client = None
            logger.warning("GEMINI_API_KEY not found or google-genai not installed. Falling back to rule-based explanations.")

    def get_insight(self, rule_based_explanation: str, severity: str, protocol: str, features: dict) -> dict:
        """
        Calls Gemini API to generate a richer natural-language insight.
        Returns a dict with {insight, action, source}.
        """
        if not self.client:
            return self._fallback(rule_based_explanation)
            
        prompt = f"""
You are an expert SOC Analyst and Cyber Threat Intelligence AI.
Analyze the following unidirectional traffic alert and provide a concise, natural-language insight (2-4 sentences) and a recommended action.

Context:
- Protocol: {protocol}
- Severity: {severity}
- Rule-based Explanation: {rule_based_explanation}
- Flow Features: {features}

Provide the output in exactly two sections:
Insight: <your concise analysis>
Recommended Action: <your specific remediation or triage step>
"""
        try:
            # We use gemini-2.5-flash as it's the recommended lightweight model
            response = self.client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                )
            )
            
            text = response.text
            
            # Parse the structured text
            insight = ""
            action = ""
            
            for line in text.split('\n'):
                if line.startswith("Insight:"):
                    insight = line.replace("Insight:", "").strip()
                elif line.startswith("Recommended Action:"):
                    action = line.replace("Recommended Action:", "").strip()
                    
            if not insight:
                insight = text  # Fallback if parsing fails
                
            if not action:
                action = "Review the raw PCAP and investigate the source IP."

            return {
                "insight": insight,
                "action": action,
                "source": "gemini"
            }
            
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return self._fallback(rule_based_explanation)
            
    def _fallback(self, rule_based_explanation: str) -> dict:
        return {
            "insight": rule_based_explanation,
            "action": "Investigate source IP and review traffic logs.",
            "source": "rule-based"
        }

gemini_service = GeminiService()
