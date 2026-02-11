"""
AI Triage Module - Validates findings using LLM.
Implements severity gating and parallel processing to optimize performance.
"""
import json
import time
from typing import Optional, List, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from config.settings import settings
from core.logger import log
from utils.notifier import notifier
from modules.scanner import ScanResult

# Conditional import for Gemini
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


@dataclass
class TriageResult:
    """Result of AI triage analysis."""
    is_valid: bool
    confidence: str  # HIGH, MEDIUM, LOW
    reasoning: str
    recommendation: str


class AITriage:
    """
    The Intelligence Layer - Uses AI to validate vulnerabilities.
    Implements pre-flight severity filtering to control API costs.
    Now processes findings in parallel for improved throughput.
    """
    
    ALLOWED_SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL"}
    
    def __init__(self):
        self.enabled = False
        self.model = None
        
        if GENAI_AVAILABLE and settings.GEMINI_API_KEY:
            try:
                genai.configure(api_key=settings.GEMINI_API_KEY)
                self.model = genai.GenerativeModel("gemini-2.0-flash")
                self.enabled = True
                log.info("[AI] Triage module initialized (Gemini)")
            except Exception as e:
                log.warning(f"[AI] Failed to initialize: {e}")
    
    def triage_findings(self, findings: List[ScanResult]) -> List[Tuple[ScanResult, TriageResult]]:
        """
        Triages a list of findings in parallel.
        Only processes MEDIUM/HIGH/CRITICAL severity.
        """
        triaged_results: List[Tuple[ScanResult, TriageResult]] = []
        findings_to_process = []
        
        # 1. Filter findings to save costs
        for finding in findings:
            if finding.severity not in self.ALLOWED_SEVERITIES:
                log.debug(f"[AI] Skipping {finding.severity} severity: {finding.description}")
                continue
            findings_to_process.append(finding)
        
        if not findings_to_process:
            return []

        # 2. Process in parallel
        # We use a smaller pool than MAX_THREADS for AI to avoid rate limits (checking GLOBAL_RATE_LIMIT implied logic)
        # Using min(5, MAX_THREADS) as a safe default for AI calls
        ai_workers = min(5, settings.MAX_THREADS)
        
        log.info(f"[AI] Analyzing {len(findings_to_process)} findings with {ai_workers} threads...")

        with ThreadPoolExecutor(max_workers=ai_workers) as executor:
            future_to_finding = {
                executor.submit(self.analyze_finding, finding): finding 
                for finding in findings_to_process
            }
            
            for future in as_completed(future_to_finding):
                finding = future_to_finding[future]
                try:
                    result = future.result()
                    triaged_results.append((finding, result))
                    
                    # Send alert if high confidence
                    if result.is_valid and result.confidence == "HIGH":
                        self._send_alert(finding, result)
                        
                except Exception as e:
                    log.error(f"[AI] Unexpected error processing {finding.target}: {e}")
        
        return triaged_results
    
    def analyze_finding(self, finding: ScanResult) -> TriageResult:
        """Analyzes a single finding using AI."""
        
        if not self.enabled:
            # Fallback: Auto-validate without AI
            return TriageResult(
                is_valid=True,
                confidence="MEDIUM",
                reasoning="AI not configured - Manual review required",
                recommendation="Verify manually"
            )
        
        prompt = self._build_prompt(finding)
        
        try:
            # Simple rate limiting: small sleep to spread requests slightly if bursty
            # time.sleep(0.2) 
            response = self.model.generate_content(prompt)
            return self._parse_response(response.text)
        except Exception as e:
            log.error(f"[AI] Analysis error for {finding.tool}: {e}")
            return TriageResult(
                is_valid=True,
                confidence="LOW",
                reasoning=f"AI error: {e}",
                recommendation="Manual review required"
            )
    
    def _build_prompt(self, finding: ScanResult) -> str:
        """Builds the analysis prompt."""
        return f"""You are a senior penetration tester analyzing vulnerability scan results.

**Finding:**
- Tool: {finding.tool}
- Target: {finding.target}
- Severity: {finding.severity}
- Description: {finding.description}
- Raw Output (truncated): {(finding.raw_output or "N/A")[:1000]}

**Your Task:**
1. Determine if this is a TRUE POSITIVE or FALSE POSITIVE.
2. Assess your confidence (HIGH/MEDIUM/LOW).
3. Provide brief reasoning.
4. Recommend next steps.

**Respond in JSON format:**
{{
    "is_valid": true/false,
    "confidence": "HIGH/MEDIUM/LOW",
    "reasoning": "Brief explanation",
    "recommendation": "Next steps"
}}
"""
    
    def _parse_response(self, response: str) -> TriageResult:
        """Parses AI response into TriageResult."""
        try:
            # Extract JSON from response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(response[start:end])
                return TriageResult(
                    is_valid=data.get("is_valid", True),
                    confidence=data.get("confidence", "MEDIUM"),
                    reasoning=data.get("reasoning", ""),
                    recommendation=data.get("recommendation", "")
                )
        except json.JSONDecodeError:
            pass
        
        # Fallback parsing
        return TriageResult(
            is_valid="false positive" not in response.lower(),
            confidence="MEDIUM",
            reasoning=response[:500],
            recommendation="Review AI output manually"
        )
    
    def _send_alert(self, finding: ScanResult, triage: TriageResult):
        """Sends notification for high-confidence findings."""
        notifier.send_alert(
            title=f"{finding.tool.upper()}: {finding.description[:50]}",
            description=f"**Target:** {finding.target}\n**Confidence:** {triage.confidence}\n**Reasoning:** {triage.reasoning}",
            severity=finding.severity
        )
