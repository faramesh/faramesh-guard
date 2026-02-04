"""
Adversarial Detector - Prompt Injection & Attack Detection

Detects adversarial attempts to manipulate or bypass Guard:
1. Prompt injection attacks
2. Obfuscation techniques
3. Social engineering patterns
4. Encoding tricks (base64, unicode, etc)

Following plan-farameshGuardV1Enhanced.prompt.md:
- Multi-layer detection
- Pattern matching + ML
- Confidence scoring
- Integration with signal fusion
"""

import re
import base64
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AdversarialSignal:
    """Signal indicating adversarial behavior"""

    attack_type: str
    confidence: float  # 0.0 to 1.0
    indicators: List[str]
    evidence: Dict[str, Any]
    detected_at: Optional[datetime] = None

    def __post_init__(self):
        if self.detected_at is None:
            self.detected_at = datetime.utcnow()


class AdversarialDetector:
    """
    Detects adversarial attacks in tool parameters and prompts.

    Uses multiple detection layers:
    1. Pattern-based (regex for known attacks)
    2. Heuristic (suspicious characteristics)
    3. Encoding detection (obfuscation attempts)
    4. Social engineering patterns
    """

    def __init__(self):
        self._prompt_injection_patterns = self._load_injection_patterns()
        self._obfuscation_patterns = self._load_obfuscation_patterns()
        self._social_engineering_patterns = self._load_social_patterns()

        # Statistics
        self._detections = []
        self._detection_count = 0

    def _load_injection_patterns(self) -> List[Tuple[re.Pattern, str, float]]:
        """Load prompt injection detection patterns"""
        # Format: (regex, attack_name, confidence)
        patterns = [
            # Direct instruction override
            (
                re.compile(
                    r"ignore\s+(previous|above|all|system)\s+(instructions?|prompts?|rules?)",
                    re.IGNORECASE,
                ),
                "instruction_override",
                0.9,
            ),
            (
                re.compile(r"disregard\s+(previous|above|all|system)", re.IGNORECASE),
                "instruction_override",
                0.9,
            ),
            (
                re.compile(r"forget\s+(previous|everything|all)", re.IGNORECASE),
                "instruction_override",
                0.8,
            ),
            # Role manipulation
            (
                re.compile(r"you\s+are\s+now\s+a", re.IGNORECASE),
                "role_manipulation",
                0.85,
            ),
            (re.compile(r"pretend\s+to\s+be", re.IGNORECASE), "role_manipulation", 0.8),
            (
                re.compile(r"act\s+as\s+(if\s+)?you\s+(are|were)", re.IGNORECASE),
                "role_manipulation",
                0.75,
            ),
            # System prompt extraction
            (
                re.compile(
                    r"(show|reveal|display|print)\s+(your\s+)?(system\s+)?(prompt|instructions?)",
                    re.IGNORECASE,
                ),
                "prompt_extraction",
                0.9,
            ),
            (
                re.compile(
                    r"what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions?)",
                    re.IGNORECASE,
                ),
                "prompt_extraction",
                0.85,
            ),
            # Delimiter manipulation
            (
                re.compile(r"---\s*(SYSTEM|ADMIN|ROOT)", re.IGNORECASE),
                "delimiter_manipulation",
                0.8,
            ),
            (
                re.compile(r"<(system|admin|root)>", re.IGNORECASE),
                "delimiter_manipulation",
                0.8,
            ),
            # Encoding markers
            (
                re.compile(r"(base64|hex|rot13|unicode)\s*[:=]", re.IGNORECASE),
                "encoding_obfuscation",
                0.7,
            ),
            # Jailbreak attempts
            (
                re.compile(
                    r"(jailbreak|bypass|exploit|hack)\s+(the\s+)?(system|guard|safety|filter)",
                    re.IGNORECASE,
                ),
                "explicit_jailbreak",
                0.95,
            ),
            # DAN (Do Anything Now) variants
            (re.compile(r"do\s+anything\s+now", re.IGNORECASE), "dan_jailbreak", 0.9),
            (
                re.compile(r"(you\s+)?(can|will|must)\s+do\s+anything", re.IGNORECASE),
                "dan_jailbreak",
                0.85,
            ),
        ]

        return [(p, name, conf) for p, name, conf in patterns]

    def _load_obfuscation_patterns(self) -> List[Tuple[re.Pattern, str]]:
        """Load obfuscation detection patterns"""
        patterns = [
            # Character substitution
            (
                re.compile(r"[a@][dm][m1][i1][n]", re.IGNORECASE),
                "character_substitution",
            ),
            (
                re.compile(r"[s5][y][s5][t][e3][m]", re.IGNORECASE),
                "character_substitution",
            ),
            # Excessive special characters
            (re.compile(r"[!@#$%^&*]{5,}"), "excessive_special_chars"),
            # Unicode homoglyphs (Cyrillic, Greek lookalikes)
            (re.compile(r"[\u0400-\u04FF\u0370-\u03FF]{3,}"), "unicode_homoglyphs"),
            # Zero-width characters
            (re.compile(r"[\u200B-\u200D\uFEFF]+"), "zero_width_chars"),
            # Repeated encoding
            (
                re.compile(r"(base64|hex|url)\s*\([^)]*\)", re.IGNORECASE),
                "nested_encoding",
            ),
        ]

        return patterns

    def _load_social_patterns(self) -> List[Tuple[re.Pattern, str, float]]:
        """Load social engineering patterns"""
        patterns = [
            # Authority exploitation
            (
                re.compile(
                    r"(i\s+am|this\s+is)\s+(your\s+)?(admin|root|owner|creator)",
                    re.IGNORECASE,
                ),
                "authority_exploit",
                0.8,
            ),
            # Urgency/pressure
            (
                re.compile(
                    r"(urgent|emergency|critical|immediately|right\s+now)",
                    re.IGNORECASE,
                ),
                "urgency_pressure",
                0.6,
            ),
            # Trust exploitation
            (
                re.compile(r"trust\s+me|you\s+can\s+trust", re.IGNORECASE),
                "trust_exploit",
                0.7,
            ),
            # Secret/hidden commands
            (
                re.compile(
                    r"(secret|hidden|special|debug)\s+(command|mode|access)",
                    re.IGNORECASE,
                ),
                "secret_command",
                0.75,
            ),
        ]

        return [(p, name, conf) for p, name, conf in patterns]

    def detect(self, parameters: Dict[str, Any]) -> Optional[AdversarialSignal]:
        """
        Detect adversarial patterns in tool parameters.

        Returns:
            AdversarialSignal if attack detected, None otherwise
        """
        # Convert parameters to searchable text
        text = self._extract_text(parameters)

        if not text:
            return None

        # Run all detection layers
        detections = []

        # Layer 1: Prompt injection
        injection_results = self._detect_prompt_injection(text)
        detections.extend(injection_results)

        # Layer 2: Obfuscation
        obfuscation_results = self._detect_obfuscation(text)
        detections.extend(obfuscation_results)

        # Layer 3: Social engineering
        social_results = self._detect_social_engineering(text)
        detections.extend(social_results)

        # Layer 4: Encoding tricks
        encoding_results = self._detect_encoding_tricks(text)
        detections.extend(encoding_results)

        # If any detections, create signal
        if detections:
            # Take highest confidence detection
            best = max(detections, key=lambda x: x["confidence"])

            indicators = [d["indicator"] for d in detections]
            attack_types = list(set(d["attack_type"] for d in detections))

            signal = AdversarialSignal(
                attack_type=", ".join(attack_types),
                confidence=best["confidence"],
                indicators=indicators,
                evidence={
                    "text_sample": text[:200],
                    "detections": detections,
                    "parameters_keys": list(parameters.keys()),
                },
            )

            self._detections.append(signal)
            self._detection_count += 1

            logger.warning(
                f"Adversarial attack detected: {signal.attack_type} "
                f"(confidence: {signal.confidence:.2f})"
            )

            return signal

        return None

    def _extract_text(self, parameters: Dict[str, Any]) -> str:
        """Extract searchable text from parameters"""
        parts = []

        def extract(obj):
            if isinstance(obj, str):
                parts.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    extract(v)
            elif isinstance(obj, (list, tuple)):
                for item in obj:
                    extract(item)

        extract(parameters)
        return " ".join(parts)

    def _detect_prompt_injection(self, text: str) -> List[Dict[str, Any]]:
        """Detect prompt injection patterns"""
        results = []

        for pattern, attack_type, confidence in self._prompt_injection_patterns:
            matches = pattern.findall(text)
            if matches:
                results.append(
                    {
                        "attack_type": attack_type,
                        "confidence": confidence,
                        "indicator": f"Pattern: {attack_type}",
                        "matches": matches[:3],  # First 3 matches
                    }
                )

        return results

    def _detect_obfuscation(self, text: str) -> List[Dict[str, Any]]:
        """Detect obfuscation attempts"""
        results = []

        for pattern, obfuscation_type in self._obfuscation_patterns:
            if pattern.search(text):
                results.append(
                    {
                        "attack_type": "obfuscation",
                        "confidence": 0.7,
                        "indicator": f"Obfuscation: {obfuscation_type}",
                        "matches": [],
                    }
                )

        return results

    def _detect_social_engineering(self, text: str) -> List[Dict[str, Any]]:
        """Detect social engineering patterns"""
        results = []

        for pattern, attack_type, confidence in self._social_engineering_patterns:
            matches = pattern.findall(text)
            if matches:
                results.append(
                    {
                        "attack_type": attack_type,
                        "confidence": confidence,
                        "indicator": f"Social: {attack_type}",
                        "matches": matches[:2],
                    }
                )

        return results

    def _detect_encoding_tricks(self, text: str) -> List[Dict[str, Any]]:
        """Detect encoding-based obfuscation"""
        results = []

        # Check for base64
        base64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        base64_matches = base64_pattern.findall(text)

        for match in base64_matches[:3]:  # Check first 3
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                # Check if decoded text has suspicious content
                if any(
                    word in decoded.lower()
                    for word in ["system", "admin", "ignore", "disregard"]
                ):
                    results.append(
                        {
                            "attack_type": "base64_obfuscation",
                            "confidence": 0.8,
                            "indicator": "Suspicious base64 content",
                            "matches": [decoded[:50]],
                        }
                    )
            except Exception:
                pass

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        attack_type_counts = {}
        for detection in self._detections[-100:]:  # Last 100
            attack_type = detection.attack_type
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1

        return {
            "total_detections": self._detection_count,
            "recent_detections": len(self._detections),
            "attack_types": attack_type_counts,
            "pattern_count": {
                "injection": len(self._prompt_injection_patterns),
                "obfuscation": len(self._obfuscation_patterns),
                "social": len(self._social_engineering_patterns),
            },
        }


# Global detector instance
_global_detector: Optional[AdversarialDetector] = None


def get_adversarial_detector() -> AdversarialDetector:
    """Get or create the global adversarial detector"""
    global _global_detector
    if _global_detector is None:
        _global_detector = AdversarialDetector()
    return _global_detector
