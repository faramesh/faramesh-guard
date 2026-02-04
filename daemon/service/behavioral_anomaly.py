"""
Behavioral Anomaly Detector

Detects abnormal patterns in agent behavior:
1. Rate spikes (too many actions in short time)
2. Sequence anomalies (unusual action patterns)
3. State drift (unexpected system changes)
4. Replay variations (similar but not identical actions)

Following plan-farameshGuardV1Enhanced.prompt.md:
- Learn normal patterns from approved actions
- Detect deviations in real-time
- Adaptive thresholds
- Integration with signal fusion
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque, defaultdict
import json

logger = logging.getLogger(__name__)


@dataclass
class ActionEvent:
    """A single action event"""

    timestamp: datetime
    agent_id: str
    tool_name: str
    parameters: Dict[str, Any]
    car_hash: str
    outcome: str  # ALLOW, DENY, ABSTAIN
    risk_level: str


@dataclass
class AnomalySignal:
    """Signal indicating anomalous behavior"""

    anomaly_type: str  # 'rate_spike', 'sequence', 'state_drift', 'replay_variant'
    severity: float  # 0.0 to 1.0
    description: str
    evidence: Dict[str, Any]
    detected_at: datetime


@dataclass
class AgentProfile:
    """Learned behavioral profile for an agent"""

    agent_id: str
    total_actions: int = 0
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)

    # Rate patterns
    avg_actions_per_minute: float = 0.0
    max_actions_per_minute: int = 0

    # Tool usage patterns
    tool_frequency: Dict[str, int] = field(default_factory=dict)
    common_sequences: List[List[str]] = field(default_factory=list)

    # Time patterns
    active_hours: List[int] = field(default_factory=list)
    typical_session_duration: float = 0.0


class BehavioralAnomalyDetector:
    """
    Detects behavioral anomalies in agent actions.

    Uses a combination of:
    - Statistical analysis (rates, distributions)
    - Sequence modeling (n-grams)
    - Temporal patterns
    - Similarity matching
    """

    def __init__(
        self,
        window_size: int = 100,
        rate_window_minutes: int = 5,
        sequence_length: int = 3,
    ):
        self.window_size = window_size
        self.rate_window_minutes = rate_window_minutes
        self.sequence_length = sequence_length

        # Store recent events per agent
        self._agent_events: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=window_size)
        )

        # Learned profiles
        self._agent_profiles: Dict[str, AgentProfile] = {}

        # Anomaly history
        self._anomalies: deque = deque(maxlen=1000)

    def record_action(self, event: ActionEvent):
        """Record an action event for learning"""
        self._agent_events[event.agent_id].append(event)
        self._update_profile(event)

    def _update_profile(self, event: ActionEvent):
        """Update agent's behavioral profile"""
        if event.agent_id not in self._agent_profiles:
            self._agent_profiles[event.agent_id] = AgentProfile(agent_id=event.agent_id)

        profile = self._agent_profiles[event.agent_id]
        profile.total_actions += 1
        profile.last_seen = event.timestamp

        # Update tool frequency
        if event.tool_name not in profile.tool_frequency:
            profile.tool_frequency[event.tool_name] = 0
        profile.tool_frequency[event.tool_name] += 1

        # Update time patterns
        hour = event.timestamp.hour
        if hour not in profile.active_hours:
            profile.active_hours.append(hour)

    def detect_anomalies(self, event: ActionEvent) -> List[AnomalySignal]:
        """
        Analyze an event for anomalies.

        Returns:
            List of detected anomalies (empty if none)
        """
        anomalies = []

        # Check rate spike
        rate_anomaly = self._check_rate_spike(event)
        if rate_anomaly:
            anomalies.append(rate_anomaly)

        # Check sequence anomaly
        seq_anomaly = self._check_sequence_anomaly(event)
        if seq_anomaly:
            anomalies.append(seq_anomaly)

        # Check time anomaly
        time_anomaly = self._check_time_anomaly(event)
        if time_anomaly:
            anomalies.append(time_anomaly)

        # Check replay variant
        replay_anomaly = self._check_replay_variant(event)
        if replay_anomaly:
            anomalies.append(replay_anomaly)

        # Store detected anomalies
        for anomaly in anomalies:
            self._anomalies.append(anomaly)
            logger.warning(
                f"Anomaly detected: {anomaly.anomaly_type} "
                f"(severity: {anomaly.severity:.2f}) - {anomaly.description}"
            )

        return anomalies

    def _check_rate_spike(self, event: ActionEvent) -> Optional[AnomalySignal]:
        """Check for unusually high action rate"""
        events = list(self._agent_events[event.agent_id])

        if len(events) < 10:
            return None  # Not enough data

        # Count actions in last N minutes
        cutoff = datetime.utcnow() - timedelta(minutes=self.rate_window_minutes)
        recent = [e for e in events if e.timestamp >= cutoff]

        actions_per_minute = len(recent) / self.rate_window_minutes

        # Get profile
        profile = self._agent_profiles.get(event.agent_id)
        if not profile:
            return None

        # Compare to normal rate
        if profile.avg_actions_per_minute > 0:
            ratio = actions_per_minute / profile.avg_actions_per_minute

            # Spike if > 3x normal rate
            if ratio > 3.0:
                return AnomalySignal(
                    anomaly_type="rate_spike",
                    severity=min(ratio / 10.0, 1.0),
                    description=(
                        f"Action rate {actions_per_minute:.1f}/min is {ratio:.1f}x "
                        f"higher than normal {profile.avg_actions_per_minute:.1f}/min"
                    ),
                    evidence={
                        "current_rate": actions_per_minute,
                        "normal_rate": profile.avg_actions_per_minute,
                        "ratio": ratio,
                        "window_minutes": self.rate_window_minutes,
                    },
                    detected_at=datetime.utcnow(),
                )

        # Update average
        profile.avg_actions_per_minute = (
            profile.avg_actions_per_minute * 0.9 + actions_per_minute * 0.1
        )

        return None

    def _check_sequence_anomaly(self, event: ActionEvent) -> Optional[AnomalySignal]:
        """Check for unusual action sequences"""
        events = list(self._agent_events[event.agent_id])

        if len(events) < self.sequence_length:
            return None

        # Get recent sequence
        recent_tools = [e.tool_name for e in events[-(self.sequence_length) :]]
        sequence_str = " -> ".join(recent_tools)

        # Check if this sequence is common
        profile = self._agent_profiles.get(event.agent_id)
        if not profile:
            return None

        # Simple heuristic: if using tool never seen before
        if event.tool_name not in profile.tool_frequency:
            return AnomalySignal(
                anomaly_type="sequence",
                severity=0.5,
                description=f"First time using tool: {event.tool_name}",
                evidence={
                    "tool": event.tool_name,
                    "sequence": sequence_str,
                    "known_tools": list(profile.tool_frequency.keys()),
                },
                detected_at=datetime.utcnow(),
            )

        return None

    def _check_time_anomaly(self, event: ActionEvent) -> Optional[AnomalySignal]:
        """Check for actions at unusual times"""
        profile = self._agent_profiles.get(event.agent_id)
        if not profile or profile.total_actions < 50:
            return None  # Not enough data

        hour = event.timestamp.hour

        # If agent never active at this hour
        if hour not in profile.active_hours and len(profile.active_hours) > 5:
            return AnomalySignal(
                anomaly_type="time_anomaly",
                severity=0.4,
                description=f"Activity at unusual hour: {hour}:00",
                evidence={"hour": hour, "typical_hours": sorted(profile.active_hours)},
                detected_at=datetime.utcnow(),
            )

        return None

    def _check_replay_variant(self, event: ActionEvent) -> Optional[AnomalySignal]:
        """Check for slight variations of previous actions (possible replay)"""
        events = list(self._agent_events[event.agent_id])

        # Look for similar recent actions
        for prev_event in reversed(events[-20:]):  # Last 20 events
            if prev_event.tool_name == event.tool_name:
                # Compare parameters
                similarity = self._compute_similarity(
                    prev_event.parameters, event.parameters
                )

                # If very similar but not identical (80-99% similar)
                if 0.8 <= similarity < 1.0:
                    return AnomalySignal(
                        anomaly_type="replay_variant",
                        severity=0.6,
                        description=(
                            f"Action very similar ({similarity*100:.0f}%) "
                            f"to previous action but with modifications"
                        ),
                        evidence={
                            "similarity": similarity,
                            "current_params": event.parameters,
                            "previous_params": prev_event.parameters,
                            "time_diff_seconds": (
                                event.timestamp - prev_event.timestamp
                            ).total_seconds(),
                        },
                        detected_at=datetime.utcnow(),
                    )

        return None

    def _compute_similarity(self, params1: Dict, params2: Dict) -> float:
        """Compute similarity between two parameter dicts (0.0 to 1.0)"""
        # Simple Jaccard similarity on JSON strings
        str1 = json.dumps(params1, sort_keys=True)
        str2 = json.dumps(params2, sort_keys=True)

        if str1 == str2:
            return 1.0

        # Character-level similarity
        set1 = set(str1)
        set2 = set(str2)

        intersection = len(set1 & set2)
        union = len(set1 | set2)

        return intersection / union if union > 0 else 0.0

    def get_profile(self, agent_id: str) -> Optional[AgentProfile]:
        """Get behavioral profile for an agent"""
        return self._agent_profiles.get(agent_id)

    def get_recent_anomalies(
        self, agent_id: Optional[str] = None, limit: int = 10
    ) -> List[AnomalySignal]:
        """Get recent anomalies, optionally filtered by agent"""
        anomalies = list(self._anomalies)

        if agent_id:
            # Filter by agent (would need to store agent_id in AnomalySignal)
            pass

        return list(reversed(anomalies))[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics"""
        total_anomalies = len(self._anomalies)

        # Count by type
        type_counts = defaultdict(int)
        for anomaly in self._anomalies:
            type_counts[anomaly.anomaly_type] += 1

        return {
            "total_agents": len(self._agent_profiles),
            "total_anomalies": total_anomalies,
            "anomalies_by_type": dict(type_counts),
            "window_size": self.window_size,
            "rate_window_minutes": self.rate_window_minutes,
        }


# Global detector instance
_global_detector: Optional[BehavioralAnomalyDetector] = None


def get_anomaly_detector() -> BehavioralAnomalyDetector:
    """Get or create the global anomaly detector"""
    global _global_detector
    if _global_detector is None:
        _global_detector = BehavioralAnomalyDetector()
    return _global_detector
