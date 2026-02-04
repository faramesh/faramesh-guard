"""
Sequence Model - Workflow-aware anomaly detection.

This module implements a sequence-based anomaly detector that learns
normal workflow patterns and flags deviations.
"""

import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum

logger = logging.getLogger("service.sequence_model")


class WorkflowStage(Enum):
    """Common workflow stages for AI agents."""

    INIT = "init"
    RESEARCH = "research"
    PLAN = "plan"
    IMPLEMENT = "implement"
    TEST = "test"
    DEPLOY = "deploy"
    CLEANUP = "cleanup"
    UNKNOWN = "unknown"


@dataclass
class ActionSequence:
    """Represents a sequence of actions."""

    actions: List[str] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    max_length: int = 50

    def add(self, action: str) -> None:
        """Add action to sequence."""
        self.actions.append(action)
        self.timestamps.append(time.time())

        # Trim if too long
        if len(self.actions) > self.max_length:
            self.actions = self.actions[-self.max_length :]
            self.timestamps = self.timestamps[-self.max_length :]

    def get_ngrams(self, n: int = 3) -> List[Tuple[str, ...]]:
        """Get n-grams from sequence."""
        if len(self.actions) < n:
            return []
        return [
            tuple(self.actions[i : i + n]) for i in range(len(self.actions) - n + 1)
        ]

    def get_last_n(self, n: int = 5) -> List[str]:
        """Get last n actions."""
        return self.actions[-n:] if len(self.actions) >= n else self.actions.copy()


@dataclass
class WorkflowProfile:
    """Learned workflow profile for an agent."""

    agent_id: str
    ngram_counts: Dict[Tuple[str, ...], int] = field(
        default_factory=lambda: defaultdict(int)
    )
    transition_counts: Dict[Tuple[str, str], int] = field(
        default_factory=lambda: defaultdict(int)
    )
    tool_stage_mapping: Dict[str, Set[WorkflowStage]] = field(
        default_factory=lambda: defaultdict(set)
    )
    total_actions: int = 0
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)

    def update(self, sequence: ActionSequence) -> None:
        """Update profile with new sequence data."""
        # Update n-grams
        for ngram in sequence.get_ngrams(3):
            self.ngram_counts[ngram] += 1

        # Update transitions
        for i in range(len(sequence.actions) - 1):
            transition = (sequence.actions[i], sequence.actions[i + 1])
            self.transition_counts[transition] += 1

        self.total_actions += len(sequence.actions)
        self.last_updated = time.time()

    def get_transition_probability(self, from_action: str, to_action: str) -> float:
        """Get probability of transition from one action to another."""
        total_from = sum(
            count
            for (f, t), count in self.transition_counts.items()
            if f == from_action
        )
        if total_from == 0:
            return 0.0

        return self.transition_counts.get((from_action, to_action), 0) / total_from

    def get_ngram_probability(self, ngram: Tuple[str, ...]) -> float:
        """Get probability of an n-gram occurring."""
        total = sum(self.ngram_counts.values())
        if total == 0:
            return 0.0
        return self.ngram_counts.get(ngram, 0) / total


@dataclass
class SequenceAnomaly:
    """Represents a detected sequence anomaly."""

    anomaly_type: str
    severity: float  # 0.0 - 1.0
    message: str
    expected: Optional[str] = None
    actual: Optional[str] = None
    context: Dict = field(default_factory=dict)


class SequenceModel:
    """
    Workflow-aware sequence anomaly detector.

    Learns normal action sequences and detects:
    - Unexpected action transitions
    - Out-of-order workflow stages
    - Unusual action combinations
    - Missing expected actions
    """

    def __init__(
        self,
        min_training_actions: int = 20,
        anomaly_threshold: float = 0.1,
        max_profiles: int = 1000,
    ):
        self.min_training_actions = min_training_actions
        self.anomaly_threshold = anomaly_threshold
        self.max_profiles = max_profiles

        # Per-agent profiles
        self.profiles: Dict[str, WorkflowProfile] = {}

        # Current sequences (in-progress)
        self.sequences: Dict[str, ActionSequence] = {}

        # Global learned patterns
        self.global_ngrams: Dict[Tuple[str, ...], int] = defaultdict(int)
        self.global_transitions: Dict[Tuple[str, str], int] = defaultdict(int)

        # Workflow stage detection
        self.tool_to_stage = self._build_tool_stage_mapping()

        # Known dangerous sequences
        self.dangerous_patterns = self._build_dangerous_patterns()

    def _build_tool_stage_mapping(self) -> Dict[str, WorkflowStage]:
        """Build mapping from tools to workflow stages."""
        return {
            # Research stage
            "search": WorkflowStage.RESEARCH,
            "web_search": WorkflowStage.RESEARCH,
            "read_file": WorkflowStage.RESEARCH,
            "list_dir": WorkflowStage.RESEARCH,
            "grep": WorkflowStage.RESEARCH,
            "find": WorkflowStage.RESEARCH,
            # Plan stage
            "think": WorkflowStage.PLAN,
            "plan": WorkflowStage.PLAN,
            "outline": WorkflowStage.PLAN,
            # Implement stage
            "write_file": WorkflowStage.IMPLEMENT,
            "edit_file": WorkflowStage.IMPLEMENT,
            "create_file": WorkflowStage.IMPLEMENT,
            "bash:git": WorkflowStage.IMPLEMENT,
            # Test stage
            "bash:test": WorkflowStage.TEST,
            "bash:pytest": WorkflowStage.TEST,
            "bash:npm test": WorkflowStage.TEST,
            "run_tests": WorkflowStage.TEST,
            # Deploy stage
            "bash:deploy": WorkflowStage.DEPLOY,
            "bash:docker": WorkflowStage.DEPLOY,
            "bash:kubectl": WorkflowStage.DEPLOY,
            "http:deploy": WorkflowStage.DEPLOY,
            # Cleanup stage
            "bash:rm": WorkflowStage.CLEANUP,
            "delete_file": WorkflowStage.CLEANUP,
            "bash:git clean": WorkflowStage.CLEANUP,
        }

    def _build_dangerous_patterns(self) -> List[Tuple[Tuple[str, ...], str]]:
        """Build list of dangerous action patterns."""
        return [
            # Data exfiltration patterns
            (
                ("read_file", "http:external"),
                "Potential data exfiltration: reading file then sending externally",
            ),
            (("bash:cat", "bash:curl"), "Potential data exfiltration via curl"),
            # Privilege escalation patterns
            (
                ("bash:chmod", "bash:sudo"),
                "Privilege escalation attempt: chmod followed by sudo",
            ),
            # Cleanup after malicious action
            (
                ("bash:rm -rf", "bash:history"),
                "Evidence destruction: delete then clear history",
            ),
            # Rapid destructive sequence
            (("bash:rm", "bash:rm", "bash:rm"), "Rapid deletion sequence"),
        ]

    def record_action(
        self,
        agent_id: str,
        tool_name: str,
        operation: str = "",
    ) -> Optional[SequenceAnomaly]:
        """
        Record an action and check for sequence anomalies.

        Returns anomaly if detected, None otherwise.
        """
        # Build action identifier
        action = f"{tool_name}:{operation}" if operation else tool_name

        # Get or create sequence
        if agent_id not in self.sequences:
            self.sequences[agent_id] = ActionSequence()

        sequence = self.sequences[agent_id]

        # Check for anomalies before adding
        anomaly = self._check_anomalies(agent_id, action, sequence)

        # Add to sequence
        sequence.add(action)

        # Update global patterns
        self._update_global_patterns(sequence)

        # Update agent profile
        self._update_profile(agent_id, sequence)

        return anomaly

    def _check_anomalies(
        self,
        agent_id: str,
        new_action: str,
        sequence: ActionSequence,
    ) -> Optional[SequenceAnomaly]:
        """Check for sequence anomalies."""

        # Check dangerous patterns
        danger = self._check_dangerous_patterns(sequence, new_action)
        if danger:
            return danger

        # Check workflow order
        workflow_anomaly = self._check_workflow_order(sequence, new_action)
        if workflow_anomaly:
            return workflow_anomaly

        # Check transition probability (if we have enough data)
        profile = self.profiles.get(agent_id)
        if profile and profile.total_actions >= self.min_training_actions:
            transition_anomaly = self._check_transition_anomaly(
                profile, sequence, new_action
            )
            if transition_anomaly:
                return transition_anomaly

        return None

    def _check_dangerous_patterns(
        self,
        sequence: ActionSequence,
        new_action: str,
    ) -> Optional[SequenceAnomaly]:
        """Check for dangerous action patterns."""
        # Build potential new sequence
        recent = sequence.get_last_n(5) + [new_action]

        for pattern, message in self.dangerous_patterns:
            pattern_len = len(pattern)
            if len(recent) >= pattern_len:
                # Check if pattern matches end of sequence
                for i in range(len(recent) - pattern_len + 1):
                    window = recent[i : i + pattern_len]
                    if self._pattern_matches(window, pattern):
                        return SequenceAnomaly(
                            anomaly_type="dangerous_pattern",
                            severity=0.9,
                            message=message,
                            actual=str(window),
                            context={"pattern": pattern},
                        )

        return None

    def _pattern_matches(
        self,
        window: List[str],
        pattern: Tuple[str, ...],
    ) -> bool:
        """Check if window matches pattern (with wildcards)."""
        if len(window) != len(pattern):
            return False

        for w, p in zip(window, pattern):
            # Exact match
            if w == p:
                continue
            # Prefix match (e.g., "bash:rm" matches "bash:rm -rf")
            if w.startswith(p):
                continue
            # Wildcard in pattern
            if "*" in p and w.startswith(p.replace("*", "")):
                continue
            return False

        return True

    def _check_workflow_order(
        self,
        sequence: ActionSequence,
        new_action: str,
    ) -> Optional[SequenceAnomaly]:
        """Check for out-of-order workflow stages."""
        # Get current and new stages
        current_stages = [self._get_workflow_stage(a) for a in sequence.get_last_n(3)]
        new_stage = self._get_workflow_stage(new_action)

        # Skip if unknown
        if new_stage == WorkflowStage.UNKNOWN:
            return None
        if all(s == WorkflowStage.UNKNOWN for s in current_stages):
            return None

        # Check for regression (going back to earlier stage after later stage)
        stage_order = [
            WorkflowStage.INIT,
            WorkflowStage.RESEARCH,
            WorkflowStage.PLAN,
            WorkflowStage.IMPLEMENT,
            WorkflowStage.TEST,
            WorkflowStage.DEPLOY,
            WorkflowStage.CLEANUP,
        ]

        # Find highest stage reached
        highest_idx = -1
        for stage in current_stages:
            if stage != WorkflowStage.UNKNOWN:
                try:
                    idx = stage_order.index(stage)
                    highest_idx = max(highest_idx, idx)
                except ValueError:
                    pass

        # Check if new stage is a significant regression
        new_idx = stage_order.index(new_stage) if new_stage in stage_order else -1

        if highest_idx >= 0 and new_idx >= 0:
            # Allow going back 1 stage (normal iteration)
            # Flag if going back more than 2 stages
            regression = highest_idx - new_idx
            if regression > 2:
                return SequenceAnomaly(
                    anomaly_type="workflow_regression",
                    severity=0.5,
                    message=f"Unusual workflow regression: {stage_order[highest_idx].value} → {new_stage.value}",
                    expected=stage_order[highest_idx].value,
                    actual=new_stage.value,
                    context={"regression_steps": regression},
                )

        return None

    def _get_workflow_stage(self, action: str) -> WorkflowStage:
        """Get workflow stage for an action."""
        # Check exact match
        if action in self.tool_to_stage:
            return self.tool_to_stage[action]

        # Check prefix match
        for tool, stage in self.tool_to_stage.items():
            if action.startswith(tool):
                return stage

        return WorkflowStage.UNKNOWN

    def _check_transition_anomaly(
        self,
        profile: WorkflowProfile,
        sequence: ActionSequence,
        new_action: str,
    ) -> Optional[SequenceAnomaly]:
        """Check if transition probability is anomalously low."""
        if not sequence.actions:
            return None

        last_action = sequence.actions[-1]
        prob = profile.get_transition_probability(last_action, new_action)

        # Also check global probability
        global_prob = self._get_global_transition_probability(last_action, new_action)

        # Use max of local and global (to avoid false positives)
        combined_prob = max(prob, global_prob)

        if combined_prob < self.anomaly_threshold:
            # Check if this transition has EVER been seen
            if combined_prob == 0:
                return SequenceAnomaly(
                    anomaly_type="unseen_transition",
                    severity=0.6,
                    message=f"Never-seen action sequence: {last_action} → {new_action}",
                    expected=self._get_expected_actions(profile, last_action),
                    actual=new_action,
                    context={
                        "transition_prob": combined_prob,
                        "last_action": last_action,
                    },
                )
            else:
                return SequenceAnomaly(
                    anomaly_type="rare_transition",
                    severity=0.4,
                    message=f"Rare action sequence: {last_action} → {new_action} (prob={combined_prob:.2%})",
                    expected=self._get_expected_actions(profile, last_action),
                    actual=new_action,
                    context={
                        "transition_prob": combined_prob,
                        "last_action": last_action,
                    },
                )

        return None

    def _get_expected_actions(
        self,
        profile: WorkflowProfile,
        from_action: str,
    ) -> str:
        """Get expected actions after a given action."""
        # Get all transitions from this action
        transitions = [
            (to, count)
            for (f, to), count in profile.transition_counts.items()
            if f == from_action
        ]

        if not transitions:
            return "unknown"

        # Sort by frequency
        transitions.sort(key=lambda x: x[1], reverse=True)

        # Return top 3
        top = [t[0] for t in transitions[:3]]
        return ", ".join(top)

    def _update_global_patterns(self, sequence: ActionSequence) -> None:
        """Update global pattern statistics."""
        # Update n-grams
        for ngram in sequence.get_ngrams(3):
            self.global_ngrams[ngram] += 1

        # Update transitions
        if len(sequence.actions) >= 2:
            transition = (sequence.actions[-2], sequence.actions[-1])
            self.global_transitions[transition] += 1

    def _get_global_transition_probability(
        self,
        from_action: str,
        to_action: str,
    ) -> float:
        """Get global transition probability."""
        total_from = sum(
            count
            for (f, t), count in self.global_transitions.items()
            if f == from_action
        )
        if total_from == 0:
            return 0.0

        return self.global_transitions.get((from_action, to_action), 0) / total_from

    def _update_profile(self, agent_id: str, sequence: ActionSequence) -> None:
        """Update or create agent profile."""
        if agent_id not in self.profiles:
            # Limit number of profiles
            if len(self.profiles) >= self.max_profiles:
                # Remove oldest profile
                oldest = min(self.profiles.items(), key=lambda x: x[1].last_updated)
                del self.profiles[oldest[0]]

            self.profiles[agent_id] = WorkflowProfile(agent_id=agent_id)

        self.profiles[agent_id].update(sequence)

    def get_profile_stats(self, agent_id: str) -> Dict:
        """Get statistics for an agent profile."""
        profile = self.profiles.get(agent_id)
        if not profile:
            return {"exists": False}

        return {
            "exists": True,
            "total_actions": profile.total_actions,
            "unique_transitions": len(profile.transition_counts),
            "unique_ngrams": len(profile.ngram_counts),
            "created_at": profile.created_at,
            "last_updated": profile.last_updated,
            "is_trained": profile.total_actions >= self.min_training_actions,
        }

    def get_global_stats(self) -> Dict:
        """Get global model statistics."""
        return {
            "total_profiles": len(self.profiles),
            "total_transitions": len(self.global_transitions),
            "total_ngrams": len(self.global_ngrams),
            "min_training_actions": self.min_training_actions,
            "anomaly_threshold": self.anomaly_threshold,
        }

    def clear_sequence(self, agent_id: str) -> None:
        """Clear sequence for an agent (e.g., on session end)."""
        if agent_id in self.sequences:
            del self.sequences[agent_id]


# Singleton instance
_sequence_model: Optional[SequenceModel] = None


def get_sequence_model() -> SequenceModel:
    """Get or create singleton sequence model."""
    global _sequence_model
    if _sequence_model is None:
        _sequence_model = SequenceModel()
    return _sequence_model
