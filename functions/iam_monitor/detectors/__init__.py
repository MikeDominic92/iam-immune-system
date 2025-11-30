"""
Detection modules for IAM security threats.

This package contains detectors for various IAM security threats including:
- Public S3 bucket exposure
- Unauthorized admin grants
- Policy tampering
- Cross-account anomalies
- Machine identity (non-human) monitoring
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from enum import Enum


class Severity(Enum):
    """Severity levels for detected threats."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectionResult:
    """Result from a threat detection."""
    is_threat: bool
    risk_score: float  # 0-100
    severity: Severity
    details: Dict[str, Any]
    recommended_actions: List[str]
    auto_remediate: bool = False
    detector_name: Optional[str] = None


class BaseDetector(ABC):
    """Base class for all threat detectors."""

    def __init__(self):
        """Initialize the detector."""
        self.name = self.__class__.__name__

    @abstractmethod
    def detect(self, event: Dict[str, Any]) -> DetectionResult:
        """
        Analyze an event for security threats.

        Args:
            event: IAM event data from CloudTrail or GCP

        Returns:
            DetectionResult indicating if a threat was detected
        """
        pass

    def _calculate_risk_score(self, factors: Dict[str, float]) -> float:
        """
        Calculate overall risk score from individual factors.

        Args:
            factors: Dictionary of risk factors and their scores (0-100)

        Returns:
            Overall risk score (0-100)
        """
        if not factors:
            return 0.0

        # Weighted average with max score capping
        weights = {k: 1.0 for k in factors}
        total_weight = sum(weights.values())
        weighted_sum = sum(score * weights[k] for k, score in factors.items())

        return min(100.0, weighted_sum / total_weight)

    def _determine_severity(self, risk_score: float) -> Severity:
        """
        Determine severity level from risk score.

        Args:
            risk_score: Risk score (0-100)

        Returns:
            Severity enum value
        """
        if risk_score >= 80:
            return Severity.CRITICAL
        elif risk_score >= 60:
            return Severity.HIGH
        elif risk_score >= 40:
            return Severity.MEDIUM
        else:
            return Severity.LOW


# Import detectors for easy access
from .public_bucket import PublicBucketDetector
from .admin_grant import AdminGrantDetector
from .policy_change import PolicyChangeDetector
from .cross_account import CrossAccountDetector
from .machine_identity import MachineIdentityDetector

__all__ = [
    'BaseDetector',
    'DetectionResult',
    'Severity',
    'PublicBucketDetector',
    'AdminGrantDetector',
    'PolicyChangeDetector',
    'CrossAccountDetector',
    'MachineIdentityDetector'
]
