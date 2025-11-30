"""
Remediation modules for security threats.

This package contains remediators that automatically fix security issues:
- Revoke unauthorized access
- Block public S3 buckets
- Send alerts to security teams
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class RemediationResult:
    """Result from a remediation action."""
    success: bool
    message: str
    details: Dict[str, Any]
    action_taken: Optional[str] = None
    error: Optional[str] = None


class BaseRemediator(ABC):
    """Base class for all remediators."""

    def __init__(self):
        """Initialize the remediator."""
        self.name = self.__class__.__name__

    @abstractmethod
    def remediate(self, detection_result) -> RemediationResult:
        """
        Execute remediation action.

        Args:
            detection_result: Detection result from a detector

        Returns:
            RemediationResult indicating success/failure
        """
        pass

    def _create_success_result(
        self,
        message: str,
        details: Dict[str, Any],
        action_taken: str
    ) -> RemediationResult:
        """Create a successful remediation result."""
        return RemediationResult(
            success=True,
            message=message,
            details=details,
            action_taken=action_taken
        )

    def _create_error_result(
        self,
        message: str,
        error: str,
        details: Dict[str, Any] = None
    ) -> RemediationResult:
        """Create a failed remediation result."""
        return RemediationResult(
            success=False,
            message=message,
            details=details or {},
            error=error
        )


# Import remediators for easy access
from .revoke_access import RevokeAccessRemediator
from .block_public import BlockPublicRemediator
from .alert_team import AlertTeamRemediator

__all__ = [
    'BaseRemediator',
    'RemediationResult',
    'RevokeAccessRemediator',
    'BlockPublicRemediator',
    'AlertTeamRemediator'
]
