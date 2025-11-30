"""
Cross-Account Access Detector

Detects suspicious cross-account role assumptions and access patterns.
"""

import logging
import os
from typing import Any, Dict, List, Set
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

from . import BaseDetector, DetectionResult, Severity

logger = logging.getLogger(__name__)


class CrossAccountDetector(BaseDetector):
    """Detects suspicious cross-account access patterns."""

    def __init__(self):
        """Initialize the cross-account detector."""
        super().__init__()
        self.sts_client = None
        self.iam_client = None
        self._cross_account_actions = {
            'AssumeRole',
            'GetFederationToken',
            'GetSessionToken'
        }
        self._trusted_accounts = self._load_trusted_accounts()

    def _get_sts_client(self):
        """Lazy initialization of STS client."""
        if self.sts_client is None:
            self.sts_client = boto3.client('sts')
        return self.sts_client

    def _get_iam_client(self):
        """Lazy initialization of IAM client."""
        if self.iam_client is None:
            self.iam_client = boto3.client('iam')
        return self.iam_client

    def _load_trusted_accounts(self) -> Set[str]:
        """Load list of trusted AWS account IDs from environment."""
        accounts_str = os.getenv('TRUSTED_ACCOUNTS', '')
        return set(a.strip() for a in accounts_str.split(',') if a.strip())

    def detect(self, event: Dict[str, Any]) -> DetectionResult:
        """
        Detect suspicious cross-account access.

        Args:
            event: CloudTrail event data

        Returns:
            DetectionResult with threat analysis
        """
        event_name = event.get('eventName', '')

        # Check if this is a relevant cross-account event
        if event_name not in self._cross_account_actions:
            return DetectionResult(
                is_threat=False,
                risk_score=0.0,
                severity=Severity.LOW,
                details={'reason': 'Not a cross-account access event'},
                recommended_actions=[],
                detector_name=self.name
            )

        try:
            # Analyze the cross-account access
            risk_factors = self._analyze_cross_account_access(event)

            # Calculate risk score
            risk_score = self._calculate_risk_score(risk_factors)
            severity = self._determine_severity(risk_score)

            is_threat = risk_score >= 40.0

            details = {
                'event_name': event_name,
                'risk_factors': risk_factors,
                'user_identity': event.get('userIdentity', {}),
                'source_ip': event.get('sourceIPAddress', 'unknown'),
                'event_time': event.get('eventTime', 'unknown'),
                'request_parameters': event.get('requestParameters', {}),
                'source_account': self._extract_source_account(event),
                'assumed_role': self._extract_assumed_role(event)
            }

            recommended_actions = []
            if is_threat:
                recommended_actions = ['alert_team']
                if risk_score >= 70:
                    recommended_actions.insert(0, 'revoke_access')

            return DetectionResult(
                is_threat=is_threat,
                risk_score=risk_score,
                severity=severity,
                details=details,
                recommended_actions=recommended_actions,
                auto_remediate=risk_score >= 80,
                detector_name=self.name
            )

        except Exception as e:
            logger.error(f"Error in cross-account detection: {e}", exc_info=True)
            return DetectionResult(
                is_threat=False,
                risk_score=0.0,
                severity=Severity.LOW,
                details={'error': str(e)},
                recommended_actions=[],
                detector_name=self.name
            )

    def _analyze_cross_account_access(self, event: Dict[str, Any]) -> Dict[str, float]:
        """
        Analyze cross-account access for security risks.

        Args:
            event: CloudTrail event data

        Returns:
            Dictionary of risk factors and their scores
        """
        risk_factors = {}

        event_name = event.get('eventName', '')
        request_params = event.get('requestParameters', {})
        response_elements = event.get('responseElements', {})

        # Extract source account
        source_account = self._extract_source_account(event)

        # Check if source account is trusted
        if source_account and source_account not in self._trusted_accounts:
            risk_factors['untrusted_source_account'] = 70.0

        # Check for assume role without ExternalId
        if event_name == 'AssumeRole':
            role_arn = request_params.get('roleArn', '')
            external_id = request_params.get('externalId')

            # Cross-account assume role without ExternalId is risky
            if role_arn and not external_id:
                target_account = self._extract_account_from_arn(role_arn)
                caller_account = event.get('recipientAccountId', '')

                if target_account != caller_account:
                    risk_factors['no_external_id'] = 60.0

            # Check for overly permissive session policy
            policy = request_params.get('policy')
            if policy:
                policy_risk = self._analyze_session_policy(policy)
                if policy_risk > 0:
                    risk_factors['dangerous_session_policy'] = policy_risk

        # Check for unusual session duration
        duration = request_params.get('durationSeconds', 3600)
        if duration > 43200:  # More than 12 hours
            risk_factors['excessive_session_duration'] = 45.0

        # Check for federated access
        if event_name == 'GetFederationToken':
            risk_factors['federated_access'] = 50.0

        # Check for unusual source IP
        source_ip = event.get('sourceIPAddress', '')
        if self._is_suspicious_ip(source_ip):
            risk_factors['suspicious_source_ip'] = 55.0

        # Check for multiple failed attempts before success
        if not event.get('errorCode') and self._has_recent_failures(event):
            risk_factors['retry_after_failures'] = 65.0

        # Check for assume role chaining
        user_identity = event.get('userIdentity', {})
        if user_identity.get('type') == 'AssumedRole':
            risk_factors['role_chaining'] = 40.0

        # Check for off-hours access
        if self._is_off_hours(event.get('eventTime', '')):
            risk_factors['off_hours_access'] = 30.0

        return risk_factors

    def _extract_source_account(self, event: Dict[str, Any]) -> str:
        """Extract source AWS account ID from event."""
        user_identity = event.get('userIdentity', {})

        # Try account ID field
        account_id = user_identity.get('accountId', '')
        if account_id:
            return account_id

        # Try extracting from principal ID
        principal_id = user_identity.get('principalId', '')
        if ':' in principal_id:
            return principal_id.split(':')[0]

        # Try extracting from ARN
        arn = user_identity.get('arn', '')
        return self._extract_account_from_arn(arn)

    def _extract_assumed_role(self, event: Dict[str, Any]) -> str:
        """Extract the assumed role ARN from event."""
        request_params = event.get('requestParameters', {})
        return request_params.get('roleArn', '')

    def _extract_account_from_arn(self, arn: str) -> str:
        """Extract AWS account ID from ARN."""
        try:
            if arn and 'arn:aws:' in arn:
                parts = arn.split(':')
                if len(parts) >= 5:
                    return parts[4]
        except Exception as e:
            logger.error(f"Error extracting account from ARN: {e}")

        return ''

    def _analyze_session_policy(self, policy: Any) -> float:
        """
        Analyze session policy for dangerous permissions.

        Args:
            policy: Session policy document

        Returns:
            Risk score (0-100)
        """
        try:
            import json
            if isinstance(policy, str):
                policy_doc = json.loads(policy)
            else:
                policy_doc = policy

            risk_score = 0.0

            for statement in policy_doc.get('Statement', []):
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])

                if not isinstance(actions, list):
                    actions = [actions]
                if not isinstance(resources, list):
                    resources = [resources]

                # Check for wildcard permissions
                if '*' in actions or '*' in resources:
                    risk_score = max(risk_score, 75.0)

                # Check for sensitive actions
                sensitive_actions = {
                    'iam:*',
                    'sts:AssumeRole',
                    's3:GetObject',
                    'secretsmanager:GetSecretValue'
                }

                if any(action in sensitive_actions for action in actions):
                    risk_score = max(risk_score, 60.0)

            return risk_score

        except Exception as e:
            logger.error(f"Error analyzing session policy: {e}")
            return 0.0

    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is suspicious.

        Args:
            ip_address: Source IP address

        Returns:
            True if IP is suspicious
        """
        # Skip AWS service IPs
        if 'amazonaws.com' in ip_address or 'AWS Internal' in ip_address:
            return False

        # TODO: Implement IP reputation checking
        # Check against threat intelligence feeds
        # Check for Tor exit nodes, known VPNs, etc.

        return False

    def _has_recent_failures(self, event: Dict[str, Any]) -> bool:
        """
        Check if there were recent failed attempts.

        Args:
            event: CloudTrail event data

        Returns:
            True if recent failures detected
        """
        # In production, query CloudTrail for recent failed attempts
        # This is a placeholder
        return False

    def _is_off_hours(self, event_time: str) -> bool:
        """
        Check if access occurred during off-hours.

        Args:
            event_time: Event timestamp

        Returns:
            True if during off-hours
        """
        try:
            dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            hour = dt.hour

            # Define off-hours as 10 PM to 6 AM (UTC)
            return hour >= 22 or hour < 6

        except Exception as e:
            logger.error(f"Error checking off-hours: {e}")
            return False
