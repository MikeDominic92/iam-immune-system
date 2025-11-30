"""
Admin Grant Detector

Detects unauthorized IAM admin grants and privilege escalation attempts.
"""

import logging
import os
from typing import Any, Dict, List, Set

import boto3
from botocore.exceptions import ClientError

from . import BaseDetector, DetectionResult, Severity

logger = logging.getLogger(__name__)


class AdminGrantDetector(BaseDetector):
    """Detects unauthorized admin permission grants."""

    def __init__(self):
        """Initialize the admin grant detector."""
        super().__init__()
        self.iam_client = None
        self._admin_actions = {
            'AttachUserPolicy',
            'AttachGroupPolicy',
            'AttachRolePolicy',
            'PutUserPolicy',
            'PutGroupPolicy',
            'PutRolePolicy',
            'CreateAccessKey',
            'UpdateAssumeRolePolicy'
        }
        self._admin_policies = {
            'AdministratorAccess',
            'PowerUserAccess',
            'IAMFullAccess',
            'SecurityAudit'
        }
        self._whitelisted_principals = self._load_whitelist()

    def _get_iam_client(self):
        """Lazy initialization of IAM client."""
        if self.iam_client is None:
            self.iam_client = boto3.client('iam')
        return self.iam_client

    def _load_whitelist(self) -> Set[str]:
        """Load whitelisted principals from environment."""
        whitelist_str = os.getenv('WHITELISTED_PRINCIPALS', '')
        return set(p.strip() for p in whitelist_str.split(',') if p.strip())

    def detect(self, event: Dict[str, Any]) -> DetectionResult:
        """
        Detect unauthorized admin permission grants.

        Args:
            event: CloudTrail event data

        Returns:
            DetectionResult with threat analysis
        """
        event_name = event.get('eventName', '')

        # Check if this is a relevant IAM event
        if event_name not in self._admin_actions:
            return DetectionResult(
                is_threat=False,
                risk_score=0.0,
                severity=Severity.LOW,
                details={'reason': 'Not an admin grant event'},
                recommended_actions=[],
                detector_name=self.name
            )

        try:
            # Extract event details
            user_identity = event.get('userIdentity', {})
            principal = self._extract_principal(user_identity)

            # Check if principal is whitelisted
            if principal in self._whitelisted_principals:
                logger.info(f"Principal {principal} is whitelisted, skipping detection")
                return DetectionResult(
                    is_threat=False,
                    risk_score=0.0,
                    severity=Severity.LOW,
                    details={'reason': f'Principal {principal} is whitelisted'},
                    recommended_actions=[],
                    detector_name=self.name
                )

            # Analyze the permission grant
            risk_factors = self._analyze_permission_grant(event)

            # Calculate risk score
            risk_score = self._calculate_risk_score(risk_factors)
            severity = self._determine_severity(risk_score)

            is_threat = risk_score >= 50.0  # Medium-high or higher is a threat

            details = {
                'event_name': event_name,
                'principal': principal,
                'risk_factors': risk_factors,
                'source_ip': event.get('sourceIPAddress', 'unknown'),
                'event_time': event.get('eventTime', 'unknown'),
                'request_parameters': event.get('requestParameters', {}),
                'user_agent': event.get('userAgent', 'unknown')
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
            logger.error(f"Error in admin grant detection: {e}", exc_info=True)
            return DetectionResult(
                is_threat=False,
                risk_score=0.0,
                severity=Severity.LOW,
                details={'error': str(e)},
                recommended_actions=[],
                detector_name=self.name
            )

    def _extract_principal(self, user_identity: Dict[str, Any]) -> str:
        """Extract principal identifier from user identity."""
        principal_id = user_identity.get('principalId', '')
        arn = user_identity.get('arn', '')
        account_id = user_identity.get('accountId', '')

        # Prefer ARN, fall back to principal ID
        return arn if arn else principal_id if principal_id else account_id

    def _analyze_permission_grant(self, event: Dict[str, Any]) -> Dict[str, float]:
        """
        Analyze permission grant for security risks.

        Args:
            event: CloudTrail event data

        Returns:
            Dictionary of risk factors and their scores
        """
        risk_factors = {}

        event_name = event.get('eventName', '')
        request_params = event.get('requestParameters', {})

        # Check for admin policy attachment
        if 'Policy' in event_name:
            policy_arn = request_params.get('policyArn', '')
            policy_name = policy_arn.split('/')[-1] if policy_arn else ''

            if any(admin in policy_name for admin in self._admin_policies):
                risk_factors['admin_policy_attached'] = 95.0

            # Check inline policy content
            policy_document = request_params.get('policyDocument')
            if policy_document:
                inline_risk = self._analyze_policy_document(policy_document)
                if inline_risk > 0:
                    risk_factors['dangerous_inline_policy'] = inline_risk

        # Check for access key creation (potential credential theft)
        if event_name == 'CreateAccessKey':
            user_name = request_params.get('userName', '')
            creator = self._extract_principal(event.get('userIdentity', {}))

            # Creating access key for another user is suspicious
            if user_name and user_name not in creator:
                risk_factors['cross_user_key_creation'] = 85.0

        # Check for assume role policy modification
        if event_name == 'UpdateAssumeRolePolicy':
            policy_document = request_params.get('policyDocument')
            if policy_document:
                assume_risk = self._analyze_assume_role_policy(policy_document)
                if assume_risk > 0:
                    risk_factors['dangerous_assume_role_policy'] = assume_risk

        # Check for unusual source IP
        source_ip = event.get('sourceIPAddress', '')
        if self._is_unusual_ip(source_ip):
            risk_factors['unusual_source_ip'] = 40.0

        # Check for off-hours activity
        if self._is_off_hours(event.get('eventTime', '')):
            risk_factors['off_hours_activity'] = 30.0

        # Check for error in event (might indicate probing)
        if event.get('errorCode') or event.get('errorMessage'):
            risk_factors['error_in_request'] = 20.0

        return risk_factors

    def _analyze_policy_document(self, policy_document: Any) -> float:
        """
        Analyze IAM policy document for dangerous permissions.

        Args:
            policy_document: IAM policy document (string or dict)

        Returns:
            Risk score (0-100)
        """
        try:
            import json
            if isinstance(policy_document, str):
                policy = json.loads(policy_document)
            else:
                policy = policy_document

            risk_score = 0.0

            for statement in policy.get('Statement', []):
                effect = statement.get('Effect', '')
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])

                if not isinstance(actions, list):
                    actions = [actions]
                if not isinstance(resources, list):
                    resources = [resources]

                if effect == 'Allow':
                    # Check for wildcard actions
                    if '*' in actions or 'iam:*' in actions:
                        risk_score = max(risk_score, 95.0)

                    # Check for dangerous IAM actions
                    dangerous_actions = {
                        'iam:CreatePolicyVersion',
                        'iam:SetDefaultPolicyVersion',
                        'iam:PassRole',
                        'iam:AttachUserPolicy',
                        'iam:AttachRolePolicy',
                        'sts:AssumeRole'
                    }

                    if any(action in dangerous_actions for action in actions):
                        risk_score = max(risk_score, 80.0)

                    # Check for wildcard resources
                    if '*' in resources:
                        risk_score = max(risk_score, 70.0)

            return risk_score

        except Exception as e:
            logger.error(f"Error analyzing policy document: {e}")
            return 0.0

    def _analyze_assume_role_policy(self, policy_document: Any) -> float:
        """
        Analyze assume role policy for dangerous trust relationships.

        Args:
            policy_document: Assume role policy document

        Returns:
            Risk score (0-100)
        """
        try:
            import json
            if isinstance(policy_document, str):
                policy = json.loads(policy_document)
            else:
                policy = policy_document

            risk_score = 0.0

            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})

                # Check for wildcard principals
                if principal == '*' or principal.get('AWS') == '*':
                    risk_score = max(risk_score, 95.0)

                # Check for cross-account access without ExternalId
                if isinstance(principal.get('AWS'), str):
                    account_id = principal['AWS'].split(':')[4] if ':' in principal['AWS'] else ''
                    if account_id and 'ExternalId' not in statement.get('Condition', {}):
                        risk_score = max(risk_score, 60.0)

            return risk_score

        except Exception as e:
            logger.error(f"Error analyzing assume role policy: {e}")
            return 0.0

    def _is_unusual_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is unusual (not from expected ranges).

        Args:
            ip_address: Source IP address

        Returns:
            True if IP is unusual
        """
        # TODO: Implement IP reputation checking
        # For now, check if it's an AWS IP or known cloud provider
        if 'amazonaws.com' in ip_address:
            return False

        # Check for Tor exit nodes, VPNs, etc.
        # This is a placeholder - in production, use IP reputation service
        return False

    def _is_off_hours(self, event_time: str) -> bool:
        """
        Check if event occurred during off-hours.

        Args:
            event_time: Event timestamp

        Returns:
            True if event occurred during off-hours
        """
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            hour = dt.hour

            # Define off-hours as 10 PM to 6 AM (UTC)
            return hour >= 22 or hour < 6

        except Exception as e:
            logger.error(f"Error checking off-hours: {e}")
            return False
