"""
Policy Change Detector

Detects unauthorized or suspicious IAM policy modifications.
"""

import logging
import json
from typing import Any, Dict, List
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError

from . import BaseDetector, DetectionResult, Severity

logger = logging.getLogger(__name__)


class PolicyChangeDetector(BaseDetector):
    """Detects suspicious IAM policy changes."""

    def __init__(self):
        """Initialize the policy change detector."""
        super().__init__()
        self.iam_client = None
        self._sensitive_policy_actions = {
            'CreatePolicy',
            'CreatePolicyVersion',
            'SetDefaultPolicyVersion',
            'DeletePolicy',
            'DeletePolicyVersion',
            'DetachRolePolicy',
            'DetachUserPolicy',
            'DetachGroupPolicy'
        }
        self._critical_resources = {
            'iam', 'kms', 'cloudtrail', 'guardduty', 'config',
            'securityhub', 'cloudwatch', 'logs'
        }

    def _get_iam_client(self):
        """Lazy initialization of IAM client."""
        if self.iam_client is None:
            self.iam_client = boto3.client('iam')
        return self.iam_client

    def detect(self, event: Dict[str, Any]) -> DetectionResult:
        """
        Detect suspicious policy changes.

        Args:
            event: CloudTrail event data

        Returns:
            DetectionResult with threat analysis
        """
        event_name = event.get('eventName', '')

        # Check if this is a relevant policy event
        if event_name not in self._sensitive_policy_actions:
            return DetectionResult(
                is_threat=False,
                risk_score=0.0,
                severity=Severity.LOW,
                details={'reason': 'Not a policy change event'},
                recommended_actions=[],
                detector_name=self.name
            )

        try:
            # Analyze the policy change
            risk_factors = self._analyze_policy_change(event)

            # Calculate risk score
            risk_score = self._calculate_risk_score(risk_factors)
            severity = self._determine_severity(risk_score)

            is_threat = risk_score >= 45.0

            details = {
                'event_name': event_name,
                'risk_factors': risk_factors,
                'user_identity': event.get('userIdentity', {}),
                'source_ip': event.get('sourceIPAddress', 'unknown'),
                'event_time': event.get('eventTime', 'unknown'),
                'request_parameters': event.get('requestParameters', {}),
                'affected_resources': self._extract_affected_resources(event)
            }

            recommended_actions = []
            if is_threat:
                recommended_actions = ['alert_team']
                if risk_score >= 75:
                    recommended_actions.insert(0, 'revoke_access')

            return DetectionResult(
                is_threat=is_threat,
                risk_score=risk_score,
                severity=severity,
                details=details,
                recommended_actions=recommended_actions,
                auto_remediate=risk_score >= 85,
                detector_name=self.name
            )

        except Exception as e:
            logger.error(f"Error in policy change detection: {e}", exc_info=True)
            return DetectionResult(
                is_threat=False,
                risk_score=0.0,
                severity=Severity.LOW,
                details={'error': str(e)},
                recommended_actions=[],
                detector_name=self.name
            )

    def _analyze_policy_change(self, event: Dict[str, Any]) -> Dict[str, float]:
        """
        Analyze policy change for security risks.

        Args:
            event: CloudTrail event data

        Returns:
            Dictionary of risk factors and their scores
        """
        risk_factors = {}

        event_name = event.get('eventName', '')
        request_params = event.get('requestParameters', {})

        # Check for policy deletion
        if event_name in ['DeletePolicy', 'DeletePolicyVersion']:
            risk_factors['policy_deletion'] = 75.0

            # Extra risk if it's a critical security policy
            policy_arn = request_params.get('policyArn', '')
            if any(critical in policy_arn.lower() for critical in self._critical_resources):
                risk_factors['critical_policy_deleted'] = 90.0

        # Check for policy version manipulation
        if event_name == 'SetDefaultPolicyVersion':
            risk_factors['policy_version_change'] = 65.0

        # Check for policy detachment
        if 'Detach' in event_name:
            risk_factors['policy_detached'] = 60.0

        # Analyze new policy content
        if event_name in ['CreatePolicy', 'CreatePolicyVersion']:
            policy_document = request_params.get('policyDocument')
            if policy_document:
                policy_risk = self._analyze_policy_content(policy_document)
                if policy_risk > 0:
                    risk_factors['dangerous_policy_content'] = policy_risk

        # Check for rapid changes (possible attack)
        if self._detect_rapid_changes(event):
            risk_factors['rapid_policy_changes'] = 50.0

        # Check error code (failed attempts might indicate probing)
        if event.get('errorCode'):
            risk_factors['failed_attempt'] = 25.0

        # Check for policy affecting critical services
        if self._affects_critical_service(event):
            risk_factors['affects_critical_service'] = 55.0

        return risk_factors

    def _analyze_policy_content(self, policy_document: Any) -> float:
        """
        Analyze policy document content for dangerous permissions.

        Args:
            policy_document: IAM policy document

        Returns:
            Risk score (0-100)
        """
        try:
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
                    # Wildcard everything
                    if '*' in actions and '*' in resources:
                        risk_score = max(risk_score, 95.0)

                    # Security service actions
                    security_actions = {
                        'cloudtrail:StopLogging',
                        'cloudtrail:DeleteTrail',
                        'guardduty:DeleteDetector',
                        'config:DeleteConfigRule',
                        'iam:DeleteAccountPasswordPolicy',
                        'kms:ScheduleKeyDeletion',
                        'logs:DeleteLogGroup'
                    }

                    if any(action in security_actions for action in actions):
                        risk_score = max(risk_score, 85.0)

                    # Data exfiltration actions
                    exfil_actions = {
                        's3:GetObject',
                        'rds:CopyDBSnapshot',
                        'ec2:CreateSnapshot',
                        'lambda:GetFunction'
                    }

                    if any(action in exfil_actions for action in actions) and '*' in resources:
                        risk_score = max(risk_score, 70.0)

                elif effect == 'Deny':
                    # Explicit denies on security services are suspicious
                    if any(critical in str(actions).lower() for critical in self._critical_resources):
                        risk_score = max(risk_score, 80.0)

            return risk_score

        except Exception as e:
            logger.error(f"Error analyzing policy content: {e}")
            return 0.0

    def _detect_rapid_changes(self, event: Dict[str, Any]) -> bool:
        """
        Detect if there have been rapid policy changes (potential attack).

        Args:
            event: CloudTrail event data

        Returns:
            True if rapid changes detected
        """
        try:
            # In production, query CloudTrail for recent similar events
            # For now, return False as we don't have access to recent history
            # This would typically query a database or CloudTrail directly
            return False

        except Exception as e:
            logger.error(f"Error detecting rapid changes: {e}")
            return False

    def _affects_critical_service(self, event: Dict[str, Any]) -> bool:
        """
        Check if policy change affects critical security services.

        Args:
            event: CloudTrail event data

        Returns:
            True if affects critical service
        """
        try:
            # Check policy ARN
            request_params = event.get('requestParameters', {})
            policy_arn = request_params.get('policyArn', '')

            if any(critical in policy_arn.lower() for critical in self._critical_resources):
                return True

            # Check policy document content
            policy_document = request_params.get('policyDocument')
            if policy_document:
                if isinstance(policy_document, str):
                    policy_text = policy_document.lower()
                else:
                    policy_text = json.dumps(policy_document).lower()

                return any(critical in policy_text for critical in self._critical_resources)

            return False

        except Exception as e:
            logger.error(f"Error checking critical service: {e}")
            return False

    def _extract_affected_resources(self, event: Dict[str, Any]) -> List[str]:
        """
        Extract list of affected resources from event.

        Args:
            event: CloudTrail event data

        Returns:
            List of affected resource ARNs
        """
        resources = []

        # Get from resources field
        for resource in event.get('resources', []):
            arn = resource.get('ARN')
            if arn:
                resources.append(arn)

        # Get from request parameters
        request_params = event.get('requestParameters', {})
        for key in ['policyArn', 'roleName', 'userName', 'groupName']:
            value = request_params.get(key)
            if value:
                resources.append(value)

        return resources
