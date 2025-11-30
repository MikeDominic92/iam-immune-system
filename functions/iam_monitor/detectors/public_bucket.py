"""
Public S3 Bucket Detector

Detects when S3 buckets are made public or have overly permissive access.
"""

import logging
import json
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from . import BaseDetector, DetectionResult, Severity

logger = logging.getLogger(__name__)


class PublicBucketDetector(BaseDetector):
    """Detects public S3 bucket configurations."""

    def __init__(self):
        """Initialize the public bucket detector."""
        super().__init__()
        self.s3_client = None
        self._dangerous_actions = {
            'PutBucketPolicy',
            'PutBucketAcl',
            'DeleteBucketPublicAccessBlock',
            'PutBucketPublicAccessBlock'
        }

    def _get_s3_client(self):
        """Lazy initialization of S3 client."""
        if self.s3_client is None:
            self.s3_client = boto3.client('s3')
        return self.s3_client

    def detect(self, event: Dict[str, Any]) -> DetectionResult:
        """
        Detect public S3 bucket configurations.

        Args:
            event: CloudTrail event data

        Returns:
            DetectionResult with threat analysis
        """
        event_name = event.get('eventName', '')

        # Check if this is a relevant S3 event
        if event_name not in self._dangerous_actions:
            return DetectionResult(
                is_threat=False,
                risk_score=0.0,
                severity=Severity.LOW,
                details={'reason': 'Not an S3 bucket access event'},
                recommended_actions=[],
                detector_name=self.name
            )

        try:
            # Extract bucket information
            bucket_name = self._extract_bucket_name(event)
            if not bucket_name:
                return DetectionResult(
                    is_threat=False,
                    risk_score=0.0,
                    severity=Severity.LOW,
                    details={'reason': 'Could not extract bucket name'},
                    recommended_actions=[],
                    detector_name=self.name
                )

            # Analyze the bucket configuration
            risk_factors = self._analyze_bucket(bucket_name, event)

            # Calculate risk score
            risk_score = self._calculate_risk_score(risk_factors)
            severity = self._determine_severity(risk_score)

            is_threat = risk_score >= 40.0  # Medium or higher is a threat

            details = {
                'bucket_name': bucket_name,
                'event_name': event_name,
                'risk_factors': risk_factors,
                'user_identity': event.get('userIdentity', {}),
                'source_ip': event.get('sourceIPAddress', 'unknown'),
                'event_time': event.get('eventTime', 'unknown')
            }

            recommended_actions = []
            if is_threat:
                recommended_actions = ['block_public', 'alert_team']
                if risk_score >= 80:
                    recommended_actions.insert(0, 'revoke_access')

            return DetectionResult(
                is_threat=is_threat,
                risk_score=risk_score,
                severity=severity,
                details=details,
                recommended_actions=recommended_actions,
                auto_remediate=risk_score >= 60,
                detector_name=self.name
            )

        except Exception as e:
            logger.error(f"Error in public bucket detection: {e}", exc_info=True)
            return DetectionResult(
                is_threat=False,
                risk_score=0.0,
                severity=Severity.LOW,
                details={'error': str(e)},
                recommended_actions=[],
                detector_name=self.name
            )

    def _extract_bucket_name(self, event: Dict[str, Any]) -> str:
        """Extract bucket name from CloudTrail event."""
        # Try request parameters
        request_params = event.get('requestParameters', {})
        bucket_name = request_params.get('bucketName')

        if not bucket_name:
            # Try resource ARN
            resources = event.get('resources', [])
            for resource in resources:
                arn = resource.get('ARN', '')
                if 'arn:aws:s3:::' in arn:
                    bucket_name = arn.split(':::')[1].split('/')[0]
                    break

        return bucket_name

    def _analyze_bucket(self, bucket_name: str, event: Dict[str, Any]) -> Dict[str, float]:
        """
        Analyze bucket configuration for security risks.

        Args:
            bucket_name: Name of the S3 bucket
            event: CloudTrail event data

        Returns:
            Dictionary of risk factors and their scores
        """
        risk_factors = {}

        event_name = event.get('eventName', '')

        # Check if public access block was removed
        if event_name == 'DeleteBucketPublicAccessBlock':
            risk_factors['public_access_block_removed'] = 90.0

        # Check if public access block was weakened
        if event_name == 'PutBucketPublicAccessBlock':
            try:
                params = event.get('requestParameters', {})
                config = params.get('PublicAccessBlockConfiguration', {})

                if not all([
                    config.get('BlockPublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('RestrictPublicBuckets', False)
                ]):
                    risk_factors['weak_public_access_block'] = 70.0
            except Exception as e:
                logger.error(f"Error analyzing public access block: {e}")

        # Check bucket policy for public access
        if event_name == 'PutBucketPolicy':
            policy_risk = self._analyze_bucket_policy(event)
            if policy_risk > 0:
                risk_factors['dangerous_bucket_policy'] = policy_risk

        # Check ACL for public access
        if event_name == 'PutBucketAcl':
            acl_risk = self._analyze_bucket_acl(event)
            if acl_risk > 0:
                risk_factors['dangerous_bucket_acl'] = acl_risk

        # Additional risk factor: Is this a sensitive bucket?
        if self._is_sensitive_bucket(bucket_name):
            risk_factors['sensitive_bucket'] = 30.0

        return risk_factors

    def _analyze_bucket_policy(self, event: Dict[str, Any]) -> float:
        """
        Analyze bucket policy for public access grants.

        Args:
            event: CloudTrail event data

        Returns:
            Risk score (0-100)
        """
        try:
            policy_text = event.get('requestParameters', {}).get('bucketPolicy')
            if not policy_text:
                return 0.0

            policy = json.loads(policy_text) if isinstance(policy_text, str) else policy_text

            risk_score = 0.0

            for statement in policy.get('Statement', []):
                effect = statement.get('Effect', '')
                principal = statement.get('Principal', {})

                # Check for wildcard principal
                if principal == '*' or principal.get('AWS') == '*':
                    if effect == 'Allow':
                        risk_score = max(risk_score, 95.0)
                    else:
                        risk_score = max(risk_score, 20.0)

                # Check for public read/write actions
                actions = statement.get('Action', [])
                if not isinstance(actions, list):
                    actions = [actions]

                dangerous_actions = {'s3:GetObject', 's3:PutObject', 's3:DeleteObject', 's3:*'}
                if any(action in dangerous_actions for action in actions):
                    risk_score = max(risk_score, 80.0)

            return risk_score

        except Exception as e:
            logger.error(f"Error analyzing bucket policy: {e}")
            return 0.0

    def _analyze_bucket_acl(self, event: Dict[str, Any]) -> float:
        """
        Analyze bucket ACL for public access grants.

        Args:
            event: CloudTrail event data

        Returns:
            Risk score (0-100)
        """
        try:
            acl = event.get('requestParameters', {}).get('AccessControlPolicy', {})

            risk_score = 0.0

            grants = acl.get('AccessControlList', {}).get('Grant', [])
            if not isinstance(grants, list):
                grants = [grants]

            for grant in grants:
                grantee = grant.get('Grantee', {})
                uri = grantee.get('URI', '')

                # Check for public grants
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    permission = grant.get('Permission', '')

                    if permission in ['FULL_CONTROL', 'WRITE']:
                        risk_score = max(risk_score, 95.0)
                    elif permission == 'READ':
                        risk_score = max(risk_score, 70.0)

            return risk_score

        except Exception as e:
            logger.error(f"Error analyzing bucket ACL: {e}")
            return 0.0

    def _is_sensitive_bucket(self, bucket_name: str) -> bool:
        """
        Check if bucket name suggests sensitive data.

        Args:
            bucket_name: S3 bucket name

        Returns:
            True if bucket appears to contain sensitive data
        """
        sensitive_keywords = [
            'pii', 'phi', 'backup', 'logs', 'audit', 'compliance',
            'customer', 'user', 'payment', 'credential', 'secret',
            'private', 'internal', 'prod', 'production'
        ]

        bucket_lower = bucket_name.lower()
        return any(keyword in bucket_lower for keyword in sensitive_keywords)
