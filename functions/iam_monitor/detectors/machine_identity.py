"""
Machine Identity Detector

Detects anomalies and security threats related to machine identities (non-human identities)
including service accounts, API keys, bots, CI/CD pipelines, and automated systems.

Machine identities now outnumber human identities 3:1 in modern enterprises, making them
a critical attack vector for credential theft, privilege escalation, and lateral movement.
"""

import logging
import os
from typing import Any, Dict, List, Set, Optional
from datetime import datetime, timedelta
import json

import boto3
from botocore.exceptions import ClientError

from . import BaseDetector, DetectionResult, Severity

logger = logging.getLogger(__name__)


class MachineIdentityDetector(BaseDetector):
    """Detects security threats targeting machine/non-human identities."""

    def __init__(self):
        """Initialize the machine identity detector."""
        super().__init__()
        self.iam_client = None
        self.sts_client = None

        # Machine identity indicators
        self._machine_identity_patterns = {
            'service-account', 'svc-', 'sa-', 'bot-', 'automation-',
            'ci-', 'cd-', 'pipeline-', 'lambda-', 'function-',
            'worker-', 'agent-', 'system-', 'app-', 'integration-'
        }

        # Monitored actions for machine identities
        self._monitored_actions = {
            # Service account actions
            'CreateServiceAccount',
            'DeleteServiceAccount',
            'UpdateServiceAccount',
            'SetIamPolicy',

            # API key actions
            'CreateAccessKey',
            'DeleteAccessKey',
            'UpdateAccessKey',
            'RotateAccessKey',

            # Service account key actions (GCP)
            'CreateServiceAccountKey',
            'DeleteServiceAccountKey',

            # Role assumption
            'AssumeRole',
            'AssumeRoleWithWebIdentity',
            'AssumeRoleWithSAML',
            'GetSessionToken',
            'GetFederationToken',

            # Token and certificate operations
            'CreateOIDCToken',
            'SignJwt',
            'SignBlob',

            # Cross-service impersonation
            'GenerateAccessToken',
            'ImpersonateServiceAccount',
        }

        # High-risk service account actions
        self._high_risk_actions = {
            'iam:CreateAccessKey',
            'iam:CreateServiceAccountKey',
            'iam:PassRole',
            'sts:AssumeRole',
            'iam:UpdateAssumeRolePolicy',
            'iam:AttachRolePolicy',
            'iam:PutRolePolicy',
            'secretsmanager:GetSecretValue',
            'kms:Decrypt',
            'dynamodb:*',
            'rds:*',
        }

        # Known CI/CD IP ranges (placeholder - should be configured per environment)
        self._known_cicd_ips = self._load_known_cicd_ips()

        # Baseline service account activity (would be loaded from database in production)
        self._service_account_baselines = {}

        # Service account key age threshold (days)
        self.key_rotation_threshold = int(os.getenv('KEY_ROTATION_THRESHOLD', '90'))

        # Dormant account activity threshold (days)
        self.dormant_threshold = int(os.getenv('DORMANT_THRESHOLD', '30'))

    def _get_iam_client(self):
        """Lazy initialization of IAM client."""
        if self.iam_client is None:
            self.iam_client = boto3.client('iam')
        return self.iam_client

    def _get_sts_client(self):
        """Lazy initialization of STS client."""
        if self.sts_client is None:
            self.sts_client = boto3.client('sts')
        return self.sts_client

    def _load_known_cicd_ips(self) -> Set[str]:
        """Load known CI/CD IP ranges from environment."""
        cicd_ips_str = os.getenv('CICD_IP_RANGES', '')
        return set(ip.strip() for ip in cicd_ips_str.split(',') if ip.strip())

    def detect(self, event: Dict[str, Any]) -> DetectionResult:
        """
        Detect machine identity security threats.

        Args:
            event: CloudTrail or GCP audit log event data

        Returns:
            DetectionResult with threat analysis
        """
        event_name = event.get('eventName', '')

        # Check if this is a machine identity related event
        if not self._is_machine_identity_event(event):
            return DetectionResult(
                is_threat=False,
                risk_score=0.0,
                severity=Severity.LOW,
                details={'reason': 'Not a machine identity event'},
                recommended_actions=[],
                detector_name=self.name
            )

        try:
            # Extract identity information
            user_identity = event.get('userIdentity', {})
            principal_type = user_identity.get('type', '')
            principal_arn = user_identity.get('arn', '')
            principal_id = user_identity.get('principalId', '')

            # Determine if this is a machine identity
            is_machine = self._is_machine_identity(user_identity)

            # Analyze different types of machine identity threats
            risk_factors = {}

            # 1. Service account key age detection
            if event_name in ['CreateAccessKey', 'CreateServiceAccountKey']:
                key_age_risk = self._check_key_age_violation(event)
                if key_age_risk > 0:
                    risk_factors['old_service_account_key'] = key_age_risk

            # 2. Unused/dormant service account detection
            dormant_risk = self._check_dormant_account(event)
            if dormant_risk > 0:
                risk_factors['dormant_account_activated'] = dormant_risk

            # 3. Service account accessing resources outside normal scope
            scope_risk = self._check_resource_scope_anomaly(event)
            if scope_risk > 0:
                risk_factors['out_of_scope_access'] = scope_risk

            # 4. API key used from unexpected IP/region
            location_risk = self._check_location_anomaly(event)
            if location_risk > 0:
                risk_factors['unexpected_location'] = location_risk

            # 5. Service account privilege escalation
            escalation_risk = self._check_privilege_escalation(event)
            if escalation_risk > 0:
                risk_factors['privilege_escalation'] = escalation_risk

            # 6. Cross-account service account usage
            cross_account_risk = self._check_cross_account_usage(event)
            if cross_account_risk > 0:
                risk_factors['cross_account_usage'] = cross_account_risk

            # 7. Service account impersonation chains
            impersonation_risk = self._check_impersonation_chain(event)
            if impersonation_risk > 0:
                risk_factors['impersonation_chain'] = impersonation_risk

            # 8. High-risk actions by service accounts
            high_risk_action = self._check_high_risk_actions(event)
            if high_risk_action > 0:
                risk_factors['high_risk_action'] = high_risk_action

            # 9. Bot/automation credential anomalies
            bot_risk = self._check_bot_anomalies(event)
            if bot_risk > 0:
                risk_factors['bot_anomaly'] = bot_risk

            # 10. CI/CD pipeline credential misuse
            cicd_risk = self._check_cicd_credential_misuse(event)
            if cicd_risk > 0:
                risk_factors['cicd_credential_misuse'] = cicd_risk

            # Calculate overall risk score
            risk_score = self._calculate_risk_score(risk_factors)
            severity = self._determine_severity(risk_score)

            is_threat = risk_score >= 40.0  # Medium or higher is a threat

            details = {
                'event_name': event_name,
                'principal_type': principal_type,
                'principal_arn': principal_arn,
                'principal_id': principal_id,
                'is_machine_identity': is_machine,
                'risk_factors': risk_factors,
                'source_ip': event.get('sourceIPAddress', 'unknown'),
                'event_time': event.get('eventTime', 'unknown'),
                'request_parameters': event.get('requestParameters', {}),
                'user_agent': event.get('userAgent', 'unknown'),
                'event_source': event.get('eventSource', 'unknown'),
            }

            recommended_actions = self._generate_recommendations(risk_score, risk_factors)

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
            logger.error(f"Error in machine identity detection: {e}", exc_info=True)
            return DetectionResult(
                is_threat=False,
                risk_score=0.0,
                severity=Severity.LOW,
                details={'error': str(e)},
                recommended_actions=[],
                detector_name=self.name
            )

    def _is_machine_identity_event(self, event: Dict[str, Any]) -> bool:
        """Check if event is related to machine identities."""
        event_name = event.get('eventName', '')

        # Check if event is in monitored actions
        if event_name in self._monitored_actions:
            return True

        # Check if identity is a machine identity
        user_identity = event.get('userIdentity', {})
        if self._is_machine_identity(user_identity):
            return True

        return False

    def _is_machine_identity(self, user_identity: Dict[str, Any]) -> bool:
        """Determine if the user identity is a machine/non-human identity."""
        principal_type = user_identity.get('type', '')
        arn = user_identity.get('arn', '').lower()
        session_name = user_identity.get('sessionContext', {}).get('sessionIssuer', {}).get('userName', '').lower()

        # Check principal type
        if principal_type in ['AssumedRole', 'FederatedUser', 'WebIdentityUser', 'SAMLUser']:
            return True

        # Check for service account patterns in ARN
        for pattern in self._machine_identity_patterns:
            if pattern in arn or pattern in session_name:
                return True

        # Check for service roles
        if ':role/' in arn and 'service-role' in arn:
            return True

        # Check for Lambda execution roles
        if 'lambda' in arn or 'function' in arn:
            return True

        return False

    def _check_key_age_violation(self, event: Dict[str, Any]) -> float:
        """Check for service account keys older than rotation threshold."""
        try:
            # In production, this would query actual key metadata
            # For now, we detect key creation and flag if account has old keys
            request_params = event.get('requestParameters', {})
            user_name = request_params.get('userName', '')

            if user_name:
                # Placeholder: In production, check actual key age from IAM
                # For demonstration, flag as risk if creating new key for existing account
                return 0.0  # Would return 75.0 if old keys detected

            return 0.0

        except Exception as e:
            logger.error(f"Error checking key age: {e}")
            return 0.0

    def _check_dormant_account(self, event: Dict[str, Any]) -> float:
        """Check if dormant service account suddenly became active."""
        try:
            user_identity = event.get('userIdentity', {})
            principal_arn = user_identity.get('arn', '')

            # In production, check against activity baseline from database
            # Placeholder: Flag if account hasn't been used in X days
            baseline = self._service_account_baselines.get(principal_arn, {})
            last_activity = baseline.get('last_activity')

            if last_activity:
                days_dormant = (datetime.now() - last_activity).days
                if days_dormant > self.dormant_threshold:
                    return min(85.0, 50.0 + days_dormant)  # Higher risk for longer dormancy

            return 0.0

        except Exception as e:
            logger.error(f"Error checking dormant account: {e}")
            return 0.0

    def _check_resource_scope_anomaly(self, event: Dict[str, Any]) -> float:
        """Check if service account is accessing resources outside normal scope."""
        try:
            request_params = event.get('requestParameters', {})
            resources = event.get('resources', [])
            user_identity = event.get('userIdentity', {})
            principal_arn = user_identity.get('arn', '')

            # In production, check against learned baseline of normal resources
            baseline = self._service_account_baselines.get(principal_arn, {})
            normal_resources = baseline.get('typical_resources', set())

            # Check if accessing new/unusual resources
            current_resources = {r.get('ARN', '') for r in resources}
            unusual_resources = current_resources - normal_resources

            if unusual_resources and len(normal_resources) > 0:
                # Calculate risk based on deviation from baseline
                deviation_ratio = len(unusual_resources) / max(1, len(normal_resources))
                return min(80.0, 40.0 + (deviation_ratio * 40.0))

            return 0.0

        except Exception as e:
            logger.error(f"Error checking resource scope: {e}")
            return 0.0

    def _check_location_anomaly(self, event: Dict[str, Any]) -> float:
        """Check if API key/service account used from unexpected IP or region."""
        try:
            source_ip = event.get('sourceIPAddress', '')
            user_identity = event.get('userIdentity', {})
            principal_arn = user_identity.get('arn', '')

            # Check if IP is from known CI/CD ranges
            is_known_cicd = any(source_ip.startswith(ip) for ip in self._known_cicd_ips)

            # In production, check against baseline of normal IPs/regions
            baseline = self._service_account_baselines.get(principal_arn, {})
            normal_ips = baseline.get('typical_ips', set())
            normal_regions = baseline.get('typical_regions', set())

            # Check for unusual IP
            if source_ip and not is_known_cicd:
                if source_ip not in normal_ips and len(normal_ips) > 0:
                    # New IP detected
                    risk = 60.0

                    # Higher risk if from public cloud provider (potential compromised instance)
                    if any(provider in source_ip for provider in ['amazonaws.com', 'azure', 'googleusercontent']):
                        risk += 20.0

                    return risk

            return 0.0

        except Exception as e:
            logger.error(f"Error checking location anomaly: {e}")
            return 0.0

    def _check_privilege_escalation(self, event: Dict[str, Any]) -> float:
        """Check for service account privilege escalation attempts."""
        try:
            event_name = event.get('eventName', '')
            request_params = event.get('requestParameters', {})

            # Check for privilege escalation actions
            escalation_actions = {
                'AttachRolePolicy',
                'PutRolePolicy',
                'UpdateAssumeRolePolicy',
                'PassRole',
                'CreatePolicyVersion',
                'SetDefaultPolicyVersion',
            }

            if event_name in escalation_actions:
                # Check if service account is modifying its own permissions
                user_identity = event.get('userIdentity', {})
                principal_arn = user_identity.get('arn', '')
                target_role = request_params.get('roleName', '')

                if target_role and target_role in principal_arn:
                    # Service account modifying its own role - high risk
                    return 90.0

                # Check for attachment of admin policies
                policy_arn = request_params.get('policyArn', '')
                if 'Admin' in policy_arn or 'FullAccess' in policy_arn:
                    return 85.0

                # General privilege escalation attempt
                return 70.0

            return 0.0

        except Exception as e:
            logger.error(f"Error checking privilege escalation: {e}")
            return 0.0

    def _check_cross_account_usage(self, event: Dict[str, Any]) -> float:
        """Check for cross-account service account usage."""
        try:
            user_identity = event.get('userIdentity', {})
            user_account = user_identity.get('accountId', '')
            recipient_account = event.get('recipientAccountId', '')

            # If accounts are different, this is cross-account access
            if user_account and recipient_account and user_account != recipient_account:
                # Check if it's a trusted account
                trusted_accounts = os.getenv('TRUSTED_ACCOUNTS', '').split(',')

                if recipient_account not in trusted_accounts:
                    # Untrusted cross-account access
                    return 75.0
                else:
                    # Trusted but still noteworthy
                    return 35.0

            return 0.0

        except Exception as e:
            logger.error(f"Error checking cross-account usage: {e}")
            return 0.0

    def _check_impersonation_chain(self, event: Dict[str, Any]) -> float:
        """Check for service account impersonation chains."""
        try:
            user_identity = event.get('userIdentity', {})
            session_context = user_identity.get('sessionContext', {})

            # Check for chained role assumptions
            if 'sessionIssuer' in session_context:
                # This is an assumed role - check the chain depth
                session_issuer = session_context['sessionIssuer']
                principal_id = user_identity.get('principalId', '')

                # Count colons in principalId to estimate chain depth
                # Format: AROAID:session1:session2:...
                chain_depth = principal_id.count(':')

                if chain_depth >= 3:
                    # Deep impersonation chain - very suspicious
                    return 85.0
                elif chain_depth >= 2:
                    # Moderate impersonation chain
                    return 60.0

            # Check for service account impersonation in GCP
            event_name = event.get('eventName', '')
            if event_name == 'ImpersonateServiceAccount':
                request_params = event.get('requestParameters', {})
                target_account = request_params.get('name', '')

                # Impersonating another service account
                return 70.0

            return 0.0

        except Exception as e:
            logger.error(f"Error checking impersonation chain: {e}")
            return 0.0

    def _check_high_risk_actions(self, event: Dict[str, Any]) -> float:
        """Check if service account is performing high-risk actions."""
        try:
            event_name = event.get('eventName', '')
            event_source = event.get('eventSource', '')

            # Construct action string
            action = f"{event_source.split('.')[0]}:{event_name}"

            # Check against high-risk actions
            for high_risk_action in self._high_risk_actions:
                if high_risk_action in action or action in high_risk_action:
                    # Risk varies by action type
                    if 'secretsmanager' in action.lower() or 'kms:decrypt' in action.lower():
                        return 80.0  # Secret access is very sensitive
                    elif 'passrole' in action.lower():
                        return 75.0  # PassRole can lead to privilege escalation
                    else:
                        return 55.0  # Other high-risk actions

            return 0.0

        except Exception as e:
            logger.error(f"Error checking high-risk actions: {e}")
            return 0.0

    def _check_bot_anomalies(self, event: Dict[str, Any]) -> float:
        """Check for bot/automation credential anomalies."""
        try:
            user_agent = event.get('userAgent', '').lower()
            user_identity = event.get('userIdentity', {})

            # Detect automation/bot indicators
            bot_indicators = ['bot', 'automation', 'script', 'curl', 'python', 'java', 'go-http']
            is_bot = any(indicator in user_agent for indicator in bot_indicators)

            if is_bot:
                # Check for unusual bot behavior
                event_time = event.get('eventTime', '')

                # Bots should have consistent patterns
                # In production, check against learned baseline

                # Check for unusual timing (bots usually run on schedule)
                if self._is_off_hours(event_time):
                    return 45.0  # Moderate risk for off-hours bot activity

            return 0.0

        except Exception as e:
            logger.error(f"Error checking bot anomalies: {e}")
            return 0.0

    def _check_cicd_credential_misuse(self, event: Dict[str, Any]) -> float:
        """Check for CI/CD pipeline credential misuse."""
        try:
            user_identity = event.get('userIdentity', {})
            principal_arn = user_identity.get('arn', '').lower()
            source_ip = event.get('sourceIPAddress', '')

            # Detect CI/CD credentials
            cicd_indicators = ['ci-', 'cd-', 'pipeline-', 'jenkins', 'gitlab', 'github', 'circleci', 'travis']
            is_cicd = any(indicator in principal_arn for indicator in cicd_indicators)

            if is_cicd:
                # Check if source IP is from known CI/CD infrastructure
                is_known_cicd_ip = any(source_ip.startswith(ip) for ip in self._known_cicd_ips)

                if not is_known_cicd_ip and source_ip:
                    # CI/CD credentials used from unexpected location
                    return 85.0  # Very high risk - potential credential theft

                # Check for unusual actions for CI/CD
                event_name = event.get('eventName', '')
                unusual_cicd_actions = {
                    'CreateAccessKey',  # CI/CD shouldn't create new keys
                    'DeleteUser',  # CI/CD shouldn't delete users
                    'AttachUserPolicy',  # CI/CD shouldn't modify user policies
                }

                if event_name in unusual_cicd_actions:
                    return 75.0  # High risk for unusual CI/CD actions

            return 0.0

        except Exception as e:
            logger.error(f"Error checking CI/CD credential misuse: {e}")
            return 0.0

    def _is_off_hours(self, event_time: str) -> bool:
        """Check if event occurred during off-hours."""
        try:
            dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            hour = dt.hour

            # Define off-hours as 10 PM to 6 AM (UTC)
            return hour >= 22 or hour < 6

        except Exception as e:
            logger.error(f"Error checking off-hours: {e}")
            return False

    def _generate_recommendations(self, risk_score: float, risk_factors: Dict[str, float]) -> List[str]:
        """Generate recommended actions based on detected risks."""
        recommendations = []

        if risk_score >= 80:
            recommendations.append('revoke_access')

        if risk_score >= 50:
            recommendations.append('alert_team')

        # Specific recommendations based on risk factors
        if 'old_service_account_key' in risk_factors:
            recommendations.append('rotate_service_account_key')

        if 'dormant_account_activated' in risk_factors:
            recommendations.append('verify_account_reactivation')

        if 'privilege_escalation' in risk_factors:
            recommendations.append('audit_permission_changes')

        if 'cross_account_usage' in risk_factors:
            recommendations.append('verify_cross_account_access')

        if 'impersonation_chain' in risk_factors:
            recommendations.append('investigate_impersonation_chain')

        if 'cicd_credential_misuse' in risk_factors:
            recommendations.append('rotate_cicd_credentials')
            recommendations.append('audit_cicd_infrastructure')

        if 'unexpected_location' in risk_factors:
            recommendations.append('verify_source_ip')
            recommendations.append('enable_ip_whitelisting')

        return recommendations
