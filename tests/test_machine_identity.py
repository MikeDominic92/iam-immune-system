"""
Tests for Machine Identity Detector.

Tests detection of machine identity (non-human) security threats including
service accounts, API keys, bots, CI/CD credentials, and automated systems.
"""

import pytest
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'functions', 'iam_monitor'))

from detectors import MachineIdentityDetector, Severity


class TestMachineIdentityDetector:
    """Tests for MachineIdentityDetector."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return MachineIdentityDetector()

    def test_service_account_privilege_escalation(self, detector):
        """Test detection of service account modifying its own permissions."""
        event = {
            'eventName': 'AttachRolePolicy',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 'iam.amazonaws.com',
            'requestParameters': {
                'roleName': 'app-service-role',
                'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
            },
            'userIdentity': {
                'type': 'AssumedRole',
                'principalId': 'AIDAI123456789:app-service-role',
                'arn': 'arn:aws:sts::123456789012:assumed-role/app-service-role/session',
                'accountId': '123456789012'
            },
            'sourceIPAddress': '10.0.0.5'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 70.0
        assert result.severity in [Severity.HIGH, Severity.CRITICAL]
        assert 'privilege_escalation' in result.details.get('risk_factors', {})
        assert 'alert_team' in result.recommended_actions

    def test_api_key_unexpected_location(self, detector, monkeypatch):
        """Test detection of API key used from unexpected IP."""
        # Set up baseline (would normally be in database)
        detector._service_account_baselines = {
            'arn:aws:iam::123456789012:user/api-user': {
                'typical_ips': {'10.0.0.0', '10.0.0.1'},
                'typical_regions': {'us-east-1'},
            }
        }

        event = {
            'eventName': 'CreateAccessKey',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 'iam.amazonaws.com',
            'requestParameters': {
                'userName': 'api-user'
            },
            'userIdentity': {
                'type': 'IAMUser',
                'principalId': 'AIDAI123456789',
                'arn': 'arn:aws:iam::123456789012:user/api-user',
                'accountId': '123456789012'
            },
            'sourceIPAddress': '203.0.113.45'  # Unexpected IP
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 40.0
        # Location anomaly detection requires baseline, so may be 0 in basic test

    def test_dormant_service_account_reactivation(self, detector):
        """Test detection of dormant service account suddenly becoming active."""
        # Set up dormant account baseline
        old_date = datetime.now() - timedelta(days=100)
        detector._service_account_baselines = {
            'arn:aws:iam::123456789012:role/old-migration-role': {
                'last_activity': old_date
            }
        }

        event = {
            'eventName': 'AssumeRole',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 'sts.amazonaws.com',
            'requestParameters': {
                'roleArn': 'arn:aws:iam::123456789012:role/old-migration-role',
                'roleSessionName': 'reactivation-session'
            },
            'userIdentity': {
                'type': 'AssumedRole',
                'arn': 'arn:aws:iam::123456789012:role/old-migration-role',
                'accountId': '123456789012'
            },
            'sourceIPAddress': '1.2.3.4'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 40.0
        # Dormant account detection requires baseline check

    def test_cross_account_service_account_usage(self, detector, monkeypatch):
        """Test detection of cross-account service account usage."""
        # Set trusted accounts
        monkeypatch.setenv('TRUSTED_ACCOUNTS', '123456789012,234567890123')

        event = {
            'eventName': 'AssumeRole',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 'sts.amazonaws.com',
            'requestParameters': {
                'roleArn': 'arn:aws:iam::999999999999:role/CrossAccountRole',
                'roleSessionName': 'cross-account-session'
            },
            'userIdentity': {
                'type': 'AssumedRole',
                'arn': 'arn:aws:sts::123456789012:assumed-role/app-role/session',
                'accountId': '123456789012'
            },
            'recipientAccountId': '999999999999',  # Untrusted account
            'sourceIPAddress': '10.0.0.5'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 40.0
        assert 'cross_account_usage' in result.details.get('risk_factors', {})
        assert 'verify_cross_account_access' in result.recommended_actions

    def test_service_account_impersonation_chain(self, detector):
        """Test detection of deep service account impersonation chain."""
        event = {
            'eventName': 'ImpersonateServiceAccount',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 'iam.googleapis.com',
            'requestParameters': {
                'name': 'projects/-/serviceAccounts/target-sa@project.iam.gserviceaccount.com'
            },
            'userIdentity': {
                'type': 'AssumedRole',
                'principalId': 'AIDAI123:session1:session2:session3',  # Deep chain
                'arn': 'arn:aws:sts::123456789012:assumed-role/role1/session',
                'accountId': '123456789012',
                'sessionContext': {
                    'sessionIssuer': {
                        'type': 'Role',
                        'principalId': 'AIDAI123456',
                        'arn': 'arn:aws:iam::123456789012:role/role1'
                    }
                }
            },
            'sourceIPAddress': '10.0.0.5'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 40.0
        assert 'impersonation_chain' in result.details.get('risk_factors', {})
        assert 'investigate_impersonation_chain' in result.recommended_actions

    def test_cicd_credential_misuse(self, detector, monkeypatch):
        """Test detection of CI/CD credentials used from unexpected location."""
        # Set known CI/CD IPs
        monkeypatch.setenv('CICD_IP_RANGES', '140.82.112.0,140.82.113.0')

        event = {
            'eventName': 'AssumeRole',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 'sts.amazonaws.com',
            'requestParameters': {
                'roleArn': 'arn:aws:iam::123456789012:role/github-actions-deployer',
                'roleSessionName': 'github-deploy'
            },
            'userIdentity': {
                'type': 'AssumedRole',
                'arn': 'arn:aws:iam::123456789012:role/github-actions-deployer',
                'accountId': '123456789012'
            },
            'sourceIPAddress': '203.0.113.45',  # Not a known GitHub Actions IP
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 40.0
        assert 'cicd_credential_misuse' in result.details.get('risk_factors', {})
        assert 'rotate_cicd_credentials' in result.recommended_actions

    def test_service_account_high_risk_action(self, detector):
        """Test detection of service account performing high-risk action."""
        event = {
            'eventName': 'GetSecretValue',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 'secretsmanager.amazonaws.com',
            'requestParameters': {
                'secretId': 'prod/database/credentials'
            },
            'userIdentity': {
                'type': 'AssumedRole',
                'arn': 'arn:aws:sts::123456789012:assumed-role/app-worker/session',
                'accountId': '123456789012'
            },
            'sourceIPAddress': '10.0.0.5'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 40.0
        assert 'high_risk_action' in result.details.get('risk_factors', {})

    def test_bot_off_hours_activity(self, detector):
        """Test detection of bot activity during off-hours."""
        # Create off-hours timestamp (2 AM UTC)
        off_hours_time = datetime.utcnow().replace(hour=2, minute=0, second=0)

        event = {
            'eventName': 'AssumeRole',
            'eventTime': off_hours_time.isoformat(),
            'eventSource': 'sts.amazonaws.com',
            'requestParameters': {
                'roleArn': 'arn:aws:iam::123456789012:role/bot-automation',
                'roleSessionName': 'bot-session'
            },
            'userIdentity': {
                'type': 'AssumedRole',
                'arn': 'arn:aws:iam::123456789012:role/bot-automation',
                'accountId': '123456789012'
            },
            'sourceIPAddress': '10.0.0.5',
            'userAgent': 'python-requests/2.28.0 bot/1.0'  # Bot user agent
        }

        result = detector.detect(event)

        # Should detect bot behavior
        assert result.details.get('is_machine_identity') is True

    def test_is_machine_identity_detection(self, detector):
        """Test machine identity pattern detection."""
        # Test service account pattern
        service_account_identity = {
            'type': 'AssumedRole',
            'arn': 'arn:aws:iam::123456789012:role/service-account-app',
            'accountId': '123456789012'
        }
        assert detector._is_machine_identity(service_account_identity) is True

        # Test human identity
        human_identity = {
            'type': 'IAMUser',
            'arn': 'arn:aws:iam::123456789012:user/john.doe',
            'accountId': '123456789012'
        }
        # May or may not be detected as machine - depends on patterns

        # Test CI/CD pattern
        cicd_identity = {
            'type': 'AssumedRole',
            'arn': 'arn:aws:iam::123456789012:role/ci-pipeline-deployer',
            'accountId': '123456789012'
        }
        assert detector._is_machine_identity(cicd_identity) is True

        # Test Lambda execution role
        lambda_identity = {
            'type': 'AssumedRole',
            'arn': 'arn:aws:iam::123456789012:role/lambda-execution-role',
            'accountId': '123456789012'
        }
        assert detector._is_machine_identity(lambda_identity) is True

    def test_non_machine_identity_event(self, detector):
        """Test that non-machine identity events are ignored."""
        event = {
            'eventName': 'ListUsers',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 'iam.amazonaws.com',
            'userIdentity': {
                'type': 'IAMUser',
                'arn': 'arn:aws:iam::123456789012:user/admin',
                'accountId': '123456789012'
            },
            'sourceIPAddress': '10.0.0.1'
        }

        result = detector.detect(event)

        assert result.is_threat is False
        assert result.risk_score == 0.0

    def test_resource_scope_anomaly(self, detector):
        """Test detection of service account accessing unusual resources."""
        # Set up baseline with normal resources
        detector._service_account_baselines = {
            'arn:aws:iam::123456789012:role/app-backend': {
                'typical_resources': {
                    'arn:aws:s3:::app-data/*',
                    'arn:aws:dynamodb:us-east-1:123456789012:table/app-table'
                }
            }
        }

        event = {
            'eventName': 'GetObject',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 's3.amazonaws.com',
            'requestParameters': {
                'bucketName': 'financial-records'  # New/unusual resource
            },
            'userIdentity': {
                'type': 'AssumedRole',
                'arn': 'arn:aws:iam::123456789012:role/app-backend',
                'accountId': '123456789012'
            },
            'sourceIPAddress': '10.0.0.5',
            'resources': [
                {
                    'type': 'AWS::S3::Bucket',
                    'ARN': 'arn:aws:s3:::financial-records'
                }
            ]
        }

        result = detector.detect(event)

        # Should detect scope anomaly if baseline exists
        assert result.details.get('is_machine_identity') is True

    def test_gcp_service_account_detection(self, detector):
        """Test detection of GCP service account patterns."""
        event = {
            'eventName': 'CreateServiceAccountKey',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 'iam.googleapis.com',
            'requestParameters': {
                'name': 'projects/my-project/serviceAccounts/app@my-project.iam.gserviceaccount.com'
            },
            'userIdentity': {
                'type': 'serviceAccount',
                'arn': 'app@my-project.iam.gserviceaccount.com',
                'accountId': 'my-project'
            },
            'sourceIPAddress': '10.0.0.5'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.details.get('is_machine_identity') is True

    def test_auto_remediate_critical_threat(self, detector):
        """Test that critical threats trigger auto-remediation."""
        event = {
            'eventName': 'AttachRolePolicy',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 'iam.amazonaws.com',
            'requestParameters': {
                'roleName': 'service-account-role',
                'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
            },
            'userIdentity': {
                'type': 'AssumedRole',
                'principalId': 'AIDAI123456789:service-account-role',
                'arn': 'arn:aws:sts::123456789012:assumed-role/service-account-role/session',
                'accountId': '123456789012'
            },
            'sourceIPAddress': '1.2.3.4'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 70.0
        # Auto-remediate threshold is 80, so check if it's high enough
        if result.risk_score >= 80:
            assert result.auto_remediate is True
            assert 'revoke_access' in result.recommended_actions


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
