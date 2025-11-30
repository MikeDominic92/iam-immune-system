"""
Tests for IAM threat detectors.
"""

import pytest
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'functions', 'iam_monitor'))

from detectors import (
    PublicBucketDetector,
    AdminGrantDetector,
    PolicyChangeDetector,
    CrossAccountDetector,
    Severity
)


class TestPublicBucketDetector:
    """Tests for PublicBucketDetector."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return PublicBucketDetector()

    def test_detect_public_bucket_policy(self, detector):
        """Test detection of public bucket policy."""
        event = {
            'eventName': 'PutBucketPolicy',
            'eventTime': datetime.utcnow().isoformat(),
            'requestParameters': {
                'bucketName': 'my-test-bucket',
                'bucketPolicy': '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]}'
            },
            'userIdentity': {
                'principalId': 'AIDAI123456789',
                'arn': 'arn:aws:iam::123456789012:user/test-user'
            },
            'sourceIPAddress': '1.2.3.4',
            'eventSource': 's3.amazonaws.com'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 40.0
        assert result.severity in [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        assert 'block_public' in result.recommended_actions
        assert 'alert_team' in result.recommended_actions

    def test_detect_public_access_block_removal(self, detector):
        """Test detection of public access block removal."""
        event = {
            'eventName': 'DeleteBucketPublicAccessBlock',
            'eventTime': datetime.utcnow().isoformat(),
            'requestParameters': {
                'bucketName': 'my-sensitive-bucket'
            },
            'userIdentity': {
                'principalId': 'AIDAI123456789'
            },
            'sourceIPAddress': '1.2.3.4',
            'eventSource': 's3.amazonaws.com'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 80.0
        assert result.severity == Severity.CRITICAL
        assert result.auto_remediate is True

    def test_non_s3_event(self, detector):
        """Test that non-S3 events are ignored."""
        event = {
            'eventName': 'ListBuckets',
            'eventTime': datetime.utcnow().isoformat(),
            'eventSource': 's3.amazonaws.com'
        }

        result = detector.detect(event)

        assert result.is_threat is False
        assert result.risk_score == 0.0


class TestAdminGrantDetector:
    """Tests for AdminGrantDetector."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return AdminGrantDetector()

    def test_detect_admin_policy_attachment(self, detector):
        """Test detection of admin policy attachment."""
        event = {
            'eventName': 'AttachUserPolicy',
            'eventTime': datetime.utcnow().isoformat(),
            'requestParameters': {
                'userName': 'test-user',
                'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
            },
            'userIdentity': {
                'principalId': 'AIDAI123456789',
                'arn': 'arn:aws:iam::123456789012:user/attacker'
            },
            'sourceIPAddress': '1.2.3.4'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 50.0
        assert 'alert_team' in result.recommended_actions

    def test_detect_dangerous_inline_policy(self, detector):
        """Test detection of dangerous inline policy."""
        event = {
            'eventName': 'PutUserPolicy',
            'eventTime': datetime.utcnow().isoformat(),
            'requestParameters': {
                'userName': 'test-user',
                'policyName': 'EvilPolicy',
                'policyDocument': '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
            },
            'userIdentity': {
                'principalId': 'AIDAI123456789'
            },
            'sourceIPAddress': '1.2.3.4'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 70.0

    def test_whitelisted_principal(self, detector, monkeypatch):
        """Test that whitelisted principals are not flagged."""
        monkeypatch.setenv('WHITELISTED_PRINCIPALS', 'arn:aws:iam::123456789012:user/admin')

        # Reload detector to pick up new env var
        detector = AdminGrantDetector()

        event = {
            'eventName': 'AttachUserPolicy',
            'eventTime': datetime.utcnow().isoformat(),
            'requestParameters': {
                'userName': 'test-user',
                'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
            },
            'userIdentity': {
                'arn': 'arn:aws:iam::123456789012:user/admin'
            },
            'sourceIPAddress': '1.2.3.4'
        }

        result = detector.detect(event)

        assert result.is_threat is False


class TestPolicyChangeDetector:
    """Tests for PolicyChangeDetector."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return PolicyChangeDetector()

    def test_detect_policy_deletion(self, detector):
        """Test detection of policy deletion."""
        event = {
            'eventName': 'DeletePolicy',
            'eventTime': datetime.utcnow().isoformat(),
            'requestParameters': {
                'policyArn': 'arn:aws:iam::123456789012:policy/ImportantPolicy'
            },
            'userIdentity': {
                'principalId': 'AIDAI123456789'
            },
            'sourceIPAddress': '1.2.3.4'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 45.0

    def test_detect_critical_policy_deletion(self, detector):
        """Test detection of critical security policy deletion."""
        event = {
            'eventName': 'DeletePolicy',
            'eventTime': datetime.utcnow().isoformat(),
            'requestParameters': {
                'policyArn': 'arn:aws:iam::123456789012:policy/CloudTrailPolicy'
            },
            'userIdentity': {
                'principalId': 'AIDAI123456789'
            },
            'sourceIPAddress': '1.2.3.4'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 75.0

    def test_non_policy_event(self, detector):
        """Test that non-policy events are ignored."""
        event = {
            'eventName': 'GetPolicy',
            'eventTime': datetime.utcnow().isoformat()
        }

        result = detector.detect(event)

        assert result.is_threat is False


class TestCrossAccountDetector:
    """Tests for CrossAccountDetector."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return CrossAccountDetector()

    def test_detect_untrusted_cross_account(self, detector):
        """Test detection of untrusted cross-account access."""
        event = {
            'eventName': 'AssumeRole',
            'eventTime': datetime.utcnow().isoformat(),
            'requestParameters': {
                'roleArn': 'arn:aws:iam::999999999999:role/AdminRole',
                'roleSessionName': 'test-session'
            },
            'userIdentity': {
                'accountId': '123456789012',
                'principalId': 'AIDAI123456789'
            },
            'recipientAccountId': '999999999999',
            'sourceIPAddress': '1.2.3.4'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 40.0

    def test_detect_no_external_id(self, detector):
        """Test detection of cross-account assume role without ExternalId."""
        event = {
            'eventName': 'AssumeRole',
            'eventTime': datetime.utcnow().isoformat(),
            'requestParameters': {
                'roleArn': 'arn:aws:iam::999999999999:role/CrossAccountRole',
                'roleSessionName': 'test-session'
            },
            'userIdentity': {
                'accountId': '123456789012'
            },
            'recipientAccountId': '999999999999',
            'sourceIPAddress': '1.2.3.4'
        }

        result = detector.detect(event)

        assert result.is_threat is True
        assert result.risk_score >= 40.0

    def test_same_account_assume_role(self, detector):
        """Test that same-account assume role has lower risk."""
        event = {
            'eventName': 'AssumeRole',
            'eventTime': datetime.utcnow().isoformat(),
            'requestParameters': {
                'roleArn': 'arn:aws:iam::123456789012:role/AppRole',
                'roleSessionName': 'app-session'
            },
            'userIdentity': {
                'accountId': '123456789012'
            },
            'recipientAccountId': '123456789012',
            'sourceIPAddress': '10.0.0.1'
        }

        result = detector.detect(event)

        # Should have lower risk since it's same account
        assert result.risk_score < 70.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
