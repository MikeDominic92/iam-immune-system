"""
Tests for IAM remediators.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'functions', 'iam_monitor'))

from remediators import (
    RevokeAccessRemediator,
    BlockPublicRemediator,
    AlertTeamRemediator,
    RemediationResult
)
from detectors import DetectionResult, Severity


class TestRevokeAccessRemediator:
    """Tests for RevokeAccessRemediator."""

    @pytest.fixture
    def remediator(self):
        """Create remediator instance."""
        return RevokeAccessRemediator()

    @pytest.fixture
    def detection_result(self):
        """Create sample detection result."""
        return DetectionResult(
            is_threat=True,
            risk_score=85.0,
            severity=Severity.CRITICAL,
            details={
                'event_name': 'AttachUserPolicy',
                'request_parameters': {
                    'userName': 'test-user',
                    'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
                }
            },
            recommended_actions=['revoke_access'],
            auto_remediate=True,
            detector_name='AdminGrantDetector'
        )

    def test_dry_run_mode(self, remediator, detection_result, monkeypatch):
        """Test dry run mode doesn't execute actions."""
        monkeypatch.setenv('REMEDIATION_DRY_RUN', 'true')
        remediator = RevokeAccessRemediator()

        result = remediator.remediate(detection_result)

        assert result.success is True
        assert result.details['dry_run'] is True

    @patch('boto3.client')
    def test_revoke_user_policy(self, mock_boto, remediator, detection_result):
        """Test revoking user policy attachment."""
        mock_iam = Mock()
        mock_boto.return_value = mock_iam

        result = remediator.remediate(detection_result)

        assert result.success is True
        mock_iam.detach_user_policy.assert_called_once()

    @patch('boto3.client')
    def test_revoke_role_policy(self, mock_boto, remediator):
        """Test revoking role policy attachment."""
        mock_iam = Mock()
        mock_boto.return_value = mock_iam

        detection_result = DetectionResult(
            is_threat=True,
            risk_score=85.0,
            severity=Severity.CRITICAL,
            details={
                'event_name': 'AttachRolePolicy',
                'request_parameters': {
                    'roleName': 'test-role',
                    'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
                }
            },
            recommended_actions=['revoke_access'],
            detector_name='AdminGrantDetector'
        )

        result = remediator.remediate(detection_result)

        assert result.success is True
        mock_iam.detach_role_policy.assert_called_once()


class TestBlockPublicRemediator:
    """Tests for BlockPublicRemediator."""

    @pytest.fixture
    def remediator(self):
        """Create remediator instance."""
        return BlockPublicRemediator()

    @pytest.fixture
    def detection_result(self):
        """Create sample detection result."""
        return DetectionResult(
            is_threat=True,
            risk_score=90.0,
            severity=Severity.CRITICAL,
            details={
                'bucket_name': 'test-public-bucket',
                'event_name': 'PutBucketPolicy'
            },
            recommended_actions=['block_public'],
            auto_remediate=True,
            detector_name='PublicBucketDetector'
        )

    def test_missing_bucket_name(self, remediator):
        """Test error handling when bucket name is missing."""
        detection_result = DetectionResult(
            is_threat=True,
            risk_score=90.0,
            severity=Severity.CRITICAL,
            details={},
            recommended_actions=['block_public'],
            detector_name='PublicBucketDetector'
        )

        result = remediator.remediate(detection_result)

        assert result.success is False
        assert 'bucket_name' in result.error

    @patch('boto3.client')
    def test_block_public_access(self, mock_boto, remediator, detection_result):
        """Test blocking public access on bucket."""
        mock_s3 = Mock()
        mock_boto.return_value = mock_s3
        mock_s3.get_bucket_policy.side_effect = Exception("NoSuchBucketPolicy")

        result = remediator.remediate(detection_result)

        assert result.success is True
        mock_s3.put_public_access_block.assert_called_once()
        mock_s3.put_bucket_acl.assert_called_with(
            Bucket='test-public-bucket',
            ACL='private'
        )

    @patch('boto3.client')
    def test_remove_public_policy(self, mock_boto, remediator, detection_result):
        """Test removal of public bucket policy."""
        mock_s3 = Mock()
        mock_boto.return_value = mock_s3
        mock_s3.get_bucket_policy.return_value = {
            'Policy': '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}'
        }

        result = remediator.remediate(detection_result)

        assert result.success is True
        mock_s3.delete_bucket_policy.assert_called_once_with(
            Bucket='test-public-bucket'
        )


class TestAlertTeamRemediator:
    """Tests for AlertTeamRemediator."""

    @pytest.fixture
    def remediator(self):
        """Create remediator instance."""
        return AlertTeamRemediator()

    @pytest.fixture
    def detection_result(self):
        """Create sample detection result."""
        return DetectionResult(
            is_threat=True,
            risk_score=85.0,
            severity=Severity.HIGH,
            details={
                'event_name': 'AttachUserPolicy',
                'principal': 'arn:aws:iam::123456789012:user/attacker',
                'risk_factors': {
                    'admin_policy_attached': 95.0
                }
            },
            recommended_actions=['alert_team'],
            detector_name='AdminGrantDetector'
        )

    def test_no_channels_configured(self, remediator, detection_result):
        """Test error when no alert channels are configured."""
        result = remediator.remediate(detection_result)

        assert result.success is False
        assert 'No alert channels configured' in result.error

    @patch('slack_sdk.WebhookClient')
    def test_send_slack_alert(self, mock_slack, remediator, detection_result, monkeypatch):
        """Test sending Slack alert."""
        monkeypatch.setenv('SLACK_WEBHOOK_URL', 'https://hooks.slack.com/test')

        mock_webhook = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_webhook.send.return_value = mock_response
        mock_slack.return_value = mock_webhook

        remediator = AlertTeamRemediator()
        result = remediator.remediate(detection_result)

        assert result.success is True
        assert 'slack' in result.details['channels']
        mock_webhook.send.assert_called_once()

    @patch('requests.post')
    def test_send_teams_alert(self, mock_post, remediator, detection_result, monkeypatch):
        """Test sending Microsoft Teams alert."""
        monkeypatch.setenv('TEAMS_WEBHOOK_URL', 'https://outlook.office.com/webhook/test')

        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        remediator = AlertTeamRemediator()
        result = remediator.remediate(detection_result)

        assert result.success is True
        assert 'teams' in result.details['channels']
        mock_post.assert_called_once()

    def test_alert_data_preparation(self, remediator, detection_result):
        """Test alert data formatting."""
        alert_data = remediator._prepare_alert_data(detection_result)

        assert alert_data['severity'] == 'high'
        assert alert_data['risk_score'] == 85.0
        assert alert_data['detector'] == 'AdminGrantDetector'
        assert 'timestamp' in alert_data
        assert 'color' in alert_data
        assert alert_data['color'] == '#FF6600'  # Orange for high severity


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
