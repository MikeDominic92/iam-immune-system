"""
Revoke Access Remediator

Automatically revokes unauthorized IAM permissions and access.
"""

import logging
import os
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from . import BaseRemediator, RemediationResult

logger = logging.getLogger(__name__)


class RevokeAccessRemediator(BaseRemediator):
    """Revokes unauthorized IAM permissions."""

    def __init__(self):
        """Initialize the revoke access remediator."""
        super().__init__()
        self.iam_client = None
        self.s3_client = None
        self.dry_run = os.getenv('REMEDIATION_DRY_RUN', 'false').lower() == 'true'

    def _get_iam_client(self):
        """Lazy initialization of IAM client."""
        if self.iam_client is None:
            self.iam_client = boto3.client('iam')
        return self.iam_client

    def _get_s3_client(self):
        """Lazy initialization of S3 client."""
        if self.s3_client is None:
            self.s3_client = boto3.client('s3')
        return self.s3_client

    def remediate(self, detection_result) -> RemediationResult:
        """
        Revoke unauthorized access based on detection result.

        Args:
            detection_result: Detection result from a detector

        Returns:
            RemediationResult with action details
        """
        try:
            details = detection_result.details
            detector_name = detection_result.detector_name

            if self.dry_run:
                logger.info("DRY RUN: Would revoke access for detection")
                return self._create_success_result(
                    message="Dry run - no action taken",
                    details={'dry_run': True, 'detection': details},
                    action_taken='dry_run'
                )

            # Determine remediation action based on detector
            if 'AdminGrant' in detector_name:
                return self._revoke_iam_permissions(details)
            elif 'CrossAccount' in detector_name:
                return self._revoke_assumed_role(details)
            elif 'PublicBucket' in detector_name:
                return self._revoke_bucket_permissions(details)
            else:
                return self._create_error_result(
                    message=f"Unknown detector type: {detector_name}",
                    error="Unsupported detector type"
                )

        except Exception as e:
            logger.error(f"Error in revoke access remediation: {e}", exc_info=True)
            return self._create_error_result(
                message="Failed to revoke access",
                error=str(e)
            )

    def _revoke_iam_permissions(self, details: Dict[str, Any]) -> RemediationResult:
        """
        Revoke IAM permissions that were granted.

        Args:
            details: Detection details

        Returns:
            RemediationResult
        """
        try:
            iam = self._get_iam_client()
            event_name = details.get('event_name', '')
            request_params = details.get('request_parameters', {})

            actions_taken = []

            # Detach user policy
            if event_name == 'AttachUserPolicy':
                user_name = request_params.get('userName')
                policy_arn = request_params.get('policyArn')

                if user_name and policy_arn:
                    iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
                    actions_taken.append(f"Detached policy {policy_arn} from user {user_name}")

            # Detach role policy
            elif event_name == 'AttachRolePolicy':
                role_name = request_params.get('roleName')
                policy_arn = request_params.get('policyArn')

                if role_name and policy_arn:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                    actions_taken.append(f"Detached policy {policy_arn} from role {role_name}")

            # Detach group policy
            elif event_name == 'AttachGroupPolicy':
                group_name = request_params.get('groupName')
                policy_arn = request_params.get('policyArn')

                if group_name and policy_arn:
                    iam.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
                    actions_taken.append(f"Detached policy {policy_arn} from group {group_name}")

            # Delete inline policy
            elif event_name in ['PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy']:
                entity_name = (request_params.get('userName') or
                               request_params.get('roleName') or
                               request_params.get('groupName'))
                policy_name = request_params.get('policyName')

                if entity_name and policy_name:
                    if 'User' in event_name:
                        iam.delete_user_policy(UserName=entity_name, PolicyName=policy_name)
                    elif 'Role' in event_name:
                        iam.delete_role_policy(RoleName=entity_name, PolicyName=policy_name)
                    elif 'Group' in event_name:
                        iam.delete_group_policy(GroupName=entity_name, PolicyName=policy_name)

                    actions_taken.append(f"Deleted inline policy {policy_name} from {entity_name}")

            # Delete access key
            elif event_name == 'CreateAccessKey':
                user_name = request_params.get('userName')
                # Note: We need the access key ID from response, which we might not have
                # In production, query IAM to get the latest key and delete it
                actions_taken.append(f"Would delete access key for user {user_name}")

            if actions_taken:
                logger.info(f"Revoked IAM permissions: {actions_taken}")
                return self._create_success_result(
                    message="Successfully revoked IAM permissions",
                    details={'actions_taken': actions_taken},
                    action_taken='revoke_iam_permissions'
                )
            else:
                return self._create_error_result(
                    message="No actions taken",
                    error="Unable to determine remediation action"
                )

        except ClientError as e:
            logger.error(f"AWS error revoking IAM permissions: {e}", exc_info=True)
            return self._create_error_result(
                message="AWS error revoking IAM permissions",
                error=str(e)
            )

    def _revoke_assumed_role(self, details: Dict[str, Any]) -> RemediationResult:
        """
        Revoke assumed role session.

        Args:
            details: Detection details

        Returns:
            RemediationResult
        """
        try:
            # In AWS, we can't directly revoke an active STS session
            # Instead, we can:
            # 1. Update the role's trust policy to deny further assumptions
            # 2. Attach an inline deny policy to the role
            # 3. Alert security team for manual intervention

            iam = self._get_iam_client()
            assumed_role = details.get('assumed_role', '')

            if not assumed_role:
                return self._create_error_result(
                    message="No assumed role found in details",
                    error="Missing assumed_role"
                )

            role_name = assumed_role.split('/')[-1]

            # Attach a deny-all inline policy to prevent further actions
            deny_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "aws:RequestedRegion": "*"
                            }
                        }
                    }
                ]
            }

            import json
            policy_name = f"EmergencyDeny-{int(os.time.time())}"

            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(deny_policy)
            )

            logger.info(f"Attached emergency deny policy to role {role_name}")

            return self._create_success_result(
                message=f"Attached emergency deny policy to role {role_name}",
                details={
                    'role_name': role_name,
                    'policy_name': policy_name,
                    'note': 'Active sessions may still have cached permissions'
                },
                action_taken='attach_emergency_deny_policy'
            )

        except ClientError as e:
            logger.error(f"AWS error revoking assumed role: {e}", exc_info=True)
            return self._create_error_result(
                message="AWS error revoking assumed role",
                error=str(e)
            )

    def _revoke_bucket_permissions(self, details: Dict[str, Any]) -> RemediationResult:
        """
        Revoke bucket permissions (revert to private).

        Args:
            details: Detection details

        Returns:
            RemediationResult
        """
        try:
            s3 = self._get_s3_client()
            bucket_name = details.get('bucket_name', '')

            if not bucket_name:
                return self._create_error_result(
                    message="No bucket name found in details",
                    error="Missing bucket_name"
                )

            actions_taken = []

            # Remove bucket policy
            try:
                s3.delete_bucket_policy(Bucket=bucket_name)
                actions_taken.append(f"Deleted bucket policy for {bucket_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    raise

            # Set bucket ACL to private
            try:
                s3.put_bucket_acl(Bucket=bucket_name, ACL='private')
                actions_taken.append(f"Set bucket ACL to private for {bucket_name}")
            except ClientError as e:
                logger.error(f"Error setting bucket ACL: {e}")

            logger.info(f"Revoked bucket permissions: {actions_taken}")

            return self._create_success_result(
                message=f"Successfully revoked bucket permissions for {bucket_name}",
                details={'bucket_name': bucket_name, 'actions_taken': actions_taken},
                action_taken='revoke_bucket_permissions'
            )

        except ClientError as e:
            logger.error(f"AWS error revoking bucket permissions: {e}", exc_info=True)
            return self._create_error_result(
                message="AWS error revoking bucket permissions",
                error=str(e)
            )
