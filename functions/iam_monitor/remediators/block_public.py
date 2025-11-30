"""
Block Public Access Remediator

Automatically blocks public access on S3 buckets and other resources.
"""

import logging
import os
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from . import BaseRemediator, RemediationResult

logger = logging.getLogger(__name__)


class BlockPublicRemediator(BaseRemediator):
    """Blocks public access on AWS resources."""

    def __init__(self):
        """Initialize the block public remediator."""
        super().__init__()
        self.s3_client = None
        self.dry_run = os.getenv('REMEDIATION_DRY_RUN', 'false').lower() == 'true'

    def _get_s3_client(self):
        """Lazy initialization of S3 client."""
        if self.s3_client is None:
            self.s3_client = boto3.client('s3')
        return self.s3_client

    def remediate(self, detection_result) -> RemediationResult:
        """
        Block public access based on detection result.

        Args:
            detection_result: Detection result from a detector

        Returns:
            RemediationResult with action details
        """
        try:
            details = detection_result.details
            bucket_name = details.get('bucket_name', '')

            if not bucket_name:
                return self._create_error_result(
                    message="No bucket name found in detection details",
                    error="Missing bucket_name"
                )

            if self.dry_run:
                logger.info(f"DRY RUN: Would block public access for bucket {bucket_name}")
                return self._create_success_result(
                    message="Dry run - no action taken",
                    details={'dry_run': True, 'bucket_name': bucket_name},
                    action_taken='dry_run'
                )

            # Block public access on the bucket
            return self._block_bucket_public_access(bucket_name)

        except Exception as e:
            logger.error(f"Error in block public remediation: {e}", exc_info=True)
            return self._create_error_result(
                message="Failed to block public access",
                error=str(e)
            )

    def _block_bucket_public_access(self, bucket_name: str) -> RemediationResult:
        """
        Enable S3 Block Public Access on a bucket.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            RemediationResult
        """
        try:
            s3 = self._get_s3_client()

            actions_taken = []

            # Enable all Block Public Access settings
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            actions_taken.append("Enabled Block Public Access (all settings)")

            # Remove any public bucket policy
            try:
                # Get current policy
                policy_response = s3.get_bucket_policy(Bucket=bucket_name)
                current_policy = policy_response.get('Policy')

                if current_policy:
                    # Check if policy grants public access
                    import json
                    policy_doc = json.loads(current_policy) if isinstance(current_policy, str) else current_policy

                    has_public_access = False
                    for statement in policy_doc.get('Statement', []):
                        principal = statement.get('Principal', {})
                        if principal == '*' or principal.get('AWS') == '*':
                            has_public_access = True
                            break

                    if has_public_access:
                        # Delete the public policy
                        s3.delete_bucket_policy(Bucket=bucket_name)
                        actions_taken.append("Removed public bucket policy")

            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    logger.warning(f"Error handling bucket policy: {e}")

            # Set bucket ACL to private
            try:
                s3.put_bucket_acl(Bucket=bucket_name, ACL='private')
                actions_taken.append("Set bucket ACL to private")
            except ClientError as e:
                logger.warning(f"Error setting bucket ACL: {e}")

            # Disable static website hosting if enabled
            try:
                s3.delete_bucket_website(Bucket=bucket_name)
                actions_taken.append("Disabled static website hosting")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchWebsiteConfiguration':
                    logger.warning(f"Error disabling website hosting: {e}")

            logger.info(f"Blocked public access on bucket {bucket_name}: {actions_taken}")

            return self._create_success_result(
                message=f"Successfully blocked public access on bucket {bucket_name}",
                details={
                    'bucket_name': bucket_name,
                    'actions_taken': actions_taken
                },
                action_taken='block_public_access'
            )

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']

            logger.error(
                f"AWS error blocking public access on bucket {bucket_name}: "
                f"{error_code} - {error_message}",
                exc_info=True
            )

            return self._create_error_result(
                message=f"AWS error blocking public access on bucket {bucket_name}",
                error=f"{error_code}: {error_message}",
                details={'bucket_name': bucket_name}
            )

        except Exception as e:
            logger.error(
                f"Unexpected error blocking public access on bucket {bucket_name}: {e}",
                exc_info=True
            )

            return self._create_error_result(
                message=f"Unexpected error blocking public access on bucket {bucket_name}",
                error=str(e),
                details={'bucket_name': bucket_name}
            )
