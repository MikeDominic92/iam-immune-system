"""
IAM Immune System - Cloud Function Entry Point

This module serves as the main entry point for the IAM Immune System Cloud Function.
It processes IAM events, runs detection logic, and triggers remediation actions.

Version 1.1 - December 2025 Enhancement:
    - Added SailPoint IdentityIQ integration
    - Identity lifecycle event processing
    - Access certification synchronization
    - Identity health scoring
"""

import base64
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional
from datetime import datetime

import functions_framework
from cloudevents.http import CloudEvent
from google.cloud import logging as cloud_logging
from google.cloud import pubsub_v1
from google.cloud import storage

from detectors import (
    PublicBucketDetector,
    AdminGrantDetector,
    PolicyChangeDetector,
    CrossAccountDetector
)
from remediators import (
    RevokeAccessRemediator,
    BlockPublicRemediator,
    AlertTeamRemediator
)
from ml.anomaly_detector import AnomalyDetector

# v1.1 Enhancement: Import SailPoint integration modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
try:
    from integrations import (
        SailPointConnector,
        WebhookHandler,
        CertificationSync,
        IdentityEventType
    )
    SAILPOINT_AVAILABLE = True
except ImportError as e:
    logger.warning(f"SailPoint integration not available: {e}")
    SAILPOINT_AVAILABLE = False


# Initialize Cloud Logging
logging_client = cloud_logging.Client()
logging_client.setup_logging()
logger = logging.getLogger(__name__)
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO'))

# Initialize clients
pubsub_publisher = pubsub_v1.PublisherClient()
storage_client = storage.Client()

# Configuration
PROJECT_ID = os.getenv('GCP_PROJECT_ID')
ALERT_TOPIC = os.getenv('PUBSUB_TOPIC', f'projects/{PROJECT_ID}/topics/iam-alerts')
AUTO_REMEDIATION = os.getenv('AUTO_REMEDIATION', 'true').lower() == 'true'


class EventProcessor:
    """
    Processes IAM events through detection and remediation pipeline.

    v1.1 Enhancement: Added SailPoint IdentityIQ integration for identity
    lifecycle management and access certification.
    """

    def __init__(self):
        """Initialize the event processor with detectors and remediators."""
        self.detectors = self._initialize_detectors()
        self.remediators = self._initialize_remediators()
        self.anomaly_detector = AnomalyDetector()

        # v1.1 Enhancement: Initialize SailPoint integration
        self.sailpoint_connector = None
        self.webhook_handler = None
        self.certification_sync = None

        if SAILPOINT_AVAILABLE and os.getenv('ENABLE_SAILPOINT_INTEGRATION', 'false').lower() == 'true':
            self._initialize_sailpoint()

        logger.info("EventProcessor initialized with %d detectors and %d remediators",
                    len(self.detectors), len(self.remediators))

    def _initialize_sailpoint(self):
        """v1.1 Enhancement: Initialize SailPoint IdentityIQ integration."""
        try:
            self.sailpoint_connector = SailPointConnector(
                mock_mode=os.getenv('SAILPOINT_MOCK_MODE', 'true').lower() == 'true'
            )

            self.webhook_handler = WebhookHandler(
                self.sailpoint_connector,
                webhook_secret=os.getenv('SAILPOINT_WEBHOOK_SECRET'),
                mock_mode=os.getenv('SAILPOINT_MOCK_MODE', 'true').lower() == 'true'
            )

            self.certification_sync = CertificationSync(
                self.sailpoint_connector,
                auto_remediate=AUTO_REMEDIATION,
                mock_mode=os.getenv('SAILPOINT_MOCK_MODE', 'true').lower() == 'true'
            )

            logger.info("SailPoint IdentityIQ integration initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize SailPoint integration: {e}", exc_info=True)
            self.sailpoint_connector = None
            self.webhook_handler = None
            self.certification_sync = None

    def _initialize_detectors(self) -> List:
        """Initialize all detection modules."""
        detectors = []

        if os.getenv('ENABLE_PUBLIC_BUCKET_DETECTION', 'true').lower() == 'true':
            detectors.append(PublicBucketDetector())

        if os.getenv('ENABLE_ADMIN_GRANT_DETECTION', 'true').lower() == 'true':
            detectors.append(AdminGrantDetector())

        if os.getenv('ENABLE_POLICY_CHANGE_DETECTION', 'true').lower() == 'true':
            detectors.append(PolicyChangeDetector())

        if os.getenv('ENABLE_CROSS_ACCOUNT_DETECTION', 'true').lower() == 'true':
            detectors.append(CrossAccountDetector())

        return detectors

    def _initialize_remediators(self) -> Dict[str, Any]:
        """Initialize all remediation modules."""
        return {
            'revoke_access': RevokeAccessRemediator(),
            'block_public': BlockPublicRemediator(),
            'alert_team': AlertTeamRemediator()
        }

    def process_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process an IAM event through the detection and remediation pipeline.

        Args:
            event_data: IAM event data from CloudTrail or GCP

        Returns:
            Dictionary containing processing results
        """
        event_id = event_data.get('eventID', 'unknown')
        event_name = event_data.get('eventName', 'unknown')

        logger.info(f"Processing event {event_id}: {event_name}")

        results = {
            'event_id': event_id,
            'event_name': event_name,
            'timestamp': datetime.utcnow().isoformat(),
            'detections': [],
            'remediations': [],
            'ml_analysis': None
        }

        try:
            # Run through all detectors
            for detector in self.detectors:
                try:
                    detection_result = detector.detect(event_data)

                    if detection_result.is_threat:
                        logger.warning(
                            f"Threat detected by {detector.__class__.__name__}: "
                            f"Risk score {detection_result.risk_score}"
                        )
                        results['detections'].append({
                            'detector': detector.__class__.__name__,
                            'risk_score': detection_result.risk_score,
                            'severity': detection_result.severity,
                            'details': detection_result.details,
                            'recommended_actions': detection_result.recommended_actions
                        })

                        # Execute remediation if auto-remediation is enabled
                        if AUTO_REMEDIATION and detection_result.auto_remediate:
                            remediation_result = self._execute_remediation(
                                detection_result
                            )
                            results['remediations'].append(remediation_result)

                except Exception as e:
                    logger.error(
                        f"Error in detector {detector.__class__.__name__}: {e}",
                        exc_info=True
                    )

            # Run ML anomaly detection
            try:
                ml_result = self.anomaly_detector.analyze(event_data)
                results['ml_analysis'] = {
                    'is_anomaly': ml_result.is_anomaly,
                    'anomaly_score': ml_result.anomaly_score,
                    'features': ml_result.features
                }

                if ml_result.is_anomaly:
                    logger.warning(
                        f"ML anomaly detected with score {ml_result.anomaly_score}"
                    )

            except Exception as e:
                logger.error(f"Error in ML analysis: {e}", exc_info=True)

            # v1.1 Enhancement: Correlate with SailPoint identity data
            if self.sailpoint_connector:
                try:
                    identity_correlation = self._correlate_with_sailpoint(event_data, results)
                    results['sailpoint_correlation'] = identity_correlation
                except Exception as e:
                    logger.error(f"Error correlating with SailPoint: {e}", exc_info=True)

            # Publish results to alert topic
            if results['detections'] or (results['ml_analysis'] and
                                         results['ml_analysis']['is_anomaly']):
                self._publish_alert(results)

            logger.info(f"Event {event_id} processed successfully")
            return results

        except Exception as e:
            logger.error(f"Error processing event {event_id}: {e}", exc_info=True)
            results['error'] = str(e)
            return results

    def _execute_remediation(self, detection_result) -> Dict[str, Any]:
        """
        Execute appropriate remediation actions based on detection result.

        Args:
            detection_result: Detection result from a detector

        Returns:
            Dictionary containing remediation results
        """
        remediation_results = {
            'actions_taken': [],
            'success': True,
            'errors': []
        }

        for action in detection_result.recommended_actions:
            try:
                remediator = self.remediators.get(action)
                if remediator:
                    result = remediator.remediate(detection_result)
                    remediation_results['actions_taken'].append({
                        'action': action,
                        'success': result.success,
                        'message': result.message,
                        'details': result.details
                    })

                    if not result.success:
                        remediation_results['success'] = False
                        remediation_results['errors'].append(result.message)
                else:
                    logger.warning(f"No remediator found for action: {action}")

            except Exception as e:
                logger.error(f"Error executing remediation {action}: {e}", exc_info=True)
                remediation_results['success'] = False
                remediation_results['errors'].append(str(e))

        return remediation_results

    def _publish_alert(self, results: Dict[str, Any]) -> None:
        """
        Publish alert to Pub/Sub topic.

        Args:
            results: Processing results to publish
        """
        try:
            message_data = json.dumps(results).encode('utf-8')
            future = pubsub_publisher.publish(ALERT_TOPIC, message_data)
            message_id = future.result(timeout=30)
            logger.info(f"Alert published with message ID: {message_id}")

        except Exception as e:
            logger.error(f"Error publishing alert: {e}", exc_info=True)

    def _correlate_with_sailpoint(
        self,
        event_data: Dict[str, Any],
        detection_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        v1.1 Enhancement: Correlate IAM event with SailPoint identity data.

        Args:
            event_data: Original IAM event
            detection_results: Detection results

        Returns:
            Correlation data including identity health score
        """
        correlation = {
            'identity_found': False,
            'identity_health_score': None,
            'sailpoint_risk_score': None,
            'active_certifications': 0,
            'recent_lifecycle_events': []
        }

        try:
            # Extract identity information from event
            identity_id = self._extract_identity_from_event(event_data)

            if not identity_id:
                return correlation

            # Get identity from SailPoint
            identity = self.sailpoint_connector.get_identity(identity_id)

            if identity:
                correlation['identity_found'] = True
                correlation['identity_name'] = identity.name
                correlation['identity_email'] = identity.email
                correlation['identity_status'] = identity.status.value
                correlation['department'] = identity.department

                # Get risk score
                risk_score = self.sailpoint_connector.get_identity_risk_score(identity_id)
                correlation['sailpoint_risk_score'] = risk_score

                # Calculate combined health score
                immune_system_risk = max(
                    [d.get('risk_score', 0) for d in detection_results.get('detections', [])],
                    default=0
                )
                ml_risk = detection_results.get('ml_analysis', {}).get('anomaly_score', 0) * 100

                # Combine scores (weighted average)
                combined_risk = (immune_system_risk * 0.4 + risk_score * 0.3 + ml_risk * 0.3)
                correlation['identity_health_score'] = max(0, 100 - combined_risk)

                logger.info(
                    f"Identity correlation: {identity.name} - "
                    f"Health Score: {correlation['identity_health_score']:.2f}"
                )

            return correlation

        except Exception as e:
            logger.error(f"Error in SailPoint correlation: {e}", exc_info=True)
            return correlation

    def _extract_identity_from_event(self, event_data: Dict[str, Any]) -> Optional[str]:
        """
        Extract identity ID from IAM event.

        Args:
            event_data: IAM event data

        Returns:
            Identity ID or None
        """
        # Try various common identity fields
        identity_fields = [
            'userIdentity.principalId',
            'userIdentity.userName',
            'user',
            'principal',
            'actor',
            'requestor'
        ]

        for field in identity_fields:
            value = event_data
            for key in field.split('.'):
                value = value.get(key) if isinstance(value, dict) else None
                if value is None:
                    break
            if value:
                return str(value)

        return None


# Global processor instance
processor = EventProcessor()


@functions_framework.cloud_event
def handle_iam_event(cloud_event: CloudEvent) -> Dict[str, Any]:
    """
    Main Cloud Function entry point for handling IAM events.

    This function is triggered by Pub/Sub messages containing IAM events
    from AWS CloudTrail or GCP Cloud Logging.

    Args:
        cloud_event: CloudEvent containing IAM event data

    Returns:
        Dictionary containing processing results
    """
    try:
        # Extract event data from Pub/Sub message
        if cloud_event.data:
            message_data = base64.b64decode(cloud_event.data['message']['data'])
            event_data = json.loads(message_data)
        else:
            logger.error("No data in cloud event")
            return {'error': 'No data in cloud event', 'status': 'failed'}

        # Log event receipt
        logger.info(
            f"Received IAM event: {event_data.get('eventName', 'unknown')} "
            f"from source: {event_data.get('eventSource', 'unknown')}"
        )

        # Process the event
        results = processor.process_event(event_data)

        # Return results
        return {
            'status': 'success',
            'results': results
        }

    except json.JSONDecodeError as e:
        logger.error(f"Error decoding event data: {e}", exc_info=True)
        return {'error': 'Invalid JSON in event data', 'status': 'failed'}

    except Exception as e:
        logger.error(f"Unexpected error in handle_iam_event: {e}", exc_info=True)
        return {'error': str(e), 'status': 'failed'}


@functions_framework.http
def health_check(request) -> tuple:
    """
    Health check endpoint for the Cloud Function.

    v1.1 Enhancement: Added SailPoint integration health status.

    Args:
        request: HTTP request object

    Returns:
        Tuple of (response_body, status_code, headers)
    """
    try:
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'detectors': len(processor.detectors),
            'remediators': len(processor.remediators),
            'auto_remediation': AUTO_REMEDIATION,
            'version': '1.1.0'
        }

        # v1.1 Enhancement: Add SailPoint health status
        if processor.sailpoint_connector:
            sailpoint_health = processor.sailpoint_connector.health_check()
            health_status['sailpoint_integration'] = sailpoint_health

        return (json.dumps(health_status), 200, {'Content-Type': 'application/json'})

    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        error_response = {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
        return (json.dumps(error_response), 503, {'Content-Type': 'application/json'})


@functions_framework.http
def sailpoint_webhook(request) -> tuple:
    """
    v1.1 Enhancement: Handle SailPoint IdentityIQ webhooks.

    This endpoint receives identity lifecycle events from SailPoint including:
    - Joiner events (new employees)
    - Mover events (role changes)
    - Leaver events (terminations)

    Args:
        request: HTTP request object

    Returns:
        Tuple of (response_body, status_code, headers)
    """
    if not processor.webhook_handler:
        return (
            json.dumps({'error': 'SailPoint integration not enabled'}),
            503,
            {'Content-Type': 'application/json'}
        )

    try:
        # Get webhook signature for verification
        signature = request.headers.get('X-SailPoint-Signature', '')

        # Parse webhook payload
        webhook_data = request.get_json()

        if not webhook_data:
            return (
                json.dumps({'error': 'Invalid webhook payload'}),
                400,
                {'Content-Type': 'application/json'}
            )

        # Verify signature
        if not processor.webhook_handler.verify_signature(
            request.get_data(),
            signature
        ):
            logger.warning("Invalid webhook signature")
            return (
                json.dumps({'error': 'Invalid signature'}),
                401,
                {'Content-Type': 'application/json'}
            )

        # Process webhook
        event = processor.webhook_handler.process_webhook(webhook_data, signature)

        if not event:
            return (
                json.dumps({'error': 'Failed to process webhook'}),
                400,
                {'Content-Type': 'application/json'}
            )

        response = {
            'status': 'success',
            'event_id': event.event_id,
            'event_type': event.event_type.value,
            'identity_id': event.identity_id,
            'risk_score': event.calculate_risk_score(),
            'timestamp': datetime.utcnow().isoformat()
        }

        logger.info(f"SailPoint webhook processed: {event.event_type.value} for {event.identity_name}")

        return (json.dumps(response), 200, {'Content-Type': 'application/json'})

    except Exception as e:
        logger.error(f"Error processing SailPoint webhook: {e}", exc_info=True)
        return (
            json.dumps({'error': str(e)}),
            500,
            {'Content-Type': 'application/json'}
        )


@functions_framework.http
def certification_status(request) -> tuple:
    """
    v1.1 Enhancement: Get access certification campaign status.

    Returns current status of active certification campaigns and recent
    revocation decisions.

    Args:
        request: HTTP request object

    Returns:
        Tuple of (response_body, status_code, headers)
    """
    if not processor.certification_sync:
        return (
            json.dumps({'error': 'SailPoint integration not enabled'}),
            503,
            {'Content-Type': 'application/json'}
        )

    try:
        # Get active campaigns
        campaigns = processor.certification_sync.get_active_campaigns()

        # Get recent revocations (last 7 days)
        revocations = processor.certification_sync.get_revocations(days=7)

        response = {
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'active_campaigns': len(campaigns),
            'campaigns': [campaign.to_dict() for campaign in campaigns[:5]],  # Limit to 5
            'recent_revocations': len(revocations),
            'revocations': [rev.to_dict() for rev in revocations[:10]]  # Limit to 10
        }

        return (json.dumps(response), 200, {'Content-Type': 'application/json'})

    except Exception as e:
        logger.error(f"Error getting certification status: {e}", exc_info=True)
        return (
            json.dumps({'error': str(e)}),
            500,
            {'Content-Type': 'application/json'}
        )
