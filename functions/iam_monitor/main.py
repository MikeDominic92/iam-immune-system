"""
IAM Immune System - Cloud Function Entry Point

This module serves as the main entry point for the IAM Immune System Cloud Function.
It processes IAM events, runs detection logic, and triggers remediation actions.
"""

import base64
import json
import logging
import os
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
    """Processes IAM events through detection and remediation pipeline."""

    def __init__(self):
        """Initialize the event processor with detectors and remediators."""
        self.detectors = self._initialize_detectors()
        self.remediators = self._initialize_remediators()
        self.anomaly_detector = AnomalyDetector()
        logger.info("EventProcessor initialized with %d detectors and %d remediators",
                    len(self.detectors), len(self.remediators))

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
            'auto_remediation': AUTO_REMEDIATION
        }

        return (json.dumps(health_status), 200, {'Content-Type': 'application/json'})

    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        error_response = {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
        return (json.dumps(error_response), 503, {'Content-Type': 'application/json'})
