"""
SailPoint IdentityIQ Webhook Handler

This module handles identity lifecycle events from SailPoint IdentityIQ including:
- Joiner events (new employees)
- Mover events (role/department changes)
- Leaver events (terminations)

Version: 1.1 - December 2025 Enhancement
Features:
    - Identity lifecycle event processing
    - Event validation and enrichment
    - Correlation with immune system detections
    - Identity health score calculation
    - Mock mode for testing
"""

import logging
import hashlib
import hmac
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

from .sailpoint_connector import SailPointConnector, Identity

logger = logging.getLogger(__name__)


class IdentityEventType(Enum):
    """Types of identity lifecycle events."""
    JOINER = "joiner"  # New employee onboarding
    MOVER = "mover"    # Role/department change
    LEAVER = "leaver"  # Employee termination
    REACTIVATION = "reactivation"  # Account reactivation
    SUSPENSION = "suspension"  # Account suspension
    ACCESS_REQUEST = "access_request"  # New access request
    ACCESS_REVOCATION = "access_revocation"  # Access revoked


@dataclass
class IdentityEvent:
    """Represents an identity lifecycle event."""
    event_id: str
    event_type: IdentityEventType
    identity_id: str
    identity_name: str
    identity_email: str
    timestamp: datetime
    source: str = "SailPoint IdentityIQ"
    previous_state: Optional[Dict[str, Any]] = None
    new_state: Optional[Dict[str, Any]] = None
    attributes: Optional[Dict[str, Any]] = None
    risk_indicators: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['timestamp'] = self.timestamp.isoformat()
        return data

    def calculate_risk_score(self) -> float:
        """
        Calculate risk score for this event.

        Returns:
            Risk score (0-100)
        """
        base_scores = {
            IdentityEventType.JOINER: 30.0,  # New accounts have medium risk
            IdentityEventType.MOVER: 45.0,   # Role changes are higher risk
            IdentityEventType.LEAVER: 80.0,  # Terminated accounts are high risk
            IdentityEventType.REACTIVATION: 60.0,  # Reactivations need review
            IdentityEventType.SUSPENSION: 20.0,
            IdentityEventType.ACCESS_REQUEST: 35.0,
            IdentityEventType.ACCESS_REVOCATION: 15.0,
        }

        score = base_scores.get(self.event_type, 30.0)

        # Adjust based on risk indicators
        if self.risk_indicators:
            score += len(self.risk_indicators) * 10
            score = min(score, 100.0)

        return score


class WebhookHandler:
    """
    Handler for SailPoint IdentityIQ webhooks.

    Processes identity lifecycle events and correlates them with
    immune system threat detections.

    Args:
        sailpoint_connector: SailPoint API connector
        webhook_secret: Shared secret for webhook signature verification
        mock_mode: Enable mock mode for demos

    Example:
        >>> handler = WebhookHandler(connector, secret="my_secret")
        >>> event = handler.process_webhook(request_data, signature)
        >>> if event:
        ...     print(f"Processed {event.event_type} for {event.identity_name}")
    """

    def __init__(
        self,
        sailpoint_connector: SailPointConnector,
        webhook_secret: Optional[str] = None,
        mock_mode: bool = False
    ):
        """Initialize webhook handler."""
        self.connector = sailpoint_connector
        self.webhook_secret = webhook_secret
        self.mock_mode = mock_mode
        self.event_handlers: Dict[IdentityEventType, List[Callable]] = {}

        logger.info(
            f"WebhookHandler initialized (mock_mode={self.mock_mode})"
        )

    def register_handler(
        self,
        event_type: IdentityEventType,
        handler: Callable[[IdentityEvent], None]
    ) -> None:
        """
        Register a handler for specific event type.

        Args:
            event_type: Type of event to handle
            handler: Callback function to handle event
        """
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
        logger.info(f"Registered handler for {event_type.value} events")

    def verify_signature(
        self,
        payload: bytes,
        signature: str
    ) -> bool:
        """
        Verify webhook signature.

        Args:
            payload: Raw webhook payload
            signature: Signature from webhook headers

        Returns:
            True if signature is valid
        """
        if not self.webhook_secret:
            logger.warning("No webhook secret configured, skipping verification")
            return True

        if self.mock_mode:
            return True

        try:
            expected_signature = hmac.new(
                self.webhook_secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()

            return hmac.compare_digest(signature, expected_signature)

        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    def process_webhook(
        self,
        webhook_data: Dict[str, Any],
        signature: Optional[str] = None
    ) -> Optional[IdentityEvent]:
        """
        Process incoming webhook from SailPoint.

        Args:
            webhook_data: Webhook payload data
            signature: Optional signature for verification

        Returns:
            Processed IdentityEvent or None if invalid
        """
        try:
            # Parse event data
            event = self._parse_webhook_data(webhook_data)

            if not event:
                logger.error("Failed to parse webhook data")
                return None

            logger.info(
                f"Processing {event.event_type.value} event for {event.identity_name}"
            )

            # Enrich event with SailPoint data
            event = self._enrich_event(event)

            # Calculate risk score
            risk_score = event.calculate_risk_score()
            logger.info(f"Event risk score: {risk_score}")

            # Execute registered handlers
            self._execute_handlers(event)

            # Correlate with immune system detections
            self._correlate_with_detections(event)

            return event

        except Exception as e:
            logger.error(f"Error processing webhook: {e}", exc_info=True)
            return None

    def _parse_webhook_data(
        self,
        data: Dict[str, Any]
    ) -> Optional[IdentityEvent]:
        """
        Parse webhook data into IdentityEvent.

        Args:
            data: Raw webhook data

        Returns:
            IdentityEvent or None if parsing fails
        """
        try:
            # Extract event type
            event_type_str = data.get('eventType', '').lower()
            event_type = IdentityEventType(event_type_str)

            # Extract identity information
            identity_data = data.get('identity', {})

            return IdentityEvent(
                event_id=data.get('eventId', data.get('id', 'unknown')),
                event_type=event_type,
                identity_id=identity_data.get('id', ''),
                identity_name=identity_data.get('name', ''),
                identity_email=identity_data.get('email', ''),
                timestamp=self._parse_timestamp(data.get('timestamp')),
                previous_state=data.get('previousState'),
                new_state=data.get('newState'),
                attributes=data.get('attributes', {}),
                risk_indicators=data.get('riskIndicators', [])
            )

        except (KeyError, ValueError) as e:
            logger.error(f"Failed to parse webhook data: {e}")
            return None

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> datetime:
        """Parse timestamp string to datetime."""
        if not timestamp_str:
            return datetime.utcnow()

        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return datetime.utcnow()

    def _enrich_event(self, event: IdentityEvent) -> IdentityEvent:
        """
        Enrich event with additional SailPoint data.

        Args:
            event: Base identity event

        Returns:
            Enriched event
        """
        try:
            # Get full identity details from SailPoint
            identity = self.connector.get_identity(event.identity_id)

            if identity:
                # Add risk score from SailPoint
                sailpoint_risk = self.connector.get_identity_risk_score(
                    event.identity_id
                )

                # Update event attributes
                if not event.attributes:
                    event.attributes = {}

                event.attributes.update({
                    'sailpoint_risk_score': sailpoint_risk,
                    'department': identity.department,
                    'manager': identity.manager,
                    'last_login': identity.last_login.isoformat() if identity.last_login else None
                })

                # Get entitlements for high-risk events
                if event.event_type in [
                    IdentityEventType.MOVER,
                    IdentityEventType.LEAVER,
                    IdentityEventType.REACTIVATION
                ]:
                    entitlements = self.connector.get_identity_entitlements(
                        event.identity_id
                    )
                    event.attributes['entitlements_count'] = len(entitlements)
                    event.attributes['privileged_entitlements'] = [
                        e['name'] for e in entitlements if e.get('privileged')
                    ]

            return event

        except Exception as e:
            logger.error(f"Error enriching event: {e}", exc_info=True)
            return event

    def _execute_handlers(self, event: IdentityEvent) -> None:
        """
        Execute registered handlers for event type.

        Args:
            event: Identity event to handle
        """
        handlers = self.event_handlers.get(event.event_type, [])

        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(
                    f"Error executing handler for {event.event_type.value}: {e}",
                    exc_info=True
                )

    def _correlate_with_detections(self, event: IdentityEvent) -> Dict[str, Any]:
        """
        Correlate identity event with immune system threat detections.

        Args:
            event: Identity event

        Returns:
            Correlation results
        """
        correlation_results = {
            'event_id': event.event_id,
            'identity_id': event.identity_id,
            'correlations': [],
            'health_score': 100.0,
            'risk_factors': []
        }

        try:
            # Check for high-risk event types
            if event.event_type == IdentityEventType.LEAVER:
                correlation_results['risk_factors'].append(
                    'Terminated user with active access'
                )
                correlation_results['health_score'] -= 40

            if event.event_type == IdentityEventType.REACTIVATION:
                correlation_results['risk_factors'].append(
                    'Account reactivation requires review'
                )
                correlation_results['health_score'] -= 20

            # Check for privileged access
            privileged = event.attributes.get('privileged_entitlements', [])
            if privileged:
                correlation_results['risk_factors'].append(
                    f'User has {len(privileged)} privileged entitlements'
                )
                correlation_results['health_score'] -= len(privileged) * 5

            # Check SailPoint risk score
            sp_risk = event.attributes.get('sailpoint_risk_score', 0.0)
            if sp_risk > 70:
                correlation_results['risk_factors'].append(
                    f'High SailPoint risk score: {sp_risk}'
                )
                correlation_results['health_score'] -= 30

            # Ensure health score is in valid range
            correlation_results['health_score'] = max(
                0.0,
                min(100.0, correlation_results['health_score'])
            )

            logger.info(
                f"Identity health score for {event.identity_name}: "
                f"{correlation_results['health_score']}"
            )

            return correlation_results

        except Exception as e:
            logger.error(f"Error correlating event: {e}", exc_info=True)
            return correlation_results

    def calculate_identity_health(
        self,
        identity_id: str,
        events: List[IdentityEvent]
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive identity health score.

        Args:
            identity_id: Identity ID
            events: Recent identity events

        Returns:
            Health assessment dictionary
        """
        health = {
            'identity_id': identity_id,
            'health_score': 100.0,
            'risk_level': 'low',
            'factors': [],
            'recent_events': len(events),
            'recommendations': []
        }

        try:
            # Analyze recent events
            for event in events:
                risk_score = event.calculate_risk_score()
                if risk_score > 60:
                    health['health_score'] -= 15
                    health['factors'].append(
                        f"High-risk event: {event.event_type.value}"
                    )

            # Get current SailPoint risk score
            sp_risk = self.connector.get_identity_risk_score(identity_id)
            if sp_risk > 70:
                health['health_score'] -= 20
                health['factors'].append(f"SailPoint risk score: {sp_risk}")

            # Determine risk level
            if health['health_score'] >= 80:
                health['risk_level'] = 'low'
            elif health['health_score'] >= 50:
                health['risk_level'] = 'medium'
                health['recommendations'].append(
                    "Review recent access changes"
                )
            else:
                health['risk_level'] = 'high'
                health['recommendations'].extend([
                    "Immediate access review required",
                    "Consider access revocation",
                    "Notify security team"
                ])

            return health

        except Exception as e:
            logger.error(f"Error calculating identity health: {e}", exc_info=True)
            return health

    def create_mock_event(
        self,
        event_type: IdentityEventType,
        identity_id: str = "mock_user"
    ) -> IdentityEvent:
        """
        Create mock event for testing.

        Args:
            event_type: Type of event to create
            identity_id: Identity ID

        Returns:
            Mock IdentityEvent
        """
        return IdentityEvent(
            event_id=f"mock_{event_type.value}_{datetime.utcnow().timestamp()}",
            event_type=event_type,
            identity_id=identity_id,
            identity_name=f"Mock User {identity_id}",
            identity_email=f"{identity_id}@company.com",
            timestamp=datetime.utcnow(),
            previous_state={'status': 'active'} if event_type != IdentityEventType.JOINER else None,
            new_state={'status': 'inactive'} if event_type == IdentityEventType.LEAVER else {'status': 'active'},
            attributes={
                'department': 'Engineering',
                'manager': 'manager@company.com'
            },
            risk_indicators=['mock_indicator'] if event_type == IdentityEventType.LEAVER else []
        )
