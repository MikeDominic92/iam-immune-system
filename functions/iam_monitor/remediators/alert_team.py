"""
Alert Team Remediator

Sends alerts to security teams via multiple channels (Slack, Teams, Email).
"""

import logging
import os
import json
from typing import Any, Dict
from datetime import datetime

import requests
from slack_sdk import WebhookClient
from slack_sdk.errors import SlackApiError

from . import BaseRemediator, RemediationResult

logger = logging.getLogger(__name__)


class AlertTeamRemediator(BaseRemediator):
    """Sends alerts to security teams via multiple channels."""

    def __init__(self):
        """Initialize the alert team remediator."""
        super().__init__()
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
        self.teams_webhook = os.getenv('TEAMS_WEBHOOK_URL')
        self.alert_email = os.getenv('ALERT_EMAIL')

    def remediate(self, detection_result) -> RemediationResult:
        """
        Send alerts to security team.

        Args:
            detection_result: Detection result from a detector

        Returns:
            RemediationResult with alert details
        """
        try:
            alerts_sent = []
            errors = []

            # Prepare alert message
            alert_data = self._prepare_alert_data(detection_result)

            # Send Slack alert
            if self.slack_webhook:
                try:
                    slack_result = self._send_slack_alert(alert_data)
                    alerts_sent.append('slack')
                except Exception as e:
                    logger.error(f"Error sending Slack alert: {e}", exc_info=True)
                    errors.append(f"Slack: {str(e)}")

            # Send Teams alert
            if self.teams_webhook:
                try:
                    teams_result = self._send_teams_alert(alert_data)
                    alerts_sent.append('teams')
                except Exception as e:
                    logger.error(f"Error sending Teams alert: {e}", exc_info=True)
                    errors.append(f"Teams: {str(e)}")

            # Send email alert
            if self.alert_email:
                try:
                    email_result = self._send_email_alert(alert_data)
                    alerts_sent.append('email')
                except Exception as e:
                    logger.error(f"Error sending email alert: {e}", exc_info=True)
                    errors.append(f"Email: {str(e)}")

            if alerts_sent:
                logger.info(f"Sent alerts via: {', '.join(alerts_sent)}")
                return self._create_success_result(
                    message=f"Alerts sent via {', '.join(alerts_sent)}",
                    details={
                        'channels': alerts_sent,
                        'errors': errors if errors else None
                    },
                    action_taken='send_alerts'
                )
            else:
                return self._create_error_result(
                    message="No alert channels configured or all alerts failed",
                    error='; '.join(errors) if errors else "No channels configured",
                    details={'errors': errors}
                )

        except Exception as e:
            logger.error(f"Error in alert team remediation: {e}", exc_info=True)
            return self._create_error_result(
                message="Failed to send alerts",
                error=str(e)
            )

    def _prepare_alert_data(self, detection_result) -> Dict[str, Any]:
        """
        Prepare alert data from detection result.

        Args:
            detection_result: Detection result

        Returns:
            Dictionary with formatted alert data
        """
        details = detection_result.details
        severity = detection_result.severity.value

        # Color coding based on severity
        color_map = {
            'critical': '#FF0000',  # Red
            'high': '#FF6600',      # Orange
            'medium': '#FFCC00',    # Yellow
            'low': '#00CC00'        # Green
        }

        return {
            'severity': severity,
            'risk_score': detection_result.risk_score,
            'detector': detection_result.detector_name,
            'timestamp': datetime.utcnow().isoformat(),
            'color': color_map.get(severity, '#808080'),
            'details': details,
            'recommended_actions': detection_result.recommended_actions
        }

    def _send_slack_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Send alert to Slack.

        Args:
            alert_data: Formatted alert data

        Returns:
            True if successful
        """
        webhook = WebhookClient(self.slack_webhook)

        severity_emoji = {
            'critical': ':rotating_light:',
            'high': ':warning:',
            'medium': ':large_orange_diamond:',
            'low': ':information_source:'
        }

        emoji = severity_emoji.get(alert_data['severity'], ':bell:')

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} IAM Security Alert - {alert_data['severity'].upper()}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Detector:*\n{alert_data['detector']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:*\n{alert_data['risk_score']:.1f}/100"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Timestamp:*\n{alert_data['timestamp']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{alert_data['severity'].upper()}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Details:*\n```{json.dumps(alert_data['details'], indent=2)[:500]}```"
                }
            }
        ]

        if alert_data.get('recommended_actions'):
            actions_text = '\n'.join(f"• {action}" for action in alert_data['recommended_actions'])
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Actions:*\n{actions_text}"
                }
            })

        blocks.append({
            "type": "divider"
        })

        response = webhook.send(
            text=f"IAM Security Alert - {alert_data['severity'].upper()}",
            blocks=blocks
        )

        return response.status_code == 200

    def _send_teams_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Send alert to Microsoft Teams.

        Args:
            alert_data: Formatted alert data

        Returns:
            True if successful
        """
        # Adaptive Card format for Teams
        card = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": alert_data['color'],
            "summary": f"IAM Security Alert - {alert_data['severity'].upper()}",
            "sections": [
                {
                    "activityTitle": f"IAM Security Alert - {alert_data['severity'].upper()}",
                    "activitySubtitle": f"Detected by {alert_data['detector']}",
                    "facts": [
                        {
                            "name": "Severity",
                            "value": alert_data['severity'].upper()
                        },
                        {
                            "name": "Risk Score",
                            "value": f"{alert_data['risk_score']:.1f}/100"
                        },
                        {
                            "name": "Timestamp",
                            "value": alert_data['timestamp']
                        }
                    ],
                    "markdown": True
                },
                {
                    "activityTitle": "Details",
                    "text": f"```\n{json.dumps(alert_data['details'], indent=2)[:500]}\n```"
                }
            ]
        }

        if alert_data.get('recommended_actions'):
            card["sections"].append({
                "activityTitle": "Recommended Actions",
                "text": '\n\n'.join(f"• {action}" for action in alert_data['recommended_actions'])
            })

        response = requests.post(
            self.teams_webhook,
            headers={'Content-Type': 'application/json'},
            data=json.dumps(card),
            timeout=10
        )

        return response.status_code == 200

    def _send_email_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Send alert via email.

        Args:
            alert_data: Formatted alert data

        Returns:
            True if successful
        """
        # In production, use SendGrid, SES, or other email service
        # This is a placeholder implementation

        subject = f"IAM Security Alert - {alert_data['severity'].upper()}"

        body = f"""
IAM Immune System Security Alert

Severity: {alert_data['severity'].upper()}
Risk Score: {alert_data['risk_score']:.1f}/100
Detector: {alert_data['detector']}
Timestamp: {alert_data['timestamp']}

Details:
{json.dumps(alert_data['details'], indent=2)}

Recommended Actions:
{chr(10).join(f'- {action}' for action in alert_data.get('recommended_actions', []))}

---
This is an automated alert from IAM Immune System.
"""

        # TODO: Implement actual email sending
        logger.info(f"Would send email to {self.alert_email}: {subject}")

        # For now, just log that we would send an email
        return True
