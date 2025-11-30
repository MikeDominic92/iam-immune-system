"""
Baseline Builder

Builds baseline models of normal IAM behavior from historical data.
"""

import logging
import os
from typing import Any, Dict, List
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from google.cloud import storage, logging as cloud_logging

logger = logging.getLogger(__name__)


class BaselineBuilder:
    """Builds baseline models from historical IAM event data."""

    def __init__(self):
        """Initialize the baseline builder."""
        self.baseline_days = int(os.getenv('ML_BASELINE_DAYS', '30'))
        self.storage_client = storage.Client()
        self.logging_client = cloud_logging.Client()
        self.project_id = os.getenv('GCP_PROJECT_ID')

    def build_baseline(self) -> IsolationForest:
        """
        Build baseline model from historical data.

        Returns:
            Trained IsolationForest model
        """
        logger.info(f"Building baseline from last {self.baseline_days} days of data")

        try:
            # Fetch historical events
            events = self._fetch_historical_events()

            if not events:
                logger.warning("No historical events found, using synthetic data")
                return self._build_synthetic_baseline()

            # Extract features from events
            features_df = self._extract_features_batch(events)

            # Train Isolation Forest
            model = IsolationForest(
                n_estimators=100,
                max_samples='auto',
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )

            model.fit(features_df.values)

            logger.info(f"Baseline model trained on {len(features_df)} events")

            return model

        except Exception as e:
            logger.error(f"Error building baseline: {e}", exc_info=True)
            return self._build_synthetic_baseline()

    def _fetch_historical_events(self) -> List[Dict[str, Any]]:
        """
        Fetch historical IAM events from Cloud Logging.

        Returns:
            List of IAM events
        """
        events = []

        try:
            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=self.baseline_days)

            # Query Cloud Logging for IAM events
            filter_str = f"""
                timestamp >= "{start_time.isoformat()}Z"
                AND timestamp <= "{end_time.isoformat()}Z"
                AND (
                    protoPayload.methodName=~"^google.iam.*"
                    OR protoPayload.methodName=~"^storage.buckets.*"
                    OR resource.type="iam_role"
                    OR resource.type="service_account"
                )
            """

            entries = self.logging_client.list_entries(
                filter_=filter_str,
                max_results=10000  # Limit to prevent excessive data
            )

            for entry in entries:
                try:
                    # Convert log entry to event format
                    event = {
                        'eventTime': entry.timestamp.isoformat(),
                        'eventName': entry.payload.get('methodName', ''),
                        'eventSource': entry.payload.get('serviceName', ''),
                        'sourceIPAddress': entry.payload.get('requestMetadata', {}).get('callerIp', ''),
                        'userAgent': entry.payload.get('requestMetadata', {}).get('callerSuppliedUserAgent', ''),
                        'userIdentity': {
                            'principalEmail': entry.payload.get('authenticationInfo', {}).get('principalEmail', ''),
                            'accountId': self.project_id
                        },
                        'requestParameters': entry.payload.get('request', {}),
                        'responseElements': entry.payload.get('response', {}),
                        'recipientAccountId': self.project_id
                    }

                    events.append(event)

                except Exception as e:
                    logger.warning(f"Error parsing log entry: {e}")
                    continue

            logger.info(f"Fetched {len(events)} historical events")

        except Exception as e:
            logger.error(f"Error fetching historical events: {e}", exc_info=True)

        return events

    def _extract_features_batch(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Extract features from a batch of events.

        Args:
            events: List of IAM events

        Returns:
            DataFrame with extracted features
        """
        features_list = []

        for event in events:
            try:
                features = self._extract_event_features(event)
                features_list.append(features)
            except Exception as e:
                logger.warning(f"Error extracting features from event: {e}")
                continue

        # Convert to DataFrame
        df = pd.DataFrame(features_list)

        # Fill missing values
        df = df.fillna(0)

        return df

    def _extract_event_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract features from a single event.

        Args:
            event: IAM event data

        Returns:
            Dictionary of features
        """
        features = {}

        # Time-based features
        event_time_str = event.get('eventTime', datetime.utcnow().isoformat())
        try:
            event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
            features['hour_of_day'] = float(event_time.hour)
            features['day_of_week'] = float(event_time.weekday())
            features['is_weekend'] = float(event_time.weekday() >= 5)
            features['is_off_hours'] = float(event_time.hour < 6 or event_time.hour >= 22)
        except Exception:
            features['hour_of_day'] = 12.0
            features['day_of_week'] = 2.0
            features['is_weekend'] = 0.0
            features['is_off_hours'] = 0.0

        # Source IP features
        source_ip = event.get('sourceIPAddress', '')
        features['source_ip_entropy'] = self._calculate_entropy(source_ip)

        # User agent features
        user_agent = event.get('userAgent', '')
        features['user_agent_entropy'] = self._calculate_entropy(user_agent)

        # Event frequency features (placeholder - would need aggregation in production)
        features['event_count_1h'] = 5.0
        features['event_count_24h'] = 50.0
        features['unique_actions_1h'] = 3.0
        features['unique_resources_1h'] = 4.0

        # Event type features
        event_name = event.get('eventName', '')
        features['is_cross_account'] = float(self._is_cross_account(event))
        features['is_admin_action'] = float(self._is_admin_action(event_name))
        features['is_policy_change'] = float('Policy' in event_name)
        features['is_s3_action'] = float('s3' in event.get('eventSource', '').lower() or 'storage' in event.get('eventSource', '').lower())

        # Request size
        request_params = event.get('requestParameters', {})
        features['request_size'] = float(len(str(request_params)))

        return features

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        text_len = len(text)

        for count in freq.values():
            prob = count / text_len
            if prob > 0:
                entropy -= prob * np.log2(prob)

        max_entropy = np.log2(len(freq)) if len(freq) > 1 else 1
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0

        return normalized_entropy

    def _is_cross_account(self, event: Dict[str, Any]) -> bool:
        """Check if event involves cross-account access."""
        user_identity = event.get('userIdentity', {})
        user_account = user_identity.get('accountId', '')
        recipient_account = event.get('recipientAccountId', '')

        return user_account != recipient_account if user_account and recipient_account else False

    def _is_admin_action(self, event_name: str) -> bool:
        """Check if event is an admin-level action."""
        admin_keywords = [
            'Attach', 'Detach', 'Put', 'Delete', 'Create',
            'Admin', 'FullAccess', 'Policy', 'Role', 'User'
        ]

        return any(keyword in event_name for keyword in admin_keywords)

    def _build_synthetic_baseline(self) -> IsolationForest:
        """
        Build baseline from synthetic data when historical data is unavailable.

        Returns:
            Trained IsolationForest model
        """
        logger.info("Building synthetic baseline")

        np.random.seed(42)

        # Generate synthetic normal behavior data
        n_samples = 1000
        data = []

        for _ in range(n_samples):
            # Normal business hours
            hour = np.random.choice(range(8, 18))
            day = np.random.choice(range(0, 5))

            features = [
                hour,
                day,
                0,
                0,
                np.random.uniform(0.1, 0.3),
                np.random.uniform(0.2, 0.4),
                np.random.poisson(5),
                np.random.poisson(50),
                np.random.poisson(3),
                np.random.poisson(4),
                0,
                0,
                0,
                np.random.choice([0, 1], p=[0.7, 0.3]),
                np.random.uniform(100, 1000)
            ]
            data.append(features)

        # Train model
        model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )

        model.fit(np.array(data))

        logger.info("Synthetic baseline model created")

        return model
