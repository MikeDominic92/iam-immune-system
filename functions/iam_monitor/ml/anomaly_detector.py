"""
Anomaly Detector using Isolation Forest

Detects anomalous IAM behavior patterns using machine learning.
"""

import logging
import os
import pickle
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from google.cloud import storage

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    """Result from anomaly detection."""
    is_anomaly: bool
    anomaly_score: float  # -1 to 1, higher is more anomalous
    features: Dict[str, Any]
    model_version: Optional[str] = None


class AnomalyDetector:
    """Detects anomalous IAM behavior using Isolation Forest."""

    def __init__(self):
        """Initialize the anomaly detector."""
        self.model = None
        self.feature_names = [
            'hour_of_day',
            'day_of_week',
            'is_weekend',
            'is_off_hours',
            'source_ip_entropy',
            'user_agent_entropy',
            'event_count_1h',
            'event_count_24h',
            'unique_actions_1h',
            'unique_resources_1h',
            'is_cross_account',
            'is_admin_action',
            'is_policy_change',
            'is_s3_action',
            'request_size'
        ]
        self.model_path = os.getenv('ML_MODEL_PATH', 'gs://iam-immune-system-ml-models/anomaly_detector.pkl')
        self.threshold = float(os.getenv('ML_ANOMALY_THRESHOLD', '0.7'))
        self._load_model()

    def _load_model(self) -> None:
        """Load trained model from GCS."""
        try:
            if self.model_path.startswith('gs://'):
                # Load from GCS
                parts = self.model_path.replace('gs://', '').split('/', 1)
                bucket_name = parts[0]
                blob_path = parts[1] if len(parts) > 1 else 'anomaly_detector.pkl'

                storage_client = storage.Client()
                bucket = storage_client.bucket(bucket_name)
                blob = bucket.blob(blob_path)

                if blob.exists():
                    model_bytes = blob.download_as_bytes()
                    self.model = pickle.loads(model_bytes)
                    logger.info(f"Loaded model from {self.model_path}")
                else:
                    logger.warning(f"Model not found at {self.model_path}, creating new model")
                    self._create_default_model()
            else:
                # Load from local file
                if os.path.exists(self.model_path):
                    with open(self.model_path, 'rb') as f:
                        self.model = pickle.load(f)
                    logger.info(f"Loaded model from {self.model_path}")
                else:
                    logger.warning(f"Model not found at {self.model_path}, creating new model")
                    self._create_default_model()

        except Exception as e:
            logger.error(f"Error loading model: {e}, creating new model", exc_info=True)
            self._create_default_model()

    def _create_default_model(self) -> None:
        """Create a default Isolation Forest model."""
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.1,  # Assume 10% of events are anomalies
            random_state=42,
            n_jobs=-1
        )

        # Train on synthetic baseline data
        baseline_data = self._generate_baseline_data()
        self.model.fit(baseline_data)

        logger.info("Created and trained default Isolation Forest model")

    def _generate_baseline_data(self, n_samples: int = 1000) -> np.ndarray:
        """
        Generate synthetic baseline data for initial model training.

        Args:
            n_samples: Number of synthetic samples to generate

        Returns:
            Numpy array of baseline features
        """
        np.random.seed(42)

        # Generate normal working hours data (8 AM - 6 PM, weekdays)
        data = []

        for _ in range(n_samples):
            # Normal business hours
            hour = np.random.choice(range(8, 18))  # 8 AM - 6 PM
            day = np.random.choice(range(0, 5))    # Monday - Friday

            features = [
                hour,                                   # hour_of_day
                day,                                    # day_of_week
                0,                                      # is_weekend
                0,                                      # is_off_hours
                np.random.uniform(0.1, 0.3),           # source_ip_entropy (low)
                np.random.uniform(0.2, 0.4),           # user_agent_entropy (low)
                np.random.poisson(5),                  # event_count_1h
                np.random.poisson(50),                 # event_count_24h
                np.random.poisson(3),                  # unique_actions_1h
                np.random.poisson(4),                  # unique_resources_1h
                0,                                      # is_cross_account
                0,                                      # is_admin_action
                0,                                      # is_policy_change
                np.random.choice([0, 1], p=[0.7, 0.3]), # is_s3_action
                np.random.uniform(100, 1000)           # request_size
            ]
            data.append(features)

        return np.array(data)

    def analyze(self, event: Dict[str, Any]) -> AnomalyResult:
        """
        Analyze an event for anomalous behavior.

        Args:
            event: IAM event data

        Returns:
            AnomalyResult with anomaly detection results
        """
        try:
            # Extract features from event
            features = self._extract_features(event)

            # Convert to feature vector
            feature_vector = self._features_to_vector(features)

            # Predict using model
            if self.model is None:
                logger.warning("Model not loaded, creating default model")
                self._create_default_model()

            # Get anomaly score (-1 for anomalies, 1 for normal)
            score = self.model.score_samples([feature_vector])[0]

            # Normalize score to 0-1 range (higher is more anomalous)
            # Isolation Forest scores are typically in range [-0.5, 0.5]
            normalized_score = max(0, min(1, (-score + 0.5)))

            is_anomaly = normalized_score >= self.threshold

            return AnomalyResult(
                is_anomaly=is_anomaly,
                anomaly_score=normalized_score,
                features=features,
                model_version='1.0'
            )

        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}", exc_info=True)
            # Return non-anomalous result on error
            return AnomalyResult(
                is_anomaly=False,
                anomaly_score=0.0,
                features={},
                model_version='error'
            )

    def _extract_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from event for ML model.

        Args:
            event: IAM event data

        Returns:
            Dictionary of extracted features
        """
        features = {}

        # Time-based features
        event_time_str = event.get('eventTime', datetime.utcnow().isoformat())
        try:
            event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
            features['hour_of_day'] = event_time.hour
            features['day_of_week'] = event_time.weekday()
            features['is_weekend'] = 1 if event_time.weekday() >= 5 else 0
            features['is_off_hours'] = 1 if event_time.hour < 6 or event_time.hour >= 22 else 0
        except Exception as e:
            logger.error(f"Error parsing event time: {e}")
            features['hour_of_day'] = 12
            features['day_of_week'] = 2
            features['is_weekend'] = 0
            features['is_off_hours'] = 0

        # Source IP features
        source_ip = event.get('sourceIPAddress', '')
        features['source_ip_entropy'] = self._calculate_entropy(source_ip)

        # User agent features
        user_agent = event.get('userAgent', '')
        features['user_agent_entropy'] = self._calculate_entropy(user_agent)

        # Event frequency features (would need historical data in production)
        # For now, use placeholder values
        features['event_count_1h'] = 5
        features['event_count_24h'] = 50
        features['unique_actions_1h'] = 3
        features['unique_resources_1h'] = 4

        # Event type features
        event_name = event.get('eventName', '')
        user_identity = event.get('userIdentity', {})

        features['is_cross_account'] = 1 if self._is_cross_account(event) else 0
        features['is_admin_action'] = 1 if self._is_admin_action(event_name) else 0
        features['is_policy_change'] = 1 if 'Policy' in event_name else 0
        features['is_s3_action'] = 1 if 's3' in event.get('eventSource', '').lower() else 0

        # Request size (estimate)
        request_params = event.get('requestParameters', {})
        features['request_size'] = len(str(request_params))

        return features

    def _features_to_vector(self, features: Dict[str, Any]) -> np.ndarray:
        """
        Convert features dictionary to numpy vector.

        Args:
            features: Dictionary of features

        Returns:
            Numpy array of feature values
        """
        vector = []
        for name in self.feature_names:
            value = features.get(name, 0)
            vector.append(float(value))

        return np.array(vector)

    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            text: Input string

        Returns:
            Entropy value (0-1)
        """
        if not text:
            return 0.0

        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        text_len = len(text)

        for count in freq.values():
            prob = count / text_len
            if prob > 0:
                entropy -= prob * np.log2(prob)

        # Normalize to 0-1 range
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

    def save_model(self, path: Optional[str] = None) -> None:
        """
        Save trained model to file or GCS.

        Args:
            path: Optional path to save model, defaults to self.model_path
        """
        if self.model is None:
            logger.warning("No model to save")
            return

        save_path = path or self.model_path

        try:
            if save_path.startswith('gs://'):
                # Save to GCS
                parts = save_path.replace('gs://', '').split('/', 1)
                bucket_name = parts[0]
                blob_path = parts[1] if len(parts) > 1 else 'anomaly_detector.pkl'

                storage_client = storage.Client()
                bucket = storage_client.bucket(bucket_name)
                blob = bucket.blob(blob_path)

                model_bytes = pickle.dumps(self.model)
                blob.upload_from_string(model_bytes)

                logger.info(f"Saved model to {save_path}")
            else:
                # Save to local file
                with open(save_path, 'wb') as f:
                    pickle.dump(self.model, f)

                logger.info(f"Saved model to {save_path}")

        except Exception as e:
            logger.error(f"Error saving model: {e}", exc_info=True)
