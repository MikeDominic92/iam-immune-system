"""
Machine Learning modules for anomaly detection.

This package contains ML models for detecting anomalous IAM behavior:
- Isolation Forest for anomaly detection
- Baseline builder for normal behavior patterns
"""

from .anomaly_detector import AnomalyDetector, AnomalyResult
from .baseline_builder import BaselineBuilder

__all__ = ['AnomalyDetector', 'AnomalyResult', 'BaselineBuilder']
