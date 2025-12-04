"""
SailPoint IdentityIQ Integration Module

This module provides integration with SailPoint IdentityIQ for identity lifecycle
management, access certification, and identity health scoring.

Version: 1.1
Created: December 2025
Author: IAM Immune System v1.1 Enhancement
"""

from .sailpoint_connector import SailPointConnector
from .webhook_handler import WebhookHandler, IdentityEvent, IdentityEventType
from .certification_sync import CertificationSync, CertificationResult

__all__ = [
    'SailPointConnector',
    'WebhookHandler',
    'IdentityEvent',
    'IdentityEventType',
    'CertificationSync',
    'CertificationResult',
]

__version__ = '1.1.0'
