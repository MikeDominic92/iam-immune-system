"""
SailPoint IdentityIQ REST API Connector

This module provides a robust connector for interacting with SailPoint IdentityIQ
REST API for identity lifecycle management and access governance.

Version: 1.1 - December 2025 Enhancement
Features:
    - REST API authentication and session management
    - Identity retrieval and management
    - Access certification operations
    - Mock mode for demos and testing
    - Comprehensive error handling and retry logic
"""

import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class IdentityStatus(Enum):
    """Identity status in SailPoint."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    TERMINATED = "terminated"


@dataclass
class Identity:
    """Represents a SailPoint identity."""
    id: str
    name: str
    email: str
    status: IdentityStatus
    department: Optional[str] = None
    manager: Optional[str] = None
    last_login: Optional[datetime] = None
    risk_score: float = 0.0
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert identity to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'status': self.status.value,
            'department': self.department,
            'manager': self.manager,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'risk_score': self.risk_score,
            'attributes': self.attributes
        }


class SailPointConnector:
    """
    Connector for SailPoint IdentityIQ REST API.

    Provides methods for interacting with SailPoint IdentityIQ including:
    - Identity management
    - Access requests
    - Certification campaigns
    - Risk scoring

    Supports both production and mock modes for testing/demos.

    Args:
        base_url: SailPoint IdentityIQ base URL
        client_id: OAuth client ID
        client_secret: OAuth client secret
        mock_mode: Enable mock mode for demos (default: False)
        timeout: Request timeout in seconds (default: 30)

    Example:
        >>> connector = SailPointConnector(
        ...     base_url="https://sailpoint.company.com",
        ...     client_id="client_id",
        ...     client_secret="secret",
        ...     mock_mode=False
        ... )
        >>> identity = connector.get_identity("john.doe")
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        mock_mode: bool = False,
        timeout: int = 30
    ):
        """Initialize SailPoint connector."""
        self.base_url = base_url or os.getenv('SAILPOINT_BASE_URL', '')
        self.client_id = client_id or os.getenv('SAILPOINT_CLIENT_ID', '')
        self.client_secret = client_secret or os.getenv('SAILPOINT_CLIENT_SECRET', '')
        self.mock_mode = mock_mode or os.getenv('SAILPOINT_MOCK_MODE', 'false').lower() == 'true'
        self.timeout = timeout
        self.access_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None

        # Configure session with retry logic
        self.session = self._create_session()

        logger.info(
            f"SailPoint connector initialized (mock_mode={self.mock_mode})"
        )

        if not self.mock_mode and not all([self.base_url, self.client_id, self.client_secret]):
            logger.warning(
                "SailPoint credentials not fully configured. "
                "Set SAILPOINT_BASE_URL, SAILPOINT_CLIENT_ID, and SAILPOINT_CLIENT_SECRET."
            )

    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic."""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def _authenticate(self) -> None:
        """
        Authenticate with SailPoint IdentityIQ and obtain access token.

        Raises:
            requests.exceptions.RequestException: If authentication fails
        """
        if self.mock_mode:
            self.access_token = "mock_token_12345"
            self.token_expiry = datetime.utcnow() + timedelta(hours=1)
            logger.info("Mock authentication successful")
            return

        auth_url = f"{self.base_url}/oauth/token"

        try:
            response = self.session.post(
                auth_url,
                data={
                    'grant_type': 'client_credentials',
                    'client_id': self.client_id,
                    'client_secret': self.client_secret
                },
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            self.access_token = data.get('access_token')
            expires_in = data.get('expires_in', 3600)
            self.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)

            logger.info("SailPoint authentication successful")

        except requests.exceptions.RequestException as e:
            logger.error(f"SailPoint authentication failed: {e}")
            raise

    def _ensure_authenticated(self) -> None:
        """Ensure we have a valid access token."""
        if not self.access_token or not self.token_expiry:
            self._authenticate()
        elif datetime.utcnow() >= self.token_expiry - timedelta(minutes=5):
            # Refresh token if expiring in 5 minutes
            logger.info("Access token expiring soon, refreshing...")
            self._authenticate()

    def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Make authenticated request to SailPoint API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            **kwargs: Additional arguments for requests

        Returns:
            Response JSON data

        Raises:
            requests.exceptions.RequestException: If request fails
        """
        self._ensure_authenticated()

        url = f"{self.base_url}/api/v3/{endpoint.lstrip('/')}"
        headers = kwargs.pop('headers', {})
        headers['Authorization'] = f'Bearer {self.access_token}'
        headers['Content-Type'] = 'application/json'

        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                timeout=self.timeout,
                **kwargs
            )
            response.raise_for_status()

            return response.json() if response.content else {}

        except requests.exceptions.RequestException as e:
            logger.error(f"SailPoint API request failed: {method} {endpoint} - {e}")
            raise

    def get_identity(self, identity_id: str) -> Optional[Identity]:
        """
        Retrieve identity by ID or email.

        Args:
            identity_id: Identity ID or email address

        Returns:
            Identity object or None if not found
        """
        if self.mock_mode:
            return self._get_mock_identity(identity_id)

        try:
            data = self._make_request('GET', f'identities/{identity_id}')
            return self._parse_identity(data)

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Identity not found: {identity_id}")
                return None
            raise

    def search_identities(
        self,
        query: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100
    ) -> List[Identity]:
        """
        Search for identities.

        Args:
            query: Search query string
            filters: Additional filters
            limit: Maximum results to return

        Returns:
            List of Identity objects
        """
        if self.mock_mode:
            return self._get_mock_identities(limit)

        try:
            params = {'limit': limit}
            if query:
                params['query'] = query
            if filters:
                params.update(filters)

            data = self._make_request('GET', 'identities', params=params)

            return [
                self._parse_identity(item)
                for item in data.get('items', [])
            ]

        except requests.exceptions.RequestException as e:
            logger.error(f"Identity search failed: {e}")
            return []

    def get_identity_risk_score(self, identity_id: str) -> float:
        """
        Get risk score for an identity.

        Args:
            identity_id: Identity ID

        Returns:
            Risk score (0-100)
        """
        if self.mock_mode:
            # Return mock risk score based on identity_id hash
            return float(hash(identity_id) % 100)

        try:
            data = self._make_request('GET', f'identities/{identity_id}/risk-score')
            return data.get('riskScore', 0.0)

        except requests.exceptions.RequestException:
            logger.warning(f"Could not retrieve risk score for {identity_id}")
            return 0.0

    def get_identity_entitlements(self, identity_id: str) -> List[Dict[str, Any]]:
        """
        Get all entitlements for an identity.

        Args:
            identity_id: Identity ID

        Returns:
            List of entitlement dictionaries
        """
        if self.mock_mode:
            return self._get_mock_entitlements(identity_id)

        try:
            data = self._make_request(
                'GET',
                f'identities/{identity_id}/entitlements'
            )
            return data.get('items', [])

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to retrieve entitlements: {e}")
            return []

    def _parse_identity(self, data: Dict[str, Any]) -> Identity:
        """Parse identity data from API response."""
        return Identity(
            id=data.get('id', ''),
            name=data.get('name', ''),
            email=data.get('email', ''),
            status=IdentityStatus(data.get('status', 'active')),
            department=data.get('department'),
            manager=data.get('manager', {}).get('name') if data.get('manager') else None,
            last_login=datetime.fromisoformat(data['lastLogin']) if data.get('lastLogin') else None,
            risk_score=data.get('riskScore', 0.0),
            attributes=data.get('attributes', {})
        )

    # Mock mode methods for demos

    def _get_mock_identity(self, identity_id: str) -> Identity:
        """Get mock identity for demo mode."""
        return Identity(
            id=identity_id,
            name=f"Mock User {identity_id}",
            email=f"{identity_id}@company.com",
            status=IdentityStatus.ACTIVE,
            department="Engineering",
            manager="manager@company.com",
            last_login=datetime.utcnow() - timedelta(hours=2),
            risk_score=45.0,
            attributes={
                'employeeNumber': '12345',
                'location': 'US-East',
                'title': 'Senior Engineer'
            }
        )

    def _get_mock_identities(self, limit: int) -> List[Identity]:
        """Get mock identities for demo mode."""
        return [
            Identity(
                id=f"user{i}",
                name=f"Mock User {i}",
                email=f"user{i}@company.com",
                status=IdentityStatus.ACTIVE,
                department="Engineering" if i % 2 == 0 else "Sales",
                manager=f"manager{i % 3}@company.com",
                last_login=datetime.utcnow() - timedelta(hours=i),
                risk_score=float(i * 10 % 100),
                attributes={}
            )
            for i in range(min(limit, 10))
        ]

    def _get_mock_entitlements(self, identity_id: str) -> List[Dict[str, Any]]:
        """Get mock entitlements for demo mode."""
        return [
            {
                'id': f'ent{i}',
                'name': f'Access to {resource}',
                'source': 'Active Directory',
                'value': f'{resource}_access',
                'privileged': i == 0
            }
            for i, resource in enumerate(['AWS', 'GitHub', 'Salesforce'])
        ]

    def health_check(self) -> Dict[str, Any]:
        """
        Check SailPoint connector health.

        Returns:
            Health status dictionary
        """
        health = {
            'status': 'unknown',
            'mock_mode': self.mock_mode,
            'authenticated': False,
            'timestamp': datetime.utcnow().isoformat()
        }

        try:
            if self.mock_mode:
                health['status'] = 'healthy'
                health['authenticated'] = True
            else:
                self._ensure_authenticated()
                health['status'] = 'healthy'
                health['authenticated'] = self.access_token is not None

        except Exception as e:
            health['status'] = 'unhealthy'
            health['error'] = str(e)
            logger.error(f"Health check failed: {e}")

        return health
