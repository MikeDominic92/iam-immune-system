"""
SailPoint Access Certification Campaign Synchronization

This module synchronizes access certification campaigns from SailPoint IdentityIQ
and processes certification results to improve identity health scoring.

Version: 1.1 - December 2025 Enhancement
Features:
    - Certification campaign retrieval
    - Decision processing (approved/revoked)
    - Policy violation tracking
    - Remediation tracking
    - Mock mode for demos
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from .sailpoint_connector import SailPointConnector

logger = logging.getLogger(__name__)


class CertificationStatus(Enum):
    """Status of certification campaign."""
    ACTIVE = "active"
    COMPLETED = "completed"
    SCHEDULED = "scheduled"
    CANCELLED = "cancelled"


class CertificationDecision(Enum):
    """Certification decision types."""
    APPROVED = "approved"
    REVOKED = "revoked"
    DELEGATED = "delegated"
    PENDING = "pending"
    EXCEPTION = "exception"


@dataclass
class CertificationItem:
    """Represents a single certification item."""
    id: str
    campaign_id: str
    identity_id: str
    identity_name: str
    entitlement_id: str
    entitlement_name: str
    decision: CertificationDecision
    decision_maker: Optional[str] = None
    decision_date: Optional[datetime] = None
    comments: Optional[str] = None
    risk_level: str = "low"
    policy_violations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'campaign_id': self.campaign_id,
            'identity_id': self.identity_id,
            'identity_name': self.identity_name,
            'entitlement_id': self.entitlement_id,
            'entitlement_name': self.entitlement_name,
            'decision': self.decision.value,
            'decision_maker': self.decision_maker,
            'decision_date': self.decision_date.isoformat() if self.decision_date else None,
            'comments': self.comments,
            'risk_level': self.risk_level,
            'policy_violations': self.policy_violations
        }


@dataclass
class CertificationCampaign:
    """Represents an access certification campaign."""
    id: str
    name: str
    description: str
    status: CertificationStatus
    start_date: datetime
    end_date: datetime
    total_items: int = 0
    completed_items: int = 0
    approved_items: int = 0
    revoked_items: int = 0
    pending_items: int = 0
    items: List[CertificationItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'status': self.status.value,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat(),
            'total_items': self.total_items,
            'completed_items': self.completed_items,
            'approved_items': self.approved_items,
            'revoked_items': self.revoked_items,
            'pending_items': self.pending_items,
            'completion_rate': self.get_completion_rate()
        }

    def get_completion_rate(self) -> float:
        """Calculate completion rate percentage."""
        if self.total_items == 0:
            return 0.0
        return (self.completed_items / self.total_items) * 100


@dataclass
class CertificationResult:
    """Results from certification sync operation."""
    campaign_id: str
    sync_timestamp: datetime
    items_processed: int = 0
    revocations_found: int = 0
    policy_violations_found: int = 0
    high_risk_items: int = 0
    errors: List[str] = field(default_factory=list)
    success: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'campaign_id': self.campaign_id,
            'sync_timestamp': self.sync_timestamp.isoformat(),
            'items_processed': self.items_processed,
            'revocations_found': self.revocations_found,
            'policy_violations_found': self.policy_violations_found,
            'high_risk_items': self.high_risk_items,
            'errors': self.errors,
            'success': self.success
        }


class CertificationSync:
    """
    Synchronizes access certification data from SailPoint IdentityIQ.

    Processes certification campaigns and decisions to:
    - Track access revocations
    - Identify policy violations
    - Update identity health scores
    - Trigger remediation actions

    Args:
        sailpoint_connector: SailPoint API connector
        auto_remediate: Automatically remediate revoked access
        mock_mode: Enable mock mode for demos

    Example:
        >>> sync = CertificationSync(connector, auto_remediate=True)
        >>> campaigns = sync.get_active_campaigns()
        >>> for campaign in campaigns:
        ...     result = sync.sync_campaign(campaign.id)
        ...     print(f"Processed {result.items_processed} items")
    """

    def __init__(
        self,
        sailpoint_connector: SailPointConnector,
        auto_remediate: bool = False,
        mock_mode: bool = False
    ):
        """Initialize certification sync."""
        self.connector = sailpoint_connector
        self.auto_remediate = auto_remediate
        self.mock_mode = mock_mode

        logger.info(
            f"CertificationSync initialized "
            f"(auto_remediate={auto_remediate}, mock_mode={mock_mode})"
        )

    def get_active_campaigns(self) -> List[CertificationCampaign]:
        """
        Get all active certification campaigns.

        Returns:
            List of active campaigns
        """
        if self.mock_mode:
            return self._get_mock_campaigns()

        try:
            data = self.connector._make_request(
                'GET',
                'certifications',
                params={'status': 'active'}
            )

            campaigns = []
            for item in data.get('items', []):
                campaign = self._parse_campaign(item)
                if campaign:
                    campaigns.append(campaign)

            logger.info(f"Found {len(campaigns)} active certification campaigns")
            return campaigns

        except Exception as e:
            logger.error(f"Failed to retrieve campaigns: {e}", exc_info=True)
            return []

    def get_campaign(self, campaign_id: str) -> Optional[CertificationCampaign]:
        """
        Get specific certification campaign.

        Args:
            campaign_id: Campaign ID

        Returns:
            Campaign or None if not found
        """
        if self.mock_mode:
            return self._get_mock_campaign(campaign_id)

        try:
            data = self.connector._make_request(
                'GET',
                f'certifications/{campaign_id}'
            )
            return self._parse_campaign(data)

        except Exception as e:
            logger.error(f"Failed to retrieve campaign {campaign_id}: {e}")
            return None

    def sync_campaign(
        self,
        campaign_id: str,
        include_items: bool = True
    ) -> CertificationResult:
        """
        Synchronize certification campaign data.

        Args:
            campaign_id: Campaign ID to sync
            include_items: Include certification items

        Returns:
            Sync result
        """
        result = CertificationResult(
            campaign_id=campaign_id,
            sync_timestamp=datetime.utcnow()
        )

        try:
            # Get campaign details
            campaign = self.get_campaign(campaign_id)

            if not campaign:
                result.success = False
                result.errors.append(f"Campaign {campaign_id} not found")
                return result

            # Get certification items if requested
            if include_items:
                items = self.get_certification_items(campaign_id)
                campaign.items = items
                result.items_processed = len(items)

                # Process items
                for item in items:
                    # Count revocations
                    if item.decision == CertificationDecision.REVOKED:
                        result.revocations_found += 1

                        # Auto-remediate if enabled
                        if self.auto_remediate:
                            self._remediate_revocation(item)

                    # Count policy violations
                    if item.policy_violations:
                        result.policy_violations_found += len(item.policy_violations)

                    # Count high-risk items
                    if item.risk_level in ['high', 'critical']:
                        result.high_risk_items += 1

            logger.info(
                f"Campaign {campaign_id} sync completed: "
                f"{result.items_processed} items, "
                f"{result.revocations_found} revocations, "
                f"{result.policy_violations_found} violations"
            )

            return result

        except Exception as e:
            logger.error(f"Error syncing campaign {campaign_id}: {e}", exc_info=True)
            result.success = False
            result.errors.append(str(e))
            return result

    def get_certification_items(
        self,
        campaign_id: str,
        decision_filter: Optional[CertificationDecision] = None
    ) -> List[CertificationItem]:
        """
        Get certification items for a campaign.

        Args:
            campaign_id: Campaign ID
            decision_filter: Optional filter by decision type

        Returns:
            List of certification items
        """
        if self.mock_mode:
            return self._get_mock_items(campaign_id, decision_filter)

        try:
            params = {}
            if decision_filter:
                params['decision'] = decision_filter.value

            data = self.connector._make_request(
                'GET',
                f'certifications/{campaign_id}/items',
                params=params
            )

            items = []
            for item_data in data.get('items', []):
                item = self._parse_certification_item(item_data, campaign_id)
                if item:
                    items.append(item)

            return items

        except Exception as e:
            logger.error(
                f"Failed to retrieve items for campaign {campaign_id}: {e}",
                exc_info=True
            )
            return []

    def get_revocations(
        self,
        campaign_id: Optional[str] = None,
        days: int = 30
    ) -> List[CertificationItem]:
        """
        Get recent access revocations.

        Args:
            campaign_id: Optional campaign ID filter
            days: Number of days to look back

        Returns:
            List of revoked items
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        if campaign_id:
            items = self.get_certification_items(
                campaign_id,
                CertificationDecision.REVOKED
            )
        else:
            # Get revocations from all campaigns
            items = []
            campaigns = self.get_active_campaigns()
            for campaign in campaigns:
                campaign_items = self.get_certification_items(
                    campaign.id,
                    CertificationDecision.REVOKED
                )
                items.extend(campaign_items)

        # Filter by date
        recent_items = [
            item for item in items
            if item.decision_date and item.decision_date >= cutoff_date
        ]

        logger.info(
            f"Found {len(recent_items)} revocations in the last {days} days"
        )

        return recent_items

    def _parse_campaign(self, data: Dict[str, Any]) -> Optional[CertificationCampaign]:
        """Parse campaign data from API response."""
        try:
            return CertificationCampaign(
                id=data['id'],
                name=data['name'],
                description=data.get('description', ''),
                status=CertificationStatus(data.get('status', 'active')),
                start_date=self._parse_date(data.get('startDate')),
                end_date=self._parse_date(data.get('endDate')),
                total_items=data.get('totalItems', 0),
                completed_items=data.get('completedItems', 0),
                approved_items=data.get('approvedItems', 0),
                revoked_items=data.get('revokedItems', 0),
                pending_items=data.get('pendingItems', 0)
            )
        except (KeyError, ValueError) as e:
            logger.error(f"Failed to parse campaign: {e}")
            return None

    def _parse_certification_item(
        self,
        data: Dict[str, Any],
        campaign_id: str
    ) -> Optional[CertificationItem]:
        """Parse certification item from API response."""
        try:
            return CertificationItem(
                id=data['id'],
                campaign_id=campaign_id,
                identity_id=data['identity']['id'],
                identity_name=data['identity']['name'],
                entitlement_id=data['entitlement']['id'],
                entitlement_name=data['entitlement']['name'],
                decision=CertificationDecision(data.get('decision', 'pending')),
                decision_maker=data.get('decisionMaker'),
                decision_date=self._parse_date(data.get('decisionDate')),
                comments=data.get('comments'),
                risk_level=data.get('riskLevel', 'low'),
                policy_violations=data.get('policyViolations', [])
            )
        except (KeyError, ValueError) as e:
            logger.error(f"Failed to parse certification item: {e}")
            return None

    def _parse_date(self, date_str: Optional[str]) -> datetime:
        """Parse date string to datetime."""
        if not date_str:
            return datetime.utcnow()

        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return datetime.utcnow()

    def _remediate_revocation(self, item: CertificationItem) -> None:
        """
        Remediate revoked access.

        Args:
            item: Certification item with revoked decision
        """
        try:
            logger.info(
                f"Auto-remediating revoked access: "
                f"{item.entitlement_name} for {item.identity_name}"
            )

            # In production, this would call the remediation API
            # For now, just log the action
            if self.mock_mode:
                logger.info(f"[MOCK] Revoked access remediated for {item.identity_id}")
            else:
                # Call SailPoint remediation API
                self.connector._make_request(
                    'POST',
                    'remediation',
                    json={
                        'certificationItemId': item.id,
                        'action': 'revoke',
                        'identityId': item.identity_id,
                        'entitlementId': item.entitlement_id
                    }
                )
                logger.info(f"Remediation initiated for {item.identity_id}")

        except Exception as e:
            logger.error(f"Failed to remediate revocation: {e}", exc_info=True)

    # Mock mode methods

    def _get_mock_campaigns(self) -> List[CertificationCampaign]:
        """Get mock campaigns for demo mode."""
        now = datetime.utcnow()
        return [
            CertificationCampaign(
                id=f"campaign{i}",
                name=f"Q{i} Access Review",
                description=f"Quarterly access certification review {i}",
                status=CertificationStatus.ACTIVE,
                start_date=now - timedelta(days=14),
                end_date=now + timedelta(days=16),
                total_items=100 + i * 20,
                completed_items=60 + i * 10,
                approved_items=50 + i * 8,
                revoked_items=8 + i,
                pending_items=42 - i * 10
            )
            for i in range(1, 3)
        ]

    def _get_mock_campaign(self, campaign_id: str) -> CertificationCampaign:
        """Get mock campaign for demo mode."""
        now = datetime.utcnow()
        return CertificationCampaign(
            id=campaign_id,
            name="Mock Q4 Access Review",
            description="Mock quarterly access certification review",
            status=CertificationStatus.ACTIVE,
            start_date=now - timedelta(days=14),
            end_date=now + timedelta(days=16),
            total_items=150,
            completed_items=90,
            approved_items=75,
            revoked_items=12,
            pending_items=60
        )

    def _get_mock_items(
        self,
        campaign_id: str,
        decision_filter: Optional[CertificationDecision] = None
    ) -> List[CertificationItem]:
        """Get mock certification items."""
        items = []
        decisions = [CertificationDecision.APPROVED, CertificationDecision.REVOKED, CertificationDecision.PENDING]

        for i in range(10):
            decision = decisions[i % 3]

            if decision_filter and decision != decision_filter:
                continue

            items.append(CertificationItem(
                id=f"item{i}",
                campaign_id=campaign_id,
                identity_id=f"user{i}",
                identity_name=f"Mock User {i}",
                entitlement_id=f"ent{i}",
                entitlement_name=f"Access to System {i % 3}",
                decision=decision,
                decision_maker=f"manager{i % 2}@company.com" if decision != CertificationDecision.PENDING else None,
                decision_date=datetime.utcnow() - timedelta(days=i) if decision != CertificationDecision.PENDING else None,
                comments=f"Mock comment {i}" if i % 2 == 0 else None,
                risk_level="high" if i % 4 == 0 else "low",
                policy_violations=["SOD_VIOLATION"] if i % 5 == 0 else []
            ))

        return items
