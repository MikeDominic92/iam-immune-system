# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2025-12-04

### Added - SailPoint IdentityIQ Integration

#### Core Integration
- **SailPoint IdentityIQ REST API Connector** (`src/integrations/sailpoint_connector.py`)
  - OAuth 2.0 authentication with automatic token refresh
  - Identity retrieval and management
  - Risk score calculation
  - Entitlement queries
  - Mock mode for demos and testing
  - Comprehensive error handling and retry logic

#### Identity Lifecycle Management
- **Webhook Handler** (`src/integrations/webhook_handler.py`)
  - Real-time processing of identity lifecycle events:
    - Joiner events (new employee onboarding)
    - Mover events (role/department changes)
    - Leaver events (employee terminations)
    - Reactivation and suspension events
    - Access request/revocation events
  - HMAC-SHA256 webhook signature verification
  - Event enrichment with SailPoint identity data
  - Risk score calculation per event type
  - Identity health score computation

#### Access Certification
- **Certification Sync** (`src/integrations/certification_sync.py`)
  - Access certification campaign retrieval
  - Certification decision processing (approved/revoked/pending)
  - Policy violation tracking
  - Automatic remediation of revoked access
  - Campaign completion rate tracking
  - Recent revocations reporting

#### Main System Integration
- Enhanced `EventProcessor` class with SailPoint correlation
- Identity correlation with IAM threat detections
- Combined identity health scoring:
  - IAM threat detection risk (40% weight)
  - SailPoint risk score (30% weight)
  - ML anomaly detection (30% weight)
- New HTTP endpoints:
  - `POST /sailpoint_webhook` - Receive SailPoint lifecycle events
  - `GET /certification_status` - View active campaigns and revocations
  - Enhanced `GET /health_check` with SailPoint integration status

#### Configuration & Documentation
- Updated `requirements.txt` with organized dependencies
- Added comprehensive v1.1 section to README.md
- Environment variable configuration:
  - `ENABLE_SAILPOINT_INTEGRATION` - Enable/disable integration
  - `SAILPOINT_BASE_URL` - SailPoint IdentityIQ URL
  - `SAILPOINT_CLIENT_ID` - OAuth client ID
  - `SAILPOINT_CLIENT_SECRET` - OAuth client secret
  - `SAILPOINT_MOCK_MODE` - Demo mode toggle
  - `SAILPOINT_WEBHOOK_SECRET` - Webhook signature verification

### Enhanced
- Health check endpoint now includes SailPoint integration status
- Event processing includes identity correlation
- System version updated to 1.1.0
- Enhanced logging for identity lifecycle events

### Technical Highlights
- Full type hints throughout integration modules
- Comprehensive docstrings and code comments
- Mock mode for demos without SailPoint instance
- Graceful degradation when SailPoint unavailable
- Production-ready error handling
- Retry logic with exponential backoff

## [1.0.0] - 2025-11-30

### Added
- Initial release of IAM Immune System
- Real-time IAM event monitoring via GCP Eventarc
- Public S3 bucket detection and auto-remediation
- Unauthorized IAM admin grant detection
- Policy change detection for sensitive resources
- Cross-account role assumption anomaly detection
- Machine learning-based anomaly detection using Isolation Forest
- Risk scoring system (0-100 scale)
- Automatic remediation capabilities:
  - Revoke unauthorized permissions
  - Block public S3 bucket access
  - Disable compromised credentials
  - Alert notifications
- Multi-channel alerting (Slack, Microsoft Teams, Email)
- Terraform infrastructure as code
- Comprehensive test suite with >90% coverage
- Full documentation including:
  - Architecture diagrams
  - API documentation
  - Security threat model
  - Cost analysis
  - Contributing guidelines
- CI/CD pipeline with GitHub Actions
- Configuration via YAML policy files
- Baseline behavioral analysis
- Continuous ML model training

### Security
- Secrets management via GCP Secret Manager
- Least-privilege IAM roles
- Encrypted data at rest and in transit
- Input validation and sanitization
- Rate limiting and DDoS protection

### Documentation
- Comprehensive README with quick start guide
- Architecture decision records (ADRs)
- Security documentation with threat model
- Cost analysis breakdown
- API reference documentation
- Contributing guidelines

## [0.1.0] - 2025-11-15

### Added
- Project scaffolding
- Basic detector framework
- Proof of concept for public bucket detection

---

[Unreleased]: https://github.com/MikeDominic92/iam-immune-system/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/MikeDominic92/iam-immune-system/releases/tag/v1.1.0
[1.0.0]: https://github.com/MikeDominic92/iam-immune-system/releases/tag/v1.0.0
[0.1.0]: https://github.com/MikeDominic92/iam-immune-system/releases/tag/v0.1.0
