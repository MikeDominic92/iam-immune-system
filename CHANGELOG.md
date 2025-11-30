# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/MikeDominic92/iam-immune-system/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/MikeDominic92/iam-immune-system/releases/tag/v1.0.0
[0.1.0]: https://github.com/MikeDominic92/iam-immune-system/releases/tag/v0.1.0
