# Security Documentation

## Overview

This document details the security architecture, threat model, and security controls for the IAM Immune System.

## Table of Contents

- [Security Architecture](#security-architecture)
- [Threat Model](#threat-model)
- [Security Controls](#security-controls)
- [Data Protection](#data-protection)
- [Access Control](#access-control)
- [Monitoring & Detection](#monitoring--detection)
- [Incident Response](#incident-response)
- [Compliance](#compliance)

## Security Architecture

### Defense in Depth

The IAM Immune System employs multiple layers of security:

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
│  - Input validation                                      │
│  - Output encoding                                       │
│  - Error handling                                        │
└─────────────────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   Authentication Layer                   │
│  - Service account authentication                        │
│  - Secret Manager for credentials                        │
│  - Short-lived tokens                                    │
└─────────────────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  Authorization Layer                     │
│  - Least privilege IAM roles                            │
│  - Resource-level permissions                           │
│  - Policy-based access control                          │
└─────────────────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────┐
│                     Network Layer                        │
│  - VPC Service Controls (optional)                      │
│  - Private Google Access                                │
│  - Firewall rules                                       │
└─────────────────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────┐
│                      Data Layer                          │
│  - Encryption at rest                                   │
│  - Encryption in transit                                │
│  - Data classification                                  │
└─────────────────────────────────────────────────────────┘
```

### Zero Trust Principles

1. **Never Trust, Always Verify**: Every request is authenticated and authorized
2. **Least Privilege**: Minimum permissions required for each component
3. **Assume Breach**: Design assumes attackers may have internal access
4. **Verify Explicitly**: All access decisions use multiple signals

## Threat Model

### Assets

**Critical Assets:**
- AWS IAM credentials (stored in Secret Manager)
- GCP service account keys
- Detection rules and policies
- ML models and baseline data
- Audit logs and security alerts

**Data Classification:**
- AWS credentials: TOP SECRET
- IAM events: CONFIDENTIAL
- Detection results: CONFIDENTIAL
- Audit logs: INTERNAL
- Documentation: PUBLIC

### Threat Actors

#### 1. External Attackers
**Capability:** Advanced persistent threat (APT)
**Motivation:** Data theft, service disruption
**Vectors:**
- Compromise AWS credentials
- Exploit Cloud Function vulnerabilities
- DDoS attack on event processing
- Poison ML training data

#### 2. Malicious Insiders
**Capability:** Privileged access
**Motivation:** Sabotage, data theft
**Vectors:**
- Disable detection rules
- Modify remediation actions
- Exfiltrate AWS credentials
- Delete audit logs

#### 3. Supply Chain Attacks
**Capability:** Code injection
**Motivation:** Backdoor installation
**Vectors:**
- Compromised Python packages
- Malicious Terraform modules
- Backdoored base images

### Attack Scenarios

#### Scenario 1: Credential Theft

**Attack Flow:**
1. Attacker gains access to GCP project
2. Attempts to read AWS credentials from Secret Manager
3. Uses credentials to access AWS environment

**Mitigations:**
- Secret Manager access requires specific IAM role
- AWS credentials have minimal permissions (read-only + specific remediation)
- Audit logging on all Secret Manager access
- Alert on unusual Secret Manager access patterns
- Use AWS STS temporary credentials where possible

**Detection:**
- Cloud Audit Logs monitoring
- Anomalous API call patterns
- Geographic anomaly detection

#### Scenario 2: Remediation Action Manipulation

**Attack Flow:**
1. Attacker modifies remediation code
2. Instead of blocking threats, system creates backdoors
3. Attacker maintains persistent access

**Mitigations:**
- Code review for all changes
- Immutable function deployments
- Dry-run mode for testing
- Approval required for critical actions
- Git commit signing required
- Function version pinning

**Detection:**
- Function code integrity monitoring
- Unexpected remediation outcomes
- Alert on function source changes

#### Scenario 3: Detection Bypass

**Attack Flow:**
1. Attacker identifies detection patterns
2. Crafts IAM events that avoid detection
3. Performs malicious actions undetected

**Mitigations:**
- Multiple detection layers (rule-based + ML)
- Regular detection rule updates
- Continuous ML model retraining
- Anomaly detection as catch-all
- Human review of high-risk events

**Detection:**
- ML drift detection
- Manual security audits
- Penetration testing

#### Scenario 4: Denial of Service

**Attack Flow:**
1. Attacker floods system with events
2. Cloud Functions overwhelmed
3. Real threats go unprocessed

**Mitigations:**
- Rate limiting at EventBridge level
- Cloud Functions concurrency limits
- Dead letter queue for failed events
- Alert on high event volumes
- Auto-scaling with caps

**Detection:**
- Event volume monitoring
- Function error rate monitoring
- Queue depth alerts

## Security Controls

### Preventive Controls

#### 1. Least Privilege IAM

**GCP Service Account Permissions:**
```yaml
roles:
  - logging.logWriter          # Write logs only
  - pubsub.publisher          # Publish alerts only
  - secretmanager.secretAccessor  # Read secrets only
  - storage.objectViewer      # Read ML models only
```

**AWS IAM Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:DetachUserPolicy",
        "iam:DetachRolePolicy",
        "iam:DeleteUserPolicy",
        "iam:DeleteRolePolicy",
        "s3:PutPublicAccessBlock",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "us-east-1"
        }
      }
    }
  ]
}
```

#### 2. Secrets Management

- All secrets stored in GCP Secret Manager
- Automatic secret rotation (30 days)
- Secret access logged and monitored
- No secrets in code or environment variables (references only)
- Separate secrets for dev/staging/prod

#### 3. Input Validation

```python
def validate_event(event: Dict[str, Any]) -> bool:
    """Validate event structure and content."""
    required_fields = ['eventName', 'eventTime', 'userIdentity']

    # Check required fields
    if not all(field in event for field in required_fields):
        return False

    # Validate timestamp
    try:
        datetime.fromisoformat(event['eventTime'])
    except ValueError:
        return False

    # Sanitize user input
    for key, value in event.items():
        if isinstance(value, str):
            event[key] = html.escape(value)

    return True
```

#### 4. Encryption

- **At Rest:**
  - GCS: AES-256 encryption (Google-managed keys)
  - Secret Manager: AES-256 encryption
  - Pub/Sub: Encrypted by default

- **In Transit:**
  - TLS 1.3 for all API calls
  - HTTPS only for webhooks
  - Certificate pinning for AWS API calls

### Detective Controls

#### 1. Audit Logging

All actions logged to Cloud Logging:
- Function invocations
- Detection results
- Remediation actions
- Secret access
- IAM changes
- Configuration changes

**Log Retention:**
- Critical logs: 365 days
- Security logs: 180 days
- Application logs: 90 days
- Debug logs: 30 days

#### 2. Monitoring Alerts

**Critical Alerts:**
- Secret Manager access from unusual location
- High error rate in detections
- Remediation action failures
- Unexpected AWS API calls
- Function code changes

**Alert Channels:**
- Slack: Real-time alerts
- Email: Daily digest
- PagerDuty: Critical incidents
- SIEM: All security events

#### 3. Anomaly Detection

ML-based detection for:
- Unusual event patterns
- Abnormal function behavior
- Unexpected API call sequences
- Geographic anomalies
- Time-based anomalies

### Corrective Controls

#### 1. Automated Remediation

- Auto-revoke dangerous permissions
- Auto-block public S3 buckets
- Auto-disable compromised credentials
- Alert security team
- Create incident tickets

#### 2. Incident Response

**Severity Levels:**
- **P1 (Critical)**: Active attack, immediate response required
- **P2 (High)**: Potential breach, urgent investigation
- **P3 (Medium)**: Policy violation, scheduled review
- **P4 (Low)**: Informational, routine monitoring

**Response Procedures:**
See [Incident Response](#incident-response) section.

## Data Protection

### Data Classification

| Classification | Examples | Protection |
|---------------|----------|------------|
| TOP SECRET | AWS credentials | Secret Manager, access logged |
| CONFIDENTIAL | IAM events, detections | Encrypted, restricted access |
| INTERNAL | Audit logs | Encrypted, retention policy |
| PUBLIC | Documentation | Version controlled |

### Data Retention

- **AWS Credentials**: Rotated every 30 days
- **IAM Events**: Retained for 90 days
- **ML Training Data**: Retained for 365 days
- **Audit Logs**: Retained for 180 days
- **Backups**: Retained for 30 days

### Data Disposal

- Secure deletion using gcloud commands
- Multi-pass overwrite for sensitive data
- Verification of deletion
- Audit log of disposal

## Access Control

### Principle of Least Privilege

**Production Access:**
- Only service accounts have access
- Human access requires break-glass procedure
- All access logged and monitored
- Time-limited access tokens

**Development Access:**
- Separate dev environment
- No access to production secrets
- Synthetic test data only
- Code review required for changes

### Break-Glass Procedure

For emergency production access:

1. Submit break-glass request with justification
2. Approval from security team (2 people)
3. Time-limited access granted (1-4 hours)
4. All actions logged
5. Post-incident review required

## Monitoring & Detection

### Key Metrics

- Event processing rate
- Detection accuracy (true/false positives)
- Remediation success rate
- Function error rate
- API latency
- Cost per event

### Security Dashboards

1. **Executive Dashboard**
   - Total threats detected
   - Auto-remediation rate
   - Current risk score
   - Cost trends

2. **Operations Dashboard**
   - Event volume
   - Function performance
   - Error rates
   - Queue depths

3. **Security Dashboard**
   - Detection breakdown by type
   - ML anomaly trends
   - Remediation actions
   - Failed attempts

## Incident Response

### Response Team

- **Incident Commander**: Security team lead
- **Technical Lead**: On-call engineer
- **Communications**: PR/Marketing
- **Legal**: Compliance officer

### Response Phases

#### 1. Detection & Analysis (0-15 minutes)
- Validate alert is legitimate
- Determine severity
- Assess scope of impact
- Begin timeline documentation

#### 2. Containment (15-60 minutes)
- Isolate affected systems
- Revoke compromised credentials
- Block malicious IPs
- Preserve evidence

#### 3. Eradication (1-4 hours)
- Remove malicious code
- Patch vulnerabilities
- Update detection rules
- Rotate all credentials

#### 4. Recovery (4-24 hours)
- Restore from backups if needed
- Re-enable services
- Verify system integrity
- Monitor for reinfection

#### 5. Post-Incident (1-7 days)
- Root cause analysis
- Update runbooks
- Improve detections
- Security training

### Communication Plan

**Internal:**
- Slack: Immediate notification
- Email: Status updates every 2 hours
- Incident report: Within 24 hours

**External:**
- Customers: Within 4 hours (if affected)
- Regulators: As required by law
- Public: Via status page

## Compliance

### Standards & Frameworks

- **SOC 2 Type II**: Security, availability, confidentiality
- **PCI-DSS**: If processing payment data
- **GDPR**: If processing EU personal data
- **HIPAA**: If processing health information
- **CIS Benchmarks**: AWS and GCP

### Compliance Controls

| Control | Implementation |
|---------|---------------|
| Access Control | IAM, Secret Manager |
| Audit Logging | Cloud Logging, 180-day retention |
| Encryption | At-rest and in-transit |
| Incident Response | Documented procedures |
| Vulnerability Management | Weekly scans |
| Change Management | Git, code review |
| Business Continuity | Disaster recovery plan |

### Audit Trail

All compliance-relevant events logged:
- User access
- Configuration changes
- Data access
- Remediation actions
- System changes

**Log Format:**
```json
{
  "timestamp": "2025-11-30T12:00:00Z",
  "action": "secret.access",
  "user": "service-account@project.iam.gserviceaccount.com",
  "resource": "projects/123/secrets/aws-credentials",
  "result": "success",
  "ip_address": "10.0.0.1"
}
```

## Security Testing

### Regular Testing

- **Daily**: Automated security scans
- **Weekly**: Dependency vulnerability scans
- **Monthly**: Penetration testing
- **Quarterly**: Security audit
- **Annually**: Third-party assessment

### Test Scenarios

1. **Credential Compromise**: Simulate AWS credential theft
2. **Privilege Escalation**: Attempt to gain admin access
3. **Detection Bypass**: Try to evade detection rules
4. **DDoS**: Flood system with events
5. **Code Injection**: Attempt to modify function code

## Security Contacts

- **Security Team**: security-team@company.com
- **CISO**: ciso@company.com
- **Incident Response**: incident-response@company.com
- **Bug Bounty**: security@company.com

## Responsible Disclosure

If you discover a security vulnerability:

1. **DO NOT** open a public GitHub issue
2. Email security@company.com with:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Your contact information
3. We will respond within 24 hours
4. We will fix critical issues within 7 days
5. We will credit you (if desired) after fix

## Security Updates

This document is reviewed and updated:
- Monthly: Routine review
- After incidents: Lessons learned
- After major changes: Architecture updates

**Last Updated:** 2025-11-30
**Next Review:** 2025-12-30
