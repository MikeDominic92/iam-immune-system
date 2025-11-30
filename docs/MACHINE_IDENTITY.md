# Machine Identity Security

## Overview

Machine identities (also known as non-human identities or NHIs) are digital credentials used by automated systems, services, and applications to authenticate and access resources. Unlike human identities, machine identities operate autonomously without human intervention, making them both critical for automation and highly attractive targets for attackers.

## The Machine Identity Crisis

### By the Numbers

- **3:1 Ratio**: Machine identities now outnumber human identities by 3 to 1 in modern enterprises
- **45x Growth**: The number of machine identities has grown 45x faster than human identities in the last 5 years
- **90% Unmanaged**: Approximately 90% of machine identities are not properly managed or monitored
- **68% of Breaches**: Involve compromised machine credentials according to Verizon DBIR 2024
- **$4.45M Average Cost**: Data breaches involving compromised machine identities cost on average $4.45M

### Why Machine Identities Matter

1. **Scale**: One compromised machine identity can affect thousands of automated processes
2. **Persistence**: Machine identities typically have long-lived credentials (days, months, or even years)
3. **Privileges**: Service accounts often have elevated privileges to perform automated tasks
4. **Visibility Gap**: Traditional IAM tools focus on human identities, leaving machine identities in blind spots
5. **Attack Surface**: Each machine identity is a potential entry point for attackers

## Types of Machine Identities

### 1. Service Accounts

**AWS/GCP/Azure Service Accounts** - Identities for applications and services

```yaml
Examples:
  - AWS: IAM Roles for EC2, Lambda execution roles
  - GCP: Service accounts (*.iam.gserviceaccount.com)
  - Azure: Managed identities, service principals
```

**Characteristics:**
- Long-lived credentials
- Often have broad permissions
- Used by applications, microservices, and cloud functions
- May have multiple access keys

**Security Risks:**
- Key sprawl (multiple keys per account)
- Overly permissive policies
- Lack of key rotation
- Difficult to track actual usage

### 2. API Keys and Tokens

**API Keys** - Static credentials for API authentication

```yaml
Types:
  - REST API keys
  - GraphQL tokens
  - OAuth client credentials
  - JWT service tokens
  - Personal Access Tokens (PATs)
```

**Characteristics:**
- Often embedded in code or configuration
- May be shared across multiple services
- Rarely rotated
- Hard to audit usage

**Security Risks:**
- Hardcoded in source code
- Committed to version control (Git leaks)
- Shared via insecure channels
- No expiration policies
- Difficult to revoke without breaking services

### 3. Bot and Automation Identities

**Automation Accounts** - Credentials for RPA, chatbots, and scripts

```yaml
Examples:
  - Slack bots
  - GitHub Actions workflows
  - Terraform/Ansible automation
  - Monitoring agents
  - Data pipeline workers
```

**Characteristics:**
- Predictable behavior patterns
- Scheduled execution
- Specific resource access patterns
- Often uses service accounts underneath

**Security Risks:**
- Over-privileged for automation tasks
- Credentials stored in automation tools
- Lack of activity monitoring
- Zombie bots (forgotten/unused)

### 4. CI/CD Pipeline Credentials

**Pipeline Identities** - Credentials for build, test, and deployment

```yaml
Examples:
  - Jenkins service accounts
  - GitHub Actions secrets
  - GitLab CI/CD variables
  - CircleCI contexts
  - Azure DevOps service connections
```

**Characteristics:**
- Need access to production resources
- Used across multiple environments
- Shared among team members
- Frequently require elevated privileges

**Security Risks:**
- Excessive permissions for deployment
- Credentials exposed in build logs
- Lack of IP restrictions
- No multi-factor authentication
- Pipeline injection attacks

### 5. Certificate-Based Authentication

**X.509 Certificates** - PKI-based machine authentication

```yaml
Types:
  - mTLS certificates
  - Client certificates
  - Code signing certificates
  - SSL/TLS certificates with client auth
```

**Characteristics:**
- Cryptographic authentication
- Time-bounded validity
- Can be revoked via CRL/OCSP
- Require private key management

**Security Risks:**
- Long certificate lifetimes (1+ years)
- Private key exposure
- Lack of certificate rotation
- Weak key storage
- No monitoring of certificate usage

### 6. Workload Identities

**Cloud-Native Workload Identities** - Container and serverless credentials

```yaml
Examples:
  - Kubernetes service accounts
  - AWS IAM Roles for Service Accounts (IRSA)
  - GCP Workload Identity
  - Azure Managed Identities for AKS
  - Lambda execution roles
```

**Characteristics:**
- Short-lived tokens
- Automatically rotated
- Tied to specific workloads
- Cloud-provider managed

**Security Risks:**
- Pod escape leading to token theft
- Overly broad RBAC policies
- Cross-namespace access
- Service mesh bypass

## Attack Vectors Targeting Machine Identities

### 1. Credential Theft

**Git Repository Leaks**
```bash
# Attackers scan GitHub for exposed credentials
Pattern: "BEGIN RSA PRIVATE KEY"
Pattern: "aws_access_key_id"
Pattern: "service_account_key.json"
```

**Impact**: Immediate access to cloud resources, data exfiltration, lateral movement

### 2. Service Account Key Sprawl

**Problem**: Organizations lose track of how many keys exist per service account

```yaml
Typical Scenario:
  Service Account: my-app-sa@project.iam.gserviceaccount.com
  Keys Created:
    - 2020-03-15: Original key (still active)
    - 2021-06-22: Backup key (forgotten)
    - 2022-11-10: CI/CD key (still active)
    - 2023-08-19: Developer test key (should be deleted)
    - 2024-01-30: New rotation key (current)

  Total: 5 keys, only 1-2 actually needed
  Attack Surface: 500% larger than necessary
```

### 3. Privilege Escalation via Service Accounts

**Attack Chain**:
1. Attacker compromises low-privilege service account
2. Service account has `iam:PassRole` permission
3. Attacker creates new role with admin permissions
4. Attacker passes admin role to Lambda/EC2 instance
5. Attacker now has admin access

**Real-World Example**: Capital One breach (2019) - SSRF led to IAM role credential theft

### 4. CI/CD Pipeline Poisoning

**Attack Vector**:
```yaml
Step 1: Compromise developer account
Step 2: Modify CI/CD pipeline configuration
Step 3: Inject malicious code in build process
Step 4: Pipeline runs with elevated service account
Step 5: Malicious code executes with production access
```

### 5. Service Account Impersonation Chains

**GCP Example**:
```bash
user@example.com
  -> impersonates -> ci-deployer@project.iam.gserviceaccount.com
    -> impersonates -> prod-admin@project.iam.gserviceaccount.com
      -> has admin access to production
```

**Detection Challenge**: Multi-hop impersonation obscures original actor

### 6. Dormant Account Reactivation

**Scenario**:
- Old service account created 2 years ago
- Original application decommissioned
- Account never deleted
- Still has admin permissions
- Attacker discovers and reactivates dormant account
- No baseline exists for "normal" behavior

## Best Practices for Machine Identity Management

### 1. Inventory and Discovery

**Maintain Complete Inventory**:
```yaml
For Each Machine Identity Track:
  - Identity name and type
  - Creation date
  - Owner/responsible team
  - Purpose and associated workload
  - Permission scope
  - Last activity timestamp
  - Rotation schedule
  - Number of active keys/credentials
```

**Tools**:
- Cloud Asset Inventory (GCP)
- AWS Config
- Azure Resource Graph
- Third-party: CyberArk, HashiCorp Vault, Venafi

### 2. Principle of Least Privilege

**Grant Minimum Necessary Permissions**:
```yaml
Bad Example:
  Service: log-processor
  Role: roles/owner  # Full project access

Good Example:
  Service: log-processor
  Permissions:
    - logging.logEntries.create
    - storage.objects.get
  Resources:
    - projects/my-project/logs/*
    - gs://log-bucket/*
```

### 3. Credential Rotation

**Establish Rotation Policies**:
```yaml
Credential Type: Rotation Frequency
  API Keys: 90 days
  Service Account Keys: 90 days
  Certificates: 180 days
  OAuth Tokens: 30 days
  CI/CD Secrets: 60 days
```

**Automated Rotation**:
- Use cloud-native secret rotation (AWS Secrets Manager, GCP Secret Manager)
- Implement zero-downtime rotation (create new, test, delete old)
- Monitor for rotation failures

### 4. Short-Lived Credentials

**Prefer Temporary Over Static**:
```yaml
Instead of:
  Static API Key: lives forever

Use:
  Workload Identity: 1-hour token
  OIDC Token: 15-minute token
  AWS STS AssumeRole: 1-hour session
```

### 5. Secrets Management

**Centralized Secret Storage**:
```yaml
Recommended Solutions:
  - HashiCorp Vault (dynamic secrets)
  - AWS Secrets Manager
  - GCP Secret Manager
  - Azure Key Vault
  - CyberArk Conjur

Features Needed:
  - Encryption at rest
  - Access logging
  - Dynamic secret generation
  - Automatic rotation
  - Version control
  - Integration with CI/CD
```

### 6. Activity Monitoring and Anomaly Detection

**Establish Behavioral Baselines**:
```yaml
For Each Service Account Track:
  Normal Behavior:
    - Typical API calls (e.g., s3:GetObject, dynamodb:Query)
    - Expected resources (specific buckets, tables)
    - Source IPs (known data center ranges)
    - Time patterns (scheduled jobs at 2 AM UTC)
    - Geographic regions (us-east-1, us-west-2)

  Alert on Deviations:
    - New API calls (e.g., iam:CreateUser)
    - Unexpected resources (different AWS account)
    - Unknown IPs (residential ISP)
    - Off-schedule activity (3 PM instead of 2 AM)
    - New regions (eu-west-1 when only used us-* before)
```

### 7. Service Account Lifecycle Management

**Formal Lifecycle Process**:
```yaml
Creation:
  - Require approval workflow
  - Document business justification
  - Assign owner and expiration date
  - Apply naming convention

Active Use:
  - Monitor usage monthly
  - Audit permissions quarterly
  - Rotate credentials per policy
  - Review access logs

Decommissioning:
  - Detect unused accounts (no activity in 90 days)
  - Notify owner before deletion
  - Archive logs and audit trail
  - Delete account and all keys
```

### 8. IP and Network Restrictions

**Restrict Source Locations**:
```yaml
AWS Example:
  PolicyCondition:
    IpAddress:
      aws:SourceIp:
        - 10.0.0.0/8        # Corporate network
        - 52.95.245.0/24    # CI/CD infrastructure

GCP Example:
  Condition:
    - title: "From known IPs only"
      expression: |
        origin.ip in ['10.0.0.0/8', '35.190.0.0/16']
```

## How IAM-Immune-System Monitors Machine Identities

### Detection Capabilities

The **MachineIdentityDetector** in IAM-Immune-System provides comprehensive monitoring:

#### 1. Service Account Anomaly Detection

```python
Detection: Service account accessing resources outside normal scope
Risk Score: 80/100
Indicators:
  - account: app-backend-sa@project.iam.gserviceaccount.com
  - normal_resources: [gs://app-data/*, bigtable/app-table]
  - anomaly: Accessed gs://financial-records/* (new resource)
Recommendation: Alert security team, verify legitimate expansion
```

#### 2. API Key Usage Monitoring

```python
Detection: API key used from unexpected IP/region
Risk Score: 75/100
Indicators:
  - key_id: AKIAIOSFODNN7EXAMPLE
  - normal_ips: [10.50.0.0/16, 10.60.0.0/16]
  - anomaly_ip: 45.77.123.45 (Vultr Cloud, Romania)
Recommendation: Rotate API key, investigate IP source
```

#### 3. Service Account Key Age Detection

```python
Detection: Service account key older than 90 days
Risk Score: 75/100
Indicators:
  - account: terraform-deploy@project.iam.gserviceaccount.com
  - key_age: 187 days
  - rotation_policy: 90 days
Recommendation: Rotate service account key immediately
```

#### 4. Dormant Account Reactivation

```python
Detection: Dormant service account suddenly active
Risk Score: 85/100
Indicators:
  - account: old-migration-sa@project.iam.gserviceaccount.com
  - last_activity: 2022-08-15 (743 days ago)
  - current_activity: 2024-11-30
  - action: iam:CreateAccessKey
Recommendation: Investigate reactivation, verify legitimacy
```

#### 5. Privilege Escalation Detection

```python
Detection: Service account privilege escalation
Risk Score: 90/100
Indicators:
  - account: app-worker-sa@project.iam.gserviceaccount.com
  - action: iam:AttachRolePolicy
  - target: self (same account)
  - policy: AdministratorAccess
Recommendation: Revoke access immediately, audit all actions
```

#### 6. Cross-Account Usage Detection

```python
Detection: Service account used across AWS accounts
Risk Score: 75/100
Indicators:
  - source_account: 123456789012 (dev)
  - destination_account: 987654321098 (prod)
  - trust_status: untrusted
  - external_id: missing
Recommendation: Verify cross-account access, require ExternalId
```

#### 7. Impersonation Chain Detection

```python
Detection: Deep service account impersonation chain
Risk Score: 85/100
Indicators:
  - chain_depth: 3 levels
  - chain: user@example.com -> sa1 -> sa2 -> sa3
  - final_permissions: roles/owner
Recommendation: Investigate impersonation chain, limit chain depth
```

#### 8. CI/CD Credential Misuse

```python
Detection: CI/CD credentials used from unexpected location
Risk Score: 85/100
Indicators:
  - account: github-actions-deployer@project.iam.gserviceaccount.com
  - expected_ips: [140.82.112.0/20] # GitHub Actions
  - actual_ip: 203.0.113.45 (unknown)
Recommendation: Rotate CI/CD credentials, audit pipeline access
```

### Integration with Secrets Managers

IAM-Immune-System can integrate with secrets managers for automated remediation:

```yaml
Integration: HashiCorp Vault
Actions:
  - Automatic credential rotation on anomaly detection
  - Dynamic secret generation for service accounts
  - Audit log forwarding to centralized SIEM

Integration: AWS Secrets Manager
Actions:
  - Rotate RDS credentials on suspicious access
  - Update Lambda environment variables
  - Trigger SNS notifications on rotation

Integration: GCP Secret Manager
Actions:
  - Create new secret versions
  - Update Cloud Run services with new credentials
  - Log rotation events to Cloud Logging
```

### Configuration

Enable machine identity monitoring in `policies/detection_rules.yaml`:

```yaml
detectors:
  machine_identity:
    enabled: true
    severity: high
    auto_remediate: false  # Manual review recommended
    risk_threshold: 70

    key_rotation_threshold: 90  # days
    dormant_threshold: 30  # days

    known_cicd_ips:
      - 140.82.112.0/20  # GitHub Actions
      - 34.74.90.64/28   # GitLab.com
      - 52.3.0.0/16      # CircleCI

    trusted_accounts:
      - "123456789012"   # Production
      - "234567890123"   # Staging

    monitored_actions:
      - CreateServiceAccount
      - CreateAccessKey
      - AssumeRole
      - ImpersonateServiceAccount
      - PassRole
```

## Machine Identity Security Roadmap

### Current Capabilities (v1.0)
- ✅ Service account anomaly detection
- ✅ API key usage monitoring
- ✅ Dormant account detection
- ✅ Privilege escalation detection
- ✅ Cross-account usage monitoring
- ✅ Impersonation chain detection
- ✅ CI/CD credential monitoring

### Planned Features (v2.0)
- 🔲 Certificate lifecycle management
- 🔲 Dynamic secret integration (Vault)
- 🔲 Machine learning-based behavioral analysis
- 🔲 Automated key rotation workflows
- 🔲 Kubernetes service account monitoring
- 🔲 OAuth/OIDC token monitoring
- 🔲 Service mesh identity tracking (Istio, Linkerd)

### Future Vision (v3.0)
- 🔲 AI-powered anomaly detection
- 🔲 Predictive credential expiration
- 🔲 Self-healing credential rotation
- 🔲 Zero-trust workload identity
- 🔲 Blockchain-based audit trail
- 🔲 Quantum-safe cryptographic identities

## Additional Resources

### Industry Standards
- [NIST SP 800-204C: DevSecOps for Microservices](https://csrc.nist.gov/publications/detail/sp/800-204c/final)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [CIS Benchmarks for Cloud Service Accounts](https://www.cisecurity.org/cis-benchmarks/)

### Research and Reports
- [Verizon DBIR 2024: Credential Theft Trends](https://www.verizon.com/business/resources/reports/dbir/)
- [Gartner: Machine Identity Management Market Guide](https://www.gartner.com/en/documents/4007899)
- [Ponemon Institute: Cost of Credential Compromise](https://www.ponemon.org/)

### Tools and Platforms
- [HashiCorp Vault](https://www.vaultproject.io/) - Dynamic secrets management
- [CyberArk Conjur](https://www.cyberark.com/products/secrets-management/conjur/) - Enterprise secrets management
- [Venafi](https://www.venafi.com/) - Machine identity management platform
- [Teleport](https://goteleport.com/) - Infrastructure access platform
- [AWS IAM Access Analyzer](https://aws.amazon.com/iam/access-analyzer/) - Permission analysis

### Community
- [SPIFFE/SPIRE](https://spiffe.io/) - Workload identity framework
- [Cloud Native Security Whitepaper](https://www.cncf.io/blog/2020/11/18/announcing-the-cloud-native-security-white-paper/)
- [Machine Identity Management LinkedIn Group](https://www.linkedin.com/groups/12345/)

---

**Last Updated**: 2024-11-30
**Maintained By**: Security Engineering Team
**Contact**: security@mikedominic.dev
