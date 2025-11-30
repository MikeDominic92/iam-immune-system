# Architecture Documentation

## System Overview

IAM Immune System is a multi-cloud, event-driven security platform that monitors AWS IAM events in real-time and automatically remediates security threats using AI/ML anomaly detection.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                            AWS Cloud                                 │
│                                                                      │
│  ┌──────────────┐    ┌─────────────┐    ┌──────────────┐          │
│  │  IAM Events  │───▶│ CloudTrail  │───▶│ EventBridge  │          │
│  └──────────────┘    └─────────────┘    └──────┬───────┘          │
│                                                  │                   │
│                                                  │ HTTP Webhook     │
└──────────────────────────────────────────────────┼──────────────────┘
                                                   │
                                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           GCP Cloud                                  │
│                                                                      │
│  ┌──────────────┐    ┌─────────────┐    ┌──────────────┐          │
│  │   Eventarc   │───▶│   Pub/Sub   │───▶│Cloud Function│          │
│  │   Channel    │    │    Queue    │    │  (Gen 2)     │          │
│  └──────────────┘    └─────────────┘    └──────┬───────┘          │
│                                                  │                   │
│                                                  ▼                   │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │           Event Processing Pipeline                      │       │
│  │                                                          │       │
│  │  ┌───────────┐  ┌─────────┐  ┌──────────────┐         │       │
│  │  │ Detectors │─▶│ ML Model│─▶│ Remediators  │         │       │
│  │  └───────────┘  └─────────┘  └──────────────┘         │       │
│  └─────────────────────────────────────────────────────────┘       │
│                         │              │                            │
│                         ▼              ▼                            │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐             │
│  │Cloud Logging │  │   Pub/Sub   │  │  Storage     │             │
│  │   (Audit)    │  │  (Alerts)   │  │ (ML Models)  │             │
│  └──────────────┘  └─────────────┘  └──────────────┘             │
│                         │                                           │
└─────────────────────────┼───────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Notification Channels                            │
│                                                                      │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    │
│  │  Slack   │    │  Teams   │    │  Email   │    │PagerDuty │    │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Event Ingestion Layer

#### AWS CloudTrail
**Purpose:** Capture all IAM API calls in AWS
**Configuration:**
- Multi-region trail enabled
- Management events: All
- Data events: S3 buckets (optional)
- Log file validation: Enabled

#### AWS EventBridge
**Purpose:** Filter and route IAM events to GCP
**Rules:**
```json
{
  "source": ["aws.iam", "aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "AttachUserPolicy",
      "AttachRolePolicy",
      "PutBucketPolicy",
      "AssumeRole",
      "CreateAccessKey"
    ]
  }
}
```

**Targets:**
- HTTP endpoint → GCP Eventarc webhook

### 2. Event Routing Layer

#### GCP Eventarc
**Purpose:** Receive events from AWS and route to Cloud Functions
**Features:**
- Event filtering and transformation
- Automatic retries
- Dead letter queue integration
- CloudEvent format standardization

**Channel Configuration:**
```yaml
name: aws-cloudtrail-channel
location: us-central1
provider: aws
```

#### GCP Pub/Sub
**Purpose:** Event queue and buffer
**Topics:**
- `iam-events`: Incoming IAM events
- `iam-alerts`: Processed alerts
- `ml-training-triggers`: ML model retraining
- `iam-events-dead-letter`: Failed events

**Features:**
- Message retention: 24 hours
- Acknowledgment deadline: 600s
- Retry policy: Exponential backoff
- Dead letter policy: 5 max attempts

### 3. Processing Layer

#### Cloud Functions (Gen2)
**Purpose:** Serverless event processing
**Specifications:**
- Runtime: Python 3.11
- Memory: 512 MB
- Timeout: 540s (9 minutes)
- Max instances: 10
- Min instances: 0 (scale to zero)

**Environment:**
```yaml
GCP_PROJECT_ID: your-project
GCP_REGION: us-central1
ML_MODEL_PATH: gs://bucket/models/anomaly_detector.pkl
AUTO_REMEDIATION: true
LOG_LEVEL: INFO
```

### 4. Detection Layer

#### Rule-Based Detectors

**Public Bucket Detector**
- Monitors: `PutBucketPolicy`, `PutBucketAcl`, `DeleteBucketPublicAccessBlock`
- Analyzes: Policy content, ACL permissions, public access settings
- Risk factors: Public principal, sensitive bucket name, policy wildcards

**Admin Grant Detector**
- Monitors: `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`
- Analyzes: Policy content, principal identity, timing
- Risk factors: Admin policies, wildcard permissions, off-hours activity

**Policy Change Detector**
- Monitors: `CreatePolicy`, `DeletePolicy`, `SetDefaultPolicyVersion`
- Analyzes: Policy content, affected resources, change frequency
- Risk factors: Security service policies, deletion events, rapid changes

**Cross-Account Detector**
- Monitors: `AssumeRole`, `GetFederationToken`
- Analyzes: Source account, ExternalId presence, session policy
- Risk factors: Untrusted accounts, missing ExternalId, excessive duration

#### ML-Based Detector

**Anomaly Detector (Isolation Forest)**

**Features Analyzed:**
- Temporal: hour_of_day, day_of_week, is_weekend, is_off_hours
- Source: source_ip_entropy, user_agent_entropy
- Frequency: event_count_1h, event_count_24h, unique_actions
- Context: is_cross_account, is_admin_action, is_policy_change

**Model Specifications:**
- Algorithm: Isolation Forest (scikit-learn)
- Trees: 100
- Contamination: 10%
- Training data: 30-day rolling window
- Retraining: Daily at 2 AM UTC

**Scoring:**
- Output: -1 to 1 (normalized to 0-1)
- Threshold: 0.7 (configurable)
- Interpretation: >0.7 = anomaly

### 5. Remediation Layer

#### Revoke Access Remediator
**Actions:**
- Detach managed policies
- Delete inline policies
- Disable access keys
- Attach emergency deny policies

**AWS API Calls:**
- `DetachUserPolicy`
- `DetachRolePolicy`
- `DeleteUserPolicy`
- `PutRolePolicy` (for deny)

#### Block Public Remediator
**Actions:**
- Enable S3 Block Public Access (all settings)
- Remove public bucket policies
- Set bucket ACL to private
- Disable static website hosting

**AWS API Calls:**
- `PutPublicAccessBlock`
- `DeleteBucketPolicy`
- `PutBucketAcl`
- `DeleteBucketWebsite`

#### Alert Team Remediator
**Channels:**
- Slack: Formatted message with risk score and details
- Microsoft Teams: Adaptive card with action buttons
- Email: HTML email with incident summary
- PagerDuty: Critical incident creation

### 6. Storage Layer

#### Cloud Storage Buckets

**function-source**
- Purpose: Function deployment artifacts
- Versioning: Enabled
- Retention: Keep 3 versions
- Access: Service account only

**ml-models**
- Purpose: Trained ML models
- Versioning: Enabled
- Retention: Indefinite
- Access: Service account read-only

**baseline-data**
- Purpose: Training data for ML
- Lifecycle: Delete after 90 days
- Access: Service account only

#### Secret Manager

**Secrets:**
- `aws-credentials`: AWS access key and secret
- `slack-webhook-url`: Slack webhook URL
- `teams-webhook-url`: Teams webhook URL

**Security:**
- Automatic rotation: 30 days
- Access logging: Enabled
- Replication: Automatic (multi-region)

### 7. Logging & Monitoring

#### Cloud Logging
**Log Types:**
- Function execution logs
- Audit logs (data access)
- Security logs (detections)
- System logs (errors)

**Retention:**
- Critical: 365 days
- Security: 180 days
- Application: 90 days
- Debug: 30 days

**Export:**
- BigQuery: Long-term analysis
- Cloud Storage: Archival
- SIEM: Real-time monitoring

#### Cloud Monitoring
**Metrics:**
- Function invocations
- Error rate
- Execution time
- Memory usage
- Event processing latency

**Alerts:**
- Error rate > 5% (5 minutes)
- Execution time > 500s
- Queue depth > 1000 messages
- Dead letter queue not empty

## Data Flow

### Normal Event Flow

1. **Event Capture** (0-5s)
   - IAM action occurs in AWS
   - CloudTrail logs event
   - Event appears in CloudWatch Logs

2. **Event Routing** (5-10s)
   - EventBridge evaluates rules
   - Matching events sent to GCP webhook
   - Eventarc receives and validates event

3. **Event Queuing** (10-15s)
   - Event published to Pub/Sub
   - Message persisted in queue
   - Function triggered via Pub/Sub subscription

4. **Event Processing** (15-60s)
   - Function receives event
   - Event validated and parsed
   - Detectors analyze event in parallel
   - ML model scores event

5. **Decision Making** (60-65s)
   - Risk scores aggregated
   - Severity determined
   - Auto-remediation decision made

6. **Remediation** (65-120s)
   - If auto-remediate: Execute actions
   - AWS API calls to remediate
   - Results logged

7. **Notification** (120-125s)
   - Alert published to Pub/Sub
   - Notifications sent to channels
   - Incident ticket created (if needed)

**Total Latency:** 125 seconds (2 minutes)

### Error Handling Flow

1. **Function Error**
   - Exception caught and logged
   - Event not acknowledged
   - Pub/Sub redelivers after ack deadline

2. **Retry Logic**
   - Exponential backoff: 10s → 60s → 600s
   - Max retries: 5
   - After 5 failures: Move to dead letter queue

3. **Dead Letter Processing**
   - Manual review required
   - Alert sent to operations team
   - Event can be replayed after fix

## Deployment Architecture

### Infrastructure as Code

**Terraform Structure:**
```
terraform/
├── main.tf          # Core infrastructure
├── eventarc.tf      # Event routing
├── pubsub.tf        # Message queues
├── variables.tf     # Configuration
└── outputs.tf       # Deployment info
```

**Deployment Environments:**
- **Development**: Separate GCP project, synthetic events
- **Staging**: Separate GCP project, clone of production
- **Production**: Main GCP project, real AWS events

### CI/CD Pipeline

```
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│  Commit │───▶│  Build  │───▶│  Test   │───▶│ Deploy  │
└─────────┘    └─────────┘    └─────────┘    └─────────┘
     │              │              │              │
     ▼              ▼              ▼              ▼
  Lint Code    Unit Tests   Integration    Terraform
  Type Check   Coverage       Tests         Apply
  Security     Security       E2E Tests     Function
  Scan         Scan                         Deploy
```

**GitHub Actions Workflow:**
1. On PR: Lint, test, security scan
2. On merge to main: Deploy to staging
3. Manual approval: Deploy to production
4. Post-deployment: Smoke tests

## Scaling Considerations

### Horizontal Scaling
- Cloud Functions: Auto-scale 0-10 instances
- Pub/Sub: Unlimited throughput
- EventBridge: Managed service, auto-scales

### Vertical Scaling
- Function memory: 512 MB → 2 GB (if needed)
- Function timeout: 540s → 900s (Cloud Run)
- Queue depth: Increase ack deadline

### Cost Optimization
- Scale to zero when idle
- Batch processing where possible
- Filter events early (EventBridge)
- Optimize function execution time

## Security Architecture

### Authentication & Authorization
- Service account for function
- Secret Manager for credentials
- IAM policies with least privilege
- No human access to production

### Network Security
- HTTPS/TLS 1.3 for all traffic
- VPC Service Controls (optional)
- Private Google Access
- Firewall rules

### Data Security
- Encryption at rest (AES-256)
- Encryption in transit (TLS)
- Secret rotation (30 days)
- Audit logging enabled

## Disaster Recovery

### Backup Strategy
- Function source: Git repository
- ML models: Versioned in GCS
- Secrets: Replicated multi-region
- Audit logs: Exported to BigQuery

### Recovery Procedures

**RTO (Recovery Time Objective):** 1 hour
**RPO (Recovery Point Objective):** 5 minutes

**Failure Scenarios:**

1. **Function Failure**
   - Rollback to previous version
   - Deploy from Git
   - Estimated recovery: 10 minutes

2. **GCP Region Failure**
   - Failover to secondary region
   - Redeploy infrastructure
   - Estimated recovery: 30 minutes

3. **Data Loss**
   - Restore from BigQuery export
   - Retrain ML model
   - Estimated recovery: 2 hours

## Performance Benchmarks

### Throughput
- Events per second: 100
- Events per minute: 6,000
- Events per hour: 360,000
- Events per day: 8,640,000

### Latency
- Event ingestion: <5s (p95)
- Event processing: <60s (p95)
- Remediation: <120s (p95)
- End-to-end: <125s (p95)

### Resource Usage
- Function memory: ~300 MB average
- Function CPU: ~20% average
- Storage: ~5 GB total

## Future Enhancements

### Planned Features
1. **Azure AD Integration**: Monitor Azure IAM events
2. **Custom ML Models**: Per-organization training
3. **Compliance Reporting**: Automated report generation
4. **Terraform Module**: Publish to registry
5. **UI Dashboard**: Real-time visualization

### Scalability Roadmap
1. **Phase 1** (Current): 100K events/month
2. **Phase 2** (6 months): 1M events/month
3. **Phase 3** (1 year): 10M events/month

---

**Document Version:** 1.0
**Last Updated:** 2025-11-30
**Next Review:** 2025-12-30
