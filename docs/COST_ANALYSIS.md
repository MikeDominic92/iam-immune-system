# Cost Analysis

Detailed monthly cost breakdown for IAM Immune System.

## Executive Summary

- **Estimated Monthly Cost**: $15-20
- **Cost per Event**: ~$0.00015
- **Break-Even Point**: 100,000 events/month
- **Scale Economics**: Costs scale linearly with event volume

## Detailed Breakdown

### GCP Services

#### 1. Cloud Functions (Gen2)

**Pricing:**
- Invocations: $0.40 per million
- Compute time: $0.00001667/GB-second
- Memory: 512MB
- Avg execution: 2 seconds

**Monthly Usage (Baseline):**
- 100,000 invocations
- Invocation cost: $0.04
- Compute cost: 100,000 × 2s × 0.5GB × $0.00001667 = $1.67
- **Total: $1.71/month**

**At Scale (1M events/month):**
- Invocation cost: $0.40
- Compute cost: $16.67
- **Total: $17.07/month**

#### 2. Cloud Logging

**Pricing:**
- First 50 GB/month: Free
- Additional: $0.50/GB

**Monthly Usage:**
- Event logs: ~5 GB
- Application logs: ~3 GB
- Audit logs: ~2 GB
- **Total: 10 GB = $0.00/month** (within free tier)

**At Scale (1M events):**
- Event logs: ~50 GB
- Application logs: ~20 GB
- Total: 70 GB
- Billable: 20 GB × $0.50 = $10.00/month

#### 3. Pub/Sub

**Pricing:**
- First 10 GB/month: Free
- Additional: $40/TB
- Message delivery: $0.40 per million

**Monthly Usage:**
- 100,000 messages
- Data: ~5 MB average = 0.5 GB
- Delivery cost: $0.04
- **Total: $0.04/month**

**At Scale:**
- 1M messages = $0.40
- Data: 5 GB (within free tier)
- **Total: $0.40/month**

#### 4. Eventarc

**Pricing:**
- $0.40 per 10,000 events

**Monthly Usage:**
- 100,000 events = $4.00/month

**At Scale:**
- 1M events = $40.00/month

#### 5. Cloud Storage

**Pricing:**
- Standard storage: $0.02/GB/month
- Operations: Minimal cost

**Monthly Usage:**
- ML models: 1 GB
- Baseline data: 2 GB
- Function source: 0.5 GB
- Total: 3.5 GB × $0.02 = $0.07/month

**At Scale:**
- 10 GB × $0.02 = $0.20/month

#### 6. Secret Manager

**Pricing:**
- First 6 active secrets: Free
- Secret versions: $0.06 per month

**Monthly Usage:**
- 3 secrets (AWS creds, Slack, Teams)
- **Total: $0.00/month** (within free tier)

### AWS Services

#### 7. CloudTrail (Data Events)

**Pricing:**
- Management events: Free
- Data events: $0.10 per 100,000 events

**Monthly Usage:**
- 100,000 IAM events (management): Free
- **Total: $0.00/month**

**Note:** If monitoring S3 data events:
- $0.10 per 100,000 events
- Could add $5-10/month depending on S3 activity

#### 8. EventBridge

**Pricing:**
- Event delivery: $1.00 per million events
- Custom event bus: $1.00 per million events

**Monthly Usage:**
- 100,000 events
- Delivery: $0.10
- Custom bus: $0.10
- **Total: $0.20/month**

**At Scale:**
- 1M events = $2.00/month

#### 9. AWS API Calls (Remediation)

**Pricing:**
- Most IAM API calls: Free
- S3 API calls: ~$0.005 per 1,000 requests

**Monthly Usage:**
- 100 remediation actions
- **Total: ~$0.00/month**

### Third-Party Services

#### 10. Slack (Free Tier)

**Cost:** $0.00/month

#### 11. Microsoft Teams (Free Tier)

**Cost:** $0.00/month

## Total Cost Summary

### Baseline (100K events/month)

| Service | Monthly Cost |
|---------|-------------|
| Cloud Functions | $1.71 |
| Cloud Logging | $0.00 |
| Pub/Sub | $0.04 |
| Eventarc | $4.00 |
| Cloud Storage | $0.07 |
| Secret Manager | $0.00 |
| CloudTrail | $0.00 |
| EventBridge | $0.20 |
| AWS API Calls | $0.00 |
| **TOTAL** | **$6.02** |

### Medium Scale (500K events/month)

| Service | Monthly Cost |
|---------|-------------|
| Cloud Functions | $8.54 |
| Cloud Logging | $2.50 |
| Pub/Sub | $0.20 |
| Eventarc | $20.00 |
| Cloud Storage | $0.10 |
| Secret Manager | $0.00 |
| CloudTrail | $0.00 |
| EventBridge | $1.00 |
| AWS API Calls | $0.00 |
| **TOTAL** | **$32.34** |

### High Scale (1M events/month)

| Service | Monthly Cost |
|---------|-------------|
| Cloud Functions | $17.07 |
| Cloud Logging | $10.00 |
| Pub/Sub | $0.40 |
| Eventarc | $40.00 |
| Cloud Storage | $0.20 |
| Secret Manager | $0.00 |
| CloudTrail | $0.00 |
| EventBridge | $2.00 |
| AWS API Calls | $0.01 |
| **TOTAL** | **$69.68** |

## Cost Optimization Strategies

### 1. Event Filtering
- Filter events at EventBridge level before sending to GCP
- Only send high-risk events (saves ~30% on Eventarc costs)
- **Savings:** $1.20-12.00/month

### 2. Log Retention Policies
- Set retention to 30 days instead of default
- Archive old logs to cheaper storage
- **Savings:** $0.50-5.00/month

### 3. Function Optimization
- Reduce memory allocation if possible (256MB vs 512MB)
- Optimize execution time
- **Savings:** $0.50-5.00/month

### 4. Batching
- Batch events when possible
- Reduce number of function invocations
- **Savings:** $0.20-2.00/month

### 5. Use Free Tiers Wisely
- Stay within Cloud Logging free tier (50 GB)
- Leverage Pub/Sub free tier (10 GB)
- **Savings:** $5.00-15.00/month

## Cost Alerts

Recommended budget alerts:

1. **Warning:** $10/month
2. **Critical:** $25/month
3. **Emergency:** $50/month

## ROI Analysis

### Cost of NOT Having IAM Immune System

**Potential Security Incident Costs:**
- Data breach: $100,000 - $1,000,000+
- Compliance fines: $10,000 - $500,000
- Reputation damage: Immeasurable
- Investigation time: $5,000 - $50,000

**ROI Calculation:**
- Monthly cost: $15-20
- Annual cost: $180-240
- Single prevented incident: $10,000+
- **ROI: 5,000%+ if prevents even one minor incident**

## Comparison with Alternatives

### AWS-Only Solution

| Service | Monthly Cost |
|---------|-------------|
| Lambda | $1.00 |
| EventBridge | $4.00 |
| CloudWatch Logs | $10.00 |
| SNS/SQS | $1.00 |
| S3 | $0.50 |
| **TOTAL** | **$16.50** |

**Conclusion:** GCP solution is comparable in cost with better features.

### Commercial CASB Solution

- Typical cost: $5-15 per user/month
- For 100 users: $500-1,500/month
- **Savings with IAM Immune System: $485-1,485/month**

## Conclusion

The IAM Immune System provides enterprise-grade security at a fraction of the cost of commercial solutions. At baseline scale (100K events/month), monthly costs are under $10, making it extremely cost-effective for small to medium organizations.

For a portfolio project, the cost is nominal ($6-20/month) while demonstrating significant technical capabilities in multi-cloud architecture, event-driven systems, and security automation.

## Cost Tracking

To monitor actual costs:

```bash
# GCP costs
gcloud billing accounts list
gcloud billing budgets list --billing-account=ACCOUNT_ID

# AWS costs
aws ce get-cost-and-usage \
  --time-period Start=2025-11-01,End=2025-11-30 \
  --granularity MONTHLY \
  --metrics UnblendedCost
```

## Last Updated

2025-11-30
