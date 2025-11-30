# ADR-001: GCP Over AWS for Event Processing

## Status

Accepted

## Context

We need to choose a cloud platform for hosting the IAM Immune System's event processing infrastructure. The system monitors AWS IAM events and needs to:

- Process events in real-time with low latency
- Scale automatically based on event volume
- Integrate with AWS CloudTrail
- Provide reliable event routing and queuing
- Support serverless architecture
- Minimize operational overhead
- Keep costs low (~$15/month target)

## Decision Drivers

1. **Event-Driven Architecture**: Need robust event routing and processing
2. **Serverless Execution**: Prefer managed services over self-managed infrastructure
3. **Cost Efficiency**: Target budget of $15/month for typical workloads
4. **Integration**: Must integrate seamlessly with AWS CloudTrail
5. **Developer Experience**: Simple deployment and maintenance
6. **Multi-Cloud Skills**: Portfolio project demonstrating multi-cloud capabilities

## Options Considered

### Option 1: AWS Lambda + EventBridge

**Pros:**
- Native AWS integration
- Direct CloudTrail to EventBridge routing
- Lambda free tier (1M requests/month)
- Mature ecosystem
- Single cloud provider

**Cons:**
- Less impressive for portfolio (single cloud)
- EventBridge costs add up ($1/million events)
- CloudWatch Logs expensive at scale
- Less differentiation from typical AWS-only projects

**Estimated Cost:** $12-18/month

### Option 2: GCP Cloud Functions + Eventarc

**Pros:**
- Multi-cloud architecture demonstrates broader skills
- Eventarc provides unified event routing
- Cloud Logging more cost-effective than CloudWatch
- Pub/Sub offers better dead letter queue handling
- Superior free tier for Cloud Functions
- Better developer experience with Cloud Code
- Demonstrates AWS/GCP integration skills

**Cons:**
- Requires AWS EventBridge → GCP Eventarc integration
- Additional complexity in cross-cloud setup
- Two cloud providers to manage
- Slightly higher learning curve

**Estimated Cost:** $15-20/month

### Option 3: Azure Functions + Event Grid

**Pros:**
- Another multi-cloud option
- Event Grid is powerful
- Good Azure integration

**Cons:**
- Most expensive option ($25-30/month)
- Less mature event routing than GCP
- Fewer AWS integration examples
- Event Grid pricing less favorable

**Estimated Cost:** $25-30/month

## Decision

**We will use GCP (Cloud Functions + Eventarc) for event processing.**

## Rationale

### Portfolio Value
- **Multi-cloud expertise**: Demonstrates ability to architect across AWS and GCP
- **Integration skills**: Shows capability to integrate services across cloud providers
- **Modern architecture**: Uses cutting-edge Eventarc (GCP's newest event service)
- **Differentiation**: Stands out from AWS-only projects

### Technical Merit
- **Better event routing**: Eventarc provides cleaner event filtering and routing than EventBridge
- **Cost-effective logging**: Cloud Logging is 50% cheaper than CloudWatch Logs
- **Superior Pub/Sub**: Better dead letter queue handling and message retention
- **Cloud Functions Gen2**: More powerful than Lambda with better cold start times
- **Terraform support**: Excellent IaC support for both AWS and GCP resources

### Cost Analysis
While GCP option is slightly more expensive (~$15-20 vs $12-18), the additional $3-5/month is worthwhile for:
- Portfolio differentiation
- Multi-cloud skills demonstration
- Better developer experience
- Superior monitoring and debugging tools

### Integration Approach
AWS CloudTrail → AWS EventBridge → GCP Eventarc → GCP Cloud Functions

This integration:
1. Uses AWS EventBridge to capture CloudTrail events
2. Routes events to GCP Eventarc via HTTP webhook
3. Processes events in GCP Cloud Functions
4. Stores results in GCP Cloud Logging and Pub/Sub

## Consequences

### Positive
- Demonstrates multi-cloud architecture skills
- Better developer experience with GCP tooling
- More impressive portfolio project
- Cleaner event routing with Eventarc
- Cost-effective logging and monitoring
- Better dead letter queue handling

### Negative
- Slightly higher complexity in initial setup
- Need to manage credentials for both AWS and GCP
- Cross-cloud network latency (minimal impact)
- Two cloud bills instead of one

### Neutral
- Need to learn GCP services (beneficial for career)
- Documentation must cover both AWS and GCP setup
- Testing requires both cloud environments

## Implementation Notes

### AWS Components
- CloudTrail: Capture IAM events
- EventBridge: Filter and route events
- IAM: Permissions for remediation actions

### GCP Components
- Eventarc: Receive events from AWS
- Cloud Functions: Process events
- Pub/Sub: Event queuing and alerts
- Cloud Logging: Centralized logging
- Secret Manager: Store AWS credentials

### Cost Mitigation
- Use Cloud Functions min instances = 0 (scale to zero)
- Implement event filtering at EventBridge level
- Use Cloud Logging retention policies
- Leverage free tiers where possible

## References

- [GCP Eventarc Documentation](https://cloud.google.com/eventarc/docs)
- [AWS EventBridge Documentation](https://docs.aws.amazon.com/eventbridge/)
- [GCP Cloud Functions Gen2](https://cloud.google.com/functions/docs/2nd-gen/overview)
- [Multi-Cloud Architecture Patterns](https://cloud.google.com/architecture/hybrid-and-multi-cloud-architecture-patterns)

## Review

- **Date**: 2025-11-30
- **Reviewers**: Self-review for portfolio project
- **Next Review**: After 3 months of operation
