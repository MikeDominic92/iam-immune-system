output "function_name" {
  description = "Name of the deployed Cloud Function"
  value       = google_cloudfunctions2_function.iam_monitor.name
}

output "function_url" {
  description = "URL of the deployed Cloud Function"
  value       = google_cloudfunctions2_function.iam_monitor.service_config[0].uri
}

output "function_service_account" {
  description = "Email of the function's service account"
  value       = google_service_account.function_sa.email
}

output "pubsub_topic_iam_events" {
  description = "Pub/Sub topic for IAM events"
  value       = google_pubsub_topic.iam_events.name
}

output "pubsub_topic_alerts" {
  description = "Pub/Sub topic for alerts"
  value       = google_pubsub_topic.alerts.name
}

output "pubsub_topic_ml_training" {
  description = "Pub/Sub topic for ML training triggers"
  value       = google_pubsub_topic.ml_training.name
}

output "storage_bucket_function_source" {
  description = "GCS bucket for function source code"
  value       = google_storage_bucket.function_source.name
}

output "storage_bucket_ml_models" {
  description = "GCS bucket for ML models"
  value       = google_storage_bucket.ml_models.name
}

output "storage_bucket_baseline_data" {
  description = "GCS bucket for baseline data"
  value       = google_storage_bucket.baseline_data.name
}

output "secret_aws_credentials" {
  description = "Secret Manager secret for AWS credentials"
  value       = google_secret_manager_secret.aws_credentials.id
}

output "secret_slack_webhook" {
  description = "Secret Manager secret for Slack webhook"
  value       = google_secret_manager_secret.slack_webhook.id
}

output "secret_teams_webhook" {
  description = "Secret Manager secret for Teams webhook"
  value       = google_secret_manager_secret.teams_webhook.id
}

output "logging_sink_writer_identity" {
  description = "Writer identity for the logging sink"
  value       = google_logging_project_sink.iam_events.writer_identity
}

output "deployment_instructions" {
  description = "Instructions for deploying the function"
  value       = <<-EOT
    To deploy the Cloud Function:

    1. Package the function source:
       cd functions/iam_monitor
       zip -r function-source.zip .

    2. Upload to GCS:
       gsutil cp function-source.zip gs://${google_storage_bucket.function_source.name}/

    3. Update function:
       gcloud functions deploy ${google_cloudfunctions2_function.iam_monitor.name} \
         --gen2 \
         --runtime python311 \
         --region ${var.region} \
         --source gs://${google_storage_bucket.function_source.name}/function-source.zip \
         --entry-point handle_iam_event
  EOT
}

output "aws_eventbridge_configuration" {
  description = "Configuration details for AWS EventBridge"
  value = {
    eventarc_channel = google_eventarc_channel.aws_events.name
    webhook_url      = "https://eventarc.googleapis.com/v1/${google_eventarc_channel.aws_events.name}:receiveEvent"
    event_patterns = [
      {
        source      = ["aws.iam"]
        detail-type = ["AWS API Call via CloudTrail"]
      },
      {
        source      = ["aws.s3"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventName = ["PutBucketPolicy", "PutBucketAcl", "PutBucketPublicAccessBlock"]
        }
      }
    ]
  }
}

output "monitoring_dashboard_url" {
  description = "URL to the monitoring dashboard"
  value       = "https://console.cloud.google.com/monitoring/dashboards?project=${var.project_id}"
}

output "logs_explorer_url" {
  description = "URL to the logs explorer"
  value       = "https://console.cloud.google.com/logs/query?project=${var.project_id}"
}

output "estimated_monthly_cost" {
  description = "Estimated monthly cost breakdown"
  value = {
    cloud_functions = "$0.40 (100K invocations)"
    cloud_logging   = "$5.00 (10GB)"
    pubsub          = "$4.00 (1M messages)"
    eventarc        = "$4.00 (100K events)"
    storage         = "$1.50 (5GB)"
    total           = "~$15.00/month"
  }
}
