# Eventarc trigger for AWS CloudTrail events
# This requires AWS EventBridge integration with GCP Eventarc

# Service Account for Eventarc
resource "google_service_account" "eventarc_sa" {
  account_id   = "eventarc-iam-monitor-sa"
  display_name = "Eventarc IAM Monitor Service Account"
  description  = "Service account for Eventarc triggers"
}

# Grant Eventarc service account permissions
resource "google_project_iam_member" "eventarc_permissions" {
  for_each = toset([
    "roles/eventarc.eventReceiver",
    "roles/run.invoker",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.eventarc_sa.email}"
}

# Eventarc trigger for AWS CloudTrail IAM events
# Note: This requires setting up AWS EventBridge -> GCP Eventarc integration
resource "google_eventarc_trigger" "aws_cloudtrail_iam" {
  name     = "aws-cloudtrail-iam-events"
  location = var.region

  matching_criteria {
    attribute = "type"
    value     = "aws.cloudtrail.event"
  }

  matching_criteria {
    attribute = "eventName"
    value     = "iam.*"
    operator  = "match-path-pattern"
  }

  destination {
    cloud_run_service {
      service = google_cloudfunctions2_function.iam_monitor.name
      region  = var.region
    }
  }

  service_account = google_service_account.eventarc_sa.email

  labels = {
    environment = var.environment
    service     = "iam-immune-system"
  }
}

# Eventarc trigger for S3 bucket policy changes
resource "google_eventarc_trigger" "aws_s3_policy" {
  name     = "aws-s3-policy-events"
  location = var.region

  matching_criteria {
    attribute = "type"
    value     = "aws.cloudtrail.event"
  }

  matching_criteria {
    attribute = "eventName"
    value     = "PutBucketPolicy"
  }

  matching_criteria {
    attribute = "eventName"
    value     = "PutBucketAcl"
  }

  destination {
    cloud_run_service {
      service = google_cloudfunctions2_function.iam_monitor.name
      region  = var.region
    }
  }

  service_account = google_service_account.eventarc_sa.email

  labels = {
    environment = var.environment
    service     = "iam-immune-system"
  }
}

# Eventarc trigger for AssumeRole events
resource "google_eventarc_trigger" "aws_assume_role" {
  name     = "aws-assume-role-events"
  location = var.region

  matching_criteria {
    attribute = "type"
    value     = "aws.cloudtrail.event"
  }

  matching_criteria {
    attribute = "eventName"
    value     = "AssumeRole"
  }

  destination {
    cloud_run_service {
      service = google_cloudfunctions2_function.iam_monitor.name
      region  = var.region
    }
  }

  service_account = google_service_account.eventarc_sa.email

  labels = {
    environment = var.environment
    service     = "iam-immune-system"
  }
}

# Channel for AWS events (requires AWS Event Bridge setup)
resource "google_eventarc_channel" "aws_events" {
  name     = "aws-cloudtrail-channel"
  location = var.region

  third_party_provider = "projects/${var.project_id}/locations/${var.region}/providers/aws"

  lifecycle {
    ignore_changes = [
      third_party_provider,
    ]
  }
}

# Outputs for AWS EventBridge configuration
output "eventarc_channel_name" {
  description = "Eventarc channel name for AWS EventBridge configuration"
  value       = google_eventarc_channel.aws_events.name
}

output "eventarc_webhook_url" {
  description = "Webhook URL for AWS EventBridge destination"
  value       = "https://eventarc.googleapis.com/v1/${google_eventarc_channel.aws_events.name}:receiveEvent"
}
