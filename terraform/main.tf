terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  backend "gcs" {
    bucket = "iam-immune-system-tfstate"
    prefix = "terraform/state"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "cloudfunctions.googleapis.com",
    "eventarc.googleapis.com",
    "pubsub.googleapis.com",
    "logging.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "run.googleapis.com",
  ])

  service            = each.value
  disable_on_destroy = false
}

# Service Account for Cloud Function
resource "google_service_account" "function_sa" {
  account_id   = "iam-immune-system-sa"
  display_name = "IAM Immune System Service Account"
  description  = "Service account for IAM Immune System Cloud Function"
}

# IAM Roles for Service Account
resource "google_project_iam_member" "function_permissions" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/pubsub.publisher",
    "roles/secretmanager.secretAccessor",
    "roles/monitoring.metricWriter",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.function_sa.email}"
}

# Cloud Storage bucket for function source code
resource "google_storage_bucket" "function_source" {
  name                        = "${var.project_id}-function-source"
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 3
    }
    action {
      type = "Delete"
    }
  }
}

# Cloud Storage bucket for ML models
resource "google_storage_bucket" "ml_models" {
  name                        = "${var.project_id}-ml-models"
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }
}

# Cloud Storage bucket for baseline data
resource "google_storage_bucket" "baseline_data" {
  name                        = "${var.project_id}-baseline-data"
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}

# Secrets in Secret Manager
resource "google_secret_manager_secret" "aws_credentials" {
  secret_id = "aws-credentials"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "slack_webhook" {
  secret_id = "slack-webhook-url"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "teams_webhook" {
  secret_id = "teams-webhook-url"

  replication {
    auto {}
  }
}

# Cloud Function (Gen2)
resource "google_cloudfunctions2_function" "iam_monitor" {
  name        = var.function_name
  location    = var.region
  description = "IAM Immune System - Event-driven security automation"

  build_config {
    runtime     = "python311"
    entry_point = "handle_iam_event"

    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = var.function_source_object
      }
    }
  }

  service_config {
    max_instance_count    = 10
    min_instance_count    = 0
    available_memory      = "512Mi"
    timeout_seconds       = 540
    service_account_email = google_service_account.function_sa.email

    environment_variables = {
      GCP_PROJECT_ID      = var.project_id
      GCP_REGION          = var.region
      ML_MODEL_PATH       = "gs://${google_storage_bucket.ml_models.name}/anomaly_detector.pkl"
      PUBSUB_TOPIC        = google_pubsub_topic.alerts.id
      LOG_LEVEL           = var.log_level
      AUTO_REMEDIATION    = var.auto_remediation_enabled
    }

    secret_environment_variables {
      key        = "AWS_CREDENTIALS"
      project_id = var.project_id
      secret     = google_secret_manager_secret.aws_credentials.secret_id
      version    = "latest"
    }

    secret_environment_variables {
      key        = "SLACK_WEBHOOK_URL"
      project_id = var.project_id
      secret     = google_secret_manager_secret.slack_webhook.secret_id
      version    = "latest"
    }

    secret_environment_variables {
      key        = "TEAMS_WEBHOOK_URL"
      project_id = var.project_id
      secret     = google_secret_manager_secret.teams_webhook.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.iam_events.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }

  depends_on = [
    google_project_service.required_apis,
  ]
}

# Cloud Scheduler for ML model retraining
resource "google_cloud_scheduler_job" "model_retraining" {
  name             = "ml-model-retraining"
  description      = "Trigger ML model retraining daily"
  schedule         = "0 2 * * *" # 2 AM daily
  time_zone        = "UTC"
  attempt_deadline = "320s"

  pubsub_target {
    topic_name = google_pubsub_topic.ml_training.id
    data       = base64encode("{\"action\": \"retrain\"}")
  }
}

# Log sink to export IAM events from Cloud Logging
resource "google_logging_project_sink" "iam_events" {
  name        = "iam-events-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.iam_events.id}"

  filter = <<-EOT
    resource.type="cloud_function"
    OR resource.type="iam_role"
    OR resource.type="service_account"
    OR protoPayload.methodName=~"^google.iam.*"
    OR protoPayload.methodName=~"^storage.buckets.setIamPolicy"
  EOT

  unique_writer_identity = true
}

# Grant Pub/Sub publisher role to log sink writer
resource "google_project_iam_member" "log_sink_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.iam_events.writer_identity
}

# Monitoring - Alert Policy for high error rate
resource "google_monitoring_alert_policy" "high_error_rate" {
  display_name = "IAM Immune System - High Error Rate"
  combiner     = "OR"

  conditions {
    display_name = "Error rate > 5% over 5 minutes"

    condition_threshold {
      filter          = "resource.type=\"cloud_function\" AND resource.labels.function_name=\"${var.function_name}\" AND metric.type=\"cloudfunctions.googleapis.com/function/execution_count\" AND metric.labels.status=\"error\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = var.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }
}

# Monitoring - Alert Policy for function timeout
resource "google_monitoring_alert_policy" "function_timeout" {
  display_name = "IAM Immune System - Function Timeout"
  combiner     = "OR"

  conditions {
    display_name = "Function execution time > 500s"

    condition_threshold {
      filter          = "resource.type=\"cloud_function\" AND resource.labels.function_name=\"${var.function_name}\" AND metric.type=\"cloudfunctions.googleapis.com/function/execution_times\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 500000 # milliseconds

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_DELTA"
      }
    }
  }

  notification_channels = var.notification_channels
}
