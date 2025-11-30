# Pub/Sub topic for incoming IAM events
resource "google_pubsub_topic" "iam_events" {
  name = "iam-events"

  message_retention_duration = "86400s" # 24 hours

  labels = {
    environment = var.environment
    service     = "iam-immune-system"
  }
}

# Pub/Sub subscription for IAM events (with dead letter queue)
resource "google_pubsub_subscription" "iam_events" {
  name  = "iam-events-subscription"
  topic = google_pubsub_topic.iam_events.name

  ack_deadline_seconds = 600

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = 5
  }

  expiration_policy {
    ttl = "" # Never expire
  }

  message_retention_duration = "86400s"
}

# Pub/Sub topic for alerts
resource "google_pubsub_topic" "alerts" {
  name = "iam-alerts"

  message_retention_duration = "86400s"

  labels = {
    environment = var.environment
    service     = "iam-immune-system"
  }
}

# Pub/Sub subscription for alerts
resource "google_pubsub_subscription" "alerts" {
  name  = "iam-alerts-subscription"
  topic = google_pubsub_topic.alerts.name

  ack_deadline_seconds = 300

  push_config {
    push_endpoint = var.alert_webhook_endpoint

    attributes = {
      x-goog-version = "v1"
    }

    oidc_token {
      service_account_email = google_service_account.function_sa.email
    }
  }
}

# Pub/Sub topic for ML training triggers
resource "google_pubsub_topic" "ml_training" {
  name = "ml-training-triggers"

  message_retention_duration = "86400s"

  labels = {
    environment = var.environment
    service     = "iam-immune-system"
  }
}

# Pub/Sub subscription for ML training
resource "google_pubsub_subscription" "ml_training" {
  name  = "ml-training-subscription"
  topic = google_pubsub_topic.ml_training.name

  ack_deadline_seconds = 600

  message_retention_duration = "86400s"
}

# Dead letter topic for failed messages
resource "google_pubsub_topic" "dead_letter" {
  name = "iam-events-dead-letter"

  message_retention_duration = "604800s" # 7 days

  labels = {
    environment = var.environment
    service     = "iam-immune-system"
  }
}

# Dead letter subscription
resource "google_pubsub_subscription" "dead_letter" {
  name  = "iam-events-dead-letter-subscription"
  topic = google_pubsub_topic.dead_letter.name

  ack_deadline_seconds = 600

  message_retention_duration = "604800s" # 7 days
}

# Grant Pub/Sub subscriber role to function service account
resource "google_pubsub_subscription_iam_member" "subscriber" {
  subscription = google_pubsub_subscription.iam_events.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.function_sa.email}"
}

# Grant Pub/Sub publisher role to function for alerts
resource "google_pubsub_topic_iam_member" "alerts_publisher" {
  topic  = google_pubsub_topic.alerts.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.function_sa.email}"
}

# Monitoring metric for Pub/Sub message age
resource "google_monitoring_alert_policy" "old_messages" {
  display_name = "IAM Events - Old Messages in Queue"
  combiner     = "OR"

  conditions {
    display_name = "Messages older than 10 minutes"

    condition_threshold {
      filter          = "resource.type=\"pubsub_subscription\" AND resource.labels.subscription_id=\"${google_pubsub_subscription.iam_events.name}\" AND metric.type=\"pubsub.googleapis.com/subscription/oldest_unacked_message_age\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 600 # 10 minutes

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MAX"
      }
    }
  }

  notification_channels = var.notification_channels

  alert_strategy {
    auto_close = "3600s"
  }
}

# Monitoring metric for dead letter queue
resource "google_monitoring_alert_policy" "dead_letter_messages" {
  display_name = "IAM Events - Messages in Dead Letter Queue"
  combiner     = "OR"

  conditions {
    display_name = "Messages in dead letter queue"

    condition_threshold {
      filter          = "resource.type=\"pubsub_subscription\" AND resource.labels.subscription_id=\"${google_pubsub_subscription.dead_letter.name}\" AND metric.type=\"pubsub.googleapis.com/subscription/num_undelivered_messages\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MAX"
      }
    }
  }

  notification_channels = var.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }
}
