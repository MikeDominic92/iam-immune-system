variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "function_name" {
  description = "Name of the Cloud Function"
  type        = string
  default     = "iam-immune-system"
}

variable "function_source_object" {
  description = "GCS object path for function source code"
  type        = string
  default     = "function-source.zip"
}

variable "log_level" {
  description = "Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
  type        = string
  default     = "INFO"

  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], var.log_level)
    error_message = "Log level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL."
  }
}

variable "auto_remediation_enabled" {
  description = "Enable automatic remediation actions"
  type        = bool
  default     = true
}

variable "alert_webhook_endpoint" {
  description = "Webhook endpoint for alert notifications"
  type        = string
  default     = ""
}

variable "notification_channels" {
  description = "List of notification channel IDs for monitoring alerts"
  type        = list(string)
  default     = []
}

variable "ml_baseline_days" {
  description = "Number of days to use for ML baseline building"
  type        = number
  default     = 30

  validation {
    condition     = var.ml_baseline_days >= 7 && var.ml_baseline_days <= 90
    error_message = "ML baseline days must be between 7 and 90."
  }
}

variable "ml_anomaly_threshold" {
  description = "Threshold for ML anomaly detection (0.0 - 1.0)"
  type        = number
  default     = 0.7

  validation {
    condition     = var.ml_anomaly_threshold >= 0.0 && var.ml_anomaly_threshold <= 1.0
    error_message = "ML anomaly threshold must be between 0.0 and 1.0."
  }
}

variable "whitelisted_principals" {
  description = "List of IAM principals to whitelist"
  type        = list(string)
  default     = []
}

variable "whitelisted_actions" {
  description = "List of IAM actions to whitelist"
  type        = list(string)
  default     = []
}

variable "enable_public_bucket_detection" {
  description = "Enable public bucket detection"
  type        = bool
  default     = true
}

variable "enable_admin_grant_detection" {
  description = "Enable admin grant detection"
  type        = bool
  default     = true
}

variable "enable_policy_change_detection" {
  description = "Enable policy change detection"
  type        = bool
  default     = true
}

variable "enable_cross_account_detection" {
  description = "Enable cross-account detection"
  type        = bool
  default     = true
}

variable "max_function_instances" {
  description = "Maximum number of Cloud Function instances"
  type        = number
  default     = 10

  validation {
    condition     = var.max_function_instances >= 1 && var.max_function_instances <= 100
    error_message = "Max function instances must be between 1 and 100."
  }
}

variable "function_memory" {
  description = "Memory allocation for Cloud Function"
  type        = string
  default     = "512Mi"

  validation {
    condition     = contains(["256Mi", "512Mi", "1Gi", "2Gi", "4Gi"], var.function_memory)
    error_message = "Function memory must be 256Mi, 512Mi, 1Gi, 2Gi, or 4Gi."
  }
}

variable "function_timeout" {
  description = "Timeout for Cloud Function in seconds"
  type        = number
  default     = 540

  validation {
    condition     = var.function_timeout >= 60 && var.function_timeout <= 540
    error_message = "Function timeout must be between 60 and 540 seconds."
  }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    project     = "iam-immune-system"
    managed_by  = "terraform"
    cost_center = "security"
  }
}
