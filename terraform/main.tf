terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.30"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# 1. Enable Required Google Cloud APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "aiplatform.googleapis.com",
    "discoveryengine.googleapis.com",
    "dlp.googleapis.com",
    "secretmanager.googleapis.com",
    "run.googleapis.com",
    "cloudtrace.googleapis.com",
    "logging.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# 2. Dedicated Least-Privilege Agent Runtime Service Account
resource "google_service_account" "sre_agent_sa" {
  account_id   = "sre-incident-agent-sa"
  display_name = "Cloud SRE Incident Response ADK Agent Service Account"
}

# 3. Principle of Least Privilege (PoLP) IAM Role Bindings
resource "google_project_iam_member" "agent_least_privilege_roles" {
  for_each = toset([
    "roles/aiplatform.user",
    "roles/discoveryengine.viewer",
    "roles/dlp.user",
    "roles/cloudtrace.agent",
    "roles/logging.logWriter",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.sre_agent_sa.email}"
}

# 4. Secure Secret Management — Human-in-the-Loop Approval Signing Secret
resource "google_secret_manager_secret" "hitl_signing_secret" {
  secret_id = "HITL_APPROVAL_SIGNING_KEY"

  replication {
    auto {}
  }

  depends_on = [google_project_service.required_apis]
}

resource "google_secret_manager_secret_iam_member" "hitl_secret_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.hitl_signing_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sre_agent_sa.email}"
}

# 5. Vertex AI Search Data Store for Persistent SRE Runbook Retrieval
resource "google_discovery_engine_data_store" "sre_runbooks_datastore" {
  location                    = "global"
  data_store_id               = "${var.agent_service_name}-runbooks"
  display_name                = "SRE Incident Remediation Runbooks Store"
  industry_vertical           = "GENERIC"
  content_config              = "CONTENT_REQUIRED"
  solution_types              = ["SOLUTION_TYPE_SEARCH"]
  create_advanced_site_search = false

  depends_on = [google_project_service.required_apis]
}

# 6. Cloud Run v2 Service Hosting the ADK / A2A Incident Response Agent
resource "google_cloud_run_v2_service" "sre_agent_runtime" {
  name     = var.agent_service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.sre_agent_sa.email

    containers {
      image = var.container_image

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }

      env {
        name  = "VERTEX_SEARCH_DATASTORE_ID"
        value = google_discovery_engine_data_store.sre_runbooks_datastore.data_store_id
      }

      env {
        name = "HITL_APPROVAL_SIGNING_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.hitl_signing_secret.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [
    google_project_service.required_apis,
    google_secret_manager_secret_iam_member.hitl_secret_accessor,
  ]
}
