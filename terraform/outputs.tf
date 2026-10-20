output "agent_service_account_email" {
  description = "Least-privilege IAM Service Account email for the SRE ADK Agent."
  value       = google_service_account.sre_agent_sa.email
}

output "vertex_search_datastore_id" {
  description = "Provisioned Vertex AI Search Data Store ID for SRE runbooks."
  value       = google_discovery_engine_data_store.sre_runbooks_datastore.data_store_id
}

output "hitl_secret_resource_name" {
  description = "Secret Manager resource name for Human-in-the-Loop signing secret."
  value       = google_secret_manager_secret.hitl_signing_secret.name
}

output "cloud_run_service_uri" {
  description = "Deployed Cloud Run v2 endpoint URI for the ADK Incident Response Agent."
  value       = google_cloud_run_v2_service.sre_agent_runtime.uri
}
