variable "project_id" {
  description = "Target Google Cloud Project ID for deploying the Cloud SRE Incident Response Agent."
  type        = string
}

variable "region" {
  description = "Primary Google Cloud region for Vertex AI Agent Engine and Cloud Run resources."
  type        = string
  default     = "us-central1"
}

variable "agent_service_name" {
  description = "Canonical service name for the deployed ADK Incident Response Agent."
  type        = string
  default     = "cloud-sre-incident-response-agent"
}

variable "container_image" {
  description = "Artifact Registry container image URI for the ADK agent runtime."
  type        = string
  default     = "us-central1-docker.pkg.dev/example-project/sre-agents/cloud-sre-incident-response-agent:v1.0.0"
}
