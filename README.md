# Enterprise Cloud Reliability & Incident Response Agent (`google-adk`)

An enterprise-grade, multi-agent **Site Reliability Engineering (SRE) Incident Response System** built with the **Google Agent Development Kit (`google-adk`)**, **Vertex AI Gemini 2.5 (`gemini-2.5-pro` & `gemini-2.5-flash`)**, **Vertex AI Search**, **Cloud Data Loss Prevention (DLP)**, **Cloud Secret Manager**, **OpenTelemetry**, and **Terraform**.

---

## 1. Problem Statement & Solution Architecture

### The Problem
During high-severity cloud production incidents (SEV1/SEV2 latency spikes, HTTP 5xx surges, or connection pool exhaustion), on-call engineers must manually correlate golden-signal metrics, cluster thousands of noisy stack traces, inspect recent deployment rollouts, locate the right remediation runbook, open incident tickets, and execute safe rollbacks—all while ensuring customer PII is never leaked into tickets or logs and no unapproved destructive changes occur.

### The Solution
The **Cloud SRE Incident Response Agent** automates end-to-end triage, root-cause correlation, and human-gated remediation using a hierarchical **Google ADK Multi-Agent Architecture**:

```text
Incoming Pager Alert / Operator Query
       │
       ▼
┌────────────────────────────────────────────────────────────────────┐
│  1. Security Guardrail & Policy Plugin Layer (sre_agent/guardrails)│
│     • before_model_guardrail_callback: Prompt-Injection Defense    │
│     • PIIRedactor (Cloud DLP API + Deterministic Regex Scrubbing)  │
│     • IntentOutcomeTracker & OpenTelemetry Distributed Tracing     │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│  2. IncidentResponseCoordinator (LlmAgent — gemini-2.5-pro)        │
│     • Constitutional System Prompt & StrategicModelRouter          │
│     • HistoryCompactor (Sliding Window + Summarization + Caching)  │
│     • PersistentSessionStore (Parameterized SQLite + Vertex Search)│
└─────────┬─────────────────────┼──────────────────────┬─────────────┘
          │                     │                      │
          ▼                     ▼                      ▼
┌───────────────────┐ ┌──────────────────────┐ ┌───────────────────────────┐
│ TelemetryTriage   │ │ RootCauseAnalyst     │ │ RemediationExecutor       │
│ Sub-Agent         │ │ Sub-Agent            │ │ Sub-Agent                 │
│ (gemini-2.5-flash)│ │ (gemini-2.5-pro)     │ │ (gemini-2.5-pro + HITL)   │
└─────────┬─────────┘ └──────────┬───────────┘ └─────────────┬─────────────┘
          │                      │                           │
          ▼                      ▼                           ▼
• query_service_      • correlate_deployment_  • create_critical_
  health_metrics        change_events            incident_ticket
• analyze_error_      • search_incident_       • execute_production_
  log_anomalies         runbooks                 rollback (HITL Gate)
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│  3. Post-Execution Verification & Async Memory Consolidation       │
│     • SelfCritiqueEvaluator (Evaluator-Optimizer Rubric Loop)      │
│     • AsyncMemoryConsolidator (Non-blocking asyncio background)    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. AgentOps Architecture & Code Evidence Matrix

| Category | Criterion | Implementation File & Code Evidence |
| :--- | :--- | :--- |
| **1. Tool & Interface Design** | **Comprehensive Tool Docstrings** | [`sre_agent/tools.py`](sre_agent/tools.py) — All 6 tools include complete Google-style docstrings detailing purpose, parameters, return schemas, and failure recovery. |
| **1. Tool & Interface Design** | **Descriptive Naming** | [`sre_agent/tools.py`](sre_agent/tools.py) — Action-specific tool names: `query_service_health_metrics`, `analyze_error_log_anomalies`, `search_incident_runbooks`, `correlate_deployment_change_events`, `create_critical_incident_ticket`, `execute_production_rollback`. |
| **1. Tool & Interface Design** | **Explicit JSON Schemas** | [`sre_agent/schemas.py`](sre_agent/schemas.py) — Strict Pydantic v2 `BaseModel` schemas (`extra="forbid"`, regex and numeric bounds) validating all tool inputs, tool outputs, and the coordinator `output_schema` (`IncidentAssessmentReport`). |
| **1. Tool & Interface Design** | **Guided Error Handling** | [`sre_agent/schemas.py`](sre_agent/schemas.py) & [`sre_agent/tools.py`](sre_agent/tools.py) — `GuidedToolError` catches validation and catalog errors and returns structured `recovery_instructions` and `suggested_next_tool` to guide LLM self-correction. |
| **2. Context & Memory** | **Robust System Instructions** | [`sre_agent/prompts.py`](sre_agent/prompts.py) — Explicit `<CONSTITUTION>`, `<PERSONA>`, `<DOMAIN_KNOWLEDGE>`, `<OPERATIONAL_CONSTRAINTS>`, and `<SAFETY_AND_HITL_POLICY>` blocks across all agents. |
| **2. Context & Memory** | **History Compaction** | [`sre_agent/memory.py`](sre_agent/memory.py) — `HistoryCompactor` enforces token budgets via sliding-window retention, abstractive summarization of evicted turns, and Vertex AI Context Caching configuration (`build_vertex_context_cache_config`). |
| **2. Context & Memory** | **Persistent Session State** | [`sre_agent/memory.py`](sre_agent/memory.py) — `PersistentSessionStore` (parameterized SQLite database) and `VertexSearchKnowledgeStore` (`google.cloud.discoveryengine_v1` Vertex AI Search with local vector index fallback). |
| **2. Context & Memory** | **Async Memory Operations** | [`sre_agent/memory.py`](sre_agent/memory.py) — `AsyncMemoryConsolidator` uses `asyncio.Queue` and `asyncio.create_task` to extract and store post-mortem lessons asynchronously without blocking agent responses. |
| **3. Orchestration & Logic** | **Multi-Agent Patterns** | [`sre_agent/agent.py`](sre_agent/agent.py) — Official ADK `LlmAgent` Coordinator (`root_agent`) orchestrating a `SequentialAgent` pipeline (`incident_response_pipeline`) across `telemetry_triage_agent`, `root_cause_analyst_agent`, and `remediation_executor_agent`. |
| **3. Orchestration & Logic** | **Strategic Model Routing** | [`sre_agent/router.py`](sre_agent/router.py) — `StrategicModelRouter` dynamically routes high-speed telemetry triage and compaction tasks to `gemini-2.5-flash` and complex root-cause analysis and remediation planning to `gemini-2.5-pro`. |
| **3. Orchestration & Logic** | **Guardrails & Policy Plugins** | [`sre_agent/guardrails.py`](sre_agent/guardrails.py) — `PolicyGuardrailPlugin` (`before_model_guardrail_callback`, `after_model_guardrail_callback`) for prompt-injection defense plus `SelfCritiqueEvaluator` (Evaluator-Optimizer rubric reflection loop). |
| **3. Orchestration & Logic** | **Human-in-the-Loop Hooks** | [`sre_agent/guardrails.py`](sre_agent/guardrails.py) & [`sre_agent/tools.py`](sre_agent/tools.py) — `HumanApprovalGate` (`before_tool_guardrail_callback`) halts `execute_production_rollback` with `PENDING_HUMAN_APPROVAL` unless a cryptographically signed HMAC `human_approval_token` is supplied. |
| **4. Observability & Tracing** | **Structured JSON Logging** | [`sre_agent/observability.py`](sre_agent/observability.py) — `StructuredJsonLogger` (`python-json-logger`) emits single-line JSON log records enriched with `session_id`, `trace_id`, `event_type`, and sanitized metadata. |
| **4. Observability & Tracing** | **Intent vs. Outcome Capture** | [`sre_agent/observability.py`](sre_agent/observability.py) — `IntentOutcomeTracker` records pre-execution `AGENT_INTENT_RECORDED` (`intended_action`, `parameters`) and post-execution `AGENT_OUTCOME_RECORDED` (`actual_outcome`, `status`, `latency_ms`) linked by `intent_id`. |
| **4. Observability & Tracing** | **Distributed Tracing** | [`sre_agent/observability.py`](sre_agent/observability.py) — `TracingManager` instruments agent turns, sub-agent delegations, and tool calls with linked OpenTelemetry parent-child spans. |
| **4. Observability & Tracing** | **PII Redaction** | [`sre_agent/observability.py`](sre_agent/observability.py) — `PIIRedactor` integrates `google.cloud.dlp_v2.DlpServiceClient` with deterministic regex scrubbing (`EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `IPV4`, `API_KEY`) before any log or memory write. |
| **5. Infrastructure & CI/CD** | **Automated Evaluation Suites** | [`sre_agent/evaluator.py`](sre_agent/evaluator.py), [`tests/eval/golden_dataset.json`](tests/eval/golden_dataset.json), [`tests/test_eval_suite.py`](tests/test_eval_suite.py), [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — Automated golden-dataset evaluation harness verifying tool trajectory recall, schema accuracy, HITL compliance, and zero PII leakage. |
| **5. Infrastructure & CI/CD** | **Infrastructure as Code** | [`terraform/main.tf`](terraform/main.tf), [`terraform/variables.tf`](terraform/variables.tf), [`terraform/outputs.tf`](terraform/outputs.tf) — Declarative Terraform provisioning Cloud Run / Vertex AI Agent Engine, Vertex AI Search, Secret Manager, and least-privilege IAM. |
| **5. Infrastructure & CI/CD** | **Secure Secret Management** | [`sre_agent/secrets.py`](sre_agent/secrets.py) — `SecretManagerClient` integrates `google.cloud.secretmanager.SecretManagerServiceClient` with multi-tiered secret resolution and zero hardcoded API keys. |

---

## 3. Quick Start & Local Verification

### Install Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run Unit Tests & Golden-Dataset Evaluation Suite
```bash
# Run the complete unit and integration test suite
pytest -v

# Run the 5-scenario Golden Dataset Regression Evaluation Suite specifically
pytest tests/test_eval_suite.py -v
```

---

## 4. Running & Deploying with Google ADK CLI and `agents-cli`

### Interactive Development with Google ADK CLI (`adk`)
```bash
# Launch the interactive ADK Web UI locally
adk web .

# Run the SRE Incident Response Coordinator in terminal mode
adk run sre_agent

# Execute ADK evaluation against the agent module
adk eval sre_agent tests/eval/golden_dataset.json
```

### Enterprise Deployment to Vertex AI Agent Engine (`agents-cli` / `agent-starter-pack`)
```bash
# 1. Authenticate and configure target Google Cloud project
gcloud auth login
gcloud config set project YOUR_GCP_PROJECT_ID

# 2. Scaffold or validate agent configuration with agents-cli
agents-cli create cloud-sre-incident-response-agent -y

# 3. Build and deploy to Vertex AI Agent Engine
UV_DEFAULT_INDEX=https://pypi.org/simple agents-cli deploy --no-confirm-project

# 4. Publish and register the agent with Gemini Enterprise
COLUMNS=250 agents-cli publish gemini-enterprise --list
agents-cli publish gemini-enterprise \
  --gemini-enterprise-app-id "projects/YOUR_PROJECT_NUMBER/locations/global/collections/default_collection/engines/YOUR_ENGINE_ID" \
  --display-name "Cloud SRE Incident Response Coordinator"
```

---

## 5. Infrastructure Provisioning with Terraform

All cloud resources (Vertex AI Search datastore, Secret Manager secrets, least-privilege Service Account, IAM bindings, and Cloud Run v2 service) are codified in [`terraform/`](terraform/):

```bash
cd terraform
terraform init
terraform plan -var="project_id=YOUR_GCP_PROJECT_ID" -var="region=us-central1"
terraform apply -var="project_id=YOUR_GCP_PROJECT_ID" -var="region=us-central1"
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
