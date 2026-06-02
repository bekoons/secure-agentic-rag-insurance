# Hardening AI Agents: A STRIDE-Hardened LangGraph Pipeline

For the full architectural breakdown and threat modeling decisions behind this implementation, read the writeup here:

👉 **[docs/writeup.md](docs/writeup.md)**

---

This pipeline is a skeleton insurance routing agent built with LangGraph and Amazon Bedrock, designed from the ground up to treat the LLM as an untrusted runtime. All data isolation, privacy controls, and compliance workflows are enforced at the application layer, completely outside the model's control.

---

## Architectural Overview

The system is organized into four layers:

* **Orchestration (`src/main.py`, `src/state.py`):** A deterministic DAG state machine that enforces bounded node execution, preventing runaway execution loops.
* **Privacy Proxy (`src/vault.py`):** A bidirectional token vault that strips PII at ingress before it touches the model or any logging framework.
* **Data Storage (`src/database.py`):** An in-memory FAISS vector index storing only pre-tokenized content, with hard ABAC metadata filters enforcing policy-level data isolation.
* **Regulatory Firewall (`src/nodes.py`):** A compliance node that evaluates queries against contextual grounding boundaries using structured JSON parsing, with asymmetric audit logging on every request.

---

## Core Security Patterns

### Ingress Tokenization Proxy
Redaction strips context and hashing destroys linguistics. Both break model utility. Instead, the `PIITokenVault` replaces raw identifiers with structured placeholder tokens like `TOKEN_PH_8821` at ingress. The model maintains logical coherence, your tracing dashboards stay compliant, and plaintext values are only restored at the egress boundary before reaching the end user.

### Cross-Policy Data Isolation
Two stacked controls prevent cross-policy data leakage:
1. **In-memory boundary validation:** The `policy_id` is verified in application memory before any database query runs.
2. **ABAC filter enforcement:** The FAISS retriever is hard-constrained to that policy's document partition via a strict metadata match.

### Fail-Closed Compliance Node
If the model returns a response that violates contextual grounding parameters or fails structured JSON parsing, the node doesn't try to recover. It defaults to a max-security block state and logs the event before short-circuiting the graph.

---

## STRIDE Threat Matrix

| STRIDE Category | Target Component | Attack Vector | Mitigation |
| :--- | :--- | :--- | :--- |
| **[S] Spoofing** | State Ingress / Gateway | Adversary forges a `policy_id` to manipulate the execution context. | In-memory boundary validation (`validate_tenant_boundary`) before any retrieval occurs. |
| **[T] Tampering** | Vector Index / Nodes | Malicious strings hidden in claims documents hijack the model's instructions via indirect prompt injection. | `compliance_audit_node` evaluates inputs against structured JSON compliance criteria. |
| **[R] Repudiation** | Node Transitions | Routing decisions occur without a verifiable audit trail. | `write_to_encrypted_audit_vault` streams structured state logs to an encrypted ledger. |
| **[I] Info Disclosure** | Vector Cache / Telemetry | Raw PII bleeds into vector storage or unencrypted monitoring dashboards. | Ingress tokenization proxy strips PII before it touches any part of the pipeline. |
| **[D] Denial of Service** | Graph Workflow | Recursive prompt strategies force an open-ended agent loop, exhausting resources and spiking costs. | Hard-bounded graph topology with deterministic termination conditions (`__end__`). |
| **[E] Privilege Elevation** | Generation Sandbox | Prompt jailbreak attempts to execute backend commands or extract system prompts. | Context-only generation sandbox with a fail-closed error posture. |

---

## Prerequisites & Setup

* Python 3.13+
* An active AWS account with model access enabled for **Amazon Nova Micro** and **Titan Embeddings V2** in your target region (`us-east-1`)

### IAM Configuration
This project uses a customer-managed IAM policy scoped strictly to runtime inference on the two approved model ARNs. Don't use `AmazonBedrockFullAccess`.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "HardenedBedrockInvocation",
            "Effect": "Allow",
            "Action": ["bedrock:InvokeModel"],
            "Resource": [
                "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0",
                "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-micro-v1:0"
            ]
        }
    ]
}
```

### Installation

```bash
git clone https://github.com/yourusername/secure-agentic-rag-insurance.git
cd secure-agentic-rag-insurance
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
AWS_ACCESS_KEY_ID="your_iam_access_key"
AWS_SECRET_ACCESS_KEY="your_iam_secret_key"
AWS_DEFAULT_REGION="us-east-1"

LANGSMITH_TRACING="true"
LANGSMITH_ENDPOINT="https://api.smith.langchain.com"
LANGSMITH_API_KEY="your_langsmith_api_key"
LANGSMITH_PROJECT="your_project_name"
```

---

## Running the Application

```bash
python -m src.main
```

A successful run initializes the routing gateway and confirms it's ready to accept requests:

```text
Secure Multi-Tenant Insurance Routing Gateway Active.
Run 'pytest -v' to verify the security controls.
```

---

## Running the Test Suite

The STRIDE threat model is codified into an automated pytest suite with two types of tests: six negative boundary tests covering each STRIDE vector, and one happy path test verifying legitimate requests still work as expected.

```bash
pytest -v
```

```text
tests/test_security_stride.py::test_stride_spoofing_mitigation PASSED               [ 14%]
tests/test_security_stride.py::test_stride_tampering_mitigation PASSED              [ 28%]
tests/test_security_stride.py::test_stride_repudiation_mitigation PASSED             [ 42%]
tests/test_security_stride.py::test_stride_information_disclosure_mitigation PASSED  [ 57%]
tests/test_security_stride.py::test_stride_denial_of_service_mitigation PASSED      [ 71%]
tests/test_security_stride.py::test_stride_elevation_of_privilege_mitigation PASSED [ 85%]
tests/test_security_stride.py::test_happy_path_compliant_flow PASSED                 [100%]

==================================== 7 passed in 1.32s ====================================
```

All seven tests pass in under 1.5 seconds. If a future pull request drops a boundary or exposes an index, this suite breaks the build before it ships.

---

## Production Gap Analysis

This is a skeleton, not a production system. Here's what would need to change before it is one.

### A. Memory State
Both the `PIITokenVault` and the FAISS index live in memory. In an auto-scaling environment, state fragments across nodes and everything breaks. The token vault needs to move to Redis or AWS Secrets Manager, and the vector index needs to move to a distributed engine like Amazon OpenSearch Service.

### B. Authentication
The current auth boundary is a string match against a client-supplied parameter. That's not authentication, it's a suggestion. Production gateways need OAuth 2.0 / OIDC through an Identity Provider like Amazon Cognito, with a cryptographically signed JWT parsed at the entry point.

### C. Audit Logging
Audit events are currently written to stdout. In production, logs need to stream via Amazon Kinesis Firehose to an isolated S3 bucket with a WORM Object Lock policy and customer-managed KMS encryption.

### D. Advanced Attack Vectors
The LLM-as-Judge compliance node can itself be targeted by recursive jailbreaks. The system also has no protection against DDoS attacks designed to exhaust API token budgets. Add Amazon Bedrock Guardrails as an upstream filter and wrap public entry points with AWS WAF for rate limiting and IP throttling.