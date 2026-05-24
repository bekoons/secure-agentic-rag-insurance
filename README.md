# Hardening AI Agents: A STRIDE-Hardened LangGraph Pipeline

This repository implements an enterprise-grade, multi-tenant AI insurance agent pipeline built with **LangGraph** and **Amazon Bedrock**. 

Unlike naive GenAI applications that rely on fragile prompt engineering as a security control, this architecture treats the Large Language Model (LLM) as an **untrusted third-party runtime environment**. All multi-tenancy boundaries, data privacy rules, and regulatory governance workflows are enforced deterministically at the application tier.

---

## 🏗️ Architectural Topology

The system isolates execution state, data indexes, and processing nodes into a zero-trust sandbox topology:

* **Orchestration Tier (`src/main.py`, `src/state.py`):** Uses a deterministic Directed Acyclic Graph (DAG) state machine to enforce bounded node execution transitions, eliminating infinite-loop token exhaustion vectors.
* **Privacy Proxy Layer (`src/vault.py`):** A bidirectional token vault intercepting text data at ingress to strip Personally Identifiable Information (PII) prior to model processing or logging.
* **Isolated Data Storage (`src/database.py`):** An in-memory vector index (`FAISS`) storing solely pre-tokenized content, backed by structural Attribute-Based Access Control (ABAC) metadata filters.
* **Regulatory Firewall (`src/nodes.py`):** A compliance node utilizing structured JSON parsing to evaluate queries against contextual grounding boundaries and proxy discrimination policies, utilizing asymmetric streaming telemetry.

---

## 🔒 Core Security Design Patterns

### 1. Ingress Tokenization Proxy
Traditional text redaction (e.g., `[REDACTED]`) and cryptographic hashing (e.g., SHA-256) degrade an LLM's attention mechanism by stripping logical context or inserting cryptographic noise. 

Our `PIITokenVault` implements bidirectional token substitution. Raw identifiers are replaced at ingress with structural placeholder entities (e.g., `TOKEN_PH_8821`). The LLM maintains perfect logic tracking, and telemetry logs (e.g., LangSmith traces) remain entirely compliant and free of PII liability. Plaintext values are safely restored at the outbound egress gateway only.

### 2. Multi-Tenant Authorization Boundaries
To defeat data cross-talk, the application enforces defensive layers:
1. **In-Memory Validation:** Incoming `policy_id` state tokens are verified against cryptographic boundaries before a database context query is executed.
2. **ABAC Filter Enforcement:** The vector database retriever strictly limits its similarity search space using absolute hard matching strings (`{'filter': {'tenant_id': policy_id}}`).

### 3. Fail-Closed Compliance Graph Node
Aligned with modern AI compliance guidelines (e.g., NAIC Model Bulletin and Colorado AI Act), an active evaluation node grades model generation inputs. If an injection attack or model anomaly forces a violation of contextual grounding parameters, or if the model fails to return structured schema arrays, the application intercepts the runtime error and triggers an immediate **fail-closed** routing path to a safe security fallback state.

---

## 📊 STRIDE Threat Matrix

Our application-layer controls map directly to Microsoft’s STRIDE threat modeling framework:

| STRIDE Category | Target Component | Agentic Attack Vector | Hardened Application Mitigation |
| :--- | :--- | :--- | :--- |
| **[S] Spoofing** | State Ingress / Gateway | Adversary forges a `policy_id` token payload to manipulate the thread execution context. | In-memory token verification check (`validate_tenant_boundary`) inside application space prior to retrieval. |
| **[T] Tampering** | Vector Index / Processing Nodes | **Indirect Prompt Injection:** Malicious text strings hidden in claims documents hijack the model's core instruction pointer. | Unified `compliance_audit_node` conducting multi-criteria compliance parsing via structured JSON evaluation. |
| **[R] Repudiation** | Node Transitions / Decisions | Automated claims routing, filtering, or system actions occur without a verifiable audit trail. | Automated streaming ledger (`write_to_encrypted_audit_vault`) exporting structured state logs securely via AWS KMS. |
| **[I] Info Disclosure** | Vector Cache / Telemetry Streams | Sensitive client records or corporate data bleed into vector cache indices or cloud logging monitors. | **Ingress Tokenization Proxy Layer:** Real PII is programmatically stripped and substituted for non-exploitable surrogate hashes. |
| **[D] Denial of Service** | Graph Workflow Topology | Recursive prompt strategies force an open-ended autonomous loop, exhausting compute resources. | Hard-bounded graph topology constructed via LangGraph that enforces strict, deterministic termination conditions (`__end__`). |
| **[E] Privilege Elevation** | Core Generation Sandbox | Prompt jailbreak overrides system rules to execute backend commands, manipulate tools, or leak instructions. | Context-only sandboxed generation arrays combined with a structural fail-closed error response posture. |

---

## 🛠️ Prerequisites & Local Setup

### System Prerequisites
* Python 3.13+ installed locally.
* An active AWS Account with model access granted for **Amazon Nova** and **Titan Embeddings V2** in your selected deployment region (e.g., `us-east-1`).

### AWS IAM Least-Privilege Governance
To satisfy enterprise blast-radius constraints and pass rigorous AppSec reviews, this project rejects the broad, AWS-managed `AmazonBedrockFullAccess` policy. Instead, create a **Customer-Managed IAM Policy** and attach it to your programmatic `insurance-agent-dev` user. 

This policy restricts actions exclusively to runtime inference (`bedrock:InvokeModel`) and explicitly scopes resources strictly to the approved model ARNs configured in `src/config.py`:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "HardenedBedrockInvocation",
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel"
            ],
            "Resource": [
                "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0",
                "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-micro-v1:0"
            ]
        }
    ]
}
```

### Installation Steps

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/yourusername/secure-agentic-rag-insurance.git](https://github.com/yourusername/secure-agentic-rag-insurance.git)
   cd secure-agentic-rag-insurance
   ```

2. **Initialize the Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Consolidated Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables:**
   Create a `.env` file in the root project directory (this file is pre-excluded by the `.gitignore` profile to prevent credential leaks):
   ```env
   AWS_ACCESS_KEY_ID=your_programmatic_iam_access_key
   AWS_SECRET_ACCESS_KEY=your_programmatic_iam_secret_key
   AWS_DEFAULT_REGION=us-east-1
   ```

---

## 🚀 Running the Application

Execute the unified execution gateway to run local validation checks:

```bash
python -m src.main
```

### Expected Output Behavior
* **Test Case 1 (Compliant Flow):** Demonstrates an incoming query containing client PII. The gateway tokenizes the data, evaluates it safely within the sandbox, creates an encrypted JSON compliance ledger event log, and restores the real values at egress.
* **Test Case 2 (Malicious Probe):** Simulates an administrative breach attempt. The system intercepts the spoofed tenant ID, triggers a security flag alert, writes the attack signature to the telemetry log, and safely terminates the runtime thread.

---

## 🧪 Automated Security Verification

The repository incorporates an automated security regression test suite that translates our whiteboard threat model directly into continuous CI/CD validation gates.

To execute the verification suite, run:

```bash
pytest -v
```

### Passing Verification Footprint
The suite executes all six STRIDE parameter assertions locally in under 1.5 seconds, guaranteeing that future code modifications or prompt adjustments can never introduce security posture regressions:

```text
=================================== test session starts ===================================
platform darwin -- Python 3.13.0, pytest-8.3.4, pluggy-1.5.1 -- 
cachedir: .pytest_cache
rootdir: /Users/username/Documents/Coding/secure-agentic-rag-insurance
collected 6 items                                                                         

tests/test_security_stride.py::test_stride_spoofing_mitigation PASSED               [ 16%]
tests/test_security_stride.py::test_stride_tampering_mitigation PASSED              [ 33%]
tests/test_security_stride.py::test_stride_repudiation_mitigation PASSED             [ 50%]
tests/test_security_stride.py::test_stride_information_disclosure_mitigation PASSED  [ 66%]
tests/test_security_stride.py::test_stride_denial_of_service_mitigation PASSED      [ 83%]
tests/test_security_stride.py::test_stride_elevation_of_privilege_mitigation PASSED [100%]

==================================== 6 passed in 1.14s ====================================
```
