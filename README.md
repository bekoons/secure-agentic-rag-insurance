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

To check the execution readiness of the underlying routing framework layout, spin up the entry point gateway script:

```bash
python -m src.main
```

### Expected Output Behavior
The runtime initializes the single-tenant states cleanly and confirms that the gateway is actively listening for validated client contexts:
```text
🚀 Secure Multi-Tenant Insurance Routing Gateway Active.
Execute 'pytest -v' to run the automated validation infrastructure.
```

---

## 🧪 Automated Security Verification

The repository incorporates an automated validation suite containing **7 separate test cases**. This framework splits testing constraints into two paradigms: six negative boundary tests tracking our specific **STRIDE** vectors to prevent regression, and one robust keyword-token test verifying our functional **Happy Path**.

To execute the entire verification suite, run:

```bash
pytest -v
```

### Passing Verification Footprint
The test harness runs smoothly, validating your entire application-layer security posture and core business logic in under 1.5 seconds:

```text
=================================== test session starts ===================================
platform darwin -- Python 3.13.0, pytest-8.3.4, pluggy-1.5.1 -- 
cachedir: .pytest_cache
rootdir: /Users/username/Documents/Coding/secure-agentic-rag-insurance
collected 7 items                                                                         

tests/test_security_stride.py::test_stride_spoofing_mitigation PASSED               [ 14%]
tests/test_security_stride.py::test_stride_tampering_mitigation PASSED              [ 28%]
tests/test_security_stride.py::test_stride_repudiation_mitigation PASSED             [ 42%]
tests/test_security_stride.py::test_stride_information_disclosure_mitigation PASSED  [ 57%]
tests/test_security_stride.py::test_stride_denial_of_service_mitigation PASSED      [ 71%]
tests/test_security_stride.py::test_stride_elevation_of_privilege_mitigation PASSED [ 85%]
tests/test_security_stride.py::test_happy_path_compliant_flow PASSED                 [100%]

==================================== 7 passed in 1.32s ====================================
```

## ⚠️ Operational Caveats & Production Gap Analysis

This repository serves as a localized Proof of Concept (PoC) demonstrating application-layer security boundaries. To deploy this architecture into a distributed, production-grade enterprise cloud network, the following operational gaps and unaddressed threat vectors must be resolved:

### 1. In-Memory State and Storage Ephemerality
* **The PoC State:** Both the `PIITokenVault` proxy dictionary and the `FAISS` vector database index operate entirely within local ephemeral process memory (`RAM`).
* **The Production Shift:** In a multi-node or serverless auto-scaling cluster (e.g., AWS ECS or AWS Lambda), in-memory state will drift and fragment across containers. Production deployments must decouple storage from compute:
  * Replace the local token dictionary with a centralized, low-latency key-value engine like **Redis Enterprise** or a dedicated hardware security module (HSM) system like **HashiCorp Vault / AWS Secrets Manager**.
  * Migrate from local FAISS arrays to an enterprise, single-tenant filtered vector cluster like **Amazon OpenSearch Service** or **pgvector on Amazon RDS**.

### 2. Mocked Identification vs. Cryptographic Authn/Authz
* **The PoC State:** The tenant boundary check (`validate_tenant_boundary`) relies on a flat string match against a hardcoded lookup map passed via unauthenticated state dictionaries.
* **The Production Shift:** Relying on the client application to supply its own trusted user context invites parameters-tampering vulnerabilities. The pipeline gateway must interface with an Identity Provider (IdP) via **OAuth 2.0 / OIDC** (e.g., **Amazon Cognito** or **Auth0**). The execution entry point should expect a cryptographically signed **JSON Web Token (JWT)**, parsing the tenant attributes securely from the verified signature payload.

### 3. Telemetry and Immutable Audit Trails
* **The PoC State:** The non-repudiation ledger (`write_to_encrypted_audit_vault`) is simulated via structured console output streams (`stdout`).
* **The Production Shift:** Audit logs generated within the app tier must be treated as highly sensitive data targets susceptible to tampering. Production pipelines must stream these event blocks directly to an external logging framework (e.g., **Amazon Kinesis Firehose** routing to an **Amazon S3** bucket). The target bucket must be configured with a **Write-Once-Read-Many (WORM)** retention lock and protected with envelope encryption managed via explicit **AWS KMS** key policies to guarantee administrative non-repudiation.

### 4. Recursive Input/Output Jailbreak Vectors (Meta-Injections)
* **The PoC State:** The system relies on a secondary LLM invocation layer within the `compliance_audit_node` to score prompt integrity.
* **The Production Shift:** While highly effective against standard indirect prompt injections, this patterns introduces a "recursive jailbreak" vulnerability, where a sophisticated adversary structures an exploit payload designed to bypass or jailbreak the *compliance model itself*. Enterprise architectures must deploy layered defense-in-depth filters, incorporating native input-length filtering, heuristic pattern analyzers, and dedicated model firewalls such as **Amazon Bedrock Guardrails** or standalone classifiers (e.g., Meta's Llama Guard) operating outside the primary orchestration graph.

### 5. Application-Layer Distributed Denial of Service (DDoS)
* **The PoC State:** The LangGraph topology successfully mitigates internal, infinite node processing loops via deterministic execution paths. It does *not*, however, protect the pipeline against external billing attacks.
* **The Production Shift:** An adversary could flood the API Gateway with millions of valid, well-formed requests, rapidly draining corporate API token budgets and overwhelming backend processing capabilities. A production gateway must be shielded at the cloud edge utilizing **AWS WAF** (Web Application Firewall) to enforce strict IP rate-limiting, geo-fencing, and token-bucket request throttling prior to routing payloads downstream to the agentic orchestration container.