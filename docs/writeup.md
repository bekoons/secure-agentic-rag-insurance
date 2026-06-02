
# Hardening AI Agents: Codifying a STRIDE Threat Model for LangGraph Pipelines

When engineering software architectures around Large Language Models (LLMs), it's easy to make the mistake of thinking that we can make an unpredictable tool give us predictable outputs if our instructions are comprehensive enough. This framing leads to an over-reliance on prompt engineering alone as the core security control, which is the equivalent of trying to secure a production  environment by asking it nicely to behave.

The fact that the model itself is unpredictable doesn't mean your application layer gets to be unpredictable too. If you're shipping an AI agent into a regulated environment like insurance processing, you need hard boundaries that exist completely outside the model's control.

This post walks through a skeleton implementation of a multi-tenant insurance pipeline built with LangGraph and Amazon Bedrock, evaluated against Microsoft's **STRIDE** threat model. The goal isn't a production-ready system, it's to demonstrate the core architectural decisions around tenant isolation, PII tokenization, and automated security testing, and show you exactly where the real boundaries need to live.

---

## Phase 1: Securing the Foundations (IAM & Secrets Hygiene)

Every build starts at ground level. When spinning up local services that talk to cloud models, the first failure point is almost always credential management. Accidentally staging a root AWS key to a public repo isn't just embarrassing, it's a compliance breach.
This architecture handles it with two layers of defense:

### The Repository Firewall (.env & .gitignore)
For local development, we keep credentials out of the codebase entirely by loading them from a .env file at runtime using python-dotenv, with the file itself blocked from git via .gitignore:
```text 
# Local Environment Secret Vaults (CRITICAL)
.env

# Python cache files
__pycache__/
*.pyc
```
In production you'd replace this with GitHub Actions secrets or a dedicated secrets manager like AWS Secrets Manager or HashiCorp Vault. The point is that credentials never touch the codebase.

### The Principle of Least Privilege (IAM Architecture)
Avoiding long-lived administrative "Root" keys is a non-negotiable security baseline. However, simply using a separate IAM user with an AWS-managed policy like `AmazonBedrockFullAccess` is still an architectural vulnerability. Managed access profiles grant broader privileges than the service needs, which violates basic security hygiene like least privilege access.

To enforce the **Principle of Least Privilege (PoLP)**, we attach a custom scoped identity policy to our programmatic `insurance-agent-dev` user. This limits access strictly to runtime inference (`bedrock:InvokeModel`) and explicitly targets the resource scope to only what's necessary for the application to function:

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
                "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1:0"
            ]
        }
    ]
}
```

> 💡 **Why explicitly scope your model ARNs?**
> By locking the policy down to specific model ARNs, you shrink your credential blast radius. If an adversary compromises this environment, they can't pivot to unvetted models or rack up runaway compute costs.

---

## Phase 2: Enforcing Single-Tenant Data Isolation

In an insurance context, cross-policy data leakage is a critical risk. If a user belonging to Policy A can trick the retrieval mechanism into pulling documents from Policy B, we have a serious problem.

While metadata filtering at the database layer is highly effective, relying *solely* on the database to handle isolation creates a single point of failure. This pipeline addresses this by stacking authorization checks in application memory *before* a query ever hits the vector index.

```python
def retrieve_secured_documents(state: SecureGraphState) -> Dict[str, Any]:
    """Retrieves documents enforcing strict attribute-based data access filters"""
    policy_id = state["policy_id"]

    # Security Control: Verify execution context boundary limits in-memory
    if not SecurityConfig.validate_tenant_boundary(policy_id):
        print(f"[SECURITY ALERT] Unauthorized Data Partition Attempt Detected on: {policy_id}")
        return {"documents": [], "security_flag": True}

    # Attribute-Based Data Access (ABAC) metadata filtering at the database layer
    retriever = vector_store.as_retriever(
        search_kwargs={'filter': {'tenant_id': policy_id}, 'k': 1}
    )
    docs = retriever.invoke(state["question"])
    return {"documents": docs, "security_flag": False}
```

### In-Memory Context Boundary Validation
The `validate_tenant_boundary` hook acts as an authorization wall. If an unrecognized or spoofed policy_id is passed into the state dictionary, the hook intercepts the state transition, sets a global `security_flag = True`, short-circuits database execution entirely, and returns an empty payload.

### Attribute-Based Access Control (ABAC) at Rest
If the boundary validation passes, the system applies a hard metadata filter inside FAISS using the `policy_id` as a strict match argument. This limits the similarity search to that specific policy's documents, eliminating cross-policy data leakage at the storage layer.

---

## Phase 3: The Privacy Layer (Ingress Tokenization Proxy)

When deploying agentic retrieval systems, data privacy and model capability are often in direct conflict. If an agent processes sensitive insurance claims containing PII, that raw text traverses your network, sits in your vector store, and streams into your tracing dashboards. Every one of those touchpoints is a potential HIPAA or GLBA liability.

### Why Redaction and Cryptographic Hashing Fail
Traditional approaches default to text redaction (replacing names with `[REDACTED]`) or cryptographic hashing (converting names to SHA-256 strings). Both break model utility in different ways:
1. **Redaction strips context:** If a document reads `[REDACTED] collided with [REDACTED]`, the model has no way to track who is the policyholder and who is the third party.
2. **Hashing destroys linguistics:** A 64-character hex string looks like noise to an LLM, which corrupts its ability to understand relationships between entities in the document.

### The Solution: The Bi-directional Tokenization Proxy
This implementation uses a simple in-memory `PIITokenVault` class to simulate what a real tokenization proxy would do. In production you'd replace this with a dedicated service like AWS Comprehend for PII detection or a purpose-built tokenization platform like Skyflow or AWS Macie, but the pattern is the same.

```python
import re
from typing import Dict

class PIITokenVault:
    """A bidirectional, in-memory Token Vault simulating a secure proxy tier."""
    def __init__(self):
        self.vault_token_to_raw: Dict[str, str] = {}
        self.vault_raw_to_token: Dict[str, str] = {}
        
        # Mapping dictionaries representing our secure enterprise vault entities
        self.pii_dictionary = {
            "John Doe": "TOKEN_PH_8821",
            "Jane Smith": "TOKEN_PH_0042",
            "windshield damage": "SEMANTIC_RISK_GLASS"
        }
        self._initialize_vault()

    def _initialize_vault(self) -> None:
        for raw_value, token in self.pii_dictionary.items():
            self.vault_token_to_raw[token] = raw_value
            self.vault_raw_to_token[raw_value] = token

    def tokenize(self, text: str) -> str:
        tokenized_text = text
        for raw_value, token in self.vault_raw_to_token.items():
            compiled_regex = re.compile(re.escape(raw_value), re.IGNORECASE)
            tokenized_text = compiled_regex.sub(token, tokenized_text)
        return tokenized_text

    def detokenize(self, tokenized_text: str) -> str:
        detokenized_text = tokenized_text
        for token, raw_value in self.vault_token_to_raw.items():
            detokenized_text = detokenized_text.replace(token, raw_value)
        return detokenized_text

token_vault = PIITokenVault()
```

By substituting raw PII with structured surrogate tokens like `TOKEN_PH_8821`, we get two things at once:
* **Linguistic utility:** The model treats the surrogate as a discrete entity, so grammatical relationships and logical flow are preserved.
* **Observability compliance:** The LangGraph state machine and AWS Bedrock only ever see anonymized tokens, so your tracing dashboards are clean of any regulatory liability.

Once the model generates its response, the egress boundary detokenizes the payload before it reaches the end user.

---

## Phase 4: Codifying the STRIDE Threat Matrix

With the core defensive layers in place, here's how they map against each STRIDE threat category. This isn't meant to be exhaustive. In production, threat modeling should be a part of regular feature planning and each of these threat vectors would be mapped to tracked GitHub issues and prioritized into development cycles like any other engineering work.

| STRIDE Threat | Target Component | Attack Vector | Mitigation |
| :--- | :--- | :--- | :--- |
| **[S] Spoofing** <br>*Identity* | State Ingress / API Gateway | Adversary inputs a forged `policy_id` to manipulate the execution context. | In-memory boundary validation (`validate_tenant_boundary`) before any retrieval occurs. |
| **[T] Tampering** <br>*Data Integrity* | Retrieval Vector Index / Nodes | Malicious strings hidden in claims documents hijack the model's instructions via indirect prompt injection. | `compliance_audit_node` evaluates inputs against structured JSON compliance criteria. |
| **[R] Repudiation** <br>*Traceability* | Node Execution Transitions | System actions and routing decisions occur without a verifiable audit trail. | `write_to_encrypted_audit_vault` streams structured state logs to an encrypted ledger. |
| **[I] Info Disclosure** <br>*Data Privacy* | Storage Tier / Telemetry Streams | Raw PII bleeds into vector storage or unencrypted monitoring dashboards. | Ingress tokenization proxy strips PII before it touches any part of the pipeline. |
| **[D] Denial of Service** <br>*Availability* | Graph Workflow State Loop | Recursive prompt strategies force an open-ended agent loop, exhausting resources and spiking costs. | Hard-bounded graph topology with deterministic termination conditions (`__end__`). |
| **[E] Privilege Elevation** <br>*Authorization* | Core Generation Sandbox | Prompt jailbreak attempts to execute backend commands or extract system prompts. | Context-only generation sandbox with a fail-closed error posture. |

### Deep Dive: The Regulatory Audit Node (`src/nodes.py`)
The `compliance_audit_node` acts as an application firewall, evaluating each request against three compliance dimensions: Contextual Grounding, Data Completeness, and Proxy Discrimination Mitigation. This is particularly relevant if you're operating under frameworks like the NAIC Model Bulletin or the Colorado AI Act.

Crucially, it implements an **asymmetric logging posture** and a **fail-closed runtime environment**:

```python
def compliance_audit_node(state: SecureGraphState) -> Dict[str, Any]:
    """
    An advanced regulatory firewall evaluating context alignment, 
    input completeness, and proxy discrimination risks prior to routing.
    """
    policy_id = state["policy_id"]
    question = state["question"]
    docs = state["documents"]
    
    # Pre-capture security flag status
    if state.get("security_flag") or not docs:
        audit_result = {"compliance_grade": "unsafe_irrelevant", "reasoning": "Administrative boundary check failure or null data retrieval."}
        
        # Audit Mandate: Even blocked or malicious requests MUST be logged for regulatory tracking
        write_to_encrypted_audit_vault({
            "policy_id": policy_id,
            "raw_input_question": question,
            "action_taken": "BLOCKED_BY_FIREWALL",
            "compliance_metrics": audit_result
        })
        return audit_result

    doc_content = docs[0].page_content

    # Advanced Regulatory Prompting (Addressing NAIC and Colorado AI Act requirements)
    regulatory_prompt = f"""
    You are an automated regulatory risk-mitigation controller operating under state insurance compliance mandates.
    Evaluate the following user query against the retrieved policy document context using these strict parameters:
    
    1. CONTEXTUAL GROUNDING: Is the user's question answerable using ONLY the facts present in the Document?
    2. DATA COMPLETENESS: Does the request provide sufficient legitimate parameters to assess an insurance term, or is it an unstructured/malicious probe?
    3. PROXY DISCRIMINATION MITIGATION: Does the user query attempt to force evaluation based on prohibited characteristics (e.g., race, age, gender, credit bias) not authorized in the policy text?
    
    Document Context: {doc_content}
    User Query: {question}
    
    Output your assessment in strict JSON format with exactly two keys:
    {{
        "grade": "safe_relevant" OR "unsafe_irrelevant",
        "reasoning": "A concise explanation detailing the compliance evaluation metrics used."
    }}
    Do not output any introductory or concluding text outside the raw JSON object.
    """

    # Invoke the model and clean the JSON string output
    response = llm.invoke(regulatory_prompt)
    try:
        compliance_payload = json.loads(response.content.strip())
        grade = compliance_payload.get("grade", "unsafe_irrelevant")
        reasoning = compliance_payload.get("reasoning", "Parsed successfully.")
    except Exception:
        # Fail-Closed Posture: If the LLM output violates JSON formatting constraints, drop to a safe state
        grade = "unsafe_irrelevant"
        reasoning = "System Error: LLM compliance output failed structural JSON parsing constraints."

    audit_result = {"compliance_grade": grade, "reasoning": reasoning}

    # Stream the complete cryptographic ledger entry
    write_to_encrypted_audit_vault({
        "policy_id": policy_id,
        "raw_input_question": question,
        "retrieved_context_snapshot": doc_content,
        "action_taken": "EVALUATED",
        "compliance_metrics": audit_result
    })

    return audit_result
```

* **Asymmetric Telemetry:** Blocked requests generate usable intel. The system captures the attack vector and logs it to an encrypted S3 vault before short-circuiting the graph.
* **Fail-Closed Parsing:** LLMs occasionally wrap JSON responses in conversational text or markdown, which breaks parsing. If the `except Exception` block catches anything malformed, the state defaults to `unsafe_irrelevant` rather than trying to recover.

---

## The Automated Threat Model Test Suite

A threat model is only as good as its enforcement. Security controls regress when developers modify prompts, swap out nodes, or update dependencies without realizing they've dropped a boundary somewhere. The test suite exists to catch that before it hits production.

To solve this, the STRIDE threat model is codified into an automated `pytest` suite with two types of tests: six negative boundary tests covering each STRIDE vector, and one happy path test (`test_happy_path_compliant_flow`) that verifies legitimate requests still work as expected.

```python
import pytest
from src.main import secure_agent_api, run_production_gateway
from src.database import vector_store

def test_stride_spoofing_mitigation():
    """Verifies that an attacker cannot spoof an unauthorized policy identifier."""
    inputs = {"question": "What is my deductible?", "policy_id": "POL-SPOOFED-ATTACKER-ID"}
    output = secure_agent_api.invoke(inputs)
    assert output["security_flag"] is True
    assert output["compliance_grade"] == "unsafe_irrelevant"
    assert "Security Exception" in output["generation"]

def test_stride_information_disclosure_vector_anonymity():
    """Verifies that no raw client PII exists at rest within the database indices."""
    database_dump = vector_store.similarity_search("John Doe", k=2)
    for document in database_dump:
        assert "John Doe" not in document.page_content
        assert "TOKEN_PH_" in document.page_content

def test_stride_denial_of_service_mitigation():
    """Verifies that the graph structure enforces immediate termination constraints."""
    graph_structure = secure_agent_api.get_graph()
    edges = [(edge.source, edge.target) for edge in graph_structure.edges]
    # Enforce that all final processing nodes map directly to the structural END checkpoint
    assert ("generate", "__end__") in edges
    assert ("fallback", "__end__") in edges

# ... remaining STRIDE tests follow the same pattern, see test_security_stride.py for full suite.

def test_happy_path_compliant_flow():
    """Validates legitimate execution and resists non-deterministic phrasing failure."""
    valid_query = "Hi, I am John Doe. Does my auto policy cover windshield damage?"
    valid_policy_id = "POL-99281"
    
    secure_output = run_production_gateway(valid_query, valid_policy_id)
    normalized_output = secure_output.lower()

    # Avoid brittle, exact phrase strings. Check decoupled keyword token sets.
    assert "security exception" not in normalized_output
    assert "windshield" in normalized_output
    assert "deductible" in normalized_output
    assert "$0" in normalized_output
    assert "policy" in normalized_output
```

### Navigating Non-Deterministic AI Testing
A common pitfall in agent testing is relying on exact string matching. Because models have natural linguistic variance, something as minor as "your auto policy" vs "your policy" will break a fragile assertion and fail the build.

The happy path test handles this by checking for strict structural exclusions on security failures, while using loose keyword assertions (`"policy"`, `"windshield"`, `"$0"`) to verify the business logic. The model can phrase its response however it wants as long as the right information is there.

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

All seven tests in the skeleton test suite pass in under 1.4 seconds. If a future pull request accidentally drops a boundary or exposes an index, this suite breaks the build before it ships.

---

## Production Gap Analysis

This skeleton gets the architectural decisions right, but there are clear gaps between what's implemented here and what a production deployment would require.

### A. Memory State Decoupling
* **The Gap:** Both the `PIITokenVault` and the FAISS index live entirely in memory. In an auto-scaling environment like AWS Lambda or ECS, state fragments across nodes and everything breaks.
* **The Fix:** Decouple compute from storage. The token vault needs to move to a centralized key-value store like Redis or a dedicated secrets manager like HashiCorp Vault or AWS Secrets Manager. The vector index needs to move to a distributed engine like Amazon OpenSearch Service.

### B. Authentication
* **The Gap:** The current auth boundary is a simple string match against a client-supplied parameter. That's not authentication, it's a suggestion.
* **The Fix:** Production gateways need OAuth 2.0 / OIDC flows through an Identity Provider like Amazon Cognito. The agent entry point should expect a cryptographically signed JWT and parse identity from verified claims rather than trusting raw client input.

### C. Audit Logging
* **The Gap:** Audit events are currently written to stdout.
* **The Fix:** Logs need to stream asynchronously via Amazon Kinesis Firehose to an isolated S3 bucket protected with a WORM Object Lock policy and encrypted with customer-managed keys via AWS KMS.

### D. Advanced Attack Vectors
* **The Gap:** The LLM-as-Judge compliance node can itself be targeted by sophisticated recursive jailbreaks. The system also has no protection against DDoS attacks designed to exhaust API token budgets.
* **The Fix:** Add Amazon Bedrock Guardrails as an upstream filter running outside the graph workflow, and wrap public entry endpoints with AWS WAF for rate limiting and IP-based throttling.

---

## Conclusion

The core idea here isn't complicated. LLMs are untrusted runtimes, and your application layer needs to treat them that way. Prompt engineering is not a security strategy.

Mapping your threat surface against STRIDE, proxying PII through a token vault, and locking your mitigations into an automated test suite won't make your agent perfectly secure, but it will make it predictable enough to actually ship.

---
*The full source code is available on my GitHub. Clone it, run the test suite, and let me know what you think in the comments.*