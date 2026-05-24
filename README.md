# 🛡️ Secure Multi-Tenant Agentic RAG Pipeline (Insurance Architecture)

An enterprise-grade, zero-trust implementation of a Corrective RAG (CRAG) system designed for regulated industries. This repository demonstrates how to decouple conversational AI from autonomous, unpredictable execution paths by enforcing strict data governance boundaries, deterministic state machines, and programmatic compliance firewalls.

Built with **LangGraph**, **Amazon Bedrock (Nova/Titan)**, and **FAISS (Multi-Tenant Simulation)**.

---

## 🦾 The Architecture Angle: Security First, AI Second

Most GenAI portfolio projects focus exclusively on model accuracy or agent autonomy. This project approaches AI agents from a **zero-trust security posture**, treating the Large Language Model (LLM) as an untrusted third-party runtime component that must be tightly sandboxed by engineering guardrails. 

In highly regulated sectors like insurance (HIPAA, SOC2, strict PII compliance), letting an autonomous agent execute open-ended loops or handle unrestricted data access is an unacceptable operational risk. This framework addresses that hurdle directly.

---

## 🔒 Key Security & Data Governance Controls

### 1. Deterministic State Machine Routing (LangGraph)
* **The Vulnerability:** Open-ended, autonomous agent loops (e.g., standard ReAct patterns) are highly susceptible to indirect prompt injection and infinite token-wasting cycles.
* **The Mitigation:** This pipeline uses `LangGraph` to enforce a strict, cyclical state graph (`START -> Retrieve -> Audit -> Generate/Fallback -> END`). The LLM cannot decide its own execution path; it is confined to deterministic transitions governed by the application runtime.

### 2. Vertical Tenant Data Isolation
* **The Vulnerability:** Multi-tenant architectures often suffer from cross-tenant data bleeding when users craft queries that trick vector databases into pulling neighbor embeddings from other organizations.
* **The Mitigation:** Implements a strict cryptographic/string session validation boundary (`SecurityConfig.validate_tenant_boundary`) before the database layer is queried. Retrieval queries are hard-filtered by explicit, validated metadata attributes (`tenant_id`), guaranteeing strict data partition isolation.

### 3. Asymmetric Input Sanitization & Compliance Auditing
* **The Vulnerability:** Over-reliance on retrieved data payloads can cause models to ingest malicious data text instructions embedded inside messy PDFs or claims documents.
* **The Mitigation:** Introduces an isolated, zero-variance (Zero-Temperature) `compliance_audit_node` that serves as an application-layer firewall. This node acts as a Boolean Evaluator, validating retrieved document context against strict criteria before passing payloads to the final generation layer.

### 4. Zero-Stochastic Variance & Cloud Data Privacy
* **The Vulnerability:** Fine-tuning public models or sending data to open endpoints risks intellectual property exposure and regulatory breaches.
* **The Mitigation:** Powered natively by `Amazon Bedrock`. All model interactions are kept within an isolated enterprise cloud perimeter, ensuring data is never used to train foundational models. Temperatures are strictly locked at `0.0` to eliminate non-deterministic hallucinations.

### 5. Production Observability and Audit Trails
* Fully configured for automated tracing via `LangSmith`. Every execution step, token budget, embedding latency, and compliance grade is logged immutably, providing the transparent data lineage required by enterprise risk management teams.
