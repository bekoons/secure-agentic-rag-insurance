import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from langchain_aws import ChatBedrockConverse
from src.config import SecurityConfig
from src.state import SecureGraphState
from src.database import vector_store

llm = ChatBedrockConverse(
    model_id=SecurityConfig.MODEL_ID, 
    region_name=SecurityConfig.AWS_REGION, 
    temperature=0.0 # Zero stochastic variance for compliance determinism
)

def write_to_encrypted_audit_vault(payload: Dict[str, Any]) -> None:
    """
    Simulates streaming a structured audit event to an immutable S3 Bucket 
    hardened with AWS KMS (Key Management Service) SSE-KMS encryption.
    """
    log_id = f"AUDIT-LOG-{uuid.uuid4()}"
    payload["audit_metadata"] = {
        "log_id": log_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "encryption_standard": "aws:kms",
        "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/compliance-ledger-key"
    }
    
    # In production, this would use boto3: s3.put_object(Bucket='compliance-vault', Key=..., Body=json.dumps(payload))
    print(f"\n🔒 [COMPLIANCE LEDGER] Securing event {log_id} to Encrypted S3 Vault...")
    print(json.dumps(payload, indent=2))

def retrieve_secured_documents(state: SecureGraphState) -> Dict[str, Any]:
    """Retrieves documents enforcing strict attribute-based data access filters"""
    policy_id = state["policy_id"]

    # Security Control: Verify execution context boundary limits
    if not SecurityConfig.validate_tenant_boundary(policy_id):
        print(f"[SECURITY ALERT] Unauthorized Data Partition Attempt Detected on: {policy_id}")
        return {"documents": [], "security_flag": True}

    # Standard Metadata filtering guarantees single-tenant data isolation
    retriever = vector_store.as_retriever(
        search_kwargs={'filter': {'tenant_id': policy_id}, 'k': 1}
    )
    docs = retriever.invoke(state["question"])
    return {"documents": docs, "security_flag": False}

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

def generate_sanitized_answer(state: SecureGraphState) -> Dict[str, Any]:
    """Generates user response inside a confined sandbox prompt scenario."""
    context = state["documents"][0].page_content

    system_instruction = (
        f"Context: {context}\n"
        "Task: Answer the user query using ONLY the verified context facts above. "
        "Governance Policy: If the answer is not supported explicitly by the context, "
        "state that you are unable to fulfill the request. Never extrapolate policy terms."
    )

    #   Construct a unified message list containing the system instructions
    messages = [
        {"role": "system", "content": system_instruction},
        {"role": "user", "content": state["question"]}
    ]
    
    response = llm.invoke(messages)
    return {"generation": response.content}

def mitigation_fallback_handler(state: SecureGraphState) -> Dict[str, Any]:
    """Safe exception-handling node preventing data exposure leaks."""
    return {"generation": "Security Exception: Fails data compliance standards. Fulfill request via standard customer service rails."}