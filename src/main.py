from langgraph.graph import START, END, StateGraph
from src.state import SecureGraphState
from src.vault import token_vault  # Wire in our secure Token Vault mapping engine
from src.nodes import (
    retrieve_secured_documents, 
    compliance_audit_node, 
    generate_sanitized_answer, 
    mitigation_fallback_handler
)

def route_governance_decision(state: SecureGraphState) -> str:
    """Conditional Edge validating path logic based on the compliance audit."""
    if state["compliance_grade"] == "safe_relevant":
        return "generate"
    return "fallback"

# =====================================================================
# LangGraph State Machine Construction
# =====================================================================
builder = StateGraph(SecureGraphState)

# Register workflow components
builder.add_node("retrieve", retrieve_secured_documents)
builder.add_node("audit", compliance_audit_node)
builder.add_node("generate", generate_sanitized_answer)
builder.add_node("fallback", mitigation_fallback_handler)

# Establish execution paths
builder.add_edge(START, "retrieve")
builder.add_edge("retrieve", "audit")
builder.add_conditional_edges("audit", route_governance_decision, {
    "generate": "generate",
    "fallback": "fallback"
})
builder.add_edge("generate", END)
builder.add_edge("fallback", END)

secure_agent_api = builder.compile()

# =====================================================================
# Production Gateway Proxy Wrapper
# =====================================================================
def run_production_gateway(user_query: str, policy_id: str) -> str:
    """
    Simulates an Edge API Gateway that tokenizes sensitive PII metrics at ingress
    and safely restores them at egress, keeping the LLM execution sandbox anonymous.
    """
    # 1. Ingress Sanitization: Intercept PII before it hits the application tier
    tokenized_query = token_vault.tokenize(user_query)
    
    inputs = {
        "question": tokenized_query,
        "policy_id": policy_id
    }
    
    # 2. Execute the isolated Graph Workflow
    final_state = secure_agent_api.invoke(inputs)
    raw_generation = final_state.get("generation", "")
    
    # 3. Egress Desanitization: Restore plaintext values for authorized UI presentation
    secure_output = token_vault.detokenize(raw_generation)
    return secure_output

# Remove the old messy print blocks from the bottom of src/main.py
if __name__ == "__main__":
    print("🚀 Secure Multi-Tenant Insurance Routing Gateway Active.")
    print("Execute 'pytest -v' to run the automated validation infrastructure.")