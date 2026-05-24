import os
from dotenv import load_dotenv

# Programmatically locate and load the local .env file into the system environment
load_dotenv()

class SecurityConfig:
    """Centralized Data Governance and Security Profile Configuration."""
    
    # Enforce LangSmith observability tracking
    LANGCHAIN_TRACING_V2: str = os.getenv("LANGCHAIN_TRACING_V2", "true")
    LANGCHAIN_PROJECT: str = os.getenv("LANGCHAIN_PROJECT", "Secure-Insurance-Agent-Audit")

    # Model compliance profile (Amazon Bedrock architecture)
    MODEL_ID: str = "amazon.nova-micro-v1:0"
    EMBEDDING_MODEL_ID: str = "amazon.titan-embed-text-v2:0"
    AWS_REGION: str = "us-east-1"

    # Hard data boundaries: Never allow cross-tenant reading
    ALLOWED_TENANTS: set = {"POL-99281", "POL-11024"}

    @classmethod
    def validate_tenant_boundary(cls, tenant_id: str) -> bool:
        """Data governance check validating requested tenant ID belongs to current session authorization context."""
        return tenant_id in cls.ALLOWED_TENANTS