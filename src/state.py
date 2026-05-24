from typing import List, Dict, Any
from typing_extensions import TypedDict
from langchain_core.documents import Document

class SecureGraphState(TypedDict):
    """
    Strictly schema-enforced state machine layout.
    Prevents unpredictable payload modification across execution nodes.
    """
    question: str
    policy_id: str
    documents: List[Document]
    compliance_grade: str # Must resolve explicitly to 'safe_relevant' or 'unsafe_irrelevant'
    generation: str
    security_flag: bool # Set to True if data boundary violations are captured
