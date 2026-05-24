from langchain_aws import BedrockEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from src.config import SecurityConfig
from src.vault import token_vault

# Initialize secure cloud-native text embedder
embeddings = BedrockEmbeddings(
    model_id=SecurityConfig.EMBEDDING_MODEL_ID,
    region_name=SecurityConfig.AWS_REGION
)

# Raw source data from our secure customer environment
RAW_UNSECURED_DATA = [
    Document(
        page_content="Policyholder: John Doe. Policy ID: POL-99281. Type: Auto. Windshield damage has a $0 deductible. Excludes track racing.",
        metadata={"tenant_id": "POL-99281"}
    ),
    Document(
        page_content="Policyholder: Jane Smith. Policy ID: POL-11024. Type: Homeowners. Flood damage is strictly EXCLUDED. Earthquake coverage requires a rider.",
        metadata={"tenant_id": "POL-11024"}
    )
]

# ZERO-PII INGESTION PIPELINE: Tokenize data BEFORE it gets vectorized
TOKENIZED_VAULT_DATA = []
for doc in RAW_UNSECURED_DATA:
    tokenized_content = token_vault.tokenize(doc.page_content)
    TOKENIZED_VAULT_DATA.append(
        Document(page_content=tokenized_content, metadata=doc.metadata)
    )

# Instantiate our isolated vector store index holding ONLY tokenized strings
vector_store = FAISS.from_documents(TOKENIZED_VAULT_DATA, embeddings)