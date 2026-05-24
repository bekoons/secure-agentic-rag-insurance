import re
from typing import Dict, Tuple

class PIITokenVault:
    """
    A bidirectional, in-memory Token Vault simulating an enterprise-grade 
    isolated tokenization proxy (e.g., AWS DynamoDB secured with KMS).
    """

    def __init__(self):
        # Bi-directional mapping tables
        self.vault_token_to_raw: Dict[str, str] = {}
        self.vault_raw_to_token: Dict[str, str] = {}

        # Simple entity seed data for our insurance lab
        # In production, this would be dynamically generated via AWS Comprehend PII or Microsoft Presidio
        self.pii_dictionary = {
            "John Doe": "TOKEN_PH_8821",
            "Jane Smith": "TOKEN_PH_0042",
            "basement flooding": "SEMANTIC_RISK_WATER",
            "windshield damage": "SEMANTIC_RISK_GLASS"
        }

        self._initialize_vault()
    
    def _initialize_vault(self) -> None:
        """Populates the bi-directional mapping lookup tables."""
        for raw_value, token in self.pii_dictionary.items():
            self.vault_token_to_raw[token] = raw_value
            self.vault_raw_to_token[raw_value] = token

    def tokenize(self, text: str) -> str:
        """Scans raw text and replaces sensitive PII/Risk entities with secure tokens."""
        tokenized_text = text
        for raw_value, token in self.vault_raw_to_token.items():
            # Case-insensitive replacement to sanitize messy inputs
            compiled_regex = re.compile(re.escape(raw_value), re.IGNORECASE)
            tokenized_text = compiled_regex.sub(token, tokenized_text)
        return tokenized_text
    
    def detokenize(self, tokenized_text: str) -> str:
        """Restores surrogate tokens back to their raw enterprise values at the secure egress gateway."""
        detokenized_text = tokenized_text
        for token, raw_value in self.vault_token_to_raw.items():
            detokenized_text = detokenized_text.replace(token, raw_value)
        return detokenized_text

# Instantiate a single global vault instance to act as our centralized proxy service
token_vault = PIITokenVault()