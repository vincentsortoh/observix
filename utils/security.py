"""
Security utilities for Observix.

This module provides utilities for handling sensitive data in observability contexts.
"""

import json
import re
from typing import Any, Dict, List, Set, Union, Pattern

# Default sensitive keys
DEFAULT_SENSITIVE_KEYS = {
    "password", "passwd", "token", "secret", "api_key", "authorization", 
    "auth", "credential", "ssn", "key", "private", "access_token",
    "refresh_token", "session_token", "client_secret"
}

# Default redaction value
DEFAULT_REDACTION_VALUE = "***REDACTED***"

# Compile regex patterns once for performance
def _compile_patterns(sensitive_keys: Set[str]) -> List[Pattern]:
    """Compile regex patterns for sensitive keys."""
    patterns = []
    for key in sensitive_keys:
        # Match the key as a whole word with optional word boundaries, 
        # case-insensitive
        patterns.append(re.compile(r'(?i)\b' + re.escape(key) + r'\b'))
    return patterns

class DataRedactor:
    """
    Utility class for redacting sensitive data in various formats.
    """
    
    def __init__(
        self, 
        sensitive_keys: Set[str] = None,
        redaction_value: str = DEFAULT_REDACTION_VALUE,
        enable_regex: bool = True
    ):
        """
        Initialize the DataRedactor.
        
        Args:
            sensitive_keys: Set of keys to consider sensitive
            redaction_value: Value to use when redacting sensitive data
            enable_regex: Whether to use regex matching for key detection
        """
        self.sensitive_keys = sensitive_keys or DEFAULT_SENSITIVE_KEYS.copy()
        self.redaction_value = redaction_value
        self.enable_regex = enable_regex
        self._patterns = _compile_patterns(self.sensitive_keys) if enable_regex else []
    
    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a key is sensitive using exact or regex matching."""
        # Check for exact matches first for performance
        if any(sk.lower() in key.lower() for sk in self.sensitive_keys):
            return True
            
        # Use regex matching if enabled
        if self.enable_regex:
            for pattern in self._patterns:
                if pattern.search(key):
                    return True
                    
        return False
    
    def redact_value(self, key: str, value: Any) -> str:
        """Redact a value if its key is sensitive."""
        return self.redaction_value if self._is_sensitive_key(key) else str(value)
    
    def redact_dict(self, data: Dict) -> Dict:
        """Redact sensitive values in a dictionary."""
        if not isinstance(data, dict):
            return data
            
        return {
            k: (
                self.redaction_value if self._is_sensitive_key(k) 
                else self.redact_json(v)
            )
            for k, v in data.items()
        }
    
    def redact_json(self, data: Any) -> Any:
        """Recursively redact sensitive data in a JSON-like structure."""
        if isinstance(data, dict):
            return self.redact_dict(data)
        elif isinstance(data, list):
            return [self.redact_json(item) for item in data]
        else:
            return data
    
    def redact_string(self, text: str) -> str:
        """
        Redact sensitive patterns in a string.
        Useful for log messages or stack traces.
        
        Note: This is a best-effort approach and can have false positives.
        """
        if not text or not isinstance(text, str):
            return text
            
        # Look for common patterns like "password=xyz" or "api_key: abc"
        for key in self.sensitive_keys:
            # Match patterns like "key=value", "key: value", "key":"value"
            patterns = [
                rf'({key}=)[^\s&]+',          # key=value
                rf'({key}:)[^\s,]+',          # key:value
                rf'({key}:\s*")[^"]+(")',     # key: "value"
                rf"({key}:\s*')[^']+('),"     # key: 'value'
            ]
            
            for pattern in patterns:
                text = re.sub(pattern, rf'\1{self.redaction_value}\2', text, flags=re.IGNORECASE)
                
        return text

# Create a default redactor instance
default_redactor = DataRedactor()

# Convenience functions using the default redactor
def redact_sensitive_data(key: str, value: Any) -> str:
    """Redacts the value if the key is considered sensitive."""
    return default_redactor.redact_value(key, value)

def redact_json(data: Any) -> Any:
    """Recursively redacts sensitive keys from a nested JSON-like structure."""
    return default_redactor.redact_json(data)

def redact_string(text: str) -> str:
    """Redact sensitive patterns in a string."""
    return default_redactor.redact_string(text)