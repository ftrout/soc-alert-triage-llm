"""
SOC Triage Agent - Security Operations Center Alert Triage Model
================================================================

A fine-tuned language model for automated security alert triage,
designed for Security Operations Centers (SOC).

Features:
- 12 security alert categories
- 5 triage decision types
- Context-aware priority assignment
- Actionable recommendations

License: Apache 2.0
"""

__version__ = "1.0.0"
__author__ = "SOC Triage Agent Contributors"
__license__ = "Apache-2.0"

from .data_generator import (
    SecurityAlertGenerator,
    AlertCategory,
    Severity,
    TriageDecision,
)
from .model import SOCTriageModel
from .evaluation import TriageEvaluator

__all__ = [
    "SecurityAlertGenerator",
    "AlertCategory", 
    "Severity",
    "TriageDecision",
    "SOCTriageModel",
    "TriageEvaluator",
    "__version__",
]
