"""SOC Triage Agent - Security Operations Center Alert Triage Model.
================================================================

A fine-tuned language model for automated security alert triage,
designed for Security Operations Centers (SOC).

Features:
- 12 security alert categories
- 5 triage decision types
- Context-aware priority assignment
- Actionable recommendations
- Adversarial example generation
- SOAR platform integrations
- Analyst feedback collection
- A/B testing prompt variants

License: Apache 2.0
"""

__version__ = "1.1.0"
__author__ = "SOC Triage Agent Contributors"
__license__ = "Apache-2.0"

from .adversarial import AdversarialGenerator, AdversarialType
from .ait_dataset import AITDatasetLoader
from .data_generator import (
    AlertCategory,
    SecurityAlertGenerator,
    Severity,
    TriageDecision,
)
from .evaluation import TriageEvaluator
from .feedback import FeedbackCollector, FeedbackMiddleware
from .model import SOCTriageModel
from .prompts import DecisionThresholds, PromptManager
from .soar_adapters import (
    SOARAdapter,
    SplunkSOARAdapter,
    WebhookAdapter,
    XSOARAdapter,
    get_adapter,
)

__all__ = [
    # Core
    "SecurityAlertGenerator",
    "SOCTriageModel",
    "TriageEvaluator",
    # Data
    "AITDatasetLoader",
    "AdversarialGenerator",
    "AdversarialType",
    # Enums
    "AlertCategory",
    "Severity",
    "TriageDecision",
    # Prompts
    "PromptManager",
    "DecisionThresholds",
    # Feedback
    "FeedbackCollector",
    "FeedbackMiddleware",
    # SOAR
    "SOARAdapter",
    "XSOARAdapter",
    "SplunkSOARAdapter",
    "WebhookAdapter",
    "get_adapter",
    # Meta
    "__version__",
]
