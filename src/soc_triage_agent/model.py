"""SOC Triage Model Interface.
===========================

Provides a unified interface for loading and using fine-tuned
security triage models from Hugging Face Hub or local files.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union


@dataclass
class TriagePrediction:
    """Structured prediction from the triage model."""

    decision: str
    priority: int
    confidence: float
    reasoning: str
    recommended_actions: list[str]
    escalation_required: bool
    escalation_target: Optional[str]
    estimated_impact: str
    raw_output: str

    def to_dict(self) -> dict[str, Any]:
        """Convert prediction to dictionary."""
        return {
            "decision": self.decision,
            "priority": self.priority,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "recommended_actions": self.recommended_actions,
            "escalation_required": self.escalation_required,
            "escalation_target": self.escalation_target,
            "estimated_impact": self.estimated_impact,
        }


class SOCTriageModel:
    """Wrapper for SOC Triage models with consistent inference interface.

    Supports loading from:
    - Hugging Face Hub
    - Local model files
    - Azure OpenAI / OpenAI API

    Example:
        >>> model = SOCTriageModel.from_pretrained("your-org/soc-triage-model")
        >>> prediction = model.predict(alert_data)
        >>> print(f"Decision: {prediction.decision}")

    """

    SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst AI assistant. Your role is to analyze security alerts and provide comprehensive triage recommendations. For each alert, you should:

1. Assess the severity and potential impact based on all available context
2. Determine the appropriate triage decision (escalate, investigate, monitor, false_positive, or close)
3. Assign a priority level (1=highest/immediate, 5=lowest)
4. Provide clear, actionable reasoning for your decision
5. Recommend specific remediation and investigation actions
6. Identify indicators of compromise (IOCs) for threat hunting
7. Determine if escalation is required and to whom

Consider the full context including:
- User information (role, department, VIP status, employment status)
- Asset criticality and data classification
- Environmental factors (business hours, change windows, threat level)
- Historical patterns and related alerts

Provide your response in a structured format that can be easily parsed and actioned by the SOC team."""

    def __init__(
        self,
        model=None,
        tokenizer=None,
        model_type: str = "transformers",
        device: str = "auto",
        **kwargs,
    ):
        """Initialize the model wrapper.

        Args:
            model: The loaded model (transformers, vllm, etc.)
            tokenizer: The tokenizer
            model_type: Type of model ("transformers", "vllm", "openai", "azure")
            device: Device to use ("auto", "cuda", "cpu")
            **kwargs: Additional configuration

        """
        self.model = model
        self.tokenizer = tokenizer
        self.model_type = model_type
        self.device = device
        self.config = kwargs

        # For API-based models
        self.api_client = None
        self.api_model_name = kwargs.get("api_model_name")

    @classmethod
    def from_pretrained(
        cls,
        model_name_or_path: str,
        device: str = "auto",
        load_in_8bit: bool = False,
        load_in_4bit: bool = False,
        use_flash_attention: bool = True,
        **kwargs,
    ) -> "SOCTriageModel":
        """Load a pre-trained SOC Triage model.

        Args:
            model_name_or_path: HuggingFace model ID or local path
            device: Device to use
            load_in_8bit: Use 8-bit quantization
            load_in_4bit: Use 4-bit quantization
            use_flash_attention: Use Flash Attention 2
            **kwargs: Additional arguments for model loading

        Returns:
            SOCTriageModel instance

        """
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as err:
            raise ImportError(
                "transformers and torch required. Install with: pip install transformers torch"
            ) from err

        # Determine device
        if device == "auto":
            device = "cuda" if torch.cuda.is_available() else "cpu"

        print(f"Loading model from {model_name_or_path}...")

        # Load tokenizer
        tokenizer = AutoTokenizer.from_pretrained(
            model_name_or_path,
            trust_remote_code=True,
            **kwargs,
        )

        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        # Prepare model loading arguments
        model_kwargs = {
            "trust_remote_code": True,
            "device_map": device if device != "cpu" else None,
        }

        if load_in_8bit:
            model_kwargs["load_in_8bit"] = True
        elif load_in_4bit:
            model_kwargs["load_in_4bit"] = True
            try:
                from transformers import BitsAndBytesConfig

                model_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_use_double_quant=True,
                    bnb_4bit_quant_type="nf4",
                )
            except ImportError:
                print("Warning: bitsandbytes not available, skipping 4-bit quantization")
                del model_kwargs["load_in_4bit"]

        if use_flash_attention:
            model_kwargs["attn_implementation"] = "flash_attention_2"

        # Load model
        model = AutoModelForCausalLM.from_pretrained(
            model_name_or_path,
            **model_kwargs,
        )

        if device == "cpu":
            model = model.to("cpu")

        print(f"Model loaded successfully on {device}")

        return cls(
            model=model,
            tokenizer=tokenizer,
            model_type="transformers",
            device=device,
        )

    @classmethod
    def from_openai(
        cls,
        model_name: str,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        **kwargs,
    ) -> "SOCTriageModel":
        """Create a model wrapper for OpenAI API.

        Args:
            model_name: OpenAI model name (e.g., "gpt-4", or fine-tuned model ID)
            api_key: OpenAI API key (uses env var if not provided)
            api_base: Custom API base URL

        Returns:
            SOCTriageModel instance

        """
        try:
            from openai import OpenAI
        except ImportError as err:
            raise ImportError("openai required. Install with: pip install openai") from err

        import os

        client = OpenAI(
            api_key=api_key or os.getenv("OPENAI_API_KEY"),
            base_url=api_base,
        )

        instance = cls(
            model=None,
            tokenizer=None,
            model_type="openai",
            api_model_name=model_name,
        )
        instance.api_client = client

        return instance

    @classmethod
    def from_azure_openai(
        cls,
        deployment_name: str,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        api_version: str = "2024-02-15-preview",
        **kwargs,
    ) -> "SOCTriageModel":
        """Create a model wrapper for Azure OpenAI.

        Args:
            deployment_name: Azure OpenAI deployment name
            endpoint: Azure OpenAI endpoint
            api_key: Azure OpenAI API key
            api_version: API version

        Returns:
            SOCTriageModel instance

        """
        try:
            from openai import AzureOpenAI
        except ImportError as err:
            raise ImportError("openai required. Install with: pip install openai") from err

        import os

        client = AzureOpenAI(
            api_key=api_key or os.getenv("AZURE_OPENAI_KEY"),
            azure_endpoint=endpoint or os.getenv("AZURE_OPENAI_ENDPOINT"),
            api_version=api_version,
        )

        instance = cls(
            model=None,
            tokenizer=None,
            model_type="azure",
            api_model_name=deployment_name,
        )
        instance.api_client = client

        return instance

    def format_alert(self, alert: dict[str, Any]) -> str:
        """Format an alert dictionary into a prompt."""
        # Handle different alert formats
        if "messages" in alert:
            # Already formatted
            return alert["messages"][1]["content"]

        prompt = f"""Analyze the following security alert and provide a comprehensive triage recommendation:

## Alert Details
- **Alert ID:** {alert.get('alert_id', 'N/A')}
- **Timestamp:** {alert.get('timestamp', 'N/A')}
- **Source System:** {alert.get('source_system', alert.get('source', 'N/A'))}
- **Category:** {alert.get('category', 'N/A')}
- **Severity:** {alert.get('severity', 'N/A')}

## Alert Information
**Title:** {alert.get('title', 'N/A')}

**Description:** {alert.get('description', 'N/A')}

**Affected Assets:** {', '.join(alert.get('affected_assets', ['N/A']))}
"""

        if alert.get("indicators"):
            prompt += f"""
## Indicators of Compromise
```json
{json.dumps(alert['indicators'], indent=2)}
```
"""

        if alert.get("user_context"):
            ctx = alert["user_context"]
            prompt += f"""
## User Context
- **Username:** {ctx.get('username', 'N/A')}
- **Department:** {ctx.get('department', 'N/A')}
- **Role:** {ctx.get('role', 'N/A')}
- **Risk Level:** {ctx.get('risk_level', 'N/A')}
- **VIP Status:** {'Yes' if ctx.get('is_vip') else 'No'}
"""

        if alert.get("asset_context"):
            ctx = alert["asset_context"]
            prompt += f"""
## Asset Context
- **Hostname:** {ctx.get('hostname', 'N/A')}
- **Asset Type:** {ctx.get('asset_type', 'N/A')}
- **Criticality:** {ctx.get('criticality', 'N/A')}
- **Data Classification:** {ctx.get('data_classification', 'N/A')}
"""

        if alert.get("raw_log"):
            prompt += f"""
## Raw Log Entry
```
{alert['raw_log']}
```
"""

        prompt += "\nProvide your triage recommendation with decision, priority, reasoning, and specific actions."

        return prompt

    def parse_response(self, response: str) -> TriagePrediction:
        """Parse model response into structured prediction."""
        # Default values
        decision = "investigate"
        priority = 3
        confidence = 0.8
        reasoning = ""
        actions = []
        escalation_required = False
        escalation_target = None
        estimated_impact = "moderate"

        # Parse decision
        decision_match = re.search(r"\*\*Decision\*\*[:\s|]+(\w+)", response, re.IGNORECASE)
        if decision_match:
            decision = decision_match.group(1).lower()

        # Parse priority
        priority_match = re.search(r"\*\*Priority\*\*[:\s|]+(\d)", response)
        if priority_match:
            priority = int(priority_match.group(1))

        # Parse confidence
        confidence_match = re.search(r"\*\*Confidence\*\*[:\s|]+(\d+)", response)
        if confidence_match:
            confidence = float(confidence_match.group(1)) / 100

        # Parse escalation
        escalation_match = re.search(
            r"\*\*Escalation Required\*\*[:\s|]+(Yes|No)", response, re.IGNORECASE
        )
        if escalation_match:
            escalation_required = escalation_match.group(1).lower() == "yes"

        escalation_target_match = re.search(r"\*\*Escalation Target\*\*[:\s|]+([^\n|]+)", response)
        if escalation_target_match:
            target = escalation_target_match.group(1).strip()
            if target.lower() != "n/a":
                escalation_target = target

        # Parse impact
        impact_match = re.search(r"\*\*Estimated Impact\*\*[:\s|]+(\w+)", response, re.IGNORECASE)
        if impact_match:
            estimated_impact = impact_match.group(1).lower()

        # Parse reasoning section
        reasoning_match = re.search(r"### Reasoning\n(.+?)(?=###|\Z)", response, re.DOTALL)
        if reasoning_match:
            reasoning = reasoning_match.group(1).strip()
        else:
            # Try to get key factors
            factors_match = re.search(r"### Key Factors\n(.+?)(?=###|\Z)", response, re.DOTALL)
            if factors_match:
                reasoning = factors_match.group(1).strip()

        # Parse actions
        actions_match = re.search(r"### Recommended Actions\n(.+?)(?=###|\Z)", response, re.DOTALL)
        if actions_match:
            actions_text = actions_match.group(1)
            for line in actions_text.split("\n"):
                line = line.strip()
                if line and (line[0].isdigit() or line.startswith("-")):
                    action = re.sub(r"^[\d\.\-\s]+", "", line).strip()
                    if action:
                        actions.append(action)

        return TriagePrediction(
            decision=decision,
            priority=priority,
            confidence=confidence,
            reasoning=reasoning,
            recommended_actions=actions[:6],
            escalation_required=escalation_required,
            escalation_target=escalation_target,
            estimated_impact=estimated_impact,
            raw_output=response,
        )

    def predict(
        self,
        alert: Union[dict[str, Any], str],
        max_new_tokens: int = 1024,
        temperature: float = 0.3,
        **kwargs,
    ) -> TriagePrediction:
        """Generate triage prediction for an alert.

        Args:
            alert: Alert data (dict) or formatted prompt (str)
            max_new_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional generation parameters

        Returns:
            TriagePrediction with structured output

        """
        # Format alert if needed
        user_message = self.format_alert(alert) if isinstance(alert, dict) else alert

        if self.model_type in ["openai", "azure"]:
            return self._predict_api(user_message, max_new_tokens, temperature, **kwargs)
        else:
            return self._predict_transformers(user_message, max_new_tokens, temperature, **kwargs)

    def _predict_api(
        self,
        user_message: str,
        max_new_tokens: int,
        temperature: float,
        **kwargs,
    ) -> TriagePrediction:
        """Generate prediction using OpenAI/Azure API."""
        response = self.api_client.chat.completions.create(
            model=self.api_model_name,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            max_tokens=max_new_tokens,
            temperature=temperature,
            **kwargs,
        )

        output_text = response.choices[0].message.content
        return self.parse_response(output_text)

    def _predict_transformers(
        self,
        user_message: str,
        max_new_tokens: int,
        temperature: float,
        **kwargs,
    ) -> TriagePrediction:
        """Generate prediction using transformers model."""
        # Format as chat
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]

        # Apply chat template
        if hasattr(self.tokenizer, "apply_chat_template"):
            prompt = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )
        else:
            prompt = f"{self.SYSTEM_PROMPT}\n\nUser: {user_message}\n\nAssistant:"

        # Tokenize
        inputs = self.tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=4096,
        )

        if self.device != "cpu":
            inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

        # Generate
        import torch

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature if temperature > 0 else None,
                do_sample=temperature > 0,
                pad_token_id=self.tokenizer.pad_token_id,
                **kwargs,
            )

        # Decode
        output_text = self.tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1] :],
            skip_special_tokens=True,
        )

        return self.parse_response(output_text)

    def batch_predict(
        self,
        alerts: list[Union[dict[str, Any], str]],
        batch_size: int = 8,
        **kwargs,
    ) -> list[TriagePrediction]:
        """Generate predictions for multiple alerts.

        Args:
            alerts: List of alerts
            batch_size: Batch size for inference
            **kwargs: Additional generation parameters

        Returns:
            List of TriagePrediction objects

        """
        predictions = []

        for i in range(0, len(alerts), batch_size):
            batch = alerts[i : i + batch_size]
            for alert in batch:
                pred = self.predict(alert, **kwargs)
                predictions.append(pred)

        return predictions

    def save_pretrained(self, output_dir: str) -> None:
        """Save model and tokenizer to directory."""
        if self.model is None or self.tokenizer is None:
            raise ValueError("Cannot save API-based model")

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        self.model.save_pretrained(output_path)
        self.tokenizer.save_pretrained(output_path)

        # Save config
        config = {
            "model_type": self.model_type,
            "system_prompt": self.SYSTEM_PROMPT,
        }
        with open(output_path / "soc_triage_config.json", "w") as f:
            json.dump(config, f, indent=2)

    def push_to_hub(
        self,
        repo_id: str,
        private: bool = False,
        **kwargs,
    ) -> str:
        """Push model to Hugging Face Hub.

        Args:
            repo_id: Repository ID (e.g., "username/model-name")
            private: Whether to create private repo
            **kwargs: Additional arguments for push_to_hub

        Returns:
            Repository URL

        """
        if self.model is None or self.tokenizer is None:
            raise ValueError("Cannot push API-based model")

        self.model.push_to_hub(repo_id, private=private, **kwargs)
        self.tokenizer.push_to_hub(repo_id, private=private, **kwargs)

        return f"https://huggingface.co/{repo_id}"
