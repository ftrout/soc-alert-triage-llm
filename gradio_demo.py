#!/usr/bin/env python3
"""Simple Gradio demo for Kodiak SecOps 1.

This is a minimal Gradio app designed for quick testing and
Hugging Face Spaces deployment.

Usage:
    python gradio_demo.py

For Hugging Face Spaces, rename this to app.py or set as the entry point.
"""

import json

import gradio as gr

# Sample alerts for demonstration
SAMPLE_ALERTS = {
    "Lateral Movement - Pass-the-Hash": {
        "alert_id": "ALERT-2024-001",
        "category": "lateral_movement",
        "severity": "high",
        "title": "Pass-the-hash attack detected",
        "description": "Suspicious authentication using NTLM hash credentials detected.",
        "indicators": {
            "source_host": "WS-PC-142",
            "destination_hosts": ["DC-01", "FILE-SRV-01"],
            "protocol": "SMB",
            "credentials_type": "pass_the_hash",
        },
        "user_context": {"username": "john.smith", "department": "Engineering", "is_vip": False},
        "asset_context": {"hostname": "WS-PC-142", "criticality": "medium"},
    },
    "Malware - Ransomware": {
        "alert_id": "ALERT-2024-002",
        "category": "malware",
        "severity": "critical",
        "title": "Ransomware signature detected",
        "description": "Known ransomware variant blocked from execution.",
        "indicators": {
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "file_name": "invoice_update.exe",
            "signature_match": "Ransomware.LockBit.A",
        },
        "user_context": {"username": "admin.user", "department": "Finance", "is_vip": True},
        "asset_context": {"hostname": "FIN-WS-001", "criticality": "high"},
    },
    "Phishing - Credential Harvesting": {
        "alert_id": "ALERT-2024-003",
        "category": "phishing",
        "severity": "medium",
        "title": "Suspected phishing link clicked",
        "description": "User clicked link redirecting to credential harvesting page.",
        "indicators": {
            "url": "https://login-microsoft.suspicious.site/auth",
            "email_sender": "security@micr0soft-support.com",
            "email_subject": "Urgent: Password Reset Required",
        },
        "user_context": {"username": "new.employee", "department": "Sales", "is_vip": False},
        "asset_context": {"hostname": "SALES-WS-042", "criticality": "low"},
    },
    "Data Exfiltration - Large Upload": {
        "alert_id": "ALERT-2024-004",
        "category": "data_exfiltration",
        "severity": "high",
        "title": "Unusual data upload to external service",
        "description": "Large volume uploaded to cloud storage outside business hours.",
        "indicators": {
            "destination": "mega.nz",
            "data_volume_mb": 2500,
            "file_types": [".docx", ".xlsx", ".pdf"],
        },
        "user_context": {
            "username": "departing.employee",
            "department": "R&D",
            "employment_status": "notice_period",
        },
        "asset_context": {"hostname": "RND-WS-007", "criticality": "high"},
    },
}


def create_demo_response(alert: dict) -> str:
    """Generate a demo triage response based on alert characteristics."""
    severity = alert.get("severity", "medium")
    category = alert.get("category", "unknown")

    # Simple rule-based demo logic
    if severity == "critical" or category in ["lateral_movement", "data_exfiltration"]:
        decision, priority, confidence = "ESCALATE", 1, 92
        escalation = "Incident Response Team"
    elif severity == "high":
        decision, priority, confidence = "INVESTIGATE", 2, 85
        escalation = "Security Operations Lead"
    elif severity == "medium":
        decision, priority, confidence = "INVESTIGATE", 3, 78
        escalation = None
    else:
        decision, priority, confidence = "MONITOR", 4, 70
        escalation = None

    user_ctx = alert.get("user_context", {})
    asset_ctx = alert.get("asset_context", {})

    # Build reasoning
    factors = []
    if severity in ["critical", "high"]:
        factors.append(f"{severity.title()} severity alert requires immediate attention")
    if category == "lateral_movement":
        factors.append("Lateral movement indicates active adversary in environment")
    if category == "data_exfiltration":
        factors.append("Data exfiltration poses significant risk of data loss")
    if user_ctx.get("is_vip"):
        factors.append("VIP user involved - elevated priority")
    if user_ctx.get("employment_status") == "notice_period":
        factors.append("User on notice period - increased insider threat risk")
    if asset_ctx.get("criticality") == "high":
        factors.append("High criticality asset affected")

    if not factors:
        factors.append("Standard triage procedures applied based on alert context")

    response = f"""## Triage Recommendation

### Decision Summary
| Field | Value |
|-------|-------|
| **Decision** | {decision} |
| **Priority** | {priority}/5 |
| **Confidence** | {confidence}% |
| **Escalation Required** | {'Yes' if escalation else 'No'} |
| **Escalation Target** | {escalation or 'N/A'} |
| **Estimated Impact** | {severity.title()} |

### Key Factors
{chr(10).join(f"- {f}" for f in factors)}

### Recommended Actions
1. Review the alert details and indicators of compromise
2. Check for related alerts in the same timeframe
3. Validate the affected assets and users
4. {'Escalate to ' + escalation + ' immediately' if escalation else 'Continue monitoring and document findings'}
5. Preserve evidence for potential investigation

---
*Demo Mode: This is a rule-based simulation. Deploy the full model for ML-powered analysis.*
"""
    return response


def triage_alert(example: str, custom_json: str) -> tuple[str, str]:
    """Process alert and return triage recommendation."""
    try:
        if example != "Custom JSON" and example in SAMPLE_ALERTS:
            alert = SAMPLE_ALERTS[example]
        elif custom_json.strip():
            alert = json.loads(custom_json)
        else:
            return "**Error:** Please select an example or enter custom JSON.", ""

        # Format alert display
        alert_display = f"""**Alert ID:** {alert.get('alert_id', 'N/A')}
**Category:** {alert.get('category', 'N/A')}
**Severity:** {alert.get('severity', 'N/A')}
**Title:** {alert.get('title', 'N/A')}

**Description:** {alert.get('description', 'N/A')}

**Indicators:**
```json
{json.dumps(alert.get('indicators', {}), indent=2)}
```"""

        result = create_demo_response(alert)
        return alert_display, result

    except json.JSONDecodeError as e:
        return f"**Error:** Invalid JSON - {e}", ""


def update_json(example: str) -> str:
    """Update JSON input when example is selected."""
    if example != "Custom JSON" and example in SAMPLE_ALERTS:
        return json.dumps(SAMPLE_ALERTS[example], indent=2)
    return ""


# Create the Gradio interface
with gr.Blocks(
    title="Kodiak SecOps 1",
    theme=gr.themes.Soft(),
) as demo:
    gr.Markdown(
        """
        # Kodiak SecOps 1

        Automated security alert triage powered by fine-tuned language models.
        Select a sample alert or enter custom JSON to get triage recommendations.

        **Model:** [ftrout/kodiak-secops-1](https://huggingface.co/ftrout/kodiak-secops-1) |
        **Dataset:** [ftrout/kodiak-secops-1-dataset](https://huggingface.co/datasets/ftrout/kodiak-secops-1-dataset)
        """
    )

    with gr.Row():
        with gr.Column(scale=1):
            example_dropdown = gr.Dropdown(
                choices=["Custom JSON"] + list(SAMPLE_ALERTS.keys()),
                value="Custom JSON",
                label="Select Example Alert",
            )
            alert_input = gr.Textbox(
                label="Alert JSON",
                placeholder='{"alert_id": "...", "category": "malware", ...}',
                lines=12,
            )
            submit_btn = gr.Button("Analyze Alert", variant="primary")

        with gr.Column(scale=1):
            alert_display = gr.Markdown(label="Alert Details")

    gr.Markdown("---")
    result_display = gr.Markdown(label="Triage Recommendation")

    # Event handlers
    example_dropdown.change(fn=update_json, inputs=[example_dropdown], outputs=[alert_input])
    submit_btn.click(
        fn=triage_alert,
        inputs=[example_dropdown, alert_input],
        outputs=[alert_display, result_display],
    )

    gr.Markdown(
        """
        ---
        ### About

        This demo showcases rule-based triage logic. For production use, deploy the
        [full fine-tuned model](https://huggingface.co/ftrout/kodiak-secops-1)
        for ML-powered analysis.

        *This tool assists security analysts - it does not replace human judgment.*
        """
    )

if __name__ == "__main__":
    demo.launch()
