"""
Pytest configuration and shared fixtures.
"""

import sys
from pathlib import Path

import pytest

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture(scope="session")
def sample_alert():
    """Sample alert for testing."""
    return {
        "alert_id": "TEST-001",
        "timestamp": "2024-01-15T10:30:00",
        "source_system": "Test System",
        "category": "malware",
        "severity": "high",
        "title": "Test malware alert",
        "description": "This is a test malware alert for unit testing.",
        "affected_assets": ["TEST-PC-001"],
        "indicators": {
            "file_hash": "abc123def456",
            "file_name": "test.exe",
            "process_id": 1234,
        },
        "user_context": {
            "username": "test.user",
            "email": "test.user@company.com",
            "department": "Engineering",
            "role": "Developer",
            "is_vip": False,
            "employment_status": "active",
        },
        "asset_context": {
            "hostname": "TEST-PC-001",
            "asset_type": "workstation",
            "criticality": "medium",
            "data_classification": "internal",
        },
        "environment_context": {
            "is_business_hours": True,
            "is_change_window": False,
            "threat_level": "normal",
        },
        "raw_log": "2024-01-15 10:30:00 MALWARE: hash=abc123 file=test.exe",
    }


@pytest.fixture(scope="session")
def sample_triage():
    """Sample triage response for testing."""
    return {
        "decision": "investigate",
        "priority": 2,
        "confidence_score": 0.85,
        "reasoning": "Suspicious executable detected with known malware patterns.",
        "key_factors": [
            "Known malware signature detected",
            "High severity alert",
        ],
        "recommended_actions": [
            "Isolate affected endpoint",
            "Collect forensic artifacts",
            "Review parent process",
        ],
        "escalation_required": False,
        "escalation_target": None,
        "estimated_impact": "moderate",
        "estimated_urgency": "hours",
        "additional_investigation": [
            "Check for lateral movement",
        ],
        "ioc_extraction": [
            "File hash: abc123def456",
        ],
    }


@pytest.fixture(scope="session")
def sample_predictions():
    """Sample predictions for evaluation testing."""
    return [
        {"decision": "escalate", "priority": 1, "escalation_required": True},
        {"decision": "investigate", "priority": 2, "escalation_required": False},
        {"decision": "monitor", "priority": 3, "escalation_required": False},
        {"decision": "false_positive", "priority": 4, "escalation_required": False},
        {"decision": "close", "priority": 5, "escalation_required": False},
    ]


@pytest.fixture(scope="session")
def sample_ground_truth():
    """Sample ground truth for evaluation testing."""
    return [
        {"decision": "escalate", "priority": 1, "escalation_required": True},
        {"decision": "investigate", "priority": 2, "escalation_required": False},
        {"decision": "investigate", "priority": 3, "escalation_required": False},
        {"decision": "false_positive", "priority": 4, "escalation_required": False},
        {"decision": "close", "priority": 5, "escalation_required": False},
    ]
