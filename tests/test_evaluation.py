"""
Tests for the Evaluation Module
"""

import pytest

from soc_triage_agent import TriageEvaluator
from soc_triage_agent.evaluation import EvaluationResult


@pytest.fixture
def evaluator():
    """Create a fresh evaluator for each test."""
    return TriageEvaluator()


class TestTriageEvaluator:
    """Tests for TriageEvaluator class."""

    def test_init(self, evaluator):
        """Test evaluator initialization."""
        assert evaluator.predictions == []
        assert evaluator.ground_truth == []

    def test_add_prediction(self, evaluator):
        """Test adding a prediction."""
        pred = {"decision": "escalate", "priority": 1, "escalation_required": True}
        gt = {"decision": "escalate", "priority": 1, "escalation_required": True}

        evaluator.add_prediction(pred, gt)

        assert len(evaluator.predictions) == 1
        assert len(evaluator.ground_truth) == 1

    def test_reset(self, evaluator):
        """Test resetting the evaluator."""
        pred = {"decision": "escalate", "priority": 1, "escalation_required": True}
        gt = {"decision": "escalate", "priority": 1, "escalation_required": True}

        evaluator.add_prediction(pred, gt)
        evaluator.reset()

        assert evaluator.predictions == []
        assert evaluator.ground_truth == []

    def test_evaluate_perfect_predictions(self, evaluator):
        """Test evaluation with perfect predictions."""
        for _i in range(10):
            pred = {"decision": "escalate", "priority": 1, "escalation_required": True}
            gt = {"decision": "escalate", "priority": 1, "escalation_required": True}
            evaluator.add_prediction(pred, gt)

        result = evaluator.evaluate()

        assert result.decision_accuracy == 1.0
        assert result.priority_mae == 0.0
        assert result.escalation_precision == 1.0
        assert result.escalation_recall == 1.0

    def test_evaluate_all_wrong_predictions(self, evaluator):
        """Test evaluation with all wrong predictions."""
        predictions = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "escalate", "priority": 1, "escalation_required": True},
        ]
        ground_truth = [
            {"decision": "close", "priority": 5, "escalation_required": False},
            {"decision": "monitor", "priority": 4, "escalation_required": False},
        ]

        result = evaluator.evaluate(predictions, ground_truth)

        assert result.decision_accuracy == 0.0

    def test_evaluate_mixed_predictions(self, evaluator):
        """Test evaluation with mixed predictions."""
        predictions = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "investigate", "priority": 2, "escalation_required": False},
            {"decision": "monitor", "priority": 3, "escalation_required": False},
            {"decision": "close", "priority": 5, "escalation_required": False},
        ]
        ground_truth = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "investigate", "priority": 3, "escalation_required": False},
            {"decision": "false_positive", "priority": 4, "escalation_required": False},
            {"decision": "close", "priority": 5, "escalation_required": False},
        ]

        result = evaluator.evaluate(predictions, ground_truth)

        # 3 out of 4 correct
        assert result.decision_accuracy == 0.75
        assert result.total_samples == 4
        assert result.correct_samples == 3

    def test_evaluate_with_categories(self, evaluator):
        """Test evaluation with category information."""
        for _i in range(5):
            pred = {
                "decision": "escalate",
                "priority": 1,
                "escalation_required": True,
                "category": "malware",
            }
            gt = {
                "decision": "escalate",
                "priority": 1,
                "escalation_required": True,
                "category": "malware",
            }
            evaluator.add_prediction(pred, gt, "malware")

        for _i in range(5):
            pred = {
                "decision": "investigate",
                "priority": 2,
                "escalation_required": False,
                "category": "phishing",
            }
            gt = {
                "decision": "investigate",
                "priority": 2,
                "escalation_required": False,
                "category": "phishing",
            }
            evaluator.add_prediction(pred, gt, "phishing")

        result = evaluator.evaluate()

        assert "malware" in result.category_metrics
        assert "phishing" in result.category_metrics
        assert result.category_metrics["malware"]["accuracy"] == 1.0
        assert result.category_metrics["phishing"]["accuracy"] == 1.0

    def test_priority_mae(self, evaluator):
        """Test priority Mean Absolute Error calculation."""
        predictions = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "escalate", "priority": 3, "escalation_required": True},
            {"decision": "escalate", "priority": 5, "escalation_required": True},
        ]
        ground_truth = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},  # diff: 0
            {"decision": "escalate", "priority": 1, "escalation_required": True},  # diff: 2
            {"decision": "escalate", "priority": 2, "escalation_required": True},  # diff: 3
        ]

        result = evaluator.evaluate(predictions, ground_truth)

        # MAE = (0 + 2 + 3) / 3 = 1.67
        assert abs(result.priority_mae - 1.67) < 0.01

    def test_priority_within_one(self, evaluator):
        """Test priority within one calculation."""
        predictions = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "escalate", "priority": 2, "escalation_required": True},
            {"decision": "escalate", "priority": 5, "escalation_required": True},
        ]
        ground_truth = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},  # within 1: yes
            {"decision": "escalate", "priority": 1, "escalation_required": True},  # within 1: yes
            {
                "decision": "escalate",
                "priority": 2,
                "escalation_required": True,
            },  # within 1: no (diff=3)
        ]

        result = evaluator.evaluate(predictions, ground_truth)

        # 2 out of 3 within 1
        assert abs(result.priority_within_one - 0.67) < 0.01

    def test_escalation_metrics(self, evaluator):
        """Test escalation precision, recall, and F1."""
        predictions = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},  # TP
            {"decision": "escalate", "priority": 1, "escalation_required": True},  # FP
            {"decision": "investigate", "priority": 2, "escalation_required": False},  # FN
            {"decision": "monitor", "priority": 3, "escalation_required": False},  # TN
        ]
        ground_truth = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "investigate", "priority": 2, "escalation_required": False},
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "monitor", "priority": 3, "escalation_required": False},
        ]

        result = evaluator.evaluate(predictions, ground_truth)

        # TP=1, FP=1, FN=1, TN=1
        # Precision = 1/(1+1) = 0.5
        # Recall = 1/(1+1) = 0.5
        # F1 = 2*0.5*0.5/(0.5+0.5) = 0.5
        assert result.escalation_precision == 0.5
        assert result.escalation_recall == 0.5
        assert result.escalation_f1 == 0.5

    def test_confusion_matrix(self, evaluator):
        """Test confusion matrix generation."""
        predictions = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "investigate", "priority": 2, "escalation_required": False},
        ]
        ground_truth = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "investigate", "priority": 2, "escalation_required": False},
            {"decision": "investigate", "priority": 2, "escalation_required": False},
        ]

        result = evaluator.evaluate(predictions, ground_truth)

        assert result.confusion_matrix["escalate"]["escalate"] == 1
        assert result.confusion_matrix["investigate"]["escalate"] == 1
        assert result.confusion_matrix["investigate"]["investigate"] == 1


class TestEvaluationResult:
    """Tests for EvaluationResult class."""

    def test_to_dict(self):
        """Test result serialization to dict."""
        result = EvaluationResult(
            decision_accuracy=0.85,
            decision_f1_macro=0.82,
            priority_mae=0.5,
            escalation_precision=0.9,
            escalation_recall=0.8,
            total_samples=100,
            correct_samples=85,
        )

        d = result.to_dict()

        assert "overall" in d
        assert "priority" in d
        assert "escalation" in d
        assert d["overall"]["decision_accuracy"] == 0.85

    def test_str_representation(self):
        """Test string representation of results."""
        result = EvaluationResult(
            decision_accuracy=0.85,
            decision_f1_macro=0.82,
            priority_mae=0.5,
            total_samples=100,
            correct_samples=85,
        )

        s = str(result)

        assert "85.00%" in s
        assert "100" in s


class TestReportGeneration:
    """Tests for report generation."""

    def test_generate_report(self, evaluator, tmp_path):
        """Test report generation."""
        predictions = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "investigate", "priority": 2, "escalation_required": False},
        ]
        ground_truth = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "investigate", "priority": 2, "escalation_required": False},
        ]

        result = evaluator.evaluate(predictions, ground_truth)
        output_file = tmp_path / "report.txt"

        report = evaluator.generate_report(result, str(output_file))

        assert "Decision Accuracy" in report
        assert output_file.exists()

        with open(output_file) as f:
            saved_report = f.read()
        assert "Decision Accuracy" in saved_report
