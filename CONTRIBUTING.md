# Contributing to SOC Triage Agent

Thank you for your interest in contributing to SOC Triage Agent! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Style Guidelines](#style-guidelines)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Please be kind and constructive in all interactions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/soc-triage-agent.git
   cd soc-triage-agent
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/your-org/soc-triage-agent.git
   ```

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Git
- (Optional) CUDA-compatible GPU for training

### Installation

```bash
# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with all dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Verify Setup

```bash
# Run tests
pytest tests/

# Run linting
ruff check src/
black --check src/

# Generate sample data
python -m soc_triage_agent.data_generator --num-samples 10 --output test_data.jsonl
```

## Making Changes

### Branch Naming

Create a branch with a descriptive name:

- `feature/add-new-alert-category` - For new features
- `fix/parsing-error` - For bug fixes
- `docs/update-readme` - For documentation
- `refactor/improve-evaluation` - For code improvements

### Workflow

1. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit frequently:
   ```bash
   git add .
   git commit -m "Add descriptive commit message"
   ```

3. **Keep your branch updated**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=soc_triage_agent --cov-report=html

# Run specific test file
pytest tests/test_data_generator.py

# Run specific test
pytest tests/test_data_generator.py::test_generate_alert
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files `test_*.py`
- Name test functions `test_*`
- Use pytest fixtures for setup/teardown
- Aim for >80% code coverage

Example test:

```python
import pytest
from soc_triage_agent import SecurityAlertGenerator, AlertCategory

@pytest.fixture
def generator():
    return SecurityAlertGenerator(seed=42)

def test_generate_alert(generator):
    alert, triage = generator.generate_alert()
    
    assert alert.alert_id is not None
    assert alert.category in [c.value for c in AlertCategory]
    assert triage.decision in ["escalate", "investigate", "monitor", "false_positive", "close"]
    assert 1 <= triage.priority <= 5

def test_balanced_dataset(generator):
    samples = generator.generate_dataset(120, balanced=True, include_metadata=True)
    
    # Check rough balance across 12 categories
    categories = [s["_metadata"]["alert"]["category"] for s in samples]
    category_counts = {cat: categories.count(cat) for cat in set(categories)}
    
    for count in category_counts.values():
        assert 5 <= count <= 15  # Allow some variance
```

## Submitting Changes

### Pull Request Process

1. **Update documentation** if needed
2. **Add tests** for new functionality
3. **Ensure all tests pass**
4. **Update the CHANGELOG** if applicable
5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
6. **Create a Pull Request** on GitHub

### PR Guidelines

- Use a clear, descriptive title
- Reference any related issues
- Describe what changes you made and why
- Include screenshots for UI changes
- Request review from maintainers

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring
- [ ] Other (please describe)

## Testing
- [ ] Tests added/updated
- [ ] All tests passing
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed code
- [ ] Documentation updated
- [ ] No new warnings
```

## Style Guidelines

### Python Code Style

We use [Black](https://github.com/psf/black) for code formatting and [Ruff](https://github.com/astral-sh/ruff) for linting.

```bash
# Format code
black src/ tests/

# Check linting
ruff check src/ tests/

# Fix auto-fixable issues
ruff check --fix src/ tests/
```

### Key Style Points

- **Line length**: 100 characters max
- **Imports**: Use absolute imports, sorted with isort
- **Type hints**: Use type hints for function signatures
- **Docstrings**: Use Google-style docstrings

Example:

```python
from typing import Optional, List, Dict

def process_alert(
    alert: Dict[str, Any],
    priority_override: Optional[int] = None,
) -> TriageResponse:
    """
    Process a security alert and return triage recommendation.
    
    Args:
        alert: Alert data dictionary containing category, severity, etc.
        priority_override: Optional priority to override calculated value.
        
    Returns:
        TriageResponse with decision, priority, and recommendations.
        
    Raises:
        ValueError: If alert is missing required fields.
        
    Example:
        >>> response = process_alert({"category": "malware", "severity": "high"})
        >>> print(response.decision)
        'escalate'
    """
    ...
```

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```
feat(generator): add support for custom alert templates
fix(evaluation): correct F1 score calculation for edge cases
docs(readme): add deployment instructions for Azure
```

## Reporting Issues

### Bug Reports

Include:
- Python version and OS
- Steps to reproduce
- Expected vs actual behavior
- Error messages/stack traces
- Minimal code example

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternative approaches considered
- Willingness to implement

### Security Issues

For security vulnerabilities, please email security@your-org.com instead of creating a public issue.

## Areas for Contribution

We especially welcome contributions in:

- **New alert categories**: Add support for additional security alert types
- **Evaluation metrics**: Implement additional evaluation metrics
- **Model support**: Add support for more base models
- **Documentation**: Improve docs, add examples, fix typos
- **Testing**: Increase test coverage
- **Performance**: Optimize data generation or inference

## Recognition

Contributors will be recognized in:
- The project README
- Release notes
- The AUTHORS file

Thank you for contributing to SOC Triage Agent! 🛡️
