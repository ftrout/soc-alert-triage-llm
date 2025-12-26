# Contributing to Kodiak SecOps 1

Thank you for your interest in contributing to Kodiak SecOps 1! This document provides guidelines for contributing to the project.

## Getting Started

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/ftrout/kodiak-secops-1.git
   cd kodiak-secops-1
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Set up pre-commit hooks**
   ```bash
   pre-commit install
   ```

## Development Workflow

### Code Style

We use the following tools to maintain code quality:

- **Black** for code formatting (line length: 100)
- **Ruff** for linting
- **mypy** for type checking

Run all checks locally:
```bash
black src/ tests/
ruff check src/ --fix
mypy src/soc_triage_agent
```

### Testing

Run the test suite:
```bash
pytest tests/ -v --cov=soc_triage_agent
```

### Generating Test Data

```bash
python -m soc_triage_agent.data_generator \
    --num-samples 100 \
    --format chat \
    --output data/test.jsonl \
    --seed 42
```

## Types of Contributions

### Bug Reports

When filing a bug report, please include:
- Python version and OS
- Minimal code to reproduce the issue
- Full error traceback
- Expected vs actual behavior

### Feature Requests

For feature requests, please describe:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Ensure tests pass (`pytest tests/`)
5. Ensure code style checks pass
6. Commit with descriptive messages
7. Push and create a Pull Request

#### PR Guidelines

- Keep PRs focused and small when possible
- Include tests for new functionality
- Update documentation as needed
- Follow existing code patterns

## Project Structure

```
kodiak-secops-1/
├── src/soc_triage_agent/    # Main package
│   ├── data_generator.py    # Synthetic data generation
│   ├── model.py             # Model wrapper
│   └── evaluation.py        # Evaluation metrics
├── scripts/                 # Training scripts
├── tests/                   # Test suite
├── configs/                 # Training configurations
└── app.py                   # Gradio interface
```

## Security Alert Categories

When contributing to alert generation, ensure new categories align with:
- MITRE ATT&CK framework
- Industry-standard SOC terminology
- Realistic enterprise scenarios

## Triage Decision Logic

Triage decisions should follow security best practices:
- **escalate**: Active threats requiring IR team
- **investigate**: Suspicious activity needs analysis
- **monitor**: Observation without immediate action
- **false_positive**: Benign activity incorrectly flagged
- **close**: No security concern

## Documentation

- Use Google-style docstrings
- Update README.md for user-facing changes
- Update MODEL_CARD.md for model-related changes
- Update DATASET_CARD.md for data generation changes

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the technical merits
- Help others learn and grow

## Questions?

- Open a [GitHub Issue](https://github.com/ftrout/kodiak-secops-1/issues)
- Check existing issues for answers

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
