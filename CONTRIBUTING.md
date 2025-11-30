# Contributing to IAM Immune System

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Prioritize security in all contributions

## Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/MikeDominic92/iam-immune-system.git
   cd iam-immune-system
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Set up development environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

## Development Guidelines

### Code Style

- Follow PEP 8 style guide
- Use type hints for all function signatures
- Maximum line length: 100 characters
- Use descriptive variable names

### Testing

- Write tests for all new features
- Maintain >90% code coverage
- Run tests before submitting PR:
  ```bash
  pytest tests/ --cov=functions
  ```

### Documentation

- Update README.md for user-facing changes
- Add docstrings to all functions and classes
- Update CHANGELOG.md following Keep a Changelog format
- Create ADRs for architectural decisions

### Commit Messages

Follow conventional commits:

```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions or changes
- `refactor`: Code refactoring
- `chore`: Maintenance tasks

Example:
```
feat(detector): add privilege escalation detection

Implements detection for common privilege escalation patterns
including:
- CreatePolicyVersion attacks
- AssumeRole chain attacks
- PassRole exploits

Closes #123
```

## Pull Request Process

1. **Update documentation**
   - README.md if needed
   - CHANGELOG.md with your changes
   - Inline code comments

2. **Run tests and linting**
   ```bash
   pytest tests/
   flake8 functions/
   mypy functions/
   ```

3. **Submit PR**
   - Use descriptive PR title
   - Reference related issues
   - Provide context and screenshots if applicable
   - Request review from maintainers

4. **Address feedback**
   - Respond to review comments
   - Make requested changes
   - Re-request review after updates

## Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead, email security@mikedominic.dev with:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Adding New Detectors

1. Create detector class in `functions/iam_monitor/detectors/`:
   ```python
   from typing import Dict, Any
   from .base import BaseDetector, DetectionResult

   class MyDetector(BaseDetector):
       def detect(self, event: Dict[str, Any]) -> DetectionResult:
           # Implementation
           pass
   ```

2. Add tests in `tests/test_detectors.py`

3. Update `policies/detection_rules.yaml`

4. Update README.md with new capability

## Adding New Remediators

1. Create remediator class in `functions/iam_monitor/remediators/`:
   ```python
   from typing import Dict, Any
   from .base import BaseRemediator, RemediationResult

   class MyRemediator(BaseRemediator):
       def remediate(self, detection: DetectionResult) -> RemediationResult:
           # Implementation
           pass
   ```

2. Add tests in `tests/test_remediators.py`

3. Update `policies/remediation_playbooks.yaml`

## Feature Requests

Open an issue with:
- Clear description of the feature
- Use case and motivation
- Proposed implementation (optional)
- Examples or mockups

## Questions?

- Open a discussion on GitHub
- Check existing documentation
- Review closed issues and PRs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in:
- CHANGELOG.md
- GitHub contributors page
- Annual contributor spotlight posts

Thank you for helping make IAM Immune System better!
