# Contributing to PurgeProof

Thank you for your interest in contributing to PurgeProof! Here's how you can help:

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/purgeproof.git`
3. Create a new branch: `git checkout -b feature/your-feature-name`
4. Set up the development environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e .[dev]
   pre-commit install
   ```
5. Make your changes and ensure tests pass: `pytest`
6. Commit your changes with a descriptive message
7. Push to your fork and open a pull request

## Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints for all new code
- Keep functions small and focused
- Write docstrings for all public functions and classes
- Include tests for new functionality

## Testing

Run the test suite:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=purgeproof tests/
```

## Pull Request Process

1. Ensure all tests pass
2. Update documentation as needed
3. Ensure your code is properly formatted with black and isort
4. Open a pull request with a clear description of changes
5. Reference any related issues

## Reporting Issues

Please include:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details (OS, Python version, etc.)
- Any relevant error messages

## Code of Conduct

Be respectful and inclusive in all communications.
