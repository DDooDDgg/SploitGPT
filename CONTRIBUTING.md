# Contributing to SploitGPT

Thanks for your interest in contributing to SploitGPT! This document provides guidelines for contributing.

## Getting Started

1. **Fork the repository** and clone your fork
2. **Set up the development environment:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/SploitGPT.git
   cd SploitGPT
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. **Run tests** to make sure everything works:
   ```bash
   python -m pytest tests/ -v
   ```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and write tests

3. Run the test suite:
   ```bash
   python -m pytest tests/ -v
   ```

4. Run the linter:
   ```bash
   python -m ruff check sploitgpt/
   ```

5. Commit your changes with a descriptive message

6. Push and open a Pull Request

## Code Style

- We use [Ruff](https://github.com/astral-sh/ruff) for linting
- Follow PEP 8 guidelines
- Add type hints to function signatures
- Write docstrings for public functions and classes

## Project Structure

```
sploitgpt/
├── agent/           # AI agent logic and response handling
├── core/            # Configuration, boot, audit, scope, credentials
├── knowledge/       # RAG, MITRE ATT&CK, GTFOBins integration
├── msf/             # Metasploit RPC client
├── tools/           # Tool implementations (nuclei, shodan, etc.)
├── training/        # Model training utilities
└── tui/             # Terminal UI
```

## Adding New Tools

To add a new security tool integration:

1. Create a new file in `sploitgpt/tools/`
2. Implement the tool following the existing patterns
3. Register it in `sploitgpt/tools/__init__.py`
4. Add tests in `tests/test_tools_*.py`
5. Update documentation if needed

## Testing

- Write tests for new functionality
- Ensure existing tests pass
- Use pytest fixtures for common setup
- Mock external services (Ollama, Metasploit) in tests

## Reporting Issues

When reporting issues, please include:

- OS and version
- Python version
- GPU info (if relevant)
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

## Pull Request Guidelines

- Keep PRs focused on a single feature/fix
- Update tests and documentation
- Ensure CI passes
- Respond to review feedback promptly

## Security

If you discover a security vulnerability, please **do not** open a public issue. Instead, contact the maintainers directly.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
