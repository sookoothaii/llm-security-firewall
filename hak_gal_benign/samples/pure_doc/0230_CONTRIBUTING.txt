---
title: "Contributing"
created: "2025-09-15T00:08:00.947080Z"
author: "system-cleanup"
topics: ["technical_reports"]
tags: ["auto-generated"]
privacy: "internal"
summary_200: |-
  Auto-generated frontmatter. Document requires review.
---

# Contributing to HAK-GAL Hexagonal

Thank you for your interest in contributing to HAK-GAL Hexagonal! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and constructive
- Follow the HAK-GAL Constitution principles
- Prioritize empirical validation

## Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/HAK-GAL-Hexagonal.git
   cd HAK-GAL-Hexagonal
   ```

3. Set up Python environment:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```

4. Set up frontend:
   ```bash
   cd frontend
   npm install
   ```

## Contribution Process

1. **Create an Issue** first to discuss the change
2. **Fork & Branch**: Create a feature branch
3. **Develop**: Make your changes following our standards
4. **Test**: Ensure all tests pass
5. **Document**: Update documentation as needed
6. **PR**: Submit a pull request

## Architecture Guidelines

Follow the hexagonal architecture pattern:
- **Core Domain**: Business logic, no external dependencies
- **Ports**: Interfaces for external communication
- **Adapters**: Implementations of ports

## Testing

- Write tests for new functionality
- Ensure existing tests pass
- Test MCP tools thoroughly
- Validate knowledge base integrity

## PR Requirements

- Clear description of changes
- Tests for new features
- Documentation updates
- No breaking changes without discussion
- Follow commit message conventions

## Commit Messages

Use conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Testing
- `refactor:` Code refactoring
- `ci:` CI/CD changes

Example: `feat: Add semantic similarity search to MCP tools`

## Reporting Issues

Include:
- Clear description
- Steps to reproduce
- Expected behavior
- Actual behavior
- System information

## Feature Requests

- Check existing issues first
- Provide use case
- Explain benefits
- Consider HAK-GAL principles

## Resources

- [System Architecture](docs/ARCHITECTURE.md)
- [HAK-GAL Constitution](PROJECT_HUB/ssot.md)
- [MCP Tools Reference](docs/MCP_TOOLS_REFERENCE.md)

## Questions?

- Open a discussion issue
- Check documentation first
- Be specific and clear

Thank you for contributing to HAK-GAL Hexagonal!
