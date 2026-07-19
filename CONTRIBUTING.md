# Contributing to did-x509

Thank you for your interest in contributing to the did-x509 reference implementations!

## About This Repository

This repository provides reference implementations for the [did:x509](https://www.w3.org/TR/did-x509/) specification in Python and TypeScript. It was originally created by Microsoft and is maintained as an open-source project with contributions from the community, including the TypeScript implementation contributed by [AyanWorks](https://ayanworks.com).

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request, please [open an issue](../../issues) with:

- A clear description of the problem or suggestion
- Steps to reproduce (for bugs)
- Your environment (OS, language runtime version)

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** from `main` for your change
3. **Make your changes** following the guidelines below
4. **Run tests** to verify nothing is broken
5. **Submit a pull request** with a clear description

### Development Setup

#### Python

```bash
cd reference-implementations/python
pip install -r requirements.txt
pytest test.py -v
```

#### TypeScript

```bash
cd reference-implementations/typescript
npm install
npm run typecheck
npm test
npm run build
```

### Code Guidelines

- Follow existing code style and conventions in each language
- Add tests for new functionality
- Keep commits focused and write clear commit messages
- Update documentation if your change affects the public API

### Attribution

When contributing, please ensure all files include proper attribution headers as described in the repository's licensing. The TypeScript implementation includes AyanWorks attribution in every source file header — maintain this convention when adding new files.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
