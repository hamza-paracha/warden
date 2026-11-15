# Contributing to Warden

Thank you for your interest in contributing to Warden! This document provides guidelines and instructions for contributing.

## 🎯 Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment

## 🚀 Getting Started

### Prerequisites

- Node.js 22.12 or higher
- Git
- A GitHub account
- Familiarity with TypeScript

### Setting Up Development Environment

1. **Fork the repository**
   ```bash
   # Click the "Fork" button on GitHub, then:
   git clone https://github.com/YOUR_USERNAME/warden.git
   cd warden
   ```

2. **Install dependencies**
   ```bash
   npm ci
   ```

3. **Optional scanner and GitHub credentials**

   No credentials are needed for the offline tests or an npm-audit scan. For Snyk
   or PR creation, create a local `.env` containing `SNYK_TOKEN` or `GITHUB_TOKEN`
   as needed. Never commit credentials.

4. **Build the project**
   ```bash
   npm run build
   ```

5. **Run tests**
   ```bash
   npm test
   ```

## 📝 Development Workflow

### Branch Naming Convention

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `test/description` - Test additions or updates

### Making Changes

1. **Create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clean, readable code
   - Follow existing code style
   - Add comments for complex logic
   - Update documentation as needed

3. **Test your changes**
   ```bash
   npm run build
   npm test
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add amazing new feature"
   ```

   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation changes
   - `test:` - Test updates
   - `refactor:` - Code refactoring
   - `chore:` - Maintenance tasks

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request**
   - Go to the original repository on GitHub
   - Click "New Pull Request"
   - Select your fork and branch
   - Fill out the PR template

## 🧪 Testing Guidelines

### Writing Tests

- Place tests in `__tests__/` directory
- Name test files as `*.test.ts`
- Aim for high code coverage
- Test both success and failure cases

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage report
npm run test:coverage
```

## 📚 Documentation

- Update README.md for user-facing changes
- Add JSDoc comments for functions and classes
- Update CHANGELOG.md (if exists)
- Include examples for new features

## 🏗️ Project Structure

```
warden/
├── src/
│   ├── agents/          # The three agents
│   │   ├── watchman/   # Scanner agent
│   │   ├── engineer/   # Fixer agent
│   │   └── diplomat/   # PR agent
│   ├── core/           # Core configuration
│   ├── verification/   # Patch comparison and test execution
│   ├── workflows/      # Scan workflows
│   ├── services/       # Process execution and artifact writes
│   ├── utils/          # Utilities
│   ├── cli.ts          # CLI interface
│   ├── orchestrator.ts # Main orchestration
│   └── setup.ts        # Setup wizard
├── __tests__/          # Test files
├── docs/SPEC/          # Specifications
└── dist/               # Compiled output
```

## 🎨 Code Style

- Use TypeScript strict mode
- Follow existing formatting (enforced by Prettier and EditorConfig)
- Use meaningful variable names
- Keep functions small and focused
- Avoid deep nesting

### Development Scripts

```bash
# Build the project
npm run build

# Run the CLI from TypeScript
npm run dev

# Clean build artifacts and logs
npm run clean

# Run specific agent (watchman example)
npm run watchman

# Run CLI commands
npm run cli validate
npm run cli setup
```

## 🐛 Reporting Bugs

When reporting bugs, please include:

1. **Description** - Clear description of the bug
2. **Steps to Reproduce** - How to reproduce the issue
3. **Expected Behavior** - What should happen
4. **Actual Behavior** - What actually happens
5. **Environment** - OS, Node version, etc.
6. **Logs** - Relevant error messages or logs

## 💡 Suggesting Features

Feature suggestions are welcome! Please:

1. Check if the feature already exists
2. Explain the use case
3. Describe the proposed solution
4. Consider alternatives

## 🔍 Code Review Process

All submissions require review. We'll:

- Review code quality and style
- Check test coverage
- Verify documentation
- Test functionality
- Provide constructive feedback

## 📋 Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code builds without errors (`npm run build`)
- [ ] All tests pass (`npm test`)
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Commit messages follow conventions
- [ ] No merge conflicts
- [ ] PR description is clear

## 🙏 Thank You!

Your contributions help make Warden better for everyone. We appreciate your time and effort!

## 📞 Questions?

- Open an issue for questions
- Tag maintainers in discussions
- Be patient - we're all volunteers!

---

*Happy Contributing! 🚀*
