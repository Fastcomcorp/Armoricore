# 🤝 Contributing to Armoricore

Thank you for your interest in contributing to Armoricore! We welcome contributions from developers, security researchers, and the open source community. This document provides guidelines for contributing to the project.

## 📋 **Table of Contents**
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Security Contributions](#security-contributions)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Documentation](#documentation)

## 🤝 **Code of Conduct**

### **Our Pledge**
We are committed to providing a welcoming environment for all contributors. We pledge to:
- Be respectful and inclusive
- Focus on constructive feedback
- Maintain professional communication
- Value diverse perspectives and experiences

### **Standards**
- **No Harassment**: Harassment of any kind is not tolerated
- **Respectful Communication**: Be kind and considerate
- **Inclusive Language**: Use inclusive and accessible language
- **Professional Conduct**: Maintain professional standards

## 🚀 **Getting Started**

### **Prerequisites**
Before contributing, ensure you have:
- **Elixir 1.14+** with Erlang/OTP 25+
- **Rust 1.70+** for media services
- **PostgreSQL 13+** for database
- **Node.js 18+** for frontend assets
- **Git** for version control

### **Quick Setup**
```bash
# Fork the repository
git clone https://github.com/Fastcomcorp/Armoricore.git
cd armoricore

# Setup development environment
./setup_development.sh

# Verify installation
mix test
```

## 🛠 **Development Setup**

### **Environment Configuration**
```bash
# Copy environment files
cp elixir_realtime/config/dev.secret.exs.example elixir_realtime/config/dev.secret.exs
cp rust-services/.env.example rust-services/.env

# Edit configuration files with your settings
# - Database connection
# - Secret keys
# - API endpoints
```

### **Database Setup**
```bash
# Create development database
createdb armoricore_dev

# Run migrations
cd elixir_realtime
mix ecto.setup
```

### **Running the Application**
```bash
# Start Phoenix server
mix phx.server

# In another terminal, start Rust services
cd ../rust-services
cargo run --bin media-processor

# Visit localhost:4000
```

## 📝 **Contributing Guidelines**

### **Types of Contributions**
- **🐛 Bug Fixes**: Fix issues and vulnerabilities
- **✨ Features**: New functionality and improvements
- **📚 Documentation**: Guides, API docs, tutorials
- **🧪 Testing**: Test cases and test infrastructure
- **🔒 Security**: Security improvements and fixes
- **🏗 Architecture**: System design and refactoring

### **Development Workflow**

#### **1. Choose an Issue**
- Check [GitHub Issues](https://github.com/Fastcomcorp/Armoricore/issues)
- Look for `good first issue` or `help wanted` labels
- Comment on the issue to indicate you're working on it

#### **2. Create a Branch**
```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-number-description
```

#### **3. Development Standards**

##### **Code Style**
```bash
# Run code quality checks
mix credo --strict
mix dialyzer

# Format code
mix format

# Run security checks
mix sobelow
```

##### **Commit Messages**
```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Testing
- `chore`: Maintenance

**Examples:**
```
feat(auth): add JWT token refresh
fix(security): prevent XSS in search results
docs(api): update authentication guide
```

#### **4. Testing Requirements**
```bash
# Run full test suite
mix test

# Run with coverage
mix test --cover

# Run specific tests
mix test test/armoricore_realtime/security_test.exs

# Integration tests
mix test integration_test.exs
```

### **Security Considerations**
- **Never commit secrets** or sensitive data
- **Use secure defaults** for new features
- **Follow OWASP guidelines** for web security
- **Implement proper input validation**
- **Use parameterized queries** to prevent SQL injection

## 🔒 **Security Contributions**

### **Reporting Security Issues**
- **Email**: security@armoricore.com
- **PGP Key**: Available at security page
- **Response**: Within 24 hours for critical issues
- **Bounty**: Up to $10,000 for qualifying vulnerabilities

### **Security Development**
- **Cryptography**: Use vetted cryptographic libraries
- **Input Validation**: Validate and sanitize all inputs
- **Authentication**: Implement proper session management
- **Authorization**: Use principle of least privilege
- **Logging**: Don't log sensitive information

## 🧪 **Testing**

### **Test Categories**
- **Unit Tests**: Individual functions and modules
- **Integration Tests**: Component interactions
- **Security Tests**: Vulnerability and penetration testing
- **Performance Tests**: Load and stress testing
- **Fuzz Tests**: Input fuzzing and edge cases

### **Writing Tests**
```elixir
# Example security test
defmodule ArmoricoreRealtime.SecurityTest do
  use ArmoricoreRealtime.DataCase

  test "prevents SQL injection in search" do
    malicious_input = "'; DROP TABLE users; --"

    result = SearchController.search(%{q: malicious_input})

    refute result.status == 500
    assert result.query_sanitized
  end
end
```

### **Test Coverage**
- **Minimum Coverage**: 80% for new code
- **Security Critical**: 95%+ for security modules
- **Continuous Integration**: All tests run on PR

## 📤 **Submitting Changes**

### **Pull Request Process**
1. **Update Documentation**: Ensure docs reflect changes
2. **Add Tests**: Include tests for new functionality
3. **Update Changelog**: Add entry to CHANGELOG.md
4. **Self Review**: Check your own code first
5. **Create PR**: Use the pull request template

### **PR Template**
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Security Impact
- [ ] No security impact
- [ ] Security improvement
- [ ] Requires security review

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Security review completed
```

### **Review Process**
1. **Automated Checks**: CI runs tests and linting
2. **Code Review**: At least one maintainer review
3. **Security Review**: For security-related changes
4. **Merge**: Squash merge with descriptive commit message

## 📚 **Documentation**

### **Documentation Standards**
- **README Updates**: Update for new features
- **API Documentation**: Document all public APIs
- **Code Comments**: Explain complex logic
- **Usage Examples**: Provide practical examples

### **Documentation Files**
- `README.md`: Main project documentation
- `API_REFERENCE.md`: API documentation
- `SECURITY.md`: Security information
- `CHANGELOG.md`: Version history
- `docs/`: Additional documentation

## 🎯 **Areas for Contribution**

### **High Priority**
- **Security Enhancements**: Cryptography improvements
- **Performance Optimization**: Database and caching
- **Mobile Support**: iOS/Android clients
- **Documentation**: API docs and tutorials

### **Community Projects**
- **Localization**: Multi-language support
- **Themes**: UI customization options
- **Integrations**: Third-party service integrations
- **Tools**: Development and deployment tools

## 📞 **Getting Help**

### **Communication Channels**
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Community Forum**: Github

### **Mentorship**
- **Good First Issues**: Beginner-friendly tasks
- **Mentor Program**: Experienced developers guide newcomers
- **Documentation**: Comprehensive guides for getting started

## 🙏 **Recognition**

### **Contributor Recognition**
- **GitHub Contributors**: Listed in repository
- **Changelog Credits**: Mentioned in release notes
- **Community Badges**: Recognition for significant contributions
- **Hall of Fame**: Outstanding security and feature contributions
---

## 📜 **License Agreement**

By contributing to Armoricore, you agree that your contributions will be licensed under the same license as the project (Apache 2.0).

**Thank you for contributing to Armoricore and helping build the future of secure communications!** 🚀

---

*Last updated: January 22, 2026*