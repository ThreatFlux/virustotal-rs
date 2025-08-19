# Pull Request

## Description

Please provide a clear and concise description of the changes in this PR.

## Type of Change

Please check the type of change your PR introduces:

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📖 Documentation update
- [ ] 🧹 Code cleanup/refactoring
- [ ] 🔒 Security improvement
- [ ] 🚀 Performance improvement
- [ ] 🔧 CI/CD or tooling changes

## API Changes

If this PR introduces changes to the public API, please describe them:

- [ ] No API changes
- [ ] Added new public methods/types
- [ ] Modified existing public methods/types
- [ ] Removed public methods/types
- [ ] Changed method signatures

## Testing

Please describe the tests that you ran to verify your changes:

- [ ] Unit tests pass (`cargo test`)
- [ ] Integration tests pass
- [ ] Documentation tests pass (`cargo test --doc`)
- [ ] All features compile (`cargo build --all-features`)
- [ ] Examples work (`cargo run --example <example_name>`)
- [ ] Manual testing performed

## Security Considerations

- [ ] This change does not introduce security vulnerabilities
- [ ] Security audit has been performed if needed
- [ ] No sensitive information (API keys, tokens) is exposed
- [ ] Input validation is properly implemented
- [ ] Error handling doesn't leak sensitive information

## Documentation

- [ ] Code is self-documenting with clear function/type names
- [ ] Public APIs are documented with doc comments
- [ ] README updated if needed
- [ ] CHANGELOG updated if this is a user-facing change
- [ ] Examples updated if API changed

## Performance

- [ ] No performance regression introduced
- [ ] Performance improvements are measured and documented
- [ ] Memory usage is reasonable
- [ ] Rate limiting is respected

## Checklist

- [ ] My code follows the project's coding standards
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published

## Related Issues

Fixes #(issue_number)
Closes #(issue_number)
Related to #(issue_number)

## Additional Notes

Add any additional notes, concerns, or implementation details here.

## Screenshots (if applicable)

If your changes include UI modifications or visual changes, please include screenshots.

---

**For Reviewers:**

Please ensure:
- [ ] Code quality and style consistency
- [ ] Security implications have been considered
- [ ] Performance impact is acceptable
- [ ] Documentation is clear and complete
- [ ] Tests provide adequate coverage
- [ ] Breaking changes are clearly documented