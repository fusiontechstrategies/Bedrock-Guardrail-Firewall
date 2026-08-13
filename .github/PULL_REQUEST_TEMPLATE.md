# Pull Request

## Summary

Describe the focused change and why it is needed.

## Security and privacy impact

Describe changes to trust boundaries, data handling, permissions, failure behavior, audit content, or downstream capabilities.

## Verification

- [ ] Python compilation passes.
- [ ] Ruff formatting and linting pass.
- [ ] Automated tests pass.
- [ ] Built-in self-test passes.
- [ ] Built-in adversarial suite meets its target.
- [ ] Bandit and dependency audits pass.
- [ ] New behavior has regression tests.
- [ ] Documentation and changelog are updated.

## Safety checklist

- [ ] The production runtime remains in `orchestrator.py`.
- [ ] No live AWS credentials or calls are required for tests.
- [ ] No credentials, private resource names, personal data, or production records are included.
- [ ] Raw prompt, output, and retrieval content do not enter operational evidence.
- [ ] Required production controls fail safely.
- [ ] Request content cannot weaken trusted configuration.
