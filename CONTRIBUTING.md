# Contributing

Thank you for your interest in AttomusOTP.

## Pull Requests

All changes must go through a pull request. Direct pushes to `main` are not permitted.

Every pull request requires explicit review and approval from Attomus before merge. Auto-merge
is not used for this repository.

## Versioning

Releases follow semantic versioning: patch releases fix compatible defects, minor releases add
backwards-compatible API, and major releases may introduce breaking changes.

## Security and Scope

This repository is the public OTP engine only. Do not introduce:

- platform-specific secret storage integrations
- application UI or account-management code
- networked features

Report vulnerabilities privately using the process in [SECURITY.md](SECURITY.md).
