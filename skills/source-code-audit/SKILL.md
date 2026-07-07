# Source Code Audit Skill

Use this skill when auditing a local open-source project for source-code security defects.

## Workflow

1. Profile the project:
   - Identify languages, frameworks, dependency files, entry points, and high-risk files.
2. Run baseline tools:
   - Semgrep for SAST.
   - Gitleaks or TruffleHog for secrets.
   - OSV-Scanner, Trivy, npm audit, pip-audit, or Safety for dependencies.
   - Bandit for Python projects.
3. Run builtin source patterns:
   - SQL injection.
   - Command injection.
   - Path traversal.
   - Hardcoded secrets.
4. Read code context for each candidate:
   - Confirm file and line.
   - Identify source, sink, sanitizer, and call path.
   - Reject findings that are not anchored in real code.
5. Verify:
   - Static anchor verification first.
   - Dynamic verification in a sandbox when the target can run.
6. Report:
   - Vulnerability type, file, line, severity, confidence.
   - Source-to-sink evidence.
   - Verification status.
   - Reproduction guidance.
   - Fix recommendation.

## Safety

Only audit authorized projects. Run dynamic payload verification inside an isolated sandbox.
