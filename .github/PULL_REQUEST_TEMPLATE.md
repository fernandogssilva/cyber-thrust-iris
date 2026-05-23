## Summary

<!-- One-paragraph description of the change. Link the issue this closes. -->

Closes #

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (please justify)
- [ ] Documentation only

## Modules touched

- [ ] Core
- [ ] EntraID
- [ ] CrowdStrike
- [ ] Forensics
- [ ] Memory
- [ ] Graph
- [ ] App (WPF UI)
- [ ] Installer / Distribution
- [ ] Docs

## How to test

<!-- Step-by-step. If a new error code was introduced, document it in docs/ERROR_CODES.md. -->

## Checklist

- [ ] `dotnet build -c Release` is clean (0 errors)
- [ ] `dotnet test` is green
- [ ] No secrets in the diff (run `gitleaks` mentally)
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] If a new public API was added, it has XML doc comments
- [ ] If a new `IrisErrorCode` was added, it appears in `docs/ERROR_CODES.md`
- [ ] I agree to license my contribution under Apache-2.0 (see `LICENSE`)

## Screenshots / Logs (optional)

<!-- Drop a screenshot of the UI change or a log excerpt. Redact identifiers. -->
