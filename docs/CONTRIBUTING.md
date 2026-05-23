# Contribuindo com o CyberThrust.IRIS

## Branches

- `main` → protegido, só merge via PR aprovado.
- `dev/<feature>` → trabalho em curso.
- `hotfix/<id>` → correções emergenciais.

## Commits

Padrão [Conventional Commits](https://www.conventionalcommits.org/):

- `feat: novo módulo X` — novo recurso
- `fix: corrige Y` — bug fix
- `docs: atualiza Z` — documentação
- `refactor:` — refactor sem mudança comportamental
- `chore:` — build/CI/dependências
- `test:` — só testes

## Estilo

- C# 12, nullable enabled, file-scoped namespaces.
- `dotnet format` antes do PR.
- Sem warnings (`TreatWarningsAsErrors` é falso só para destravar build inicial — meta é `true` na v0.2).

## Testes

- xUnit em `tests/CyberThrust.IRIS.Tests`.
- Mínimo: 1 teste por bug fix, 1 teste por feature nova.

## PR Checklist

- [ ] Build limpo `dotnet build -c Release`
- [ ] `dotnet test` verde
- [ ] Docs atualizadas (README, ARCHITECTURE, ERROR_CODES se aplicável)
- [ ] CHANGELOG atualizado
- [ ] Nada de secret no diff (`gitleaks` no CI)
