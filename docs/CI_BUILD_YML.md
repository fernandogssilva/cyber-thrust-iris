# TODO — Restaurar CI

O workflow .github/workflows/build.yml foi gerado em `docs/CI_BUILD_YML.md` mas
não pôde ser publicado no commit inicial porque o token OAuth do GitHub CLI não tem o scope `workflow`.

## Para restaurar

```powershell
gh auth refresh -h github.com -s workflow
```

Depois copie o conteúdo de `docs/CI_BUILD_YML.md` (bloco de código YAML) para `.github/workflows/build.yml` e:

```powershell
git add .github/workflows/build.yml
git commit -m "ci: restaurar build workflow"
git push
```
