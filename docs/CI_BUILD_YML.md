# Restaurar GitHub Actions CI

O arquivo `.github/workflows/build.yml` foi removido do commit inicial porque o token OAuth do `gh` CLI no momento do push não carregava o scope `workflow`. O conteúdo do workflow está embed abaixo para reposição posterior.

## Passos para restaurar

```powershell
# 1. Conceder scope workflow ao token gh CLI
gh auth refresh -h github.com -s workflow

# 2. Recriar o arquivo a partir do bloco YAML abaixo
$root = 'C:\Users\ferna\OneDrive\Documentos\Empresas\CYBER THRUST\Tecnologias\10-Resposta a Incidente'
New-Item -ItemType Directory -Path "$root\.github\workflows" -Force | Out-Null

@'
name: build

on:
  push:
    branches: [main, dev/**]
  pull_request:
    branches: [main]
  workflow_dispatch:

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET 8
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 8.0.x

      - name: Restore
        run: dotnet restore

      - name: Build (Release)
        run: dotnet build --configuration Release --no-restore

      - name: Test
        run: dotnet test --configuration Release --no-build --logger "trx;LogFileName=test_results.trx"

      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: '**/TestResults/*.trx'
'@ | Out-File -Encoding utf8 "$root\.github\workflows\build.yml"

# 3. Commit e push
Set-Location -LiteralPath $root
git add .github/workflows/build.yml
git commit -m "ci: restaurar build workflow"
git push
```

## YAML do workflow (somente leitura)

```yaml
name: build

on:
  push:
    branches: [main, dev/**]
  pull_request:
    branches: [main]
  workflow_dispatch:

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET 8
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 8.0.x

      - name: Restore
        run: dotnet restore

      - name: Build (Release)
        run: dotnet build --configuration Release --no-restore

      - name: Test
        run: dotnet test --configuration Release --no-build --logger "trx;LogFileName=test_results.trx"

      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: '**/TestResults/*.trx'
```

## Por que não foi publicado no commit inicial?

`gh auth status` mostrou o token como OAuth App (keyring). OAuth Apps no GitHub não podem criar/atualizar arquivos em `.github/workflows/**` sem o scope `workflow` — proteção do GitHub para evitar que apps comprometidas injetem CI malicioso.

`gh auth refresh -s workflow` adiciona o scope ao token existente sem precisar recriar a autenticação.
