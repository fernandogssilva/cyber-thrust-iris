# Web Assets — Attack Graph

Renderizado em **Cytoscape.js** dentro de um WebView2 hospedado pela `AttackTreeView.xaml`.

## API JS exposta
- `window.loadGraph(payload)` — recebe `{ elements: [...] }` (formato Cytoscape) e desenha.

## Convenções de cor (paleta IRIS)
- `Detection` → magenta neon `#FF0080` (diamante)
- `Host` → ciano neon `#00E5FF`
- `User` / `IOC` → roxo `#7C4DFF`
- `Process` → verde `#00E676`
- `NetworkEndpoint` → amarelo `#FFD740` (hexágono)

## Modo air-gap
Substitua as tags `<script src="https://unpkg.com/...">` por arquivos locais nesta pasta
para deploys sem internet — Cytoscape + dagre cabem em ~600KB.
