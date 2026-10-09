# Analyser les serveurs que démarrent vos clients MCP

> 🌐 [English](scan.md) · [Русский](scan.ru.md) · [Español](scan.es.md) · **Français** · [中文](scan.zh.md)

`warden-mcp scan` lit la configuration MCP que vous avez déjà, se connecte à chaque serveur qu’elle démarre et vérifie les définitions d’outils avant qu’un modèle ne les voie. C’est la même chaîne de portes que [`wrap`](../README-fr.md) et la [bibliothèque](integration.fr.md), exécutée une fois sur vos configurations au lieu de se placer devant un seul serveur.

```bash
npx -y @aimarket/warden@0.9.0 scan
```

```text
WARDEN scan 0.9.0 · ruleset 9 sha256-nC+ybcePE8AW… · block at high
  read .mcp.json (claude-code, 3 servers)

  ✓ allow   notes        claude-code    1 tool · score 0.90
  ✗ BLOCK   evil-notes   claude-code    1 tool · score 0.00 · TOOL_DEF_EXFIL(notes) TOOL_DEF_SECRET_REQUEST(notes)
  ! error   broken       claude-code    could not start: spawn /nonexistent/bin/server ENOENT

3 servers: 1 allowed, 1 blocked, 1 not checked, 0 skipped.
```

Pas de compte, pas de clé d’API, pas de modèle. Le seul trafic réseau va vers les serveurs de votre configuration et, si vous passez `--histor`, vers le journal HISTOR.

## Où il cherche

Sans argument, chaque fichier du tableau qui existe. Passez des fichiers pour n’analyser que ceux-là, `--project` pour les fichiers du projet dans le répertoire courant, ou `--client NAME` pour un seul client.

| Client | Fichier du projet | Fichier de l’utilisateur |
|---|---|---|
| Claude Code | `.mcp.json` | `~/.claude.json` (serveurs de l’utilisateur et de ce projet) |
| Claude Desktop | — | `claude_desktop_config.json` dans le répertoire de configuration de l’application |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json` (JSONC) | `mcp.json` dans le répertoire des paramètres utilisateur |
| Windsurf | — | `~/.codeium/windsurf/mcp_config.json` |

Un serveur que la configuration démarre via `warden-mcp wrap` est analysé comme le serveur derrière l’enveloppe, sous l’identifiant de pin qu’utilise `wrap`, si bien que la dérive par rapport à l’instantané approuvé apparaît dans le rapport. Les entrées désactivées, celles qui demandent une valeur `${input:…}` que le client réclame à l’utilisateur, et celles sans `command` ni `url` sont listées comme ignorées, jamais supprimées en silence.

## Démarrer les serveurs

Pour lire les outils d’un serveur stdio, `scan` le démarre avec la commande, les arguments et l’environnement de la configuration, exactement comme votre client, puis l’arrête après `tools/list`. Il n’appelle jamais d’outil. Le programme s’exécute tout de même. Là où vous ne le voulez pas, par exemple en CI sur une pull request, `--no-launch` ne vérifie que la ligne de lancement : les enregistrements de commandes du threat feed et l’identité de lancement du lock.

Les serveurs distants (`url`, streamable HTTP ou l’ancien HTTP+SSE) sont interrogés sur le réseau avec les en-têtes de la configuration. `--public-only` refuse ceux qui se résolvent en adresses loopback, privées, link-local ou de métadonnées cloud, en vérifiant l’adresse réellement contactée. Les redirections ne sont pas suivies.

## Sortie et codes de sortie

| Option | Écrit |
|---|---|
| (par défaut) | un tableau sur stdout |
| `--json` | le rapport JSON sur stdout |
| `--json-file FILE` | le rapport JSON dans un fichier, en plus du tableau |
| `--sarif FILE` | du SARIF 2.1.0 pour GitHub code scanning ; uniquement les constats bloquants, situés à la ligne du serveur dans la configuration |
| `--markdown FILE` | un résumé avec des détails repliables, pour `$GITHUB_STEP_SUMMARY` ou un commentaire de PR |

Code `0` : rien de bloqué. `1` : un serveur a été bloqué ou, avec `--fail-on-error`, n’a pas pu être vérifié. `2` : erreur d’utilisation ou de configuration. `--fail-on SEVERITY` déplace le seuil de blocage ; `--policy FILE` accepte le même fichier de politique strict que `wrap`.

Les identifiants présents dans les lignes de lancement et les URL sont affichés comme `***`. Dans le rapport Markdown, les descriptions d’outils sont placées dans des blocs de code que ce texte ne peut pas refermer.

## Le fichier lock : relire les définitions, pas seulement la commande

Une ligne de configuration dit quel programme démarre. Elle ne dit pas ce que ce programme dira à votre modèle. Le lock enregistre ce second point, pour qu’une pull request le montre.

```bash
warden-mcp scan --project --lock warden.lock.json --update-lock   # après avoir lu ce qui a changé
git add .mcp.json warden.lock.json
```

`--update-lock` écrit l’identité de lancement de chaque serveur et ses définitions d’outils complètes, et refuse d’enregistrer un serveur que WARDEN bloque. Le relancer sur des serveurs inchangés ne modifie pas le fichier. Avec `--lock` seul :

- un serveur que le lock ne connaît pas est bloqué (`LOCK_MISSING`) ;
- un serveur démarré autrement est bloqué (`SERVER_IDENTITY_DRIFT`) ;
- un serveur qui annonce désormais d’autres outils est bloqué (`TOOL_DEF_DRIFT`), et le rapport Markdown montre le changement sous forme de diff des noms, descriptions et schémas.

Les entrées du lock qu’aucune configuration ne démarre sont listées, puis supprimées à la mise à jour suivante.

## GitHub Action

```yaml
name: MCP servers
on: [pull_request]
permissions:
  contents: read
  security-events: write   # uniquement pour upload-sarif
jobs:
  warden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: alexar76/warden@v0.9.0
        with:
          upload-sarif: 'true'
```

Par défaut, elle lit les fichiers du projet, ne démarre pas les serveurs stdio (c’est la pull request qui choisit ce programme), refuse les adresses non publiques, utilise `warden.lock.json` s’il existe, écrit le résumé du job et échoue sur un serveur bloqué. Entrées : `config`, `working-directory`, `lock`, `launch-stdio`, `public-only`, `fail-on`, `histor`, `sarif`, `upload-sarif`, `version`. Sorties : `blocked`, `servers`, `sarif`. Dans les workflows de production, épinglez l’action par SHA de commit.

## pre-commit

```yaml
repos:
  - repo: https://github.com/alexar76/warden
    rev: v0.9.0
    hooks:
      - id: warden-scan     # configurations modifiées ; ne démarre pas les serveurs stdio
      - id: warden-lock     # le projet correspond à warden.lock.json ; démarre les serveurs stdio
```

Les deux exécutent le paquet publié via `npx` : Node 20 ou plus récent doit être dans le `PATH`.

## Plugin Claude Code

```text
/plugin marketplace add alexar76/warden
/plugin install warden@warden
```

Au début de la session, il analyse les serveurs que Claude Code démarre pour le projet, vous indique lesquels sont bloqués, et ne donne au modèle que le nom et le code du constat. Une description bloquée n’entre jamais dans le contexte du modèle. Ensuite, un hook `PreToolUse` refuse les appels aux outils d’un serveur bloqué ou à un outil bloqué ; il lit un petit fichier et ne démarre rien. Détails et limites : [claude-plugin/README.md](../claude-plugin/README.md).

## HISTOR : ce serveur vous sert-il ce qu’il sert à tout le monde ?

[HISTOR](https://histor.modelmarket.dev) est un journal public qui enregistre chaque jour les définitions d’outils de tous les serveurs distants du registre MCP officiel. `--histor` lui pose une question par serveur distant : l’ensemble d’outils qu’on vient de vous servir est-il celui qu’observe HISTOR ?

Ce qui est envoyé : l’endpoint, réduit au schéma, à l’hôte et au chemin (sans query, sans nom d’utilisateur ni mot de passe), et le condensé [MTL/1](https://github.com/alexar76/awr) de l’ensemble d’outils. Aucune description d’outil, aucun en-tête, aucun serveur stdio. Les endpoints sur des hôtes ou adresses privés, et les chemins qui semblent contenir une clé, ne sont pas envoyés du tout ; le rapport dit pourquoi.

| Réponse | Signification |
|---|---|
| `same` | On vous a servi l’ensemble qu’HISTOR observe actuellement |
| `different` | HISTOR n’a jamais vu cet ensemble : il a changé après le dernier passage quotidien, ou le serveur vous sert autre chose qu’au robot public. Signalé comme constat à titre consultatif uniquement `HISTOR_UNSEEN_TOOLSET` |
| `previously-observed` | Un ensemble qu’HISTOR a vu auparavant, pas l’actuel. Constat consultatif `HISTOR_OLDER_TOOLSET` |
| `not-listed`, `not-observed` | HISTOR ne connaît pas cet endpoint ou ne l’a encore jamais lu avec succès |

Les réponses d’HISTOR ne bloquent jamais. Si HISTOR ne répond pas, c’est signalé et l’analyse continue.

## Ce que scan ne fait pas

- Il lit les définitions une fois. Un serveur qui change ensuite est repéré par l’analyse suivante, par le lock en CI, ou à chaque appel par `wrap`.
- Il n’analyse ni les arguments ni les résultats des appels, ni les prompts, ni les resources, et ce n’est pas un bac à sable : démarrer un serveur stdio l’exécute.
- Ses verdicts sont les règles statiques et les enregistrements de menaces de WARDEN. Une paraphrase qu’aucune règle ne couvre passe ; voir [la chaîne de portes](gates.fr.md) et l’[étude de terrain](mcp-survey.fr.md) pour ce que les règles détectent et la fréquence de leurs erreurs.
