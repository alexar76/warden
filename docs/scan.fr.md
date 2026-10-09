# Analyser les serveurs que démarrent vos clients MCP

> 🌐 [English](scan.md) · [Русский](scan.ru.md) · [Español](scan.es.md) · **Français** · [中文](scan.zh.md)

`warden-mcp scan` lit la configuration MCP que vous avez déjà, se connecte à chaque serveur qu’elle démarre et vérifie les définitions d’outils avant qu’un modèle ne les voie. C’est la même chaîne de portes que [`wrap`](../README-fr.md) et la [bibliothèque](integration.fr.md), exécutée une fois sur vos configurations au lieu de se placer devant un seul serveur.

```bash
npx -y @aimarket/warden@0.9.0 scan
```

```text
WARDEN scan 0.9.0 · ruleset 10 sha256-lJuKKKV5mtru… · block at high
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

Par défaut, elle lit les fichiers du projet, ne démarre pas les serveurs stdio (c’est la pull request qui choisit ce programme), refuse les adresses non publiques, utilise `warden.lock.json` s’il existe, écrit le résumé du job et échoue sur un serveur bloqué. Entrées : `config`, `working-directory`, `lock`, `launch-stdio`, `public-only`, `fail-on`, `histor`, `classifier-url`, `classifier-model`, `classifier-blocks`, `sarif`, `upload-sarif`, `version`. Sorties : `blocked`, `servers`, `sarif`. Dans les workflows de production, épinglez l’action par SHA de commit.

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

## Le classificateur optionnel

Les règles de WARDEN fonctionnent hors ligne et de façon déterministe, et elles manquent ce qu'aucune règle ne nomme : une paraphrase, une consigne dans une autre langue. `--classifier-url` et `--classifier-model` ajoutent l'avis d'un modèle que vous choisissez, via n'importe quel endpoint compatible OpenAI : Ollama, vLLM ou LM Studio en local, ou une API hébergée.

```bash
warden-mcp scan --classifier-url http://localhost:11434/v1 --classifier-model qwen2.5:14b
WARDEN_CLASSIFIER_API_KEY=… warden-mcp scan --classifier-url https://api.deepseek.com --classifier-model deepseek-flash
```

- **Désactivé par défaut, il envoie le texte des outils.** Avec les deux options, le nom, la description et les schémas de chaque outil partent vers cet endpoint. Un modèle local les garde sur votre machine. La clé, si nécessaire, vient uniquement de `WARDEN_CLASSIFIER_API_KEY`, jamais d'une option.
- **Consultatif sauf avec `--classifier-blocks`.** Ses verdicts sont signalés comme `TOOL_DEF_CLASSIFIER`. Avec `--classifier-blocks`, un verdict au seuil de blocage ou au-dessus (`high` par défaut) bloque l'outil comme une règle. Un classificateur qui ne répond pas est signalé et ne bloque jamais.
- **La même question que HISTOR.** Le prompt, les quatre catégories (`instruction_to_model`, `exfiltration`, `secret_request`, `concealment`) et le format de réponse sont ceux du classificateur du journal HISTOR. Le texte des outils est placé entre des marqueurs à suffixe aléatoire qu'il ne peut pas forger, et la réponse du modèle est vérifiée champ par champ. Avec `--histor`, le verdict que le journal a lui-même enregistré sur l'ensemble qu'on vous a servi s'affiche aussi (`HISTOR_CLASSIFIER`, consultatif).
- **Il ne lit ni les annotations ni les champs d'extension.** Les règles, si.

Mesuré le 9 octobre 2026 avec `deepseek-flash`, le modèle qu'utilise HISTOR, sur MCPTox (le benchmark publié décrit dans la comparaison ci-dessous) et sur nos propres jeux :

| | Règles (v10) | Règles + classificateur, blocage à `high` | Règles + toute marque du classificateur (consultative) |
|---|---|---|---|
| Moitié réservée de MCPTox, détectés sur 218 outils empoisonnés | 171 | 191 | 218 |
| 45 serveurs propres de MCPTox, bloqués ou marqués | 0 | 0 | 4 marqués |
| 200 serveurs du corpus tirés au hasard, bloqués ou marqués | 2 bloqués | 2 bloqués | 2 bloqués, 12 autres marqués |
| 23 attaques écrites par nous / 12 cas bénins difficiles | 20 / 0 | 22 / 0 | 23 / 0 |

Les deux que bloquent les règles sont le service d’identité et l’outil de déploiement de la comparaison ci-dessous. Les 13 serveurs marqués par le classificateur l'ont été en `medium` ou `low`, jamais en `high`. Six méritent un regard humain : l'un demande au modèle d'effectuer un transfert irréversible de nom ENS « comme première et unique action » sans demander à l'utilisateur, un autre de ne pas révéler d'où viennent ses données. Le modèle marque aussi le serveur officiel Fetch, dont la description dit au modèle qu'il a désormais accès à internet et ne doit pas refuser. C'est une consigne au modèle, mais pas une attaque. Le modèle a manqué ce que les règles détectent : une injection dans les annotations, une clé privée ou une phrase de récupération demandée comme paramètre, et `rm -rf ~`.

## Comparaison

Le 9 octobre 2026, nous avons exécuté WARDEN, mcp-audit 0.18.2 (`--connect`) et mcp-shield 1.0.4 sur les mêmes serveurs. Chaque serveur était rejoué en stdio, si bien que chaque scanner s’y connectait comme sur le terrain. Le banc, les jeux et chaque jugement sont dans [`scripts/scanner-comparison`](../scripts/scanner-comparison/). L’étude complète, avec la méthode et toutes les réserves, est la [comparaison de scanners](scanner-comparison.fr.md).

Les trois dernières lignes viennent de MCPTox (Wang et al., AAAI 2026), un benchmark publié de 485 outils empoisonnés écrits pour 45 vrais serveurs MCP. Nous avons coupé ses serveurs en deux par un hachage fixe. Le ruleset v10 a été écrit à partir de 22 serveurs ; le tableau rend compte des 23 autres, avec 218 outils empoisonnés sur lesquels aucune règle n’a été ajustée.

| Serveurs | WARDEN 0.8.2 (v8) | WARDEN 0.9.0 (v10) | mcp-audit 0.18.2 | mcp-shield 1.0.4 |
|---|---|---|---|---|
| 23 attaques écrites par nous, bloquées | 14 | 20 | 10 | 6 |
| 10 attaques tirées des fixtures de mcp-audit et de mcp-shield, bloquées | 7 | 10 | 10 | 8 |
| 12 cas bénins difficiles, bloqués | 0 | 0 | 1 | 1 |
| 986 serveurs publics, bloqués | 3 | 3 | 33 | 343 |
| …blocages justifiés à la lecture du texte | 1, et 1 discutable | 1, et 1 discutable | 0 | 0 sur 20 tirés au hasard |
| 218 outils empoisonnés de MCPTox sur les serveurs réservés, bloqués | 26 | 171 | 25 | 41 |
| 225 outils de MCPTox précédés de `<IMPORTANT>` ou « Ignore the previous instructions », bloqués | 225 | 225 | 222 | non exécuté |
| 45 serveurs propres de MCPTox, bloqués | 0 | 0 | 2 | 3 |

- **Lisez d’abord la ligne du corpus.** Aucune règle n’a été ajustée sur elle. Les 33 blocages de mcp-audit sont 16 « homoglyphes » dans un texte écrit entièrement dans son propre alphabet (ponctuation chinoise, symboles grecs, cyrillique), 12 consignes d’honnêteté comme « do not tell the user the check digits are wrong », 3 utilitaires base64, un outil de clé publique SSH et l’outil de déploiement que WARDEN bloque lui aussi à tort. mcp-shield bloque 35 % des serveurs réels, presque toujours sur un mot-clé : « API key », « token », `.env`, « .. ». Des points de suspension (« Shopify... ») comptent comme une remontée de répertoire. Il bloque bien le service d’identité que bloque WARDEN, mais pour le mot « credentials ».
- **Sachez quels chiffres sont ajustés.** Nous avons écrit le premier jeu d’attaques. Le ruleset v9 a été écrit après la lecture des deux jeux d’attaques, et v10 après les 22 serveurs MCPTox de l’autre moitié. 20 et 10 sont donc le rappel de règles ajustées à ce qu’elles ont vu. La ligne MCPTox réservée, les serveurs propres, le corpus et toute la colonne 0.8.2 ne sont pas ajustés. Sur le corpus, v10 bloque exactement ce que bloquait v8.
- **MCPTox teste une forme, pas un mot-clé.** Presque chaque outil empoisonné dit au modèle d’appeler d’abord un autre outil, ou de changer les arguments d’un autre outil. v10 nomme cette forme (`TOOL_DEF_CROSS_TOOL`, voir [la chaîne de portes](gates.fr.md)) et bloque 171 des 218 outils réservés, contre 189 sur 267 dans la moitié qui a servi à l’écrire. Avec le préfixe `<IMPORTANT>` ou « Ignore the previous instructions » du benchmark, tous les scanners que nous avons lancés les attrapent ; nous n’avons pas lancé mcp-shield sur ce jeu. Sur les serveurs propres, mcp-audit bloque AmapMap et BaiduMap, et mcp-shield bloque FileSystem, AdFin et Commander pour « sensitive file access ».
- **Ce que WARDEN manque encore :** 47 des 218 outils MCPTox réservés, une consigne en chinois de lire `.env`, une paraphrase sans mot-clé (« gather every credential file … keep this step to yourself ») et « include the output of env ». Il signale 41 de ces 47, et nos trois, à titre consultatif, sans bloquer. Il faut une vérification par le sens, pas une règle de plus : avec le classificateur optionnel ci-dessus, 191 des 218 sont bloqués au niveau `high` et les 218 sont signalés.
- **Non comparé :** Snyk Agent Scan, anciennement Invariant mcp-scan et le scanner le plus utilisé. Il juge les descriptions sur les serveurs de Snyk et exige un jeton de compte. mcp-audit propose lui aussi un fichier lock, un mode diff pour les PR et SARIF ; WARDEN n’est pas seul sur ce créneau.

## Ce que scan ne fait pas

- Il lit les définitions une fois. Un serveur qui change ensuite est repéré par l’analyse suivante, par le lock en CI, ou à chaque appel par `wrap`.
- Il n’analyse ni les arguments ni les résultats des appels, ni les prompts, ni les resources, et ce n’est pas un bac à sable : démarrer un serveur stdio l’exécute.
- Ses verdicts sont les règles statiques et les enregistrements de menaces de WARDEN. Une paraphrase qu’aucune règle ne couvre passe ; voir [la chaîne de portes](gates.fr.md) et l’[étude de terrain](mcp-survey.fr.md) pour ce que les règles détectent et la fréquence de leurs erreurs.
