# Analyser les serveurs que démarrent vos clients MCP

> 🌐 [English](scan.md) · [Русский](scan.ru.md) · [Español](scan.es.md) · **Français** · [中文](scan.zh.md)

`warden-mcp scan` lit la configuration MCP que vous avez déjà, se connecte à chaque serveur qu’elle démarre et vérifie les définitions d’outils avant qu’un modèle ne les voie. C’est la même chaîne de portes que [`wrap`](../README-fr.md) et la [bibliothèque](integration.fr.md), exécutée une fois sur vos configurations au lieu de se placer devant un seul serveur.

```bash
npx -y @aimarket/warden@0.11.0 scan
```

```text
WARDEN scan 0.10.0 · ruleset 10 sha256-lJuKKKV5mtru… · block at high
  read .mcp.json (claude-code, 3 servers)

  ✓ allow   notes       claude-code    1 tool · score 0.90
  ✗ BLOCK   evil-notes  claude-code    1 tool · score 0.00 · TOOL_DEF_EXFIL(notes) TOOL_DEF_SECRET_REQUEST(notes) THREAT_SSH_KEY_READ(notes)
  ! error   broken      claude-code    could not start: spawn /nonexistent/bin/server ENOENT

3 servers: 1 allowed, 1 blocked, 1 not checked, 0 skipped.
Details: warden-mcp scan --json, or --markdown FILE. To review a changed server: warden-mcp scan --lock warden.lock.json --update-lock.
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
      - uses: alexar76/warden@v0.11.0
        with:
          upload-sarif: 'true'
```

Par défaut, elle lit les fichiers du projet, ne démarre pas les serveurs stdio (c’est la pull request qui choisit ce programme), refuse les adresses non publiques, utilise `warden.lock.json` s’il existe, écrit le résumé du job et échoue sur un serveur bloqué. Entrées : `config`, `working-directory`, `lock`, `launch-stdio`, `public-only`, `fail-on`, `histor`, `classifier-url`, `classifier-model`, `classifier-blocks`, `sarif`, `upload-sarif`, `version`. Sorties : `blocked`, `servers`, `sarif`. Dans les workflows de production, épinglez l’action par SHA de commit.

Pour être prévenu quand un serveur que vous utilisez change, lancez aussi le même job selon un horaire (`on: { schedule: [{ cron: '17 6 * * *' }] }`) : avec un `warden.lock.json` versionné, un serveur dont les définitions d’outils ont changé fait échouer l’exécution avec `TOOL_DEF_DRIFT`, et le résumé montre le diff.

## pre-commit

```yaml
repos:
  - repo: https://github.com/alexar76/warden
    rev: v0.10.0
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

## Flux toxiques : sûrs un par un, dangereux ensemble

Un client confie les outils de tous ses serveurs à un même modèle. Si l’un lit vos données privées, si un autre laisse entrer du texte venu de l’extérieur (une page web, une issue, un e-mail) et si un troisième peut envoyer des données dehors, un texte arrivé par le deuxième peut demander au modèle de lire avec le premier et d’envoyer avec le troisième. Aucun serveur n’est en faute : aucun verdict par serveur ne le montre. `scan` le signale par client :

```text
  ⚠ toxic flow  claude-code can read private data (filesystem.read_file, …), take in text from outside (fetch.fetch) and send data out (fetch.fetch). …
```

Les capacités sont lues dans les noms des outils et de leurs paramètres (`read_file`, `send_email`, un paramètre `url` ou `to`), pas dans les descriptions : la lecture ne dépend pas de la langue, et une description ne peut pas s’en justifier. Un flux est indicatif : il ne bloque jamais et ne change pas le code de sortie. Il figure dans `--json` (`flows`) et dans le résumé Markdown. Pour le casser, retirez une patte : un serveur `fetch` inutile, ou un serveur de fichiers limité à un dossier dans un autre client.

## HISTOR : ce serveur vous sert-il ce qu’il sert à tout le monde ?

[HISTOR](https://histor.modelmarket.dev) est un journal public qui enregistre chaque jour les définitions d’outils de tous les serveurs distants du registre MCP officiel. `--histor` lui pose une question par serveur distant : l’ensemble d’outils qu’on vient de vous servir est-il celui qu’observe HISTOR ?

Ce qui est envoyé : l’endpoint, réduit au schéma, à l’hôte et au chemin (sans query, sans nom d’utilisateur ni mot de passe), et le condensé [MTL/1](https://github.com/alexar76/awr) de l’ensemble d’outils. Aucune description d’outil, aucun en-tête. Les endpoints sur des hôtes ou adresses privés, et les chemins qui semblent contenir une clé, ne sont pas envoyés du tout ; le rapport dit pourquoi.

Un serveur stdio lancé depuis le registre public npm ou PyPI (`npx`, `bunx`, `npm exec`, `pnpm dlx`, `uvx`, `uv tool run`, `pipx run`) est désigné par son paquet — `npm:<nom>` ou `pypi:<nom>`, sans la version — et le même condensé. HISTOR installe chaque version publiée d’un tel paquet dans un bac à sable gVisor (identifiants leurres, sans route vers l’extérieur ; chaque outil appelé une fois avec des arguments canaris, sans agir sur rien de réel) et enregistre ses outils et ce qu’il a fait : ici, `previously-observed` signifie que vous exécutez une version plus ancienne, et `different` une version qu’HISTOR n’a pas encore atteinte, un paquet dont les outils dépendent de ce que votre machine possède et que le bac à sable n’a pas (un lanceur qui passe la main à un programme installé localement, une vraie clé ou un vrai réglage) ou un paquet qui n’est pas celui publié. Le constat donne le nombre d’outils des deux côtés. Un chemin local, une URL git ou tarball, un registre privé (`--registry`, `--index-url`) ou un simple lancement `node`/`python` n’est jamais envoyé. Pour un paquet, HISTOR indique aussi, en constats indicatifs, si son nom imite celui d’un paquet populaire (`HISTOR_PACKAGE_LOOKALIKE` : à un caractère près, le même nom sous un autre scope ou d’autres séparateurs, face à un paquet téléchargé au moins 100 fois plus) et si la version observée porte les marques d’un jeton de publication volé : `HISTOR_PACKAGE_PROVENANCE_LOST` (pas de compilation attestée en CI alors que la version précédente en avait une), `HISTOR_PACKAGE_INSTALL_SCRIPTS` (nouveaux scripts d’installation), `HISTOR_PACKAGE_PUBLISHER_CHANGED`, `HISTOR_PACKAGE_NEW_DEPENDENCIES`. Et ce que le paquet a fait dans le bac à sable : `HISTOR_PACKAGE_READS_SECRETS` (il a ouvert des identifiants leurres — clés SSH, jetons cloud ou de registre, portefeuille — à l’installation, au démarrage ou lors d’un appel d’outil), `HISTOR_PACKAGE_PERSISTENCE` (il a écrit là où il survivrait à la session, comme `.bashrc` ou `authorized_keys`), `HISTOR_PACKAGE_STARTUP_NETWORK` (il a contacté le réseau avant tout appel d’outil), `HISTOR_PACKAGE_STARTS_PROGRAMS`, `HISTOR_PACKAGE_INSTALL_BEHAVIOUR` (ce que font ses scripts d’installation). Charger `.env` depuis le répertoire de travail et appeler sa propre API pendant un appel ne sont pas des constats. Pourquoi un paquet n’a pas démarré, d’après ce qu’il a affiché : `HISTOR_PACKAGE_SDK_INCOMPATIBLE` (medium — écrit pour le SDK MCP 1.x, donc une installation neuve avec `mcp` 2.x échoue à l’import ; si HISTOR l’a aussi lancé avec `mcp<2`, combien d’outils il listait alors), `HISTOR_PACKAGE_NEEDS_CONFIG` (info — la clé ou le réglage qu’il a réclamé, ou le fait que ses outils ont été lus avec des valeurs factices) et `HISTOR_PACKAGE_KEY_SENT_TO` (low — où il a envoyé la clé factice posée par HISTOR ; vérifiez que c’est l’API du service lui-même). Tous les constats du bac à sable viennent des mêmes conditions : Linux sous gVisor, sans internet, secrets leurres ([conditions de test](https://histor.modelmarket.dev/#conditions)). Avec `--histor`, le rapport donne aussi un lien vers un flux HISTOR des changements des serveurs scannés qu’HISTOR connaît (`historWatch` dans `--json`) : abonnez-vous dans n’importe quel lecteur de flux.

| Réponse | Signification |
|---|---|
| `same` | On vous a servi l’ensemble qu’HISTOR observe actuellement |
| `different` | HISTOR n’a jamais vu cet ensemble : il a changé après le dernier passage quotidien, ou le serveur vous sert autre chose qu’au robot public. Pour un paquet, aussi : ses outils dépendent de ce que possède votre machine (voir plus haut). Signalé comme constat à titre consultatif uniquement `HISTOR_UNSEEN_TOOLSET` |
| `previously-observed` | Un ensemble qu’HISTOR a vu auparavant, pas l’actuel. Constat consultatif `HISTOR_OLDER_TOOLSET` |
| `not-listed`, `not-observed` | HISTOR ne connaît pas cet endpoint ou ne l’a encore jamais lu avec succès |

Si l’ensemble reçu est un ensemble que l’éditeur du serveur déclare dans son entrée du registre ([comment un éditeur déclare un ensemble](https://github.com/alexar76/histor/blob/main/docs/api.fr.md)), par exemple les outils d’un lanceur là où son programme est installé, le constat est `HISTOR_DECLARED_TOOLSET` au lieu de `HISTOR_UNSEEN_TOOLSET` : low, ou info quand HISTOR n’a pas d’ensemble à lui, avec la condition de l’éditeur dans ses mots. C’est la parole de l’éditeur, pas une observation, et toutes les autres vérifications lisent toujours les outils.

Les réponses d’HISTOR ne bloquent jamais. Si HISTOR ne répond pas, c’est signalé et l’analyse continue.

## Pour les éditeurs : déclarez les ensembles d’outils de votre serveur

HISTOR ne peut enregistrer que les outils que votre serveur liste dans son bac à sable. S’il en liste d’autres là où est installé ce que le bac à sable n’a pas — le runner d’un lanceur, un par système d’exploitation, une vraie clé —, déclarez ces ensembles, et ceux qui les reçoivent verront `HISTOR_DECLARED_TOOLSET` (low) au lieu de `HISTOR_UNSEEN_TOOLSET` (medium). Sur une machine qui reçoit l’ensemble :

```bash
npx -y @aimarket/warden declare --when "runner 1.4, macOS" --out mcp-tool-sets.json -- npx -y @acme/launcher
```

WARDEN démarre le serveur comme le ferait un client, calcule le condensé de son `tools/list` (MTL/1) et ajoute l’ensemble à `mcp-tool-sets.json`, en gardant ceux qui y sont et en remplaçant le même condensé. Recommencez sur chaque système et chaque version du runner. Ensuite :

1. Publiez le fichier sur le domaine que le registre a vérifié pour l’espace de noms de votre serveur — `ai.acme/launcher` → `acme.ai` ou un sous-domaine ; `io.github.<user>/…` → `<user>.github.io` ou vos fichiers raw GitHub —, par exemple à `https://acme.ai/.well-known/mcp-tool-sets.json`.
2. Faites-y pointer votre entrée du registre, une fois : `npx -y @aimarket/warden declare --server-json --link <url>` affiche le bloc `_meta` pour `server.json` ; publiez cette version au registre.
3. Vérifiez : `npx -y @aimarket/warden declare --check <url> --name ai.acme/launcher` lit le fichier comme HISTOR le lira et dit ce qu’HISTOR en retiendra.

Ensuite, une version du runner ne demande que `declare --out` et un nouvel envoi du fichier : HISTOR le relit toutes les heures. Un ensemble retiré du fichier est retiré ; un fichier qu’HISTOR ne peut pas lire garde ce qu’il déclarait. Sans fichier, `--server-json` avec le serveur après `--` met l’ensemble dans l’entrée elle-même, jusqu’à 8 ensembles. Les règles qu’applique HISTOR : [déclarer des ensembles](https://github.com/alexar76/histor/blob/main/docs/api.fr.md). Une déclaration est la parole de l’éditeur, pas une observation : WARDEN applique toujours toutes ses vérifications aux outils qu’il reçoit.

## Le classificateur optionnel

Les règles de WARDEN fonctionnent hors ligne et de façon déterministe, et elles manquent ce qu'aucune règle ne nomme : une paraphrase, une consigne dans une autre langue. `--classifier-url` et `--classifier-model` ajoutent l'avis d'un modèle que vous choisissez, via n'importe quel endpoint compatible OpenAI : Ollama, vLLM ou LM Studio en local, ou une API hébergée.

```bash
warden-mcp scan --classifier-url http://localhost:11434/v1 --classifier-model qwen2.5:14b
WARDEN_CLASSIFIER_API_KEY=… warden-mcp scan --classifier-url https://api.deepseek.com --classifier-model deepseek-flash --classifier-reasoning-effort none
```

- **Optatif ; transmet tous les champs annoncés.** Nom, titre, description, schémas, annotations et extensions, avec une lecture normalisée si nécessaire. La clé provient uniquement de `WARDEN_CLASSIFIER_API_KEY`.
- **Consultatif par défaut ; refus si incomplet avec `--classifier-blocks`.** Les résultats utilisent `TOOL_DEF_CLASSIFIER`. Troncature, incertitude, couverture incomplète, réponse invalide, erreur ou délai dépassé donnent `CLASSIFIER_INCOMPLETE`. Ce sont des échecs d’inspection, pas des attaques détectées ; `--update-lock` ne peut pas les approuver.
- **Cinq catégories.** `instruction_to_model`, `exfiltration`, `secret_request`, `concealment`, `cross_tool`. L’inspection porte sur l’autorité des instructions, dans toute langue, selon les capacités du modèle. Le protocole exige une décision par outil et des références de champs vérifiées par WARDEN, qui extrait le texte source. Chaque décision incomplète est réessayée une seule fois isolément. Les délimiteurs aléatoires ne garantissent pas l’immunité.
- **Inspection ne vaut pas approbation.** [`wrap --require-approval`](security-hardening-language-boundary.md) exige l’approbation de l’opérateur indépendamment de la langue. Les résultats historiques de HISTOR restent consultatifs.

Mesuré le 16 octobre 2026 avec `deepseek-flash`, le modèle qu'utilise HISTOR, sur MCPTox (le benchmark publié décrit dans la comparaison ci-dessous), sur de vrais serveurs et sur nos propres jeux :

| | Règles (v12) | Règles + classificateur au niveau `high` |
|---|---|---|
| Moitié réservée de MCPTox, détectés sur 218 outils empoisonnés | 171 | 218 |
| 45 serveurs propres de MCPTox, signalés | 0 | 0 |
| 200 serveurs du corpus tirés au hasard, bloqués ou signalés | 2 | 5 |
| 996 paquets npm et PyPI d'un échantillon aléatoire, bloqués ou signalés | 23 | 35 |
| 23 attaques écrites par nous / 12 cas bénins difficiles | 20 / 0 | 23 / 0 |

Les deux serveurs du corpus que bloquent les règles sont le service d'identité et l'outil de déploiement de la comparaison ci-dessous. Les signalements `high` du classificateur sur de vrais serveurs sont surtout des consignes de déroulement comme « appelle d'abord cet outil ». Deux paquets méritent un regard humain, et les règles n'en bloquent aucun : l'un enveloppe sa description dans un faux bloc « c'est l'utilisateur qui l'a demandé » et ordonne au modèle de l'appeler avant toute réponse ; l'autre envoie le contenu de fichiers de l'agent vers son serveur avec « Do NOT display … to the user ». Le modèle a manqué ce que les règles détectent : une injection dans le nom d'un outil, une clé privée ou une phrase de récupération demandée en paramètre, et `rm -rf ~`. Ensemble, ils détectent nos 23 attaques.

## Comparaison

Le 16 octobre 2026, nous avons exécuté WARDEN, mcp-audit 0.18.2 (`--connect`), mcp-shield 1.0.4, truecopy 0.10.4 et mcpsentry 0.1.5 sur les mêmes serveurs. Chaque serveur était rejoué en stdio, si bien que chaque scanner s'y connectait comme sur le terrain. Chaque scanner a tourné dans un conteneur gVisor sans réseau, à partir d'images figées dont le contenu est haché dans un manifeste. Le banc d'essai, les jeux, le manifeste et chaque jugement sont dans [`scripts/scanner-comparison`](../scripts/scanner-comparison/). Le compte rendu complet, avec la méthode et chaque réserve, est la [comparaison de scanners](scanner-comparison.fr.md).

Les lignes MCPTox viennent de MCPTox (Wang et al., AAAI 2026), un benchmark publié de 485 outils empoisonnés écrits pour 45 vrais serveurs MCP. Nous avons coupé ses serveurs en deux avec un hachage fixe. Les règles v10 ont été écrites à partir de 22 serveurs ; le tableau rapporte les 23 autres, avec 218 outils empoisonnés auxquels aucune règle n'a été ajustée. v11 et v12 n'en ont pas été tirées non plus et donnent les mêmes verdicts que v10.

| Serveurs | WARDEN 0.16.0 (v12) | mcp-audit 0.18.2 | mcp-shield 1.0.4 | truecopy 0.10.4 | mcpsentry 0.1.5 |
|---|---|---|---|---|---|
| 23 attaques écrites par nous, bloquées | 20 | 10 | 6 | 8 | 4 |
| 10 attaques tirées des fixtures de mcp-audit et de mcp-shield, bloquées | 10 | 10 | 8 | 7 | 5 |
| 12 cas bénins difficiles, bloqués | 0 | 1 | 1 | 1 | 2 |
| 218 outils empoisonnés de MCPTox sur les serveurs réservés, bloqués | 171 | 25 | 41 | 27 | 8 |
| 225 outils de MCPTox avec un préfixe `<IMPORTANT>` ou « Ignore the previous instructions », bloqués | 225 | 222 | 41 | 141 | 136 |
| 45 serveurs propres de MCPTox, bloqués | 0 | 2 | 3 | 0 | 1 |
| 986 serveurs publics, bloqués | 3 | 33 | 343 | 39 | 86 |
| …blocages qui tiennent à la lecture du texte | 1, et 1 discutable | 0 | 1 sur les 34 lus | 1 | 0 |
| 14 933 paquets npm et PyPI observés par HISTOR, bloqués | 369 | 928 | 5 354 | 252 | 1 449 |

- **Lisez d'abord les lignes sur de vrais serveurs.** Aucune règle n'y a été ajustée. Les 33 blocages de mcp-audit sur le corpus sont surtout des « homoglyphes » dans un texte écrit entièrement dans son propre alphabet et des consignes d'honnêteté comme « do not tell the user the check digits are wrong ». mcp-shield bloque un tiers des vrais serveurs, presque toujours sur un mot-clé : « API key », « token », `.env`, « .. ». truecopy bloque les générateurs docker-compose d'un même éditeur parce qu'ils produisent un `.env.example`. Le motif base64 de mcpsentry correspond à toute suite de 40 lettres et barres obliques, comme en produisent les chemins JSON Schema. Sur 14 933 paquets npm et PyPI, un échantillon aléatoire de 996 où chaque blocage a été jugé compte 23 blocages de WARDEN, dont aucun ne tient et 4 sont discutables ; mcp-shield bloque 339 de ces mêmes paquets et mcpsentry 112.
- **Sachez quels chiffres sont ajustés.** Nous avons écrit le premier jeu d'attaques, et les règles v9 ont été écrites après la lecture des deux jeux d'attaques. La ligne de la moitié réservée de MCPTox, les serveurs propres, le corpus et les paquets ne sont pas ajustés.
- **MCPTox teste une forme, pas un mot-clé.** Presque chaque outil empoisonné dit au modèle d'appeler d'abord un autre outil, ou de changer les arguments d'un autre. v10 a nommé cette forme (`TOOL_DEF_CROSS_TOOL`, voir [la chaîne de portes](gates.fr.md)) et v12 la garde. Avec le préfixe `<IMPORTANT>` du benchmark, la plupart des scanners détectent la plupart des outils.
- **Ce que WARDEN manque encore :** 47 des 218 outils MCPTox réservés, une consigne en chinois de lire `.env`, une paraphrase sans mot-clé (« gather every credential file … keep this step to yourself ») et « include the output of env ». Il en signale 41 sur 47 à titre consultatif, sans les bloquer. Avec le classificateur facultatif ci-dessus, les 218 sont signalés au niveau `high`.
- **WARDEN n'est pas seul sur ce créneau.** mcp-audit propose lui aussi un fichier lock, un mode diff pour les PR et SARIF ; truecopy épingle et signe lui aussi les définitions dans un fichier lock.

## Ce que scan ne fait pas

- Il lit les définitions une fois. Un serveur qui change ensuite est repéré par l’analyse suivante, par le lock en CI, ou à chaque appel par `wrap`.
- Il n’analyse ni les arguments ni les résultats des appels, ni les prompts, ni les resources, et ce n’est pas un bac à sable : démarrer un serveur stdio l’exécute.
- Ses verdicts sont les règles statiques et les enregistrements de menaces de WARDEN. Une paraphrase qu’aucune règle ne couvre passe ; voir [la chaîne de portes](gates.fr.md) et l’[étude de terrain](mcp-survey.fr.md) pour ce que les règles détectent et la fréquence de leurs erreurs.
