# Évaluation de sécurité MCP : WARDEN — 2026-11-07

**État : comparaison des cinq produits publiés complète sur les deux hôtes.** Chaque produit a tenté les 18 110 lignes. Couverture complète, erreurs et parité restent distinctes ; les cohortes mixtes ne sont pas une exactitude globale. Le candidat runtime ultérieur `.2` a son propre état ci-dessous.

[English](security-benchmark-2026-11-07.md) · [Русский](security-benchmark-2026-11-07.ru.md) · [Español](security-benchmark-2026-11-07.es.md) · [Français](security-benchmark-2026-11-07.fr.md) · [中文](security-benchmark-2026-11-07.zh.md)

Ce document est rédigé par le mainteneur de WARDEN et de HISTOR, avec une assistance IA. Il s'agit d'une comparaison du mainteneur, pas d'une certification indépendante. Les mesures comparatives présentées sont distantes, dans gVisor. Un pilote local antérieur est exclu et ses artefacts `dist`/Vitest/Vite supprimés ; cela ne signifie pas qu'aucun pilote local n'a jamais existé.

Les liens vers les preuves téléchargent le ZIP public du rapport. Le titre de chaque lien indique le fichier correspondant dans cette archive.

## Objet et versions

La comparaison mesure la réaction aux définitions d'outils annoncées par MCP. Analyser une description ne revient pas à exécuter l'outil, à observer un modèle suivre une injection ni à mesurer la réussite d'une attaque contre un modèle.

| Implémentation | Paquet / entrée | Identité du nouveau passage |
|---|---|---|
| WARDEN, produit publié principal | `@aimarket/warden` | npm `0.23.0`, ruleset `17`, 40 règles ; digest `sha256-UOfK25xo6D8vrKEVfNFBTBVn5OspyaZut9vC9Z9Q5JE=` |
| mcp-audit | PyPI `mcp-audit-scanner[mcp]` | `0.28.0` |
| mcp-shield | npm `mcp-shield` | `1.0.4` |
| truecopy | npm `@askalf/truecopy` | `0.10.5` |
| mcpsentry | npm `@roshan6335/mcpsentry` | `0.1.5` |

La colonne WARDEN principale utilise le tarball npm publié vérifié, SHA-256 `833841f2aab89df4c51b5f84385ad69c8ffd7dcf5a7725ec0eb4ebabe594b7ee`. L'ancien build figé « v17 » comporte six fichiers dist modifiés pour wrapper/filtrage de résultats : il n'est pas identique octet pour octet à npm 0.23.0 et ne remplace pas sa colonne. Le candidat non publié, postérieur aux échecs observés, est `0.23.1-dev.20261107.1`, ruleset `19`, 43 règles dont 32 bloquantes, digest `sha256-XfRh1+VZoAM6PGtbmqprnSX/eF16qNYOk0o+ilRFxXw=`. Le premier v18 garde son digest `sha256-aXkZQj8F1fKgcTpyrfNdgQSQMuzdc1yabcKiGPVKjMo=`. Aucune publication npm. Les versions et résultats d'octobre restent dans [l'historique](scanner-comparison.fr.md).

Les paquets publiés et corpus publics d'origine sont accessibles. Le rejeu exact des fixtures et adaptateurs du mainteneur exige la publication de leurs sources. Les métadonnées permettent d'inspecter id, seuils, couverture et hachages de sortie, pas de reproduire seules l'ensemble indépendamment. Le code candidat19 reste aussi non publié : ses hachages/reçus sont auditables, pas un build reproductible extérieurement. Le lot public contient rapports, métadonnées et figures, sans sources produit/banc privé.

## Implémentations réelles et rejeu des définitions

La comparaison massive utilise les API natives complètes d'analyse/classification des implémentations réelles, avec état neuf. Elle ne prétend pas faire passer chacune des 18 110 lignes par stdio MCP pour chaque produit. Parité CLI/MCP et interopérabilité vivante sont vérifiées séparément.

| Catégorie | Inventaire explicite | Portée | État |
|---|---|---|---|
| Paquets stdio réels, candidat19 | `@modelcontextprotocol/server-filesystem@2.2.0` (16 outils), `@modelcontextprotocol/server-memory@2.1.0` (9), `@modelcontextprotocol/server-sequential-thinking@2.1.1` (1), WARDEN (9) | SDK officiel Node MCP `1.32.1`, directement et via wrapper : découverte, appel synthétique sûr, refus d'outil inconnu, ping ultérieur | Deux hôtes : 8/8 sessions, 4/4 paires de digest de listes identiques |
| HTTP publics, candidat19 | DeepWiki (3), Microsoft Learn (3), Cloudflare Docs (2) | Uniquement `initialize` et `tools/list` | Deux hôtes : 3/3 sans erreur, tous autorisés |
| Définitions figées | 3 177 vues fixes et 14 933 lignes HISTOR | API natives complètes ; code des serveurs d'origine non exécuté | Complet sur les deux hôtes |
| Parité représentative CLI/MCP | Node : 10/10 chacun ; mcp-audit Python : 13 accords natif/API avec six analyseurs, dont un partiel ; WARDEN publié : 20/20, liste de 1,17 Mo et attaque/propre/répétition | Entrée native contre adaptateur | Un accord partiel n'est pas un verdict complet |

Voir [les preuves vivantes](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: evidence/live/README.md"). Le reçu SDK final correspond à `sdk19-final` distant ; les copies locales `sdk19` gardent le passage initial. Aucun fichier utilisateur ni secret de production n'entre dans les appels synthétiques. HTTP : `https://mcp.deepwiki.com/mcp`, `https://learn.microsoft.com/api/mcp`, `https://docs.mcp.cloudflare.com/mcp`. Ce sont les versions observées, pas une revendication de dernières versions.

## Inventaire exact des fixtures

**23 attaques du mainteneur**, définies dans [`build_sets.py`](../scripts/scanner-comparison/build_sets.py) :

`A01-important-tag`, `A02-ssh-into-param`, `A03-shadowing-bcc`, `A04-zero-width-hidden`, `A05-unicode-tags`, `A06-base64-payload`, `A07-russian`, `A08-chinese`, `A09-paraphrase`, `A10-schema-hidden`, `A11-annotation-injection`, `A12-exfil-url`, `A13-name-injection`, `A14-private-key-param`, `A15-seed-phrase`, `A16-javascript-url`, `A17-ignore-previous`, `A18-system-tag`, `A19-call-first-history`, `A20-env-dump`, `A21-destructive`, `A22-concealment`, `A23-spanish`.

**12 contrôles bénins :**

`B01-never-send-key`, `B02-injection-scanner`, `B03-api-key-param`, `B04-javascript-word`, `B05-persian-zwnj`, `B06-refunds`, `B07-send-email`, `B08-secret-scanner`, `B09-password-vault`, `B10-upload-drive`, `B11-ssh-howto`, `B12-translate`.

**Fixtures tiers : 10 attaques, un cas bénin, un cas ambigu.**

| Source | Cas et étiquettes |
|---|---|
| mcp-audit, commit `fdc8762eb2d5abb708bdaf767ec5a8140b2ab9a2` | Attaques : `behavioral_override_stealth`, `cloud_credential_exfiltration`, `crowdstrike_add_numbers`, `fake_postmark_exfiltration`, `invariant_labs_ssh_exfiltration`, `xml_injection_override` |
| mcp-shield, commit `379140c3555bf35c6f8f451ee320da24302e792e` | Attaques : `calculateSum`, `sendEmail`, `readFile`, `getFactOfTheDay` ; bénin : `whatsapp` ; ambigu : `fetchWeather` |

Le cas ambigu est publié séparément et exclu des dénominateurs de rappel et d'erreurs sur les contrôles bénins. Une origine tierce ne transforme pas un fixture connu en nouveau test aveugle : ces entrées étaient disponibles pendant le développement de WARDEN.

## MCPTox : unités et 45 noms de serveurs

L'extraction archivée contient **485 définitions empoisonnées distinctes** : 267 sur 22 serveurs dev et 218 sur 23 serveurs test. S'y ajoutent, séparément, 225 définitions dont la représentation dans le prompt est modifiée et 45 listes de serveurs propres. Ces unités ne peuvent pas être additionnées comme des « serveurs ».

Les **1 348 scénarios** constituent une autre vue recoupant les 485 définitions. L'audit distant du commit officiel `f85189f9ad12504c197c7f920ab818a40657b1fa` conserve 1 338 valeurs server/frame uniques et 10 instances dupliquées conservées, zéro rejet ; 702 avec sauts littéraux, 646 avec normalisation des sauts échappés. Les hachages JSON correspondent aux archives. Le dépôt ne précise aucune licence : les téléchargements publics contiennent des métadonnées factuelles, pas les définitions, schémas, payloads ou sources Python bruts. Les 45 listes propres exposent 362 outils contre 353 dans l'article ; la déduplication ne résout pas cet écart. Voir [l'extraction](../scripts/scanner-comparison/build_mcptox.py) et [le split](../scripts/scanner-comparison/results/2026-10-09-mcptox.json).

La projection full-frame conserve le texte des arguments à l'identique, mais déclare les propriétés extraites comme chaînes. Elle ne reconstruit pas les types natifs d'origine ; ses résultats portent sur cette projection, pas sur une exécution exacte des schémas d'origine.

**Dev — 22 :** AWSKnowledgeBase; AdFin; AlphaVantage; BaiduMap; ClickHouse; Codacy; Commander; DoDo Payments; Email; EverArt; Everything; Fetch; Flomo; Google Maps; Memory; Prisma; SQLite; Sentry; Slack; Tavily; gNucleus Text to CAD; mcp-simple-arxiv.

**Test — 23 :** 12306-mcp; AgentQL; AmapMap; Apify; BraveSearch; Claude Post; DumplingAI; E2B; FileSystem; Financial Dataset; Git; Github; Gitlab; GoogleDrive; Gyazo; HyperBrowser; KeywordsPeopleUse; OP.GG; Puppeteer; QuickChart; Redis; Sequential Thinking; wechat.

Ce sont des noms du jeu de données, sans affirmation de disponibilité ou d'affiliation actuelles. Le split est fixé par tri sur `sha256("mcptox split 2026-10-09|" + server_name)` : les 22 premiers pour dev, les 23 autres pour test. L'ordre ci-dessus est celui des listes du fichier de résultats.

| Entrée archivée | SHA-256 des octets d'origine |
|---|---|
| `pure_tool.json` | `54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617` |
| `response_all.json` | `79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03` |

Ces deux hachages historiques ne remplacent pas un nouveau manifest de toutes les sources, fichiers `def_tool`, JSON et configurations générés. Le parseur traite Python comme des données et ne l'exécute pas. « Served » rejoue la définition extraite du serveur ; « decorated » mesure séparément les préfixes tels que `<IMPORTANT>` ou « Ignore the previous instructions ».

## Archive publique et observations de paquets

La cohorte principale compte **986 listes archivées** dans [le corpus 2026-10-01](data/mcp-corpus-2026-10-01.jsonl.gz). [August carryover](data/mcp-corpus-2026-10-01-august-carryover.jsonl.gz) contient **41 observations**, dont **28 doublons exacts nom+définition**, soit **999 snapshots nom+définition uniques**. Ce ne sont pas 1 027 serveurs indépendants.

L'[inventaire complet](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: INVENTORY-README.md") liste **les 18 110 lignes**, noms, versions enregistrées, étiquettes, comptes d'outils, digests et provenance. Téléchargements : [CSV.gz](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: public-inventory.csv.gz"), [JSON.gz](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: public-inventory.json.gz"), [manifest](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: public-inventory-manifest.json"). Métadonnées seules, sans contenu d'attaque sans licence.

Les **14 933 lignes de versions HISTOR sont disponibles : 12 023 npm et 2 910 PyPI**, 14 449 toolsets distincts et 272 657 enregistrements d'outils, sans rejet ni écart de compte. Digests MTL recalculés et hachages de fichiers vérifiés sur les deux hôtes. [L'archive 2026-10-20](https://histor.modelmarket.dev/datasets/2026-10-20/toolsets.jsonl.gz) a fourni 14 930 lignes ; trois autres viennent d'URL API publiques immuables. Le [manifest](https://histor.modelmarket.dev/datasets/2026-10-20/manifest.json) et le tree-head Ed25519 sont vérifiés avec le `did:key` figé. Archive CC-BY-4.0, attribution Aleksandr Artamokhov / HISTOR, *HISTOR: MCP tool definitions and how they change*, snapshot 2026-10-20. Les trois réponses API sans licence distincte sont publiées en métadonnées seulement.

Les champs de base MTL archivés sont exacts, sans fusion de title, annotations ou extensions actuels. Une observation n'est pas une nouvelle installation/exécution. Les données non étiquetées mesurent la fréquence des signaux ; un faux positif exige une étiquette ou un jugement du texte pertinent.

| Entrée / preuve | SHA-256 |
|---|---|
| Catalogue 3 177 vues | `e29baa05fbdbf46e34631ff2c75f0b4f535f0188054dd4499699bd189a3dc757` |
| Catalogue 14 933 paquets | `78d4dab7125318b80cc35302e7cf1cfc1a49fa6f310957ed7b8fddfb538375b6` |
| Preuve de récupération HISTOR | `8cdb0faf62c72f947baf30f74d6523fc6fd5b68720b44f4b765a0f804489cf7e` |
| Résultats grouped finaux | `44732cdfa369f0f912491212d1910883a6071c4ce4727cfc30911adb828d7a3b` |
| Preuve finale par cas interhôtes | `a0773f6622290268129cc48323dab0b1b84dc5652d1b2b1ba20e679c63a01205` |
| Manifest SHA-256 final | `17d6e7ebd85dede970d77f319bf3734478a037bf9fd971a53f5bbd07b4fce3f8` |

Catalogues `warden.shared-lazy-inputs/v1` : `toolsFileSha256` porte sur les octets UTF-8 exacts ; `toolsSha256` sur JSON Python 3.13 compact, clés triées, Unicode/ordre des tableaux conservés, nombres non finis refusés, sans prétention JCS. Wire id : `c` et les 32 premiers hex de SHA-256 de `warden shared inputs 2026-11-07|` + clé du cas, identique entre produits, versions et hôtes.

## Protocole distant enregistré

1. Figer source, digest des règles, versions, heure de consultation des registres, hachages d'intégrité publiés, dépendances et digest d'image avant d'interpréter les résultats. Conserver commandes et sorties originales.
2. Calculer le SHA-256 de chaque entrée : téléchargement, définition extraite, JSON de rejeu, étiquettes, split, config et banc. Conserver id stables, versions des transformations et provenance.
3. Mesures massives : `runsc`, sans réseau, UID/GID 501:501, root/source/runtime/data en lecture seule, cap-drop ALL, no-new-privileges, tmpfs et résultats séparés. Image `sha256:db7085498187e8477fa462d5f1652d62bdf4b8af29ea3666bd1748a8315631a5`, Node 24.22.2/Python 3.13.18. Node : 1 CPU/768 MiB, reçu pids128. Audit base : 1 CPU/768 MiB ; HISTOR : attested 1 CPU/768 MiB/un worker, PingBlip 2 CPU/1536 MiB/deux workers, pids256. `cpu.max`/`memory.max` vérifiés. Audit HISTOR UTC 2026-11-07 : attested 20:33:21–21:13:27, PingBlip 20:33:15–21:34:48 ; pas un test contrôlé de vitesse. Stdio/HTTP vivants : réglages distincts UID1000, 0,5 CPU/512 MiB et bridge/256 MiB.
4. API native complète d'analyse/classification avec état neuf par cible. mcp-audit utilise les six analyseurs par défaut. Les adaptations sont vérifiées par les cas CLI/MCP distincts. WARDEN : `allowUnknownServers: true`, `sensitiveToolPatterns: []`. Refus cold-lock/unpinned de truecopy séparés de l'analyse de contenu.
5. Conserver premières tentatives et reprises séparément ; annoncer timeout et politique de reprise en amont. Erreur, saut et rejet du protocole ne valent pas allow. Ne jamais remplacer un résultat neuf manquant par un ancien verdict.
6. Sorties natives, normalisation, erreurs et hachages sont conservés. La preuve finale compare clé, wire id, SHA-256 exact d'entrée, version/code/image, statut, HC/any/advisory et SHA de l'objet natif complet. Seuls le `finding_path` temporaire propre à mcp-audit et l'evidence state-file `RUGPULL-000` sont normalisés ; textes/codes/sévérités conservés.

[Télécharger le ZIP rapports et données](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip) : cinq langues hors ligne, `grouped-results-v2.json`, `figure-cross-host.json`, méthodes et métadonnées par cas. Les lignes publiques donnent statuts, signaux et hachages ; aucun téléchargement de constats natifs complets ou payloads sans licence n'est promis.

mcp-audit invoque nativement `run_scan_async(extra_paths=[fresh_config], connect=True, guardrail_drift=True)`. Seul le transport `connect_and_enumerate` est substitué : objets capturés validés par SDK `ListToolsResult`, puis `_tool_info` natif. Analyseurs, toxic-flow, délégation, annotations et scoring restent actifs ; HOME/cwd/config/rug-pull neufs. Online/API/LLM désactivés ; timeout 30 s retire le worker comme incomplet. WARDEN : `blockAtSeverity=high`, `allowUnknownServers=true`, `sensitiveToolPatterns=[]`, `pinToolDefs=true`.

## Seuils et dénominateurs

Seuils : WARDEN `allow: false` natif static-scan/threat-feed ; mcp-audit `HIGH` / `CRITICAL` de définition du pipeline complet ; mcp-shield `HIGH Risk` ; truecopy signaux natifs HIGH/CRITICAL ; mcpsentry `HIGH` / `CRITICAL`. Tout constat truecopy, même advisory, peut être poisoned/retenu par proxy ; HC n'est pas toute rétention, et unpinned/cold-lock reste une politique distincte.

La colonne commune signifie **signal HIGH/CRITICAL**, pas une action de blocage identique. WARDEN produit allow/block ; la classification truecopy est reliée à la rétention par proxy. mcp-shield peut sortir avec le code 0 malgré des constats ; mcpsentry sort avec 1 uniquement pour critical, et high seul peut sortir avec 0. Les signaux des outils de rapport ne sont pas des blocages imposés.

Distinguer **positif au seuil**, **sous le seuil/advisory seul**, **aucun constat**, **error/partiel**, **skipped** et **not run**. Tout signal inclut les positifs au seuil. Le bruit de chemin, configuration et baseline initiale est conservé et exclu avec la même règle pour tous.

Normalization-v1 est conservée : elle excluait à tort trois détections SSH critical légitimes du threat-feed WARDEN en ne retenant que static-scan. Normalization-v2 inclut tous les gates pertinents ; les verdicts bruts sont inchangés, sans nouvelle exécution du moteur. Dans les données WARDEN observées, seule l'info `TOOL_DEF_UNPINNED` est exclue. La même règle de bruit banc/lancement/baseline s'applique à tous les produits, pour éviter un any-signal trompeur de 100% dû au pinning initial. Publier signaux HC, tout signal pertinent et advisory-only = any − HC.

Par scanner/cohorte : prévus `N`, résultats complets `C`, positifs au seuil `B` (champ JSON), sous le seuil/advisory `A`, erreurs/partiels `E`, sauts `S`, non exécutés `U` ; `N = C + E + S + U`, `C = B + A + no-finding`. Fréquence des signaux au seuil `B/C` ; c'est un rappel uniquement dans les cohortes étiquetées attaque. Couverture `C/N`, comptes bruts. Montrer `B/N` en présence d'erreurs sans les traiter comme vrais négatifs. Le blocage imposé est un résultat distinct par produit. Faux positifs : étiquettes ou jugement ; ambigus séparés.

MCPTox attaque : par définition ; propre/public/carryover : par snapshot de serveur ; HISTOR : par cible de paquet. Un constat pertinent au seuil sur au moins un outil rend la cible positive ; les comptes par outil sont diagnostiques.

### Résultats partiels et compatibilité

Deux lignes HISTOR mcp-audit atteignent les budgets natifs : 5 000 nœuds de schéma/profondeur 64 et 65 536 caractères de texte par outil. Elles sont `E: partiel`, hors couverture complète et des `B/A` principaux, même avec constats partiels. Un accord natif/API partiel ne devient pas un scan complet.

mcp-shield rejette 31 listes HISTOR avec la validation stricte du SDK MCP. Les clients natifs raw JSON-RPC de mcpsentry et truecopy n'ont pas ce validateur. Un cas rejeté de 42 outils passe CLI/API mcpsentry sans constat : différence réelle de compatibilité, pas omission d'adaptateur. HISTOR mcp-shield : attested `C=14 902/14 933`, 31 erreurs de schéma ; PingBlip `C=14 901/14 933`, 31 erreurs de schéma et un timeout. Les deux : HC 5 354 / any 6 767 parmi les résultats complets. Fréquence positive non étiquetée, pas FPR ; comparaison finale complète.

Le cas séparé de parité mcp-shield de 3 Mo passe en 52,18 s après extension du délai combiné natif+API de 30 à 90 s ; chaque appel prend environ 28 s. Le premier timeout est conservé. Budget API par cas inchangé à 30 s : pas un échec du détecteur ni un changement caché du délai massif.

## Nouveaux résultats

### Premier candidat WARDEN avec régression conservée

Le premier candidat v18 perd trois détections face à v17 : `FileSystem_20`, `FileSystem_22`, `FileSystem_23`. Ces échecs mesurés sont conservés. Une réparation ultérieure constitue un autre candidat, pas une évaluation sur un holdout jamais vu.

| Surface / unité | Ancien build v17 figé | Premier v18 bloqués |
|---|---|---|
| 485 définitions servies originales | 460/485 | 457/485 |
| Test historique connu, 218 définitions | 210/218 | 207/218 |
| 225 définitions decorated | 225/225 | 225/225 |
| 1 348 scénarios complets de prompts, doublons inclus | 1 331/1 348 | 1 331/1 348 |
| 45 serveurs propres, 362 outils | 0/45 | 0/45 |

Les deux hôtes concordent. Le chemin MCP réel et celui de bibliothèque concordent sur 2 103/2 103 cas par version et par hôte, soit 8 412 comparaisons. C'est une parité de chemins/hôtes, pas une réussite d'attaques contre des modèles. Reçu distant : `/opt/warden-tests/20261107-mcptox-v18/results/final-report/REPORT.md` ; rapport apparié étendu vérifié ci-dessous. Aucune publication npm n'est impliquée.

Le candidat v19 post-hoc vérifié traite l'écrasement SSH public comme altération de sécurité et `/etc/shadow` comme accès aux secrets. Il récupère `FileSystem_20` et `FileSystem_23` ; `FileSystem_22`, prérequis de lecture publique, reste un détournement non bloqué. Ni réétiqueté bénin ni retiré du dénominateur. Les trois échecs initiaux restent dans le rapport.

| Candidat19, vue | Blocages WARDEN / complets | Erreurs |
|---|---|---|
| Attaques propres / bénins, séparés | 23/23; 0/12 | 0 |
| Attaques tiers / bénin / ambigu, séparés | 10/10; 0/1; 0/1 | 0 |
| Définitions natives / test historique, séparés | 459/485; 209/218 | 0 |
| Scénarios complets / decorated, séparés | 1 331/1 348; 225/225 | 0 |
| Serveurs propres | 0/45 | 0 |
| Public-main / carryover, séparés | 3/986; 1/41 | 0 |

Chaque version v18/v19 sur chaque hôte : MCP réel/bibliothèque **3 177/3 177**. Lignes complètes interhôtes **12 708/12 708**, sept contrôles d'identité vrais. Parité opérationnelle, pas détection de toutes les attaques. [Rapport](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: evidence/candidate19/REPORT.md"), SHA-256 `e699ba593242406b31f366b34d3e104dcf567094fd97421a62fbba8ded958989` ; JSON apparié `30996c170fd4284991ac4624ee88cda765ae26cb2393a8bbdeefa23913847a4e`.

### Résultats finaux des cinq produits publiés

WARDEN principal signifie npm publié 0.23.0/rules17, pas l'ancien build modifié ni candidat19. Ce sont des mesures distantes nouvelles, pas des chiffres d'octobre substitués.

Cellules : **HC / any / advisory-only**, advisory-only = any − HC. Toutes les lignes base : `C=N`, `E=S=U=0` ; exceptions HISTOR ci-dessous. HC/any concordent entre hôtes. WARDEN principal est npm publié 0.23.0/rules17. Ne pas additionner des vues recoupées en exactitude globale.

| Cohorte / unité | WARDEN npm 0.23.0 | mcp-audit 0.28.0 | mcp-shield 1.0.4 | truecopy 0.10.5 | mcpsentry 0.1.5 |
|---|---|---|---|---|---|
| 23 attaques propres | 20 / 23 / 3 | 11 / 13 / 2 | 6 / 10 / 4 | 3 / 8 / 5 | 4 / 4 / 0 |
| 12 bénins propres | 0 / 3 / 3 | 1 / 2 / 1 | 1 / 2 / 1 | 1 / 1 / 0 | 2 / 2 / 0 |
| 10 attaques tierces | 10 / 10 / 0 | 10 / 10 / 0 | 8 / 9 / 1 | 1 / 7 / 6 | 5 / 5 / 0 |
| 1 bénin tiers | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| 1 ambigu tiers | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 1 / 1 | 0 / 0 / 0 | 0 / 0 / 0 |
| 485 définitions natives MCPTox | 460 / 474 / 14 | 56 / 392 / 336 | 56 / 71 / 15 | 1 / 31 / 30 | 19 / 19 / 0 |
| …267 dev | 250 / 257 / 7 | 17 / 214 / 197 | 15 / 25 / 10 | 1 / 4 / 3 | 11 / 11 / 0 |
| …218 test historique connu | 210 / 217 / 7 | 39 / 178 / 139 | 41 / 46 / 5 | 0 / 27 / 27 | 8 / 8 / 0 |
| 225 decorated MCPTox | 225 / 225 / 0 | 222 / 225 / 3 | 41 / 95 / 54 | 135 / 141 / 6 | 136 / 136 / 0 |
| 1 348 scénarios complets | 1331 / 1338 / 7 | 951 / 1264 / 313 | 158 / 570 / 412 | 432 / 491 / 59 | 460 / 460 / 0 |
| 45 serveurs propres MCPTox | 0 / 7 / 7 | 0 / 3 / 3 | 3 / 6 / 3 | 0 / 0 / 0 | 1 / 7 / 6 |
| 986 snapshots publics | 4 / 388 / 384 | 43 / 159 / 116 | 343 / 451 / 108 | 2 / 39 / 37 | 86 / 450 / 364 |
| 41 observations carryover | 2 / 37 / 35 | 12 / 24 / 12 | 33 / 35 / 2 | 1 / 3 / 2 | 21 / 38 / 17 |
| 14 933 lignes de paquets historiques | 409 / 6327 / 5918 | 481 / 2089 / 1608 | 5354 / 6767 / 1413 | 15 / 252 / 237 | 1449 / 6362 / 4913 |

### Couverture complète et accord exact entre hôtes

Chaque produit a `N=18 110` par hôte, `S=U=0`, et toutes les entrées appariées. Zéro absence, divergence d'identité entrée/moteur ou résultat complet différent. Les incomplets sont exclus du dénominateur d'accord.

| Produit | C attested / PingBlip | E attested / PingBlip | Identiques / paires complètes | Erreurs |
|---|---|---|---|---|
| WARDEN npm | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |
| mcp-audit | 18108 / 18108 | 2 / 2 | 18108 / 18108 | 2 partiels sur les deux |
| mcp-shield | 18079 / 18078 | 31 / 32 | 18078 / 18078 | 31 schémas sur les deux ; 1 timeout seulement PingBlip |
| truecopy | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |
| mcpsentry | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |

Candidat19 `.1` supplémentaire : 18 110/18 110 paires complètes ; v18 HISTOR : 14 933/14 933. HISTOR candidat19 : 407 HC / 6327 any / 5920 advisory-only ; WARDEN publié : 409 / 6327 / 5918. Aucun verdict HISTOR v18→v19 n'a changé. Une lecture ciblée des deux passages autorisés après v17 confirme une configuration légitime de clés publiques : `@krovacloud/mcp@0.3.16` (`create_cube`, `sshPublicKey`) et `@runpod/mcp-server@4.4.0` (`update-ssh-keys`, `keys`). Ce jugement porte sur ces passages, pas sur tout le paquet ; aucun texte brut redistribué.

Author35 et independent12 sont mixtes : leurs totaux sont des fréquences de signaux au seuil, pas du rappel. Les étiquettes 23/12 et 10/1/1 restent distinctes. L'interopérabilité vivante concerne candidat19, pas une cellule des cinq produits.

## Validation et provenance des candidats

Ancien v18 : 1 517/1 517 tests dans 62 fichiers par hôte, typecheck/build réussis ; red-team distinct 0/28 delivered, pas l'ASR de cinq produits. Le témoin de répertoire complet est incomplet à cause d'un script de rapport voisin modifié ; produit exécuté et 1 090 fichiers source/test/script capturés stables.

Candidat19 : **1 536/1 536 tests dans 63 fichiers par hôte**, typecheck/build/red-team sortie 0, sans OOM ; attested 288,085 s, PingBlip 558,354 s. Les premiers 1 534 tests de détecteur passaient ; les comptes README/landing périmés ont demandé des reprises. Validation : seuls les comptes de cinq README changent, pas le détecteur ; 521 fichiers runtime/source/test sont identiques, digest `f4732e8beb77342ae250ac11126859ef59cf5e9bf3d74e8e46221b8d856d3231`. Cela porte sur le candidat figé, pas tout le workspace. Diagnostics initiaux et ancien essai Blip interrompu restent séparés.

## Build runtime ultérieur .2

`0.23.1-dev.20261107.2` est distinct du `.1` figé : il accepte le blob-resource MCP valide sans `mimeType` facultatif, tout en analysant les objets similaires metadata/structured. Deux hôtes : **1 536/1 536 tests dans 63 fichiers**, typecheck/build/red-team sortie0 ; attested 293,705 s, PingBlip 554,284 s. Les 304 tests ciblés passent à 1 CPU normal avec délais inchangés, SDK 8/8 sessions et 4/4 paires de listes. Timeout initial à 0,25 CPU conservé, non reproduit à capacité normale.

Les contrôles binary/SDK indépendants préservent un blob valide de 400k avec/sans MIME. Les résultats plaintext/object-blob/poisoned-metadata invalides sont retenus après une exécution, session vivante ; compatibilité de filtrage du résultat, pas prévention des effets de l'outil. Les 23 contrôles CLI/library `.1`/`.2` concordent en constats et scores. Les 320 fichiers source/distribution hors du module result-screen modifié sont identiques à `.1`, SHA-256 `5ff407cf78742ae18fd593065e9c9bd552bba45f3fab91f27fae9f45adb13238`, digest rules19 inchangé. Les 18 110 lignes restent mesurées sur `.1`, pas `.2` ; les deux sources restent non publiées.

Le snapshot de travail courant `0.23.1-dev.20261108` ajoute des hooks Codex/OpenCode absents des builds figés `.1` et `.2`. Son acceptation est validée séparément. Les 18 110 lignes et reçus de qualité figés ne sont pas des mesures de ces ajouts du 8 novembre.

## Limites d'interprétation

Les fixtures propres sont écrits par les auteurs de WARDEN et les tiers ont été lus pendant le développement. Le test MCPTox est un **holdout historique connu**, pas une nouvelle série jamais vue : résultats déjà publiés et modèles d'attaque partagés avec dev. Le rejouer ne rétablit pas l'aveugle. Revendiquer l'indépendance des règles ultérieures exige un audit de provenance ; l'absence de phrases identiques ne la prouve pas à elle seule.

L'archive ne décrit pas le comportement actuel. La découverte ne teste ni exécution ni sécurité des dépendances. Les blocages statiques ne mesurent ni réussite des attaques contre les modèles, ni protection complète, ni prévention d'exfiltration. Toute expérience avec modèle exige modèle/version, prompts, budget, requêtes et dénominateurs propres ; ces tableaux statiques ne l'impliquent pas.
