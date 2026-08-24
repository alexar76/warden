# Ce que WARDEN a trouvé dans 1 108 serveurs MCP publics — et ce qu'il a mal jugé

> 🌐 [English](mcp-survey.md) · [Русский](mcp-survey.ru.md) · [Español](mcp-survey.es.md) · **Français** · [中文](mcp-survey.zh.md)

Le 2026-08-24, quelques heures après la publication de `@aimarket/warden` 0.3.0, nous l'avons pointé
vers tous les serveurs MCP publics que nous pouvions légitimement atteindre : 2 787 serveurs listés
dans le registre officiel avec un endpoint réseau, dont 1 108 ont répondu à un vrai `tools/list` et
nous ont livré 17 491 définitions d'outil.

L'essentiel ne concerne pas l'écosystème. Il nous concerne. WARDEN a bloqué 50 de ces 1 108 serveurs,
et dans **4** cas sur 50 nous avons pu étayer une véritable préoccupation. Les 46 autres sont notre
scanner qui se trompe, de six façons que nous pouvons nommer, reproduire et corriger.

Nous publions les échecs avec les preuves, parce que le profil de faux positifs d'un scanner est le
seul chiffre qui décide si quelqu'un l'activera. Un scanner d'empoisonnement d'outils qui refuse des
serveurs honnêtes n'est pas un scanner prudent ; c'est un scanner qu'on désinstalle, et le ruleset v1
nous l'a déjà appris une fois.

## Ce qui a été mesuré

| | |
|---|---|
| Paquet testé | `@aimarket/warden@0.3.0`, installé depuis le registre npm dans un projet vide — pas l'arbre de travail |
| Ruleset en vigueur | v2, `sha256-gWC14PR4kUylkJaAGMnIYYX6tPhZTJ60cSB61UZxuWc=` (voir [le défaut de release](#le-défaut-de-release) plus bas) |
| Corpus | `registry.modelcontextprotocol.io`, 8 000 lignes → 3 121 serveurs uniques → 2 787 avec endpoint distant |
| Acquisition | MCP `initialize` + `tools/list` en streamable-http, une tentative par serveur, timeout 20 s |
| Gates exécutés | `static-scan` et `threat-feed` (liste de blocage intégrée, sans flux distant) |
| Gates non exécutés | `origin` et `pinning` — tous deux décident sur l'*état de l'hôte* (l'opérateur a-t-il déclaré ce serveur, ses définitions ont-elles dérivé depuis l'approbation) ; aucun n'est une propriété du serveur, et dans une étude tous deux renverraient la même réponse pour les 1 108 |
| Politique | `blockAtSeverity: "high"`, `allowUnknownServers: true`, `pinToolDefs: false` |

**Aucun code tiers n'a été exécuté.** Chaque définition d'outil provient de la réponse du serveur
lui-même sur le réseau. C'est pourquoi le corpus est fait de serveurs distants et non des serveurs
stdio des diverses listes « awesome » : les atteindre voudrait dire télécharger et exécuter le code
d'un inconnu, ce qu'une étude de sécurité ne peut pas se permettre à la légère.

### L'accessibilité — un résultat en soi

Seuls 41 % des endpoints distants annoncés par le registre ont abouti à un handshake :

| Résultat | Serveurs |
|---|---|
| ont répondu `tools/list` | 1 149 (41,2 %) |
| refus en 4xx (authentification requise, ou disparu) | 1 215 |
| échec de connexion / TLS | 298 |
| transport `sse`, non tenté | 37 |
| 5xx | 34 |
| désaccord de protocole (pas de résultat `initialize` exploitable) | 21 |
| redirection / 410 / 429 | 32 |

Sur les 1 149 qui ont répondu, 1 108 annonçaient au moins un outil. Qui construit un client sur ce
registre devrait dimensionner ses reprises et sa gestion d'authentification pour un **taux d'échec de
59 % au premier contact**.

## Résultats

| | Serveurs | Constats |
|---|---|---|
| scannés | 1 108 | 3 964 |
| propres | 664 | — |
| constats mais autorisés | 394 | 3 472 advisory |
| **bloqués** | **50** | **492 bloquants** |

Constats bloquants par règle. Un serveur peut déclencher plusieurs règles, la colonne des serveurs ne
totalise donc pas 50 :

| Code | Constats | Serveurs | Après examen |
|---|---|---|---|
| `TOOL_DEF_SECRET_REQUEST` | 401 | 13 | 4 étayés, 9 aveugles à la polarité |
| `TOOL_DEF_DATA_URL` | 31 | 11 | tous faux — `JavaScript:` et exemples d'API d'images |
| `TOOL_DEF_INJECTION` | 21 | 13 | tous faux — `system prompt` comme vocabulaire du domaine, consignes d'honnêteté |
| `TOOL_DEF_SECRET_HARVEST` | 14 | 10 | tous faux — collocation verbe+nom, fenêtre de 30 caractères |
| `THREAT_CRYPTO_DRAINER` | 9 | 4 | tous faux — jokers sur sous-chaînes |
| `TOOL_DEF_HIDDEN_UNICODE` | 5 | 1 | tous faux — ZWNJ persan |
| `TOOL_DEF_BASE64_BLOB` | 3 | 2 | tous faux — pointeurs `$ref` de JSON Schema |
| `THREAT_SEED_PHRASE` | 3 | 2 | tous faux — jokers sur sous-chaînes |
| `TOOL_DEF_EXFIL` | 3 | 3 | tous faux — outils de sécurité nommant l'attaque |
| `THREAT_SSH_KEY_READ` | 2 | 1 | tous faux — invocation `ssh -i` documentée |

Compté par serveur et non par constat, car une ligne de gabarit répétée dans 377 outils est un
défaut, pas 377. Les quatre cas étayés relèvent des deux règles sur les identifiants.

## Ce qui a tenu

Quatre serveurs annoncent des outils par lesquels du matériel secret transite réellement dans le
contexte du modèle. Nous les décrivons sans les nommer : ils ne se comportent pas mal, ils font un
travail légitime d'une manière qu'un hôte d'agents devrait effectivement contrôler, et une étude n'est
pas un canal de divulgation.

- Un serveur de trésorerie pour marché de prédiction dont l'outil prend `signer_private_key`, décrit
  comme *« signer EOA private key, 0x… »*. Une clé de signature de portefeuille, demandée en
  paramètre d'API. Exactement le cas pour lequel WARDEN existe.
- Un serveur de paiements entre agents qui provisionne un portefeuille sandbox et *« return[s] its
  private key exactly once »* par le canal de l'outil.
- Un serveur d'identité d'agents dont la prose demande au modèle de lire un `credentials.json` local
  et d'écrire des `private_key` en JWK sur le disque avec `chmod 0600`.
- Un serveur de base de données managée avec un paramètre `pvkPassword` — *« Password that encrypts
  the private key »*. Un paramètre documenté d'une grande API cloud, et malgré tout un identifiant
  dans un schéma d'outil.

Soit 4 sur 50 bloqués, ou 4 sur 1 108 scannés. Tout ce qui suit concerne les 46 autres.

## Ce qui n'a pas tenu

### 1. Aveuglement à la polarité — le plus gros défaut

`TOOL_DEF_SECRET_REQUEST` cherche le groupe nominal `private key`. Il ne lit pas la phrase autour.
Tout ce qui suit a donc été bloqué en `critical`, qui est fatal — le serveur entier, tous ses outils :

> Never send a private key: none is needed and the request is refused if one is present.
> — un générateur d'enregistrements DANE/TLSA

> Use this to import your own public key so you can SSH into instances. **The private key never
> leaves your machine.**
> — un gestionnaire d'instances cloud

> YOU sign and broadcast the returned transaction yourself, with your own wallet's private key, on
> your own infrastructure — **Otto never sees or holds your key**.
> — un serveur de cotation de swap

> …does NOT confirm the certificate matches any private key.
> — un inspecteur de certificats

> Use exact field names from this schema; **do not guess aliases or include private key material.**
> — un serveur SAP, dans le gabarit de schéma de **ses 377 outils**

Ce dernier résume tout le problème en une ligne : un serveur qui dit au modèle de *ne pas* envoyer de
clés privées est noté comme celui qui en demande, et comme la règle est `critical` donc fatale, une
seule occurrence nominale dans un gabarit partagé a ramené un serveur de 377 outils à 0,00. 390 de nos
492 constats bloquants tiennent à ce seul nom.

`TOOL_DEF_SECRET_HARVEST` — un verbe parmi `read|extract|retrieve|fetch|obtain|dump|reveal|collect|…`
à moins de 30 caractères d'un nom d'identifiant — échoue de la même façon :

> Anyone holding the URL can read it, so **never store secrets**, credentials or personal data
> — un serveur de stockage temporaire

> Public read-only: **never collect card data, secrets or email**
> — un serveur de réservation

> it does **not** reveal or mint a standalone agent credential
> — un serveur d'enregistrement d'agents

Trois serveurs bloqués pour avoir promis, par écrit, de ne pas faire ce que la règle cherche.

### 2. Aveuglement au rôle — les scanners se font bloquer

Une définition d'outil qui *décrit* une attaque est notée comme si elle en *commettait* une. Cinq
serveurs, tous des outils défensifs :

> …for prompt-injection and social-engineering (`'ignore previous instructions'`, `'send funds to'`,
> `'approve this'`, `'admin override'`, `'claim your airdrop'`…)
> — un vérificateur d'instructions, bloqué sur `ignore previous`

> hidden directives that hijack agents — instruction overrides, `'don't tell the user'`, data
> exfiltration, secret harvesting, tool-shadowing, and invisible-unicode / homoglyph steganography
> — un scanner d'endpoints MCP, bloqué sur `exfiltration`

> `"enum": ["exfiltration", "recon_then_destroy", "injection_then_action"]`
> — un constructeur de politiques, bloqué sur les valeurs de son propre enum

> Detect likely leaked API keys, tokens, private-key headers, JWTs…
> — un scanner de secrets, bloqué sur `private-key`

Un attaquant écrit un outil empoisonné sans nommer l'attaque. Un défenseur la nomme à chaque phrase.
Nos règles sélectionnent le défenseur.

### 3. « do not tell the user » est une consigne d'honnêteté

La règle `TOOL_DEF_INJECTION` traite `do not tell the user` comme de la dissimulation. Dans tous les
cas réels trouvés — quatre serveurs, quatre sur quatre — c'est l'inverse : le serveur empêche le
modèle de dire à l'utilisateur quelque chose de *faux*.

> some convert in real time during the session, others batch once or twice daily, so **do NOT tell
> the user** a payment is "held until the next session"

> AFTER payment succeeds, no refund is issued automatically — the result says so explicitly; **do
> not tell the user** a refund is coming

> a `facturx-en16931` result is the payload and not a Factur-X document — **do not tell the user
> otherwise**

> **Do not tell the user** to drag assets into chat

La prémisse de la règle est inversée sur des données réelles. Les auteurs consciencieux emploient
cette formule pour supprimer des réassurances hallucinées — précisément le comportement que veut un
hôte d'agents.

### 4. Collisions de vocabulaire

- **`system prompt`** → `TOOL_DEF_INJECTION`, 15 constats sur 6 serveurs. Tous sont des proxys de
  LLM, des gestionnaires de personas ou des outils de configuration d'agents dont la fonction même
  est de fixer un system prompt, et qui déclarent un paramètre `system` dans leur schéma. Le mot est
  le domaine, pas l'attaque.
- **`\bjavascript:`** avec le drapeau `i` → `TOOL_DEF_DATA_URL`, high. Il correspond au mot
  *JavaScript* suivi d'un deux-points, c'est-à-dire à toute liste de langages qui existe :
  *« TypeScript/JavaScript: `*.spec/test.{ts,js}` »*, *« plain async JavaScript: … »*,
  *« javascript: Enable JavaScript execution »*. Il se déclenche aussi sur des serveurs qui annoncent
  supprimer le schéma : *« the sanitizer strips … `javascript:` and `data:text/html` URIs »*.
- **`data:…;base64,`** → la même règle, sur des API d'images dont l'exemple de schéma est
  littéralement `"<url> OR data:image/png;base64,..."`, et sur un scraper qui déclare *filtrer* les
  schémas `data:`.
- **la fenêtre de 30 caractères** de `SECRET_HARVEST` franchit les frontières de phrase et de JSON :
  `read an open or sealed run (pass api_key` est une correspondance qui va de la prose au nom d'un
  paramètre.

### 5. Aveuglement à l'encodage — WARDEN signale un système d'écriture

`TOOL_DEF_HIDDEN_UNICODE` signale « zero-width or bidi control characters hiding text from review ».
Un serveur l'a déclenché cinq fois. C'est un serveur iranien de calculs juridiques, et le caractère
est **U+200C ZERO WIDTH NON-JOINER**, un caractère orthographique *obligatoire* en persan :

- `بخشنامه‌ها` (circulaires)
- `سهم‌الارث` (part héréditaire)
- `حق‌الثبت` (droit d'enregistrement)
- `حق‌التحریر` (émolument notarial)

Rien n'est caché. C'est ainsi que la langue s'écrit. En l'état, la règle pénalise les serveurs en
persan, en arabe et en écritures indiennes pour leur orthographe — un contrôle de sécurité qui se lit
comme une politique linguistique, ce qui est pire qu'un faux positif.

`TOOL_DEF_BASE64_BLOB` a le défaut miroir : `/` fait partie de l'alphabet base64, donc un pointeur
JSON Schema profondément imbriqué — `#/properties/flow/items/anyOf/2/properties/outcomes/items` — est
rapporté comme « a long base64-encoded blob — possible hidden payload ».

### 6. Les jokers du threat-feed correspondent à des sous-chaînes

La liste de blocage intégrée applique des jokers `*a*b*` à la définition d'outil concaténée, sans
frontières de mot ni contrainte de proximité :

- `*sweep*funds*` a correspondu à un outil de rachat de plancher ENS : *« Floor-sweep: buy the
  CHEAPEST N listed ENS names »* … *« and **refunds** the excess »*. Le motif a trouvé `funds` à
  l'intérieur de **refunds**.
- `*drain*wallet*` a correspondu à un scanner anti-drainer : *« Find risky allowances that could
  **drain** your tokens »* … *« a **wallet** granted »*. L'outil existe pour arrêter les drainers.
- `*seed*phrase*` a correspondu à un outil de mots-clés YouTube : *« For a **seed** topic, returns
  suggested search **phrases** »*.

Les trois sont rapportés en `critical` avec le message *« Crypto-drainer keyword in server identity »*
— qui se trompe en outre sur l'*endroit* de la correspondance : c'était la définition de l'outil, pas
l'identité du serveur.

## Ce qui a fonctionné exactement comme prévu

La seule partie du ruleset qui sort intacte du contact, c'est la **hiérarchisation**. Les constats
`advisory` se sont déclenchés 3 472 fois — `TOOL_DEF_CREDENTIAL_PARAM` 2 016, `TOOL_DEF_IMPERATIVE`
1 437, `TOOL_DEF_ENV_REFERENCE` 19 — sans rien bloquer, sans coûter de score et sans mettre un seul
outil en quarantaine. Sous le ruleset v1, où `api_key` dans un schéma bloquait, ces 2 016 occurrences
auraient refusé une large part de l'écosystème honnête. La leçon v1→v2 tient sur des données réelles ;
le travail restant est dans les règles du niveau bloquant.

## Le défaut de release

Le paquet avec lequel nous avons scanné annonce le ruleset **v2**, digest `sha256-gWC14PR4…`. Le
README **contenu dans la même archive** documente le ruleset **v3** et imprime le digest
`sha256-pah/sT4I…`. Les deux énoncés sont vrais, à propos de codes différents :

| | |
|---|---|
| `0.3.0` publié sur npm | 2026-08-24 08:34:08 UTC |
| commit d'extraction du paquet | 2026-08-24 08:35:12 UTC — 64 secondes plus tard |
| commit introduisant le ruleset v3 | 2026-08-24 09:26:50 UTC — 52 minutes après la publication |

L'artefact qu'installe un inconnu n'a donc aucune règle sur la surface `name`, là où v3 en porte 17
sur 24 ; un caractère de largeur nulle ou un blob base64 dans le *nom* d'un outil lui est invisible.

Nous avons ensuite mesuré ce que cela coûte. Nous avons rejoué le corpus identique contre une build v3
et comparé par serveur, par outil et par code :

**Aucune différence.** 444 serveurs avec constats, 50 bloqués, 3 964 constats — identique sous les
deux rulesets. Aucun des 1 108 serveurs réels ne met dans un nom d'outil quoi que ce soit que v3
attrape et que v2 laisse passer. La publication périmée est un vrai défaut de processus — le garde-fou CI est le point 9 ci-dessous —
et sur ce corpus, son impact comportemental est nul, et nous préférons le dire
plutôt que de laisser entendre une gravité que nous n'avons pas mesurée.

## Ce qui change en conséquence

Classé par le nombre des 46 que chaque point corrige :

1. **Polarité.** Un nom d'identifiant précédé d'un marqueur de refus (`never`, `not`, `no`,
   `does not`, `without`, `refused`) dans la même proposition n'est pas une demande. En attendant,
   les correspondances purement nominales ne doivent pas être `critical`, car `critical` est fatal et
   un nom dans un gabarit partagé ne devrait jamais abattre 377 outils.
2. **Texte cité et énuméré.** Une expression dans un littéral de chaîne, un `enum` JSON ou une
   taxonomie séparée par des virgules est une *mention*. Les mentions ne bloquent pas.
3. **`do not tell the user`** → rétrograder en `advisory` en attendant une règle exigeant un objet de
   dissimulation (l'outil, le transfert, le fichier) et non la formule seule.
4. **`\bjavascript:`** → la rendre sensible à la casse et exiger un contexte d'URI ; `JavaScript:`
   comme étiquette n'est pas un schéma.
5. **U+200C / U+200D** → exemptés lorsqu'ils sont adjacents à une écriture arabe, persane ou indienne.
   Continuer de signaler U+200B, U+FEFF et les overrides bidi.
6. **Détection base64** → exclure les pointeurs JSON et les chemins ; exiger un remplissage ou un
   seuil d'entropie, pas seulement l'alphabet.
7. **Jokers du threat-feed** → sémantique de frontière de mot et borne de proximité, pour que
   `*sweep*funds*` ne puisse pas correspondre à `refunds`.
8. **Messages de constat** → porter l'extrait correspondant assaini. Les nôtres tronquent le motif en
   `signature (\b(?:read|extract|…)`, si bien qu'un relecteur ne peut pas savoir quelle alternative
   s'est déclenchée sans la source. Dans cette étude même, cela nous a coûté des heures.
9. **Digest du ruleset en CI** → une release doit échouer si le `dist` publié annonce une version de
   ruleset différente de celle de la source dont il est issu.

## Limites

- **Un seul transport.** streamable-http uniquement ; 37 serveurs `sse` ont été ignorés, et tous les
  serveurs stdio de l'écosystème sont hors périmètre du fait de la règle de non-exécution. Or les
  serveurs stdio sont l'essentiel de ce que les gens exécutent réellement en local.
- **Un seul instant.** Un `tools/list` par serveur, le 2026-08-24. Les définitions changent, et un
  serveur honnête au moment de la requête peut modifier une description ensuite — c'est à cela que
  sert le gate `pinning`, et c'est précisément ce que cette étude ne pouvait pas exercer.
- **« Faux positif » est notre jugement.** Nous avons lu la définition et estimé que le signalement
  était erroné. Nous n'avons pas audité les serveurs, et un faux positif sur la *définition* ne
  certifie pas l'*implémentation* : un outil à la prose irréprochable peut encore exfiltrer à
  l'invocation. L'analyse statique des définitions ne le voit pas, par construction.
- **Pas de vérité de référence.** Rien n'est étiqueté dans ce corpus. Nous pouvons rapporter que 46
  blocages sur 50 étaient erronés ; nous ne pouvons pas rapporter combien de serveurs empoisonnés
  nous avons dépassés sans les voir. Les faux négatifs sont invisibles à cette méthode, et une
  précision de 4/50 ne dit rien du rappel.
- **Les serveurs authentifiés sont absents.** 1 215 serveurs ont refusé sans identifiants. Ce sont
  disproportionnellement les serveurs commerciaux, le corpus penche donc vers les serveurs ouverts et
  amateurs.

## Reproduire

Rien ici ne requiert notre infrastructure ni une clé. Les scripts sont dans
[`scripts/mcp-survey/`](../scripts/mcp-survey/) et l'agrégat dans
[`data/mcp-survey-2026-08-24.json`](data/mcp-survey-2026-08-24.json).

```bash
cd scripts/mcp-survey
python3 harvest_registry.py          # registre -> registry_remotes.json
python3 harvest_tools.py             # tools/list en direct -> tools_raw.jsonl
npm install @aimarket/warden@0.3.0
node scan.mjs tools_raw.jsonl scan.json
python3 classify.py                  # extrait exact pour chaque constat bloquant
```

`harvest_tools.py` fait deux ou trois requêtes par serveur et n'exécute rien. Si vous le relancez, vos
chiffres d'accessibilité différeront des nôtres — les endpoints apparaissent et disparaissent d'heure
en heure.

## Point de départ

Pour mémoire, afin que la prochaine lecture de ces chiffres ait un sens. Le 2026-08-24, jour de cette
étude et jour de publication de 0.3.0 :

| | |
|---|---|
| version npm | 0.3.0, publiée à 08:34 UTC |
| téléchargements npm de 0.3.0 | aucun enregistré — les compteurs du registre s'arrêtent au 2026-08-23, aucune donnée n'existe encore |
| téléchargements npm, semaine précédente | 1, celui du jalon de nom `0.0.1` |
| étoiles GitHub | 0 |

Quels que soient ces nombres à la prochaine mise à jour de cette page, voilà d'où ils partent.
