# La chaîne de portes

> 🌐 [English](gates.md) · [Русский](gates.ru.md) · [Español](gates.es.md) · **Français** · [中文](gates.zh.md)

`Warden.vet(server, tools)` exécute une chaîne ordonnée et renvoie un seul verdict. Cette page est
toute la procédure de décision : ce que regarde chaque porte, ce qu'elle peut bloquer, et comment le
nombre final se construit.

```
static-scan  →  threat-feed  →  origin  →  pinning
 (gratuit)       (gratuit après  (gratuit)  (gratuit)
                  load)
```

L'ordre va du moins coûteux et du plus local d'abord. Rien dans la chaîne n'effectue de requête réseau :
le seul téléchargement que WARDEN émette jamais est `ThreatFeed.load(url)`, que vous appelez vous-même,
avant tout examen.

## Comment un verdict est assemblé

Chaque porte renvoie `{ findings, score, fatal? }`. La chaîne :

1. exécute toutes les portes dans l'ordre, en accumulant les constats (chaque porte voit `prior`) ;
2. multiplie les scores des portes — le composite est un **produit**, donc une porte mauvaise tire tout
   le serveur vers le bas au lieu d'être moyennée par trois bonnes ;
3. bloque si une porte a renvoyé `fatal`, ou si un constat non advisory atteint
   `policy.blockAtSeverity` ;
4. n'interrompt la chaîne **que** sur un `fatal` explicite. Un constat bloquant mais non fatal laisse
   les portes restantes rapporter, pour que la trace du *pourquoi* reste complète.

```ts
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
```

Si `policy.blockAtSeverity` n'est pas l'une de ces cinq clés, le constructeur journalise un
avertissement et retombe sur `"high"`. Une coquille à cet endroit était auparavant la pire défaillance
possible : `rank >= undefined` est `false` pour toute comparaison, donc un seuil mal orthographié
désactivait silencieusement tout blocage.

### Deux axes : sévérité et palier

La sévérité répond à *quelle attention cela mérite-t-il*. Le **palier** (tier) répond à *est-ce un
défaut ?* — et c'est une donnée portée par le constat (`advisory: true`), non une conséquence de la
sévérité.

Un constat `advisory` est rapporté, ne bloque jamais et ne coûte jamais un outil, avec **n'importe
quel** `blockAtSeverity`. Un outil dont le schéma accepte une `api_key` mérite qu'on le signale et n'est
pas un défaut ; l'exprimer en abaissant sa sévérité le rendait de nouveau bloquant pour quiconque
durcissait le seuil.

## static-scan

Analyse locale par expressions régulières du `name`, de la `description` et de l'`inputSchema` de
chaque outil. 25 règles dans le jeu **v3** : 18 `block`, 7 `advise`.

Chaque règle déclare sur laquelle de ces trois **surfaces** elle s'exécute, et 17 des 25 incluent le
nom. Les trois qui ne l'incluent pas sont celles qui reposent sur un NOM COMMUN
(`TOOL_DEF_SECRET_REQUEST`, `TOOL_DEF_CREDENTIAL_PARAM`, `TOOL_DEF_ENV_REFERENCE`) : un nom d'outil
est un identifiant, `api_key` et `private_key` en sont des morceaux ordinaires, et refuser
`sign_with_private_key` reviendrait à commettre l'erreur de calibrage de v1 sur une nouvelle
surface. Les règles reposant sur une PHRASE exigent des espaces et ne peuvent donc pas correspondre
à du `snake_case`, et les deux règles de charge cachée portent sur des caractères qui ne sont jamais
légitimes dans un nom : celles-là s'exécutent partout.

Jusqu'à v3, le nom n'était analysé par **rien** : une phrase d'injection, un caractère de largeur
nulle ou un blob base64 dans le premier champ que lit le modèle n'était pas rapporté du tout.

Le score de la porte est `1 − pénalité(pire sévérité bloquante)` ; les constats indicatifs ne
l'affectent jamais.

| pire sévérité bloquante | aucune | info | low | medium | high | critical |
|---|---|---|---|---|---|---|
| score de la porte | 1 | 1 | 0.9 | 0.7 | 0.4 | 0 |

| Code | Sévérité | Palier | Nom ? | Ce qu'il attrape |
|---|---|---|---|---|
| `TOOL_DEF_INJECTION` | critical / high | block | ✅ | « ignore all previous instructions », « do not tell the user », balises `<system>`, références au prompt développeur |
| `TOOL_DEF_SECRET_REQUEST` | critical | block | — | `private_key`, `seed_phrase`/`mnemonic`, chemins `~/.ssh` |
| `TOOL_DEF_SECRET_HARVEST` | critical | block | ✅ | un outil dont la mission déclarée est de lire/extraire/révéler des secrets |
| `TOOL_DEF_EXFIL` | critical / high | block | ✅ | « post to https://… », « forward it to… », « exfiltrate », formulations d'upload vers un hôte |
| `TOOL_DEF_HIDDEN_UNICODE` | high | block | ✅ | caractères de largeur nulle et de contrôle bidi — du texte que le relecteur ne voit pas |
| `TOOL_DEF_BASE64_BLOB` | high | block | ✅ | une suite base64 de 120+ caractères dans un nom, une description ou un schéma |
| `TOOL_DEF_DATA_URL` | high | block | ✅ | URLs `data:…;base64,` et `javascript:` |
| `TOOL_DEF_CREDENTIAL_PARAM` | medium / low | advise | — | schéma ou description réclamant `api_key`, `password`, `secret`, jetons bearer |
| `TOOL_DEF_ENV_REFERENCE` | medium | advise | — | `.env`, « environment variables » |
| `TOOL_DEF_IMPERATIVE` | low / info | advise | ✅ | « you must », « instead of » — formulation en forme de prompt, qui à elle seule ne prouve rien |

`staticScanRuleset()` renvoie chaque règle avec **la source de sa regex, ses drapeaux et ses surfaces**, pour qu'un
tiers puisse rejouer exactement la même règle, plus `{ version, digest }`, où l'empreinte est un sha256
sur la forme canonique RFC 8785 de la liste triée des règles. Le tri se fait par comparaison d'unités
de code, jamais `localeCompare` : une collation dépendante de la locale ferait que la même table
produise une empreinte différente sur un hôte configuré autrement — précisément la divergence que
l'empreinte existe pour détecter.

## threat-feed

Confronte l'identité du serveur et les définitions d'outils à des `ThreatRecord` — 11 intégrés plus ce
qu'un feed signé a ajouté (voir [le contrat du feed](threat-feed.fr.md)).

- Toute correspondance ⇒ score de la porte **0**.
- `fatal` **uniquement** pour un enregistrement `critical` correspondant au *serveur*. Une
  correspondance critique sur un *outil* n'est pas fatale : le reste de la chaîne continue de
  rapporter et la faute reste circonscrite à cet outil — c'est ce qui permet à un serveur globalement
  correct de rester utilisable avec un outil en quarantaine.
- `ThreatRecord.scope` choisit la surface : `server` (id/name/url/command/args), `tool`
  (name/description/inputSchema) ou `any` — la valeur par défaut quand l'enregistrement l'omet.

Codes intégrés : `THREAT_TYPOSQUAT`, `THREAT_CRYPTO_DRAINER`, `THREAT_SEED_PHRASE`,
`THREAT_SSH_KEY_READ`, `THREAT_ENV_EXFIL`, `THREAT_DESTRUCTIVE_CMD`, `THREAT_FORK_BOMB`.

## origin

L'opérateur a-t-il déclaré ce serveur, ou provient-il d'un catalogue distant (`McpServerRef.catalog`
est renseigné) ?

| `allowUnknownServers` | constat | score | fatal |
|---|---|---|---|
| `false` (fail-closed) | `SERVER_UNDECLARED`, high | 0 | oui |
| `true` | `SERVER_UNDECLARED`, info | 1 | non |

Ce réglage signifiait auparavant « n'a pas encore de score de réputation », ce qu'aucun déploiement ne
pouvait satisfaire : personne n'a jamais fourni d'arêtes de confiance à l'oracle, donc chaque serveur
revenait non cautionné et `false` les bloquait tous. La provenance de catalogue est un fait que l'hôte
détient déjà localement, ne demande aucun réseau et ne peut pas provoquer d'interblocage.

## pinning

Compare les définitions actuelles à l'instantané approuvé par l'utilisateur. L'empreinte est un sha256
sur la forme canonique RFC 8785 du jeu de définitions — la même canonicalisation que la signature du
feed, pas une seconde sérialisation.

| Situation | Code | Sévérité | Score | Fatal |
|---|---|---|---|---|
| Pas encore de pin (premier contact) | `TOOL_DEF_UNPINNED` | info | 0.9 | non |
| L'empreinte diffère du pin | `TOOL_DEF_DRIFT` | high | 0 | avec `pinToolDefs` |
| Les définitions n'ont pas de forme canonique (sans pin) | `TOOL_DEF_UNCANONICAL` | medium | 0.5 | non |
| Les définitions n'ont pas de forme canonique (avec pin) | `TOOL_DEF_UNCANONICAL` | high | 0 | avec `pinToolDefs` |

Le premier contact coûte 0,1 et non un blocage : un serveur propre, déclaré et sans pin marque
exactement **0,9**, et `TOOL_DEF_UNPINNED` est en `info` à dessein — avec `blockAtSeverity: "info"`, un
premier regard bloquant rendrait tout serveur inutilisable à jamais, puisque rien ne peut être épinglé
avant d'avoir été approuvé une fois.

`warden.approve(server, tools)` écrit le pin via votre `PinStore`. L'opération est idempotente.

## Partition par outil

`allowedTools` / `blockedTools` répartissent les outils annoncés :

- un outil est **bloqué** si un constat non advisory le nomme (`finding.tool`) et atteint le seuil ;
- tous les autres outils sont autorisés ;
- les outils sensibles (`policy.sensitiveToolPatterns`) restent *autorisés* : ils sont signalés pour que
  la boucle de votre agent puisse exiger une approbation à chaque appel à l'exécution. Voir
  `classifyTools` / `isSensitiveTool`.

## Ajouter une porte

`WardenGate` fait trois lignes d'interface, et `new Warden({ gates, policy, log })` prend la chaîne
directement : vous pouvez insérer la vôtre sans forker.

```ts
import { Warden, StaticScanGate, ThreatGate, OriginGate, PinningGate } from "@aimarket/warden";
import type { WardenGate, WardenGateInput, WardenGateResult } from "@aimarket/warden";

class DenyByPublisher implements WardenGate {
  readonly name = "publisher-allowlist";
  async evaluate(input: WardenGateInput): Promise<WardenGateResult> {
    const ok = ALLOWED.has(input.server.name);
    return ok
      ? { findings: [], score: 1 }
      : { findings: [{ gate: this.name, severity: "high", code: "PUBLISHER_UNKNOWN",
                       message: `${input.server.name} n'est pas un éditeur autorisé` }],
          score: 0, fatal: true };
  }
}

const warden = new Warden({
  gates: [new StaticScanGate(), new ThreatGate(feed), new DenyByPublisher(), new OriginGate(), new PinningGate(store)],
  policy,
});
```

Deux règles pour une porte que vous écrivez : **ne prétendez jamais qu'un service distant est
injoignable si vous n'avez pas réellement envoyé de requête** (`test/no-phantom-gate.test.ts` l'impose
sur les portes livrées), et renvoyez un score que vous pouvez défendre — une porte qui n'a rien mesuré
doit renvoyer `1`, pas un 0,6 « neutre », sinon elle taxe chaque serveur pour une mesure qu'elle n'a
jamais prise.
