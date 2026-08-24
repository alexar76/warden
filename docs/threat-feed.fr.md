# Le threat feed signé

> 🌐 [English](threat-feed.md) · [Русский](threat-feed.ru.md) · [Español](threat-feed.es.md) · **Français** · [中文](threat-feed.zh.md)

WARDEN embarque 11 enregistrements de menaces intégrés. C'est un socle, pas un catalogue : l'intérêt du
feed est que quelqu'un qui chasse réellement les serveurs MCP hostiles puisse pousser ses trouvailles
vers chaque installation — sans pour autant pouvoir *débloquer* quoi que ce soit.

## Le contrat sur le fil

```
GET https://votre-hote/threat-feed

{
  "records": [
    { "pattern": "*wallet-drainer*", "severity": "critical", "code": "THREAT_CRYPTO_DRAINER",
      "reason": "Crypto-drainer keyword in server identity", "source": "your-scanner",
      "scope": "server" }
  ],
  "timestamp": 1786205907380,
  "signature": "f588d5a4…9706"
}
```

| Champ | Règle |
|---|---|
| `records` | tableau de `ThreatRecord` ; les entrées qui ne respectent pas le type sont écartées, ce n'est pas fatal |
| `timestamp` | epoch en **millisecondes, entier**. Non optionnel — c'est lui qui rend le rejeu détectable |
| `signature` | Ed25519, hex, sur la forme canonique RFC 8785 de `{records, timestamp}` — **pas** sur le corps brut |

`ThreatRecord` :

| Champ | Signification |
|---|---|
| `pattern` | comparé sans tenir compte de la casse ; `*` est un glob, un motif sans `*` est un test de sous-chaîne |
| `severity` | de `info` à `critical`. Un `critical` correspondant au **serveur** est fatal pour la connexion |
| `code` | code machine stable, p. ex. `THREAT_TYPOSQUAT` |
| `reason` | phrase lisible montrée à l'opérateur |
| `source` | qui l'affirme — repris dans le constat |
| `scope` | `server` \| `tool` \| `any` (défaut). Contre quelle surface le motif a du sens |

Le scope compte plus qu'il n'y paraît. `*token*` est un motif raisonnable pour l'*identité d'un
serveur* et un motif catastrophique pour un *outil* : la moitié des serveurs MCP honnêtes mentionnent
des tokens dans un schéma.

## Ce que WARDEN vérifie, et ce qu'il fait en cas d'échec

La règle est la même pour tous les échecs ci-dessous : **conserver le socle intégré**. Un feed
invérifiable est ignoré ; il ne diminue jamais la protection déjà en place et ne bloque jamais le
démarrage.

| Vérification | Ce qu'elle empêche |
|---|---|
| `feedPublicKey` configurée | Un feed non signé est refusé d'emblée — sans clé, pas d'enregistrements distants, même si une URL est définie |
| Signature Ed25519 sur les octets canoniques | Celui qui sert l'URL ne peut ni ajouter ni modifier d'enregistrements |
| Fraîcheur : le `timestamp` signé dans `maxAgeMs` (24 h par défaut, `DEFAULT_FEED_MAX_AGE_MS`) | Le rejeu d'un instantané vieux de plusieurs mois qui effacerait en silence tout enregistrement ajouté depuis. *Une signature dit qui a écrit un document, jamais quand il vous a été remis* |
| Dérive future : pas daté plus de `FEED_CLOCK_SKEW_MS` (5 min) en avance | Un timestamp très dans le futur qui garderait un document périmé « frais » pour toujours |
| Octets canoniques (RFC 8785) | Un désaccord éditeur/vérificateur dû à l'ordre des clés JSON |
| Taille : `content-length` et corps ≤ 512 000 octets | L'URL du feed utilisée comme vecteur d'épuisement mémoire ; le corps est mesuré aussi, car content-length peut manquer ou mentir |
| Délai de 10 s sur la requête | Un feed qui pend et bloque votre démarrage |

Les enregistrements distants **s'ajoutent aux** intégrés (`[...BUILTIN, ...remote]`). Un feed ne peut
pas supprimer un enregistrement intégré, donc un éditeur compromis ne peut pas éteindre la protection —
seulement y ajouter. Cette asymétrie est délibérée : le canal montant (n'importe qui signale un
soupçon) et le canal descendant (le feed qui peut refuser un serveur) ne doivent pas avoir le même
niveau de confiance.

## Publier un feed que WARDEN acceptera

La clé se génère une fois. WARDEN attend la clé publique en **SPKI DER encodé en hex** (88 caractères
hex pour Ed25519) :

```js
import { generateKeyPairSync } from "node:crypto";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const spkiHex = publicKey.export({ format: "der", type: "spki" }).toString("hex");
console.log(spkiHex); // → c'est ce que vos consommateurs épinglent comme feedPublicKey
```

Signez la forme canonique de `{records, timestamp}` — réutilisez le canonicaliseur de WARDEN pour qu'il
n'y ait qu'une implémentation des octets, pas deux :

```js
import { sign } from "node:crypto";
import { canonicalize } from "@aimarket/warden/jcs";

function document(records, privateKey) {
  const timestamp = Date.now();                       // ms entiers
  const payload = canonicalize({ records, timestamp }); // RFC 8785 fixe l'ordre des clés
  const signature = sign(null, Buffer.from(payload, "utf8"), privateKey).toString("hex");
  return { records, timestamp, signature };
}
```

Deux pièges classiques pour un éditeur :

- **Ne cachez pas le document.** `timestamp` est une affirmation de fraîcheur ; une réponse mise en
  cache finit par publier un document périmé, que chaque consommateur refuse.
- **Signez la forme canonique, pas `JSON.stringify`.** Elles concordent bien plus souvent qu'elles ne
  divergent — c'est exactement ce qui rend la divergence si coûteuse à trouver ensuite.

## Le consommer

```ts
const feed = new ThreatFeed({
  feedPublicKey: process.env.FEED_PUBKEY,   // épinglée à l'avance, hors bande
  maxAgeMs: 6 * 60 * 60 * 1000,             // optionnel ; non fini ou ≤0 retombe sur 24 h
  log: myLogger,                            // optionnel, mais c'est là que les refus sont rapportés
});
await feed.load(process.env.FEED_URL);      // sans URL → intégrés seulement, sans réseau
```

`feed.builtins` renvoie le socle intégré si vous voulez montrer ce qui s'applique sans aucun feed.
Chaque refus est un `log.warn` motivé : sans logger, un feed silencieusement vide et un feed refusé sont
indiscernables — passez donc un logger en production.

## Un éditeur de référence

[MOMUS](https://github.com/alexar76/momus) publie ce contrat sur `/warden/threat-feed`, avec un point
d'entrée `/warden/threat-feed/summary` qui expose la clé SPKI en hex et les compteurs d'enregistrements,
et une prise `/warden/report` pour les soupçons de terrain non vérifiés. Son script de vérification
(`momus/scripts/verify_warden_channel.mjs`) contrôle un déploiement en direct avec le canonicaliseur
**de ce paquet** — la seule façon de prouver que les deux côtés s'accordent sur les octets.
