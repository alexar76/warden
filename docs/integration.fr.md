# Guide d'intégration

> 🌐 [English](integration.md) · [Русский](integration.ru.md) · [Español](integration.es.md) · **Français** · [中文](integration.zh.md)

WARDEN est une bibliothèque, pas un proxy. Vous l'appelez en un point du cycle de vie de votre hôte MCP :
après que le serveur a annoncé ce qu'il sait faire, avant que le modèle en soit informé.

```
connect ──► listTools ──► warden.vet() ──► exposer allowedTools au modèle
                              │                    │
                              │                    └─► à chaque appel : isSensitiveTool → demander à l'utilisateur
                              └─► bloqué : se déconnecter et consigner le verdict
                                           approuvé une fois : warden.approve() épingle les définitions
```

## Où se trouve la couture

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Warden, ThreatFeed, isSensitiveTool, EgressGuard } from "@aimarket/warden";

const feed = new ThreatFeed({ feedPublicKey: process.env.FEED_PUBKEY, log });
await feed.load(process.env.FEED_URL);

const warden = Warden.create({ policy, threatFeed: feed, store, log });

async function connect(ref) {
  const client = new Client({ name: "my-host", version: "1.0.0" });
  await client.connect(new StdioClientTransport({ command: ref.command, args: ref.args }));

  const { tools } = await client.listTools();
  const verdict = await warden.vet(ref, tools);

  if (!verdict.allow) {
    await client.close();                       // rien n'a jamais été exposé au modèle
    await audit.write({ server: ref.id, verdict, at: new Date().toISOString() });
    throw new Error(`${ref.id} bloqué par ${verdict.decidedBy}`);
  }

  const usable = tools.filter((t) => verdict.allowedTools.includes(t.name));
  await audit.write({ server: ref.id, verdict, at: new Date().toISOString() });
  return { client, tools: usable, verdict };
}
```

Trois choses que cet ordre vous achète, et qu'il est facile de perdre en déplaçant une ligne :

1. **`vet()` avant que le modèle ne voie quoi que ce soit.** Une définition d'outil bloquée est du texte
   de prompt qui n'est jamais entré dans le contexte. Examiner après avoir déjà passé les outils au
   modèle, c'est du théâtre.
2. **`blockedTools` n'est pas la même chose que bloquer.** Un serveur avec un outil empoisonné et neuf
   bons reste utilisable ; ne retirez que ce que le verdict a nommé.
3. **Consignez le verdict, y compris `verdict.rulesets`.** Sans la version et l'empreinte du jeu de
   règles, un scan archivé ne peut pas être distingué d'un serveur qui a changé après coup.

## Approbation par appel

Un verdict est une décision sur les *définitions*. Les outils sensibles concernent les *appels* :

```ts
async function callTool(name, args) {
  if (isSensitiveTool(name, policy) && !(await confirmWithUser(name, args))) {
    throw new Error(`${name} exige une approbation`);
  }
  return client.callTool({ name, arguments: args });
}
```

Les motifs sont des globs, comparés sans tenir compte de la casse au nom complet de l'outil :
`"*delete*"`, `"*transfer*"`, `"*key*"`. `classifyTools(tools, policy)` vous donne la répartition en
amont si vous voulez montrer à l'utilisateur ce qui exigera une confirmation avant qu'il approuve le
serveur.

Si vos outils émettent des requêtes sortantes, enveloppez-les :

```ts
const egress = new EgressGuard(["api.github.com", "*.internal.example.com"]);
const { allowed, reason } = egress.check(url);
if (!allowed) throw new Error(reason);   // une liste vide bloque tout, à dessein
```

## Les deux coutures que vous devez fournir

**`PinStore`** — deux méthodes. N'importe quoi convient ; la seule exigence est de survivre à un
redémarrage, car ce sont les pins qui rendent la dérive détectable :

```ts
// Développement : en mémoire. Chaque redémarrage redevient un « premier contact ».
const pins = new Map();
const store = {
  getPin: async (id) => pins.get(id),
  putPin: async (p) => void pins.set(p.serverId, p),
};

// Production : un seul fichier JSON suffit — un pin, c'est 4 petits champs.
import { readFile, writeFile } from "node:fs/promises";
const store = {
  async getPin(id) {
    const all = JSON.parse(await readFile(PATH, "utf8").catch(() => "{}"));
    return all[id];
  },
  async putPin(p) {
    const all = JSON.parse(await readFile(PATH, "utf8").catch(() => "{}"));
    all[p.serverId] = p;
    await writeFile(PATH, JSON.stringify(all, null, 2), { mode: 0o600 });
  },
};
```

**`WardenLogger`** — `debug/info/warn/error/child`. La plupart des loggers d'hôte le satisfont déjà
structurellement, vous pouvez donc généralement passer le vôtre tel quel ; `silentLogger()` est la
valeur par défaut documentée. En production, passez-en un vrai : toutes les décisions des portes et
tous les refus de feed y sont rapportés, et sans cela un threat feed silencieusement vide ressemble
exactement à un feed qui fonctionne.

En TypeScript, vous pouvez rendre le contrat explicite et laisser le compilateur le tenir :

```ts
import type { PinStore, WardenLogger } from "@aimarket/warden";
export interface MyStore extends PinStore { /* vos propres méthodes */ }
export interface MyLogger extends WardenLogger { /* … */ }
```

## Choisir une politique

```ts
const policy = {
  blockAtSeverity: "high",
  sensitiveToolPatterns: ["*delete*", "*transfer*", "*key*", "*password*"],
  allowUnknownServers: false,
  pinToolDefs: true,
};
```

| | `blockAtSeverity` | `allowUnknownServers` | `pinToolDefs` |
|---|---|---|---|
| Verrouillé | `medium` | `false` | `true` |
| Défaut recommandé | `high` | `false` | `true` |
| Exploration d'un catalogue | `high` | `true` | `true` |
| Rapport seul (audit d'un parc) | `critical` | `true` | `false` |

Notes issues de l'exploitation réelle :

- `blockAtSeverity: "info"` n'est pas « sécurité maximale », c'est un déploiement cassé : il bloque
  `TOOL_DEF_UNPINNED`, que tout serveur porte au premier contact, donc rien ne peut jamais être
  approuvé. Les portes maintiennent ce constat en `info` précisément pour que durcir le seuil dégrade
  proprement ; ne descendez pas sous `medium` sans lire [le tableau des portes](gates.fr.md).
- Le mode rapport seul est un vrai mode : gardez les verdicts, ne bloquez rien, et observez ce que votre
  parc aurait refusé avant de l'activer.

## Ne passez pas vos propres outils dans WARDEN

WARDEN examine les serveurs MCP **tiers**. Vos propres outils intégrés ne sont pas un éditeur non fiable,
et les passer dans la chaîne produit exactement le mauvais résultat : votre propre outil nommé
`transfer_funds` avec une description honnête déclenche des règles `TOOL_DEF_*` écrites pour attraper un
inconnu qui annonce la même chose. Gardez les outils de première partie sur une voie séparée et de
confiance — c'est une leçon d'ARGUS, où les outils de première partie de l'écosystème contournent
explicitement le pare-feu.

## Références

- [ARGUS](https://github.com/alexar76/argus) — l'hôte de référence. `src/mcp/host.ts` est cette
  intégration en version de production : examen à la connexion, quarantaine par outil, approbation par
  appel, garde de sortie.
- [MOMUS](https://github.com/alexar76/momus) — le côté éditeur : un feed signé sur
  `/warden/threat-feed` plus une prise pour les soupçons non vérifiés.
- [La chaîne de portes](gates.fr.md) · [Le threat feed signé](threat-feed.fr.md)
