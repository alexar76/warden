# Warden 0.7.0 : approbations et vérification continue

> 🌐 [English](security-hardening.md) · [Русский](security-hardening.ru.md) · [Español](security-hardening.es.md) · **Français** · [中文](security-hardening.zh.md)

Warden 0.7.0 et ARGUS 0.3.2 corrigent six lacunes. Ils vérifient les définitions et la configuration de lancement, sans constituer un bac à sable du système ni garantir le comportement du serveur.

1. **Avant la connexion.** Appeler `warden.vetLaunch(server)` avant de lancer le processus stdio ou d'ouvrir le transport distant. Vérification de la provenance, des commandes/adresses dangereuses connues et de l'identité de lancement approuvée. Ensuite récupérer toutes les pages de `tools/list` et appeler `vet(server, tools)` avant exposition au modèle. Une vérification du lancement ne vaut pas approbation des outils.
2. **Rejeu du feed signé.** Timestamp, digest et enregistrements du dernier snapshot sont conservés par clé d'éditeur dans `feeds/`. Un timestamp antérieur ou un contenu différent au même timestamp est refusé, même après redémarrage. Un snapshot signé plus récent peut retirer des règles. En cas d'échec, les derniers enregistrements acceptés restent actifs ; `feed.status.stale` indique séparément leur fraîcheur. Le délai de dix secondes couvre en-têtes et corps complet ; les limites de taille et de nombre restent actives.
3. **Stdio.** Enveloppe JSON-RPC invalide : `-32600` ; paramètres invalides : `-32602` ; syntaxe JSON invalide : `-32700`. UTF-8 est décodé après réception d'une trame complète. Limites : 1 MiB par trame, 8 KiB pour l'en-tête Content-Length. Une trame incorrecte ou trop grande ferme volontairement la connexion ; un objet de requête invalide ne tue pas le processus. La limite indépendante des arguments reste 256 000 caractères.
4. **Approbations persistantes.** `vet_mcp_server` lit les empreintes enregistrées. `status_mcp_server({server, tools})` renvoie `previous`, `previousRevision`, `currentTools`, `currentToolsHash`, `currentIdentityHash` et `changed` pour comparaison. L'approbation exige les empreintes exactes examinées et `previous_pin_revision` (null pour la première approbation). La révocation exige également la révision précédente. Une modification concurrente invalide une ancienne revue. Les définitions sont conservées : ne pas y inclure de véritables secrets.
5. **Définitions complètes.** Le format v2 couvre tous les champs annoncés : `title`, `outputSchema`, `annotations` et extensions. Les champs supérieurs undefined sont omis. Les définitions simples name/description/inputSchema gardent leur digest. Les anciennes empreintes ne couvrant pas les champs supplémentaires exigent une nouvelle approbation explicite (`PIN_FORMAT_UPGRADE_REQUIRED`) ; les nouvelles portent `toolsHashVersion: 2`. Le jeu v6 analyse ces surfaces. Les guillemets de sérialisation JSON ne transforment plus une instruction en citation inoffensive. Les annotations restent des indications non fiables, jamais des permissions.
6. **Pendant la session.** ARGUS suspend immédiatement les outils à réception de `notifications/tools/list_changed` puis vérifie toutes les pages. Il vérifie aussi avant chaque appel, même sans notification. Une ancienne référence ne peut pas exécuter une définition modifiée après réapprobation. Échec du listing, noms dupliqués, curseurs répétés, plus de 32 pages, 256 outils ou 1 MiB de définitions bloquent l'usage. Aucun changement n'est réapprouvé automatiquement. La première connexion saine conserve la politique ARGUS existante : premier pin automatique, sans revue humaine implicite. Un échec d'écriture ferme désormais la connexion. Un changement pendant l'exécution masque le résultat mais n'annule pas une action déjà effectuée ; ne pas réessayer automatiquement.

## État et droits de l'opérateur

Répertoire : `WARDEN_STATE_DIR`, sinon `$XDG_STATE_HOME/warden`, sinon `~/.local/state/warden`. La bibliothèque accepte `ThreatFeed({stateDir})` et `FilePinStore(directory)`. ARGUS place le feed dans `warden/` sous son répertoire mémoire. Noms de fichiers dérivés du hash des ID, remplacement atomique, permissions réservées au propriétaire et verrous par fichier. Si un processus meurt avec un verrou, les mutations échouent en sécurité : arrêter tous les rédacteurs, inspecter et supprimer uniquement le `.lock` abandonné. Ne pas effacer les snapshots pour masquer une erreur. Utiliser un volume local persistant ; sa suppression efface approbations et historique anti-rejeu.

Les mutations MCP sont désactivées par défaut. L'opérateur peut définir `WARDEN_ALLOW_PIN_CHANGES=1` avant de lancer `warden-mcp`. Cela délègue au client MCP le droit d'approuver/révoquer ; un argument ne peut pas l'activer. La revue humaine relève du host ou d'une session opérateur séparée. Scanner n'approuve pas silencieusement ; toute réapprobation passe encore les autres contrôles.

## Mise à jour et limites

Publier/installer d'abord `@aimarket/warden@0.7.0`, puis `@alexar76/argus3@0.3.2`, et redémarrer les clients MCP. Examiner les migrations des anciens pins au lieu de les supprimer. Les autres hosts doivent brancher `vetLaunch` et la revalidation. Un comportement modifié derrière des définitions identiques échappe aux hashes. Les résultats restent non fiables : aucun filtrage du contenu des résultats ni isolation des processus n'est ajouté ici. Les tests locaux couvrent rejeu, redémarrage, délai du corps, UTF-8 fragmenté, requêtes invalides, persistance, changements de métadonnées et blocage ARGUS, sans paiements ni déploiement en production.

```js
const state = (await client.callTool({
  name: "status_mcp_server", arguments: { server, tools },
})).structuredContent;
// Review state.previous against state.currentTools and the launch identity first.
await client.callTool({ name: "approve_mcp_server", arguments: {
  server, tools,
  reviewed_tools_hash: state.currentToolsHash,
  reviewed_identity_hash: state.currentIdentityHash,
  previous_pin_revision: state.previousRevision,
} });
const verdict = (await client.callTool({
  name: "vet_mcp_server", arguments: { server, tools },
})).structuredContent;
if (!verdict.allow) throw new Error("WARDEN blocked the server");
// Revoke using a freshly reviewed status, not the pre-approval revision.
```
