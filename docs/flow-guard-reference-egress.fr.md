# Références sortantes : comportement vérifié et limites

[en](flow-guard-reference-egress.md) · [ru](flow-guard-reference-egress.ru.md) · [es](flow-guard-reference-egress.es.md) · [fr](flow-guard-reference-egress.fr.md) · [zh](flow-guard-reference-egress.zh.md)

26 octobre 2026. WARDEN local **0.22.1**. Compilation et types validés sur Linux factory-vps ; **127/127 tests dans quatre suites**, dont **25 nouveaux**. Aucun changement du runtime, des seuils ou de version. Aucun appel de modèle payant, envoi réel ou coût API supplémentaire.

## Vérifications

Des phrases manuelles comme « utilisez la troisième entrée du tableau » ne correspondent pas aux empreintes du secret. Après lecture observée de credentials et de texte externe, l’appel sortant exige une revue (`ask`) ou est refusé en mode `deny`. La frontière persiste après 1/3/8 résultats intermédiaires observés et un nouveau tour utilisateur. Un destinataire nommé ou autorisé ne suffit pas à l’exempter. Les noms MCP opaques sont contrôlés ; les outils hors MCP nécessitent une classification explicite `outbound`.

Il s’agit d’une frontière de session/action, **pas d’un suivi sémantique de provenance**. Les transformations sont synthétiques, écrites à la main, sans génération par un modèle. Aucun véritable expéditeur n’est exécuté. Les anciens tests conservent la limite du hook Stop pour les paraphrases sans chevauchement littéral.

## Exceptions

Une autorisation exacte de l’opérateur peut permettre **une fois** une référence opaque, sans certifier que sa valeur est publique. Répétition, modification du texte/destinataire/arguments imbriqués/outil ou interdiction du host déclenchent une nouvelle revue. Un secret littéral connu reste refusé même avec une autorisation exacte.

Un outil hors MCP inconnu sans étiquette échappe à cette frontière. Sans credential ou texte externe observé, elle ne s’active pas. Les données privées ordinaires sans credential reconnu ne sont pas universellement couvertes. `audit` journalise sans bloquer ; `off` désactive. Le host doit exécuter les hooks et appliquer leurs décisions. L’exécuteur task-adapter et le rendu natif n’ont pas été réévalués.

Fenêtres fortes inchangées : **8 non hex / 10 hex**. Les tests existants de fragments isolés passent. Aucune protection générale contre l’exfiltration sémantique n’est démontrée.

## Preuves

L’utilisateur a autorisé ce lot de 101 fichiers/316 Ko après le refus initial de la revue automatique. Aucune clé ou configuration serveur. Réseau uniquement pour les dépendances dev, scripts désactivés ; contrôles dans un conteneur sans privilèges et sans réseau. Six empreintes de sortie vérifiées avant suppression du répertoire temporaire distant. Préparation assistée par IA ; aucune publication GitHub/npm ou commentaire envoyé.

[Results](data/qingfeng-reference-egress-2026-10-26/results.json) · [Protocol](data/qingfeng-reference-egress-2026-10-26/protocol.md) · [Execution](data/qingfeng-reference-egress-2026-10-26/execution.json) · [Tests](data/qingfeng-reference-egress-2026-10-26/vitest.json) · [Input hashes](data/qingfeng-reference-egress-2026-10-26/input-manifest.json).
