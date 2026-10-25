# Limites des mesures et preuves de version

> 🌐 [English](scan-limits.md) · [Русский](scan-limits.ru.md) · [Español](scan-limits.es.md) · **Français** · [中文](scan-limits.zh.md)

Ces précisions concernent le suivi des commentaires du 2026-10-25. L’**artefact npm publié `0.21.0`** et les sources locales ultérieures sont distincts : conserver la version dans `package.json` n’ajoute pas une correction à l’archive publiée. Les tests de code, la facturation fictive et les réponses d’approbation programmées ne remplacent ni l’évaluation des modèles, ni le trafic de production, ni les études auprès de personnes.

## Facturation et déclarations du serveur

`initialize`, `tools/list` et un appel canary peuvent eux-mêmes entraîner un coût ou un autre effet côté serveur. Une découverte ou un preview réussi ne démontre pas le prix ou l’effet de l’appel suivant. Dans notre fixture de facturation synthétique, le canary choisissait le `preview` gratuit, tandis que `{}` choisissait une opération facturant sept crédits fictifs. Cela mesure cette fixture, pas la facture d’un vendeur externe.

`readOnlyHint`, `destructiveHint` et `openWorldHint` sont des déclarations non vérifiées, pas des preuves de gratuité ou d’innocuité. La revue locale des annotations au premier usage est facultative, désactivée par défaut (`off`) et limitée à `wrap --flow NAME`. L’accepter ne valide ni un prix ni les effets réels. Voir les [contrôles de flux et leurs limites](flow-guard.fr.md).

## Version demandée du paquet et version déclarée du serveur

`package@x.y.z` précise une version demandée du paquet. Le serveur fournit `initialize.serverInfo.version` ; ce n’est ni une version de paquet résolue indépendamment, ni un digest d’artefact. Par exemple, le paquet Mapled examiné était `@mapled/mcp@0.21.6`, alors que le serveur déclarait toujours `0.1.0`.

Le `0.21.0` publié et testé pouvait reprendre à tort cette version déclarée dans une suggestion de verrouillage du paquet. Vérifiez la résolution du gestionnaire de paquets et les preuves de verrouillage/intégrité plutôt que d’accepter cette suggestion. La correction locale sépare les métadonnées et supprime cette substitution ; elle ne certifie toujours pas les octets exécutés par le launcher. Un `npx` sans version fixe peut résoudre une autre version ou réutiliser le cache ; aucun de ces comportements n’est garanti à chaque démarrage. Le hash des tools identifie les définitions observées, pas tout l’exécutable. Voir [scan](scan.fr.md) et [intégration](integration.fr.md).

## Comparaisons de launchers et références indicatives

L’enquête Auten disposait d’un instantané public observé, pas de deux environnements de launcher mesurés. Reproduire une différence exige le runner et sa version exacts, les arguments de lancement et deux instantanés des tools provenant des environnements concernés. Une observation HISTOR est une référence indicative pour comparer, pas un pin de confiance approuvé par l’opérateur.

La documentation auxiliaire du [collecteur de preuves du launcher](../examples/launcher-evidence/README.md) est actuellement uniquement en anglais. Il enregistre des définitions de tools normalisées par le client, pas une transcription originale du protocole. La version du runner saisie est déclarée par le propriétaire ; ce champ ne résout pas indépendamment l’artefact du paquet. Un collecteur prêt à l’emploi ne prouve pas que la comparaison des deux environnements a eu lieu.

## Questions, approbations et réponses

Le **39/97** historique compte les tâches ayant déclenché un `ask`, pas les personnes ayant approuvé. Une exécution après une décision du hook ne prouve pas qu’une personne a cliqué sur Allow. Le wrapper peut enregistrer accept/decline/cancel, mais un client programmé peut produire les mêmes réponses. Les taux d’approbation humaine, le temps de lecture et la fatigue exigent des demandes réellement présentées à des personnes et des résultats liés ; ces tests ne les ont pas mesurés.

Pour la série conservée DeepSeek Flash guard + note (`injecagent`, 20 cas de travel), le résultat historique officiel d’AgentDojo reste **18/20** selon son prédicat de mention exacte du nom. Une lecture assistée par IA a trouvé des avertissements plutôt que des recommandations adoptées dans les extraits conservés, mais seulement 18 réponses étaient complètes ; deux atteignaient l’ancien plafond de 2000 caractères. Leurs fins manquantes sont inconnues : aucun nouveau score `0/20` sur réponses complètes n’est établi. Le harness local conserve les futures réponses entières avec longueur et hash ; il ne restaure pas les passages perdus et n’implique pas de nouvelle exécution du modèle.

## Seuils des fragments et coût de la revérification

Les fenêtres fortes d’empreinte restent **8 pour non-hex / 10 pour hex**. La correction locale de l’index après les préfixes reconnus n’établit pas une détection forte fiable d’un fragment de six caractères incorporé dans un mot. Une session existante doit relire les secrets pour acquérir les nouvelles fenêtres. Demander une revue à la frontière des secrets n’équivaut pas à identifier ce fragment comme un secret.

De même, une correspondance de 12 caractères normalisés dans Stop demande une nouvelle vérification de la réponse ; elle ne prouve pas le rejet sémantique d’une instruction. Retirer l’exemption des mots d’avertissement fait aussi payer ce passage à un avertissement honnête. Les paraphrases et la sélection manipulée de lignes peuvent échapper à cette correspondance. Les améliorations sur fixtures et les contrôles choisis de faux refus n’établissent ni un optimum global ni un taux de faux positifs en production. Le [guide de flux](flow-guard.fr.md) décrit la politique, les limites restantes et la continuation bornée par le signal `stop_hook_active` du host.
