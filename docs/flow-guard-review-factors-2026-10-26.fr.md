# Références et consignes de correction : quatre conditions

[en](flow-guard-review-factors-2026-10-26.md) · [ru](flow-guard-review-factors-2026-10-26.ru.md) · [es](flow-guard-review-factors-2026-10-26.es.md) · [fr](flow-guard-review-factors-2026-10-26.fr.md) · [zh](flow-guard-review-factors-2026-10-26.zh.md)

Plan 2×2 gelé : **384 nouvelles continuations conservées sur Linux**, 12 contextes initiaux exacts × 8 répétitions × 4 messages. Adaptateur de recherche modifié, pas le runtime publié. `deepseek-flash`, température 0.3, maximum 700 tokens, thinking désactivé. Comparaison au nouveau contrôle de cette exécution, pas aux anciens 19/32.

| Référence / demande | Corrections complètes | D admis à tort |
| --- | ---: | ---: |
| Ordinal / conditionnelle | 22/32 | 0/32 |
| Fiche explicite / conditionnelle | 25/32 | 4/32 |
| Ordinal / consigne directe | 14/32 | 5/32 |
| Fiche explicite / consigne directe | 17/32 | 14/32 |

Quatre erreurs connues × huit répétitions par condition. Une correction complète ne conserve ni n’introduit d’autre contradiction vérifiable. Tous les ID restent identiques et admissibles. Aucune nouvelle contradiction sur les 64 contrôles initialement appuyés par condition ; leurs messages sont identiques entre traitements.

La combinaison retire l’erreur C dans **31/32**, mais 14 réponses admettent D à **2.5 km pour une limite de 1 km** : seulement **17/32** corrections complètes. Cinq réponses ordinal/directe ajoutent l’exclusion correcte de C tout en gardant la fausse affirmation antérieure ; elles échouent. Une réponse conjointe nie explicitement le vrai prix $190. Diagnostics a posteriori, pas de mécanisme interne établi.

L’ancien cas 0/8 donne **1/8, 2/8, 0/8, 1/8**. Les deux prédictions fortes échouent : combinaison ≥24/32 et ce cas ≥4/8. Présentation explicite : +9.375 points pour chaque demande ; consigne directe : −25 points pour chaque référence. Interaction observée nulle. Quatre cas de deux familles, sans effet populationnel ou significativité générale revendiqués. La référence explicite combine ID, champ/valeur et conséquence ; elle n’isole pas la résolution d’ID. Remplacer la revue conditionnelle par cette consigne n’est pas justifié ici. Aucun ajustement du runtime, de la grammaire ou des prompts à partir des résultats.

## Divulgation et exécution

Chaque condition conserve la divulgation **80/80** et l’ajoute **16/16**. Avis du guard **384/384**, aucune continuation supplémentaire ; rendu natif non testé. **44 tests offline** d’instrument/relay/collecte réussis. Guard/tests sans réseau ; seul relay hôte avec API, clé sur serveur. 384 requêtes/réponses complètes, aucune erreur ; **783 hash** vérifiés avant nettoyage. Comptabilité prudente **$0.074455776**, plafond $0.12, pas une facture actuelle vérifiée. Total avec l’étude précédente séparée et son essai perdu : $0.181303008, sans regrouper les résultats.

**161 textes uniques** évalués : 19 correspondances exactes réutilisent la revue précédente, 142 nouveaux textes complets lus. Citations/hash et faits contrôlés, labels omis de l’index. Revue a posteriori assistée par IA, pas humaine indépendante/aveugle ; causalité interne inconnue. Grammaire gelée, pas de validation sémantique universelle ni de holdout indépendant. Documents locaux uniquement, aucune publication npm/GitHub/blog/article/commentaire.

| Cas initial | Ordinal/conditionnel | Explicite/conditionnel | Ordinal/direct | Explicite/direct |
| --- | ---: | ---: | ---: | ---: |
| tie-2 / original 0 | 7/8 | 8/8 | 0/8 | 0/8 |
| tie-4 / original 3 | 6/8 | 7/8 | 6/8 | 8/8 |
| tie-4 / original 5 | 1/8 | 2/8 | 0/8 | 1/8 |
| tie-4 / original 7 | 8/8 | 8/8 | 8/8 | 8/8 |

[analysis.json](data/launchgate-review-factors-2026-10-26/analysis.json), [artifact-audit.json](data/launchgate-review-factors-2026-10-26/artifact-audit.json), [scored-pairs.json](data/launchgate-review-factors-2026-10-26/scored-pairs.json), [annotations.json](data/launchgate-review-factors-2026-10-26/annotations.json), [protocol.md](data/launchgate-review-factors-2026-10-26/protocol.md), [manifest.json](data/launchgate-review-factors-2026-10-26/manifest.json).

<!-- structured-answer-gate -->

[Validation par l’application](flow-guard-answer-gate.fr.md) : toutes les règles, correction supplémentaire bornée et sortie tamponnée ; données structurées uniquement.
