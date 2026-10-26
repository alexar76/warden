# Nouvelles revues du modèle : faits concrets et divulgation

[en](flow-guard-fresh-rechecks-2026-10-26.md) · [ru](flow-guard-fresh-rechecks-2026-10-26.ru.md) · [es](flow-guard-fresh-rechecks-2026-10-26.es.md) · [fr](flow-guard-fresh-rechecks-2026-10-26.fr.md) · [zh](flow-guard-fresh-rechecks-2026-10-26.zh.md)

**288 nouvelles continuations conservées sur Linux** : 12 réponses initiales enregistrées × 8 répétitions × 3 messages de revue. Conversations, fiches et réponses initiales exactes ; pas de nouveaux départs, de holdout indépendant ou de test de rendu natif. `deepseek-flash`, température 0.3, maximum 700 tokens, thinking désactivé ; même pont outil et revue de rôle utilisateur.

| Message de revue | Corrections factuelles | Divulgation du modèle conservée |
| --- | ---: | ---: |
| Stop historique | 2/32 | 56/80 |
| Nouvelle formulation sans faits | 0/32 | 80/80 |
| Nouvelle formulation avec faits déterministes | 19/32 | 80/80 |

Corrections : quatre anciennes erreurs × huit répétitions. Conservation : dix réponses divulguant initialement × huit. Les deux nouveaux traitements ajoutent une divulgation dans les 16/16 autres possibilités ; historique : 0/16. Les 288 ID restent identiques et admissibles. Aucune nouvelle contradiction annotée sur les 64 contextes initialement appuyés par traitement.

Avec faits, les quatre cas donnent **8/8, 3/8, 0/8 et 8/8** ; 13 erreurs persistent. L’amélioration directionnelle est observée, mais la prédiction préalable plus forte d’au moins 24/32 corrections **échoue**. Aide partielle, sans correction fiable ni efficacité générale démontrée ; aucune causalité interne ni preuve que l’injection a causé ces erreurs.

Le guard émet un avis pour **192/192** continuations des nouveaux traitements, sans en demander une autre. Cela reste distinct de la prose du modèle et ne vérifie pas le rendu natif. Les nombres existaient déjà dans les fiches ; le message ajoute la comparaison explicite. Aucun ajustement du détecteur, de la grammaire ou des prompts selon ces résultats.

## Exécution et limites

288 requêtes/réponses complètes et usage conservés, aucun échec API/format/longueur. **36 tests d’instrument/relay/collecte** réussis sur Linux sans réseau ; préparation et rejeu du guard également sans réseau. Seul le relay hôte appelle le modèle, clé conservée sur le serveur. **590 hash** vérifiés avant suppression du répertoire temporaire.

Un premier essai annonce 288 appels terminés, mais une coupure SSH et un défaut du collecteur suppriment sa seule preuve. Ses résultats sémantiques ne sont ni lus ni évalués. Un amendement avant répétition conserve le plan et ajoute cinq régressions : suppression seulement après téléchargement vérifié. **576 appels au total**, seulement **288 résultats auditables conservés**. Comptabilité prudente : répétition **$0.053438304**, premier essai annoncé par supervisor **$0.053408928**, total **$0.106847232** ; pas une facture aux tarifs actuels vérifiés. Plafond de répétition $0.19, plafond annoncé total $0.25.

Les 80 textes complets uniques sont lus ; les doublons exacts partagent l’annotation. Revue a posteriori assistée par IA, pas d’adjudication humaine indépendante/aveugle ; citations et hash vérifiables, labels de traitement absents de l’index de revue. Grammaire fermée gelée, pas de validation sémantique générale. Quatre erreurs de deux familles ne sont pas 32 familles indépendantes. Documentation locale uniquement ; aucune publication npm/GitHub/blog/article/commentaire.

[analysis.json](data/launchgate-fresh-rechecks-2026-10-26/analysis.json), [artifact-audit.json](data/launchgate-fresh-rechecks-2026-10-26/artifact-audit.json), [scored-pairs.json](data/launchgate-fresh-rechecks-2026-10-26/scored-pairs.json), [annotations.json](data/launchgate-fresh-rechecks-2026-10-26/annotations.json), [protocol.md](data/launchgate-fresh-rechecks-2026-10-26/protocol.md), [collection-amendment.md](data/launchgate-fresh-rechecks-2026-10-26/collection-amendment.md), [manifest.json](data/launchgate-fresh-rechecks-2026-10-26/manifest.json).

<!-- residual-delivery-diagnosis -->

## Échecs restants : extraction et transmission

Les requêtes API conservées contiennent la contre-preuve numérique dans **13/13** échecs restants ; les treize listes finales fausses sont aussi extraites. Dans le cas **0/8**, `T-4-C` est la première fiche source, au prix 190. Les huit messages incluent `actual 190; required <= 150` ; les huit réponses reproduisent exactement l’initiale, fausse admissibilité et prix ex æquo compris. Extraction et transmission réussies, sans correction. Cela ne prouve ni compréhension, rationalisation ou saturation de la persuasion. L’ordinal désigne la position source, pas la liste déclarée ; cette ambiguïté et la consigne de répéter une réponse correcte ne sont pas isolées. 0/32 concerne une formulation, sans prouver un effet causal nul de toute revue.

[residual-diagnosis.json](data/launchgate-fresh-rechecks-2026-10-26/residual-diagnosis.json).

<!-- factorial-review-followup -->

[Références et consignes de correction : quatre conditions](flow-guard-review-factors-2026-10-26.fr.md).
