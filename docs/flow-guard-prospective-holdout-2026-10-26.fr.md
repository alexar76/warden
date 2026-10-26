# Nouveaux cas après gel du produit

<!-- final-ranking-witness -->
**[Comparaison finale des messages de classement, 26 octobre](flow-guard-final-witness-2026-10-26.fr.md).** Sur les cinq contextes précédemment retenus, l’ancien message a corrigé 6/40 continuations et la comparaison explicite du choix avec le meilleur a corrigé 40/40. Les contrôles valides sont restés valides 20/20 par groupe nominal. La série se termine sur des échecs connus, sans nouvel échantillon réservé. Ce résultat actualise la limite antérieure de vérification hors ligne pour le classement ; l’efficacité du message d’ensemble incomplet reste non mesurée.
<!-- /final-ranking-witness -->

[en](flow-guard-prospective-holdout-2026-10-26.md) · [ru](flow-guard-prospective-holdout-2026-10-26.ru.md) · [es](flow-guard-prospective-holdout-2026-10-26.es.md) · [fr](flow-guard-prospective-holdout-2026-10-26.fr.md) · [zh](flow-guard-prospective-holdout-2026-10-26.zh.md)

26 octobre 2026. Sources, binaire, commit, protocole et générateur figés avant tirage d’une graine aléatoire et création de 24 cas. Six étiquettes de domaines synthétiques, six enregistrements, maximum/minimum numérique, égalité numérique et booléenne, classement min/max ; six ex æquo optimaux. Les quatre pièges restent dans chaque catalogue ordinaire (144/144). Nouvelles combinaisons de types supportés, pas de nouvelles unités/NLP ni corpus réel. Le même auteur assisté par IA connaît l’implémentation : pas d’auteur indépendant ou d’étude aveugle.

| Population | Résultat |
|---|---|
| Naturel propre, 48 | 47 premières valides ; 1 corrigée ; 48 remises |
| Naturel injecté, 48 | 42 premières valides ; 4 corrigées ; 46 remises, 2 retenues |
| Alternative inadmissible semée, 24 | 24 corrigées au premier essai |
| Admissible omis semé, 12 | 11 corrigés, 1 retenu |
| Sélection sous-optimale semée, 12 | 10 corrigées, 2 retenues |
| Contrôles déterministes, 12 | 4 valides remis ; 4 incomplets et 4 sans admissible retenus ; sans API |

**89/96** premières propositions naturelles valides ; **94/96** remises finales. Les sept erreurs initiales concernent le classement, avec ensemble admissible correct : cinq corrigées, deux retenues. Réparation contrôlée **45/48**, dénominateur distinct. Deuxième réparation déclenchée dans sept trajectoires réelles : deux passent, cinq sont retenues. Une omission devient une erreur de classement ; aucun nouveau piège admis. Retenir ne vaut pas résoudre.

Audit arithmétique sans validateur runtime : **143 remises valides, 13 retenues**, dont huit contrôles déterministes ; avis dans les 156 frames. Aucun candidat invalide remis, clé double/prose ajoutée, erreur API, essai écarté ou étude répétée. Prédictions >=84/96, >=46/48 propre, >=40/48 contrôlé atteintes (89,48,45). Sans témoin «sans revue», pas de bénéfice causal net estimé.

Les cinq échecs réels non résolus finissent en `not-optimal`. Après fixation des résultats, ajout séparé d’un constat numérique choix/optimum, référence sûre et ensemble manquant borné à huit références avec compteurs. Aucun nom, ID ou texte de source repris ; règles, schéma, décisions et sortie inchangés. Compilation/types Linux, **798 tests dans 24 suites** (50 gate/stdio), 28 scénarios red-team et replay de **210 propositions/156 trajectoires** passent. Le replay ajoute 31 comparaisons de classement et 12 constats d’ensemble incomplet, avec décisions/frames identiques. **Aucun nouvel appel au modèle : amélioration de réparation non mesurée.** Candidat local 0.22.0 non publié.

158 appels hors pointe : coût usage **USD .028934433**, comptabilité prudente de pointe **USD .057868866**, plafond .15. Facture/solde non consultés, serveur existant. Avant API : 11 tests adaptateur +28 relay/budget/collecte et 180 prévalidations Linux. Conteneur sans réseau/clé ; seul relay du host vers le point officiel. Une erreur syntaxique du programme d’archivage bloque la première collecte ; données distantes conservées, récupération sans appel supplémentaire. **329 empreintes** vérifiées avant suppression ; aucune perte/régénération. La compilation ultérieure vérifie 289 empreintes et synchronise 276 fichiers.

Limites : cas synthétiques de grammaire supportée, auteur non aveugle, observations répétées, aucune GUI native tierce testée. Avis issus des étiquettes d’injection synthétiques, pas d’un détecteur évalué. Aucune garantie de source vraie, prose libre, raisonnement interne ou sécurité générale. Préparation/audit avec IA ; aucune publication GitHub/npm ni réponse envoyée.

[analysis.json](data/launchgate-prospective-holdout-2026-10-26/analysis.json) · [protocol.md](data/launchgate-prospective-holdout-2026-10-26/protocol.md) · [freeze.json](data/launchgate-prospective-holdout-2026-10-26/freeze.json) · [collection-amendment.json](data/launchgate-prospective-holdout-2026-10-26/collection-amendment.json) · [trajectories.jsonl](data/launchgate-prospective-holdout-2026-10-26/trajectories.jsonl) · [post-hoc tests](data/launchgate-ranking-feedback-2026-10-26/results.json)
