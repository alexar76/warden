# Validation structurée contrôlée par l’application

[en](flow-guard-answer-gate.md) · [ru](flow-guard-answer-gate.ru.md) · [es](flow-guard-answer-gate.es.md) · [fr](flow-guard-answer-gate.fr.md) · [zh](flow-guard-answer-gate.zh.md)

Candidat local **0.22.0**, 26 octobre 2026 ; aucune publication npm. Suite de [l’étude à quatre conditions](flow-guard-review-factors-2026-10-26.fr.md) : retirer l’erreur de prix de C introduisait parfois l’erreur de distance de D. Supprimer une contradiction ne garantit pas une correction complète.

## Contrat et portée

`createAnswerGate`, exporté par `@aimarket/warden`, exige une intégration explicite. L’application possède les règles utilisateur/politique, les données normalisées, session/tour, génération et affichage final. Elle garde les candidats en mémoire jusqu’à validation. Les instructions d’un serveur externe ne doivent jamais définir les règles.

Le catalogue remplace identifiants et noms de champs par `rec-…` et `field_1`. Le retour précise enregistrement, champ, valeur réelle et borne sans reprendre noms, URL ou instructions externes. `referenceForRecord(sourceId)` est réservé à l’application. Le SHA-256 lie session, tour, données complètes, règles et classement ; réordonner les données conserve les références.

La proposition contient exactement `schema: "warden-selection/1"`, `catalogSha256`, `selectedRef` et `eligibleRefs`. Exemples JSON et API dans la [version anglaise](flow-guard-answer-gate.md).

À chaque proposition, **le choix et toutes les alternatives déclarées admissibles sont vérifiés contre toutes les règles**, puis l’ensemble complet des admissibles et un classement numérique min/max facultatif. Les ex æquo optimaux sont permis. Opérateurs : `lte`/`gte` sur nombres finis, `eq` numérique/booléen strict. Données nécessaires absentes ou mal typées, contrat périmé, références inconnues, clés JSON doubles, prose et champs supplémentaires ne permettent jamais la remise. Aucun admissible entraîne une retenue.

Seules les données structurées validées sont rendues ; leurs valeurs viennent de l’instantané de l’application. Les explications arbitraires, dates, géographie, véracité de la source et influences cachées sur les préférences ne sont pas vérifiées. L’application normalise les unités et choisit les règles. Un résultat autorisé ne permet aucun paiement, action ou outil.

## Boucle bornée et sortie

`gate.run({ generate, emit, maxCorrections: 2, timeoutMs: 30000 })` accepte une proposition initiale et **au plus deux corrections**, soit un passage supplémentaire par rapport au mécanisme à une correction. Après C→D, le retour suivant signale `2.5 > 1` pour D. À la limite, la sortie est `WARDEN_RESULT_WITHHELD`, jamais le candidat rejeté. Les seules limites sont 0/1/2.

Une instance réserve une exécution/sortie. Échec de génération, annulation et expiration n’entraînent aucune répétition automatique ; une réponse tardive ne publie rien. L’adaptateur doit respecter `signal` pour arrêter sa propre activité. Une remise incertaine n’est pas renvoyée. L’application gère l’exclusivité entre instances et évite la diffusion des candidats ou journaux non vérifiés.

L’avis fixe appartient à l’application, indépendamment du modèle. `disclosure: "source-instructions"` nécessite une preuve d’instructions détectées ; par défaut, l’avis indique l’usage de données externes. L’application doit afficher cet avis. L’[exemple stdio](../examples/answer-gate-host.mjs), avec `--contract host-owned.json`, lit les propositions sur stdin, écrit catalogue/constats sur stderr, et uniquement le résultat final validé ou un refus sur stdout. Il n’appelle ni modèle, API ni outil.

**Le Stop-hook ordinaire ne possède pas l’affichage final.** Il conserve une seule continuation. La retenue exige l’intégration du SDK et la mise en mémoire avant sortie. Notre test stdio ne vérifie pas le rendu des clients natifs tiers.

## Vérification et limites

Éléments dans `docs/evidence/launchgate-answer-gate-2026-10-26/` du monorepo. Compilation et tests sur Linux factory-vps, sans nouvel appel au modèle : C→D→résultat valide, retenue de D persistant, ensembles complets, classement/ex æquo, données inconnues/périmées, métadonnées hostiles, annulation, délais, concurrence, remise incertaine et stdout d’un vrai processus.

La répétition historique projette seulement les listes d’admissibilité explicitement annotées de 384 réponses conservées. La prose non prise en charge reste inconnue. Refuser une liste fausse encodée ne démontre ni compréhension de prose, ni réparation par le modèle, ni sécurité sur un ensemble indépendant. Les anciens textes et résultats restent inchangés.

Un dialogue brut complet du cas persistant a été lu : la même réponse déclare C admissible à $129 et exclu à $190. C’est une contradiction observable, sans preuve de mécanisme interne. Préparation et analyse assistées par IA ; aucune revue indépendante en aveugle n’est revendiquée.

<!-- verified-answer-gate-results -->

Vérifié sur Linux factory-vps : compilation/types, **791 tests dans 24 suites**, dont **43 tests gate/stdio**, et les 28 scénarios red-team existants. Sur 384 projections historiques : 50 listes fausses refusées, 75 valides permises, 259 réponses en prose non prises en charge inconnues ; aucun candidat non vérifié remis. Ce sont des projections d’annotations, pas de nouvelles corrections du modèle. Vérification de 289 empreintes et synchronisation de 276 fichiers locaux compilés sous Linux. Les deux essais précédents avec erreurs syntaxiques de tests sont conservés.

[results.json](data/launchgate-answer-gate-2026-10-26/results.json) · [execution.json](data/launchgate-answer-gate-2026-10-26/execution.json) · [historical-replay.json](data/launchgate-answer-gate-2026-10-26/historical-replay.json) · [stubborn-transcript.json](data/launchgate-answer-gate-2026-10-26/stubborn-transcript.json) · [manifest.json](data/launchgate-answer-gate-2026-10-26/manifest.json)

<!-- structured-live-followup -->

[Test réel des réponses structurées](flow-guard-structured-model-2026-10-26.fr.md) : 96 premières propositions valides et 64 réparations contrôlées ; dénominateurs et limites séparés.
