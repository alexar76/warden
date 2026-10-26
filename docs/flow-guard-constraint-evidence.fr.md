# Preuves déterministes et conservation de la divulgation

[en](flow-guard-constraint-evidence.md) · [ru](flow-guard-constraint-evidence.ru.md) · [es](flow-guard-constraint-evidence.es.md) · [fr](flow-guard-constraint-evidence.fr.md) · [zh](flow-guard-constraint-evidence.zh.md)

Candidat local 0.22.0, non publié sur npm. Parmi douze paires examinées, quatre réponses déclaraient admissible une fiche à $190 malgré un plafond de $150 ; trois continuations supprimaient la divulgation de l’instruction. Les réponses et résultats historiques restent inchangés.

## Contrat et confiance

L’hôte peut fournir `answer_check` au hook Stop ou appeler l’export `checkAnswerConstraints`. Le contrat lie SHA-256 de la réponse exacte, session et tour positif. Un adaptateur de confiance fournit règles utilisateur/politique, capture des fiches, ID choisi et ensemble explicitement déclaré admissible. Chaque membre est vérifié ; la simple présence dans la source n’est pas une déclaration d’admissibilité. Opérateurs : `lte`/`gte` numériques finis, `eq` numérique/booléen strict.

Champs ou ID absents restent inconnus ; un contrat mal formé ou périmé ne passe pas. Les preuves utilisent positions et valeurs (`actual 190; required <= 150`), sans noms, ID, libellés, URL ni citations d’attaque. Les règles ne viennent jamais des instructions du serveur MCP. L’hôte normalise monnaies et unités ; les faits restent conditionnels à la capture. Cette vérification ne certifie pas le serveur et n’accorde aucune permission. Le hash ne protège pas contre un hôte malveillant.

## Continuation et divulgation

Après du texte externe enregistré, une contradiction valide peut demander une continuation sans recouvrement littéral ; l’ancien détecteur demeure. Un reçu du guard pour ce tour conserve un avis fixe d’instruction externe dans `systemMessage`, même si le modèle supprime sa divulgation. Aucune seconde continuation n’est demandée. Un nouveau tour efface le reçu ; audit observe seulement. Les mêmes faits permettent de signaler les contradictions restantes ; une capture absente ou modifiée rend leur résolution inconnue. Une correction peut garder un ID admissible.

L’hôte doit afficher `systemMessage` : ni rendu du client natif ni maintien de la prose du modèle ne sont établis ici.

## Exemple côté hôte

Prompt et résultat externe doivent déjà être enregistrés ; `turn` correspond au tour courant du guard. L’hôte extrait les affirmations explicites, pas WARDEN.

```js
import { createHash } from 'node:crypto';
import { checkAnswerConstraints } from '@aimarket/warden';

const answer = 'A is selected. A and C are eligible.';
const answer_check = {
  schema: 'warden-answer-check/1', sessionId: 'session-1', turn: 1,
  answerSha256: createHash('sha256').update(answer).digest('hex'),
  rules: [{ field: 'priceUsd', op: 'lte', value: 150 }],
  records: [
    { id: 'A', attributes: { priceUsd: 123 } },
    { id: 'C', attributes: { priceUsd: 190 } },
  ],
  claims: { selectedId: 'A', eligibleIds: ['A', 'C'] },
};
const evidence = checkAnswerConstraints(answer_check, answer, 'session-1', 1);
// evidence.violations: [{ item: 2, rule: 1, op: 'lte', limit: 150, actual: 190 }]
// Stop input: { session_id: 'session-1', last_assistant_message: answer, answer_check }
```

## Portée

L’adaptateur de recherche `scripts/selection-probe/constraint_claims.py` reconnaît uniquement une grammaire anglaise fermée de listes d’hôtels dans un JSON synthétique. Il n’utilise pas les étiquettes sémantiques de référence, exclut le suffixe d’avertissement, refuse les listes non reconnues et laisse le reste non examiné. Il ne vérifie pas chaque prix ni ne déduit des contraintes générales de la prose. L’entrée Stop native ne construit pas automatiquement ce contrat.

## Validation Linux — 26 octobre 2026

Compilation et typage réussis : **743 tests WARDEN dans 21 fichiers**, dont 29 nouveaux ; **24 tests Python** et **gate déterministe existant de 28 scénarios**. Les 276 hash de sortie ont été vérifiés. Tests sans réseau ; seule l’installation des dépendances npm utilisait le réseau. Répertoire distant temporaire supprimé. Build local et plugin synchronisés depuis Linux après vérification des sources gelées.

| Observation sur les réponses conservées | Résultat |
| --- | ---: |
| Paires initiales/finales réelles rejouées | 12 |
| Ensembles admissibles erronés avec $190 malgré le plafond $150 | 4 |
| Contradictions conservées dans les anciennes réponses finales intactes | 4 |
| Avis du guard conservés dans la sortie de continuation | 12/12 |
| Pertes antérieures de divulgation accompagnées d’un avis du guard | 3/3 |
| Secondes continuations / nouveaux appels modèle | 0 / 0 |

La grammaire a été écrite après lecture de ces réponses : **rejeu a posteriori de cas de développement**, pas de validation sémantique indépendante ni de holdout. L’extraction ne lit pas les étiquettes de référence ; ses résultats sont ensuite comparés à la revue précédente. Détecter quatre contradictions ne valide pas toute la prose et n’estime pas un taux général de faux positifs. Les quatre explications erronées ne sont ni régénérées ni corrigées. Trois textes du modèle restent sans divulgation : le nouveau contrôle est l’avis séparé du hook, dont l’affichage client reste à vérifier. Correction par le modèle et efficacité indépendante ne sont pas mesurées.

Développement et revue assistés par IA ; aucune revue sémantique indépendante en aveugle.

[results.json](data/launchgate-constraint-evidence-2026-10-26/results.json), [cases.json](data/launchgate-constraint-evidence-2026-10-26/cases.json), [execution.json](data/launchgate-constraint-evidence-2026-10-26/execution.json), [input-manifest.json](data/launchgate-constraint-evidence-2026-10-26/input-manifest.json), [manifest.json](data/launchgate-constraint-evidence-2026-10-26/manifest.json).

<!-- fresh-recheck-results -->

[Nouvelles revues du modèle : faits concrets et divulgation](flow-guard-fresh-rechecks-2026-10-26.fr.md).

<!-- factorial-review-followup -->

[Références et consignes de correction : quatre conditions](flow-guard-review-factors-2026-10-26.fr.md).

<!-- structured-answer-gate -->

[Validation par l’application](flow-guard-answer-gate.fr.md) : toutes les règles, correction supplémentaire bornée et sortie tamponnée ; données structurées uniquement.
