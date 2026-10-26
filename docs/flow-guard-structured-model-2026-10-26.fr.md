# Test réel du modèle avec réponses structurées

[en](flow-guard-structured-model-2026-10-26.md) · [ru](flow-guard-structured-model-2026-10-26.ru.md) · [es](flow-guard-structured-model-2026-10-26.es.md) · [fr](flow-guard-structured-model-2026-10-26.fr.md) · [zh](flow-guard-structured-model-2026-10-26.zh.md)

26 octobre 2026. WARDEN local **0.22.0**, runtime inchangé, non publié sur npm. Suite du [gate de l’application](flow-guard-answer-gate.fr.md) et de [l’étude à quatre conditions](flow-guard-review-factors-2026-10-26.fr.md).

## Protocole et résultats

160 nouveaux appels `deepseek-flash` sur Linux factory-vps : température .3, thinking désactivé, JSON object mode, maximum 700 tokens de sortie. Le véritable SDK contrôle toutes les règles, l’ensemble complet des admissibles et le prix minimal. Aucune proposition n’est modifiée silencieusement pour la faire passer.

Douze conversations enregistrées conservent l’instruction externe et l’ancienne réponse en prose. Une nouvelle demande exige son remplacement complet par le catalogue normalisé et quatre champs. Huit répétitions par contexte donnent **96/96 premières propositions valides**, dont **32/32** issues des quatre contextes auparavant contradictoires. Les huit autres contextes avaient des explications étayées. Il n’y a donc aucune occasion naturelle de réparation.

Séparément, l’expérimentateur introduit de fausses listes : ensemble réellement admissible plus C (190 > 150) ou D (2.5 > 1). Ce sont des **erreurs initiales synthétiques**, pas de nouveaux échecs spontanés du modèle. Quatre contextes et huit répétitions par type donnent **32/32 C et 32/32 D corrigés au premier appel réel de réparation**. La graine consomme la proposition initiale du SDK ; au plus deux réparations restent. Cette population ne se mélange pas à l’exactitude des premières propositions naturelles.

Aucune des 160 propositions nouvelles n’admet C/D, de clés JSON doubles, de format invalide ou de champs supplémentaires. **160 résultats validés et 160 avis de l’application** sont capturés, sans candidat non vérifié ni erreur API. Aucune substitution C→D ni tentative écartée. Les deux prédictions figées sont atteintes : >=80/96 naturel, >=48/64 contrôlé.

**Aucun cas n’a nécessité une deuxième réparation ou une retenue.** Leurs taux avec modèle réel ne sont donc pas mesurés ; les tests déterministes/stdio antérieurs vérifient leur mécanisme. Chaque trajectoire a utilisé un seul appel réel.

L’accumulation de l’ancienne affirmation fausse n’apparaît pas sur la surface structurée mesurée. Le schéma contient une seule liste d’admissibles, sans prose, prix ou exclusion rédigés par le modèle. Contrat, catalogue et instruction ont changé ensemble : pas de témoin prose contemporain, d’effet causal isolé du format ni de jeu indépendant. Douze contextes connus répétés ne prouvent ni fiabilité générale ni résistance universelle aux injections.

## Audit, coût et limites

Les valeurs finales sont recalculées sur les faits d’origine, sans appeler le validateur runtime. Le frame capturé est la frontière mesurée ; le rendu dans une GUI native tierce reste non testé. Véracité de la source, explications libres, autorisation de paiements/actions et influence cachée entre ex æquo restent hors portée.

Avant API : **9 tests Node + 28 tests relay/budget/collecte**, et 480 prévalidations de requêtes, sous Linux. Le conteneur n’a ni réseau ni clé ; seul le relay local accède au point officiel. Tous les échanges sont conservés ; **333 empreintes** vérifiées avant suppression du dossier temporaire. Aucun nouvel essai automatique ou répétition de l’étude. Aucun correctif runtime nécessaire.

Tous les appels sont hors pointe. Usage : 211 200 tokens d’entrée, dont 103 936 en cache ; 17 946 en sortie. Selon le [tarif publié](https://api-docs.deepseek.com/quick_start/pricing/), **USD 0.027169008** ; comptabilité prudente aux prix de pointe **USD 0.054338016**, sous le plafond **USD 0.15**. Facture et variation du solde non consultées ; serveur existant utilisé.

Préparation/audit assistés par IA et non aveugles ; aucune revue humaine indépendante revendiquée. Aucune publication GitHub/npm ni réponse envoyée.

[analysis.json](data/launchgate-structured-model-2026-10-26/analysis.json) · [protocol.md](data/launchgate-structured-model-2026-10-26/protocol.md) · [execution.json](data/launchgate-structured-model-2026-10-26/execution.json) · [output-audit.json](data/launchgate-structured-model-2026-10-26/output-audit.json) · [trajectories.jsonl](data/launchgate-structured-model-2026-10-26/trajectories.jsonl) · [manifest.json](data/launchgate-structured-model-2026-10-26/manifest.json)
