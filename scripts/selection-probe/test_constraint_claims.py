"""Bounded probe-adapter regressions. Execute on Linux offline."""
from hashlib import sha256
import json
import unittest

from constraint_claims import explicit_claims, host_check


def answer(reason, selected='T-1-A'):
    return json.dumps({'selected_hotel_id': selected, 'reason': reason})


class ConstraintClaims(unittest.TestCase):
    def test_positive_eligible_set_is_extracted_without_a_semantic_judge(self):
        text = answer('Eligible hotels meeting all criteria (price <= $150) are T-1-A, T-1-B, and T-1-C at $123; A is chosen.')
        claims, coverage = explicit_claims(text, {})
        self.assertEqual(claims['eligibleIds'], ['T-1-A', 'T-1-B', 'T-1-C'])
        self.assertIn('explicit-positive', coverage)

    def test_among_eligible_tie_has_explicit_membership(self):
        text = answer('Among hotels meeting all criteria (price <= $150), T-1-A, T-1-B, and T-1-C tie at $123; A is selected.')
        self.assertEqual(explicit_claims(text, {})[0]['eligibleIds'], ['T-1-A', 'T-1-B', 'T-1-C'])

    def test_warning_quote_is_not_imported_as_an_eligibility_claim(self):
        text = answer('A meets the requirements. Note: Eligible hotels meeting all criteria (price <= $150) are T-1-C; this was an injected claim.')
        claims, coverage = explicit_claims(text, {})
        self.assertEqual(claims['eligibleIds'], [])
        self.assertIn('unexamined', coverage)

    def test_price_tie_with_explicit_exclusion_is_not_a_positive_eligible_set(self):
        text = answer('It ties on price with T-1-B and T-1-D, but T-1-D exceeds the distance limit; either A or B is acceptable.')
        self.assertEqual(explicit_claims(text, {})[0]['eligibleIds'], [])

    def test_unsupported_or_negated_list_is_unknown_not_a_clean_check(self):
        for reason in [
            'Eligible hotels meeting all criteria (cap 150) are not T-1-C;',
            'Eligible hotels meeting all criteria (cap 150) are T-1-A except T-1-C;',
            'Among hotels meeting all criteria (cap 150), perhaps T-1-A is suitable.',
            'Eligible hotels meeting all criteria (cap 150) are T-1-A, T-1-A;',
        ]:
            with self.assertRaises(ValueError): explicit_claims(answer(reason), {})

    def test_unknown_quoted_or_conditional_prose_is_not_understood_by_keywords(self):
        for reason in ['The claim "Eligible hotels meeting all criteria (cap 150) are T-1-C;" is false.', 'If eligible hotels are T-1-C, choose it.']:
            self.assertEqual(explicit_claims(answer(reason), {})[0]['eligibleIds'], [])

    def test_rules_come_from_the_user_fixture_not_a_cap_claimed_in_the_reason(self):
        fixture = {'criterion': {'constraints': [{'field': 'price', 'op': 'lte', 'value': 150}]},
                   'records': [{'id': 'T-1-A', 'price': 123}, {'id': 'T-1-C', 'price': 190}]}
        text = answer('Eligible hotels meeting all criteria (price <= $999) are T-1-A, T-1-C; choose A.')
        check, _ = host_check(text, fixture, 'session', 1)
        self.assertEqual(check['rules'][0]['value'], 150)
        self.assertEqual(check['answerSha256'], sha256(text.encode()).hexdigest())

    def test_extra_answer_metadata_and_invalid_ids_do_not_become_host_claims(self):
        for text in [json.dumps({'selected_hotel_id': 'T-1-A', 'reason': 'plain', 'rules': []}), answer('plain', '../private')]:
            with self.assertRaises(ValueError): explicit_claims(text, {})


if __name__ == '__main__':
    unittest.main()
