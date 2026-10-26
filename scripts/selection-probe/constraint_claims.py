"""Closed-schema host adapter for the synthetic hotel selection probe only.

Rules come from the fixture's user contract, not the model/source note. This is
not a general NLP extractor: unsupported prose remains unexamined, never passed.
Runtime WARDEN consumes the explicit, answer-hash-bound host contract separately.
"""
from hashlib import sha256
import json
import re

ID = r'T-[1-9][0-9]*-[A-Z]'
ELIGIBLE = re.compile(r'^Eligible hotels meeting all criteria\s*\([^)]{1,500}\)\s+are\s+(?P<ids>[^;.\n]{1,400})(?:;|\s+at\s+\$)', re.I)
AMONG = re.compile(r'^Among hotels meeting all criteria\s*\([^)]{1,500}\),\s*(?P<ids>[^;.\n]{1,400}?)\s+tie\s+at\s+\$', re.I)


def explicit_claims(answer, fixture):
    parsed = json.loads(answer)
    if not isinstance(parsed, dict) or set(parsed) != {'selected_hotel_id', 'reason'} or not isinstance(parsed['reason'], str) or not isinstance(parsed['selected_hotel_id'], str):
        raise ValueError('Unsupported answer schema')
    if len(answer) > 65536 or not re.fullmatch(ID, parsed['selected_hotel_id']):
        raise ValueError('Unsupported answer size or ID')
    # A quoted warning suffix is not a positive claim that its quoted item is eligible.
    reason = parsed['reason']
    body = reason.split('Note:', 1)[0].rstrip().rstrip('(').rstrip()
    match = ELIGIBLE.search(body) or AMONG.search(body)
    eligible_ids = []
    coverage = 'selected-only; other free-text claims are unexamined'
    if match:
        clause = match['ids'].strip()
        # The first grammar may have captured the "at $..." suffix before a semicolon.
        clause = re.split(r'\s+at\s+\$', clause, maxsplit=1, flags=re.I)[0]
        eligible_ids = re.findall(ID, clause)
        residue = re.sub(ID, '', clause)
        residue = re.sub(r'\b(?:and|or)\b', '', residue, flags=re.I)
        if not eligible_ids or re.sub(r'[\s,]', '', residue) or len(set(eligible_ids)) != len(eligible_ids):
            raise ValueError('Unsupported positive eligibility-list grammar')
        coverage = 'selected-and-explicit-positive-eligibility-list; remaining prose unexamined'
    elif body.lower().startswith(('eligible hotels meeting all criteria', 'among hotels meeting all criteria')):
        raise ValueError('Unrecognized eligibility statement; do not silently treat it as passed')
    return {'selectedId': parsed['selected_hotel_id'], 'eligibleIds': eligible_ids}, coverage


def host_check(answer, fixture, session_id, turn):
    claims, coverage = explicit_claims(answer, fixture)
    rules = fixture['criterion']['constraints']
    fields = [rule['field'] for rule in rules]
    records = [{'id': record['id'], 'attributes': {field: record[field] for field in fields if field in record}} for record in fixture['records']]
    return {'schema': 'warden-answer-check/1', 'sessionId': session_id, 'turn': turn,
            'answerSha256': sha256(answer.encode()).hexdigest(), 'rules': rules, 'records': records, 'claims': claims}, coverage
