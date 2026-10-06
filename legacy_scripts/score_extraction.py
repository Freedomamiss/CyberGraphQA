"""Score accepted literal graphs; reject unreviewed references and retain failure coverage."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

import extract_cves as extractor


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def literal_sets(graph):
    """Match names/types and edge endpoints, independent of model-generated graph IDs."""
    entities = {e['id']: (e['type'], e['name'].strip().casefold())
                for e in graph['entities'] if e['type'] in {'Product', 'Vendor'}}
    relations = set()
    for edge in graph['relationships']:
        if edge['predicate'] not in {'AFFECTS', 'MADE_BY'}:
            continue
        subject = ('CVE', graph['cve_id']) if edge['subject'] == graph['cve_id'] else entities[edge['subject']]
        relations.add((subject, edge['predicate'], entities[edge['object']]))
    return set(entities.values()), relations


def compare(predicted, reference):
    return {'tp': len(predicted & reference), 'fp': len(predicted - reference),
            'fn': len(reference - predicted)}


def metrics(counts):
    tp, fp, fn = (counts[k] for k in ('tp', 'fp', 'fn'))
    # Undefined precision/recall are null, rather than rewarding an empty output.
    return {**counts, 'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def load_references(path, allow_ai=False):
    data = read(path)
    if not isinstance(data, dict) or not isinstance(data.get('records'), list):
        raise ValueError('Reference must be a reviewed object with a records array; drafts cannot be scored.')
    kind = data.get('reference_kind')
    if kind == 'ai_reviewed_development':
        if not allow_ai:
            raise ValueError('AI reference requires --allow-ai-reference; results are development diagnostics.')
        if data.get('human_reviewed') is not False or data.get('independent_or_blinded') is not False:
            raise ValueError('AI reference provenance must explicitly deny human and blinded review.')
        status = 'ai_reviewed'
    elif kind == 'human_reviewed':
        if data.get('human_reviewed') is not True:
            raise ValueError('Human reference provenance is inconsistent.')
        status = 'approved'
    else:
        raise ValueError('Reference must declare a reviewed reference_kind; drafts cannot be scored.')
    result = {}
    for record in data['records']:
        identifier = record['cve_id']
        if identifier in result:
            raise ValueError('Duplicate reference CVE.')
        if record.get('review_status') != status or not record.get('reviewer') or not record.get('review_date') or not record.get('review_method'):
            raise ValueError('Every reference needs matching review status, reviewer, date, and method.')
        extractor.validate_track(record['reference'], {'cve_id': identifier, 'description': record['description']}, 'literal')
        result[identifier] = record
    if not result:
        raise ValueError('Reference set is empty.')
    return data, result


def score_run(run, reference_path, allow_ai=False):
    run = Path(run)
    data, references = load_references(reference_path, allow_ai)
    config = read(run / 'config.json')
    statuses = read(run / 'statuses.json')
    identifiers = [s['cve_id'] for s in statuses]
    if len(set(identifiers)) != len(identifiers) or set(identifiers) != set(references):
        raise ValueError('Run statuses must cover exactly the reference IDs, without duplicates.')
    if config['selected_cve_ids'] != identifiers:
        raise ValueError('Config selection and statuses disagree.')
    totals = {'entities': Counter(tp=0, fp=0, fn=0), 'relationships': Counter(tp=0, fp=0, fn=0)}
    rows = []
    accepted = 0
    for status in statuses:
        identifier = status['cve_id']
        source = {k: references[identifier][k] for k in ('cve_id', 'description')}
        source_hash = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
        if status['record_sha256'] != source_hash:
            raise ValueError('Source mismatch for ' + identifier)
        if status['status'] == 'validated':
            graph = read(run / 'validated' / (identifier + '.json'))
            extractor.validate_track(graph, source, config.get('extraction_track', 'combined'))
            predicted = literal_sets(graph)
            accepted += 1
        elif status['status'] == 'failed':
            if (run / 'validated' / (identifier + '.json')).exists():
                raise ValueError('Failed record has a validated graph: ' + identifier)
            predicted = (set(), set())
        else:
            raise ValueError('Unexpected status for ' + identifier)
        reference = literal_sets(references[identifier]['reference'])
        row = {'cve_id': identifier, 'pipeline_status': status['status']}
        for index, category in enumerate(totals):
            counts = compare(predicted[index], reference[index])
            totals[category].update(counts)
            row[category] = {**metrics(counts),
                'missing': sorted(reference[index] - predicted[index]),
                'extra': sorted(predicted[index] - reference[index])}
        row['exact_literal_match'] = predicted == reference
        rows.append(row)
    ai = data['reference_kind'] == 'ai_reviewed_development'
    return {'run_id': config['run_id'], 'extraction_track': config.get('extraction_track', 'combined'),
        'model': config['model_requested'], 'reference_kind': data['reference_kind'],
        'development_diagnostic_only': ai, 'human_reference_accuracy_scored': not ai,
        'reference_sha256': digest(reference_path),
        'run_config_sha256': digest(run / 'config.json'), 'statuses_sha256': digest(run / 'statuses.json'),
        'scorer_sha256': digest(__file__),
        'scoring_policy': 'Micro counts summed per CVE; exact type/name matching after strip+casefold; graph IDs ignored; no alias/fuzzy matching; literal projection only; failed records predict empty sets; no raw-output salvage.',
        'requested_records': len(rows), 'validated_records': accepted,
        'failed_records': len(rows) - accepted, 'validation_pass_rate': accepted / len(rows),
        'exact_literal_matches': sum(row['exact_literal_match'] for row in rows),
        'entities': metrics(dict(totals['entities'])),
        'relationships': metrics(dict(totals['relationships'])), 'records': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--runs', type=Path, nargs='+', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-ai-reference', action='store_true')
    args = parser.parse_args()
    try:
        results = [score_run(run, args.reference, args.allow_ai_reference) for run in args.runs]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as handle:
            json.dump({'results': results}, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, 'Scoring stopped: ' + str(error) + '\n')
    for result in results:
        entity_f1 = result['entities']['f1']
        edge_f1 = result['relationships']['f1']
        print(result['run_id'], 'accepted', str(result['validated_records']) + '/' + str(result['requested_records']),
              'entity F1', round(entity_f1, 4) if entity_f1 is not None else 'undefined',
              'edge F1', round(edge_f1, 4) if edge_f1 is not None else 'undefined',
              '(AI-reference development diagnostic)' if result['development_diagnostic_only'] else '(human-reviewed reference)')


if __name__ == '__main__':
    main()
