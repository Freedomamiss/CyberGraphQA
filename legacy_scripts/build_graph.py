"""Build evidence-bearing literal development graphs without repairing extraction outputs."""
import argparse
import hashlib
import json
from pathlib import Path

import extract_cves as extractor
from score_extraction import load_references, digest, read


def node_id(kind, name):
    return kind.lower() + ':' + hashlib.sha256(name.strip().casefold().encode()).hexdigest()[:24]


def assemble(records, graph_kind, source_manifest):
    nodes, edges = {}, {}
    for record in records:
        source = record['source']
        cve = source['cve_id']
        nodes[cve] = {'id': cve, 'type': 'CVE', 'name': cve,
                      'description': source['description'], 'extraction_status': record['status']}
        graph = record['graph']
        if graph is None:
            continue
        local_ids = {}
        for entity in graph['entities']:
            if entity['type'] not in {'Product', 'Vendor'}:
                continue
            identifier = node_id(entity['type'], entity['name'])
            local_ids[entity['id']] = identifier
            node = nodes.setdefault(identifier, {'id': identifier, 'type': entity['type'],
                                   'name': entity['name'], 'observations': []})
            node['observations'].append({**record['provenance'], 'cve_id': cve,
                'source_name': entity['name'], 'evidence': entity['evidence'], 'basis': entity['basis']})
        for relation in graph['relationships']:
            if relation['predicate'] not in {'AFFECTS', 'MADE_BY'}:
                continue
            subject = cve if relation['subject'] == cve else local_ids[relation['subject']]
            target = local_ids[relation['object']]
            key = (subject, relation['predicate'], target)
            edge = edges.setdefault(key, {'subject': subject, 'predicate': relation['predicate'],
                                        'object': target, 'observations': []})
            edge['observations'].append({**record['provenance'], 'cve_id': cve,
                                       'evidence': relation['evidence'], 'basis': relation['basis']})
    return {'schema_version': 1, 'graph_kind': graph_kind, 'production_ready': False,
        'identity_policy': 'Exact label after strip+casefold, scoped by entity type; no aliases or external identity resolution. Shared labels are development identity hypotheses.',
        'source_manifest': source_manifest,
        'record_statuses': [{'cve_id': r['source']['cve_id'], 'status': r['status']} for r in records],
        'nodes': sorted(nodes.values(), key=lambda n: n['id']),
        'edges': sorted(edges.values(), key=lambda e: (e['subject'], e['predicate'], e['object']))}


def from_reference(path, allow_ai=False):
    data, refs = load_references(path, allow_ai)
    provenance = {'origin': 'reviewed_reference', 'reference_sha256': digest(path)}
    records = []
    for row in refs.values():
        records.append({'source': {k: row[k] for k in ('cve_id', 'description')},
            'status': row['review_status'], 'graph': row['reference'],
            'provenance': {**provenance, 'review_status': row['review_status'],
                'reviewer': row['reviewer'], 'review_date': row['review_date'],
                'review_method': row['review_method']}})
    kind = 'ai_reviewed_development' if data['reference_kind'] == 'ai_reviewed_development' else 'human_reviewed_reference'
    return assemble(records, kind, {'reference_sha256': digest(path),
        'reference_kind': data['reference_kind'], 'human_reviewed': data['human_reviewed'],
        'independent_or_blinded': data.get('independent_or_blinded', False), 'policy': data.get('policy', [])})


def from_run(run, inputs):
    run = Path(run)
    config, statuses = read(run / 'config.json'), read(run / 'statuses.json')
    if config.get('dry_run'):
        raise ValueError('Dry runs cannot supply extraction graph facts.')
    if digest(inputs) != config['input_sha256']:
        raise ValueError('Extraction input hash differs from the run.')
    sources = {r['cve_id']: r for r in extractor.load_inputs(Path(inputs))}
    identifiers = [s['cve_id'] for s in statuses]
    if identifiers != config['selected_cve_ids'] or len(set(identifiers)) != len(identifiers):
        raise ValueError('Run selection/status coverage mismatch.')
    records = []
    for status in statuses:
        cve = status['cve_id']; source = sources[cve]
        record_hash = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
        if record_hash != status['record_sha256']:
            raise ValueError('Record hash mismatch: ' + cve)
        path = run / 'validated' / (cve + '.json')
        provenance = {'origin': 'model_extraction', 'run_id': config['run_id'],
            'model_requested': config['model_requested'], 'record_sha256': record_hash,
            'prompt_sha256': config['prompt_sha256'], 'review_status': 'structural_validation_only'}
        if status['status'] == 'validated':
            graph = read(path)
            extractor.validate_track(graph, source, config.get('extraction_track', 'combined'))
            provenance['validated_graph_sha256'] = digest(path)
        elif status['status'] == 'failed':
            if path.exists():
                raise ValueError('Failed record has a validated graph: ' + cve)
            graph = None
        else:
            raise ValueError('Unknown extraction status: ' + cve)
        records.append({'source': source, 'status': status['status'], 'graph': graph, 'provenance': provenance})
    return assemble(records, 'model_candidate_development', {
        'run_id': config['run_id'], 'config_sha256': digest(run / 'config.json'),
        'statuses_sha256': digest(run / 'statuses.json'), 'input_sha256': digest(inputs),
        'model_requested': config['model_requested'], 'extraction_track': config.get('extraction_track', 'combined'),
        'runner_sha256': config['runner_sha256'], 'prompt_sha256': config['prompt_sha256'],
        'schema_sha256': config['schema_sha256'], 'model_provenance_sha256': digest(run / 'model_provenance.json'),
        'semantic_review_performed': False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--reference', type=Path)
    source.add_argument('--run', type=Path)
    parser.add_argument('--input', type=Path, default=Path('data/processed/extraction_inputs.jsonl'))
    parser.add_argument('--allow-ai-reference', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        graph = from_reference(args.reference, args.allow_ai_reference) if args.reference else from_run(args.run, args.input)
        graph['builder_sha256'] = digest(__file__)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as handle:
            json.dump(graph, handle, indent=2, ensure_ascii=False); handle.write('\n')
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, 'Graph build stopped: ' + str(error) + '\n')
    print(json.dumps({'graph_kind': graph['graph_kind'], 'nodes': len(graph['nodes']),
        'edges': len(graph['edges']), 'records': len(graph['record_statuses']), 'production_ready': False}))


if __name__ == '__main__':
    main()
