"""Build a structured-source development graph and an identical-fact text export.

Schema 2 is separate from the literal pilot graph. This is not LLM extraction,
conflict adjudication, or a held-out QA experiment.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from audit_frozen_dataset import audit, digest, read, require


def stable(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def identifier(kind, key):
    return kind.lower() + ':' + hashlib.sha256(key.encode()).hexdigest()[:24]


def assemble(rows, source_manifest):
    nodes, edges, units = {}, {}, []
    require(len({r['cve_id'] for r in rows}) == len(rows), 'Duplicate CVEs')
    for row in sorted(rows, key=lambda r: r['cve_id']):
        cve = row['cve_id']; fp = row['field_provenance_json']
        nodes[cve] = {'id': cve, 'type': 'CVE', 'name': cve,
            'kev_listed': row['kev_listed'], 'snapshot_id': row['snapshot_id']}

        def node(kind, key, name):
            nid = identifier(kind, key)
            nodes.setdefault(nid, {'id': nid, 'type': kind, 'name': name, 'identity_key': key})
            return nid

        def evidence(kind, key, text, value, provenance):
            eid = 'source:' + hashlib.sha256(stable([cve, kind, key]).encode()).hexdigest()[:24]
            unit = {'evidence_id': eid, 'cve_id': cve, 'kind': kind, 'value': value,
                'origin': 'frozen_structured_sources', 'snapshot_id': row['snapshot_id'],
                'canonical_source_sha256': source_manifest['input_sha256']['data/processed/cves.json'],
                'provenance': provenance, 'source_urls': row['source_urls_json'],
                'conflict_flags': row['conflict_flags_json'], 'missing_fields': row['missing_fields_json'],
                'human_verified': False, 'source_conflicts_adjudicated': False,
                'text': text + ' | snapshot=' + row['snapshot_id'] +
                    ' | flags=' + stable(row['conflict_flags_json']) +
                    ' | missing=' + stable(row['missing_fields_json'])}
            units.append(unit)
            return eid

        def relation(subject, predicate, obj, provenance):
            key = (subject, predicate, obj)
            eid = evidence('relation', key, nodes[subject]['name'] + ' ' + predicate + ' ' + nodes[obj]['name'],
                {'subject': subject, 'predicate': predicate, 'object': obj}, provenance)
            edge = edges.setdefault(key, {'subject': subject, 'predicate': predicate, 'object': obj, 'evidence_ids': []})
            edge['evidence_ids'].append(eid)

        evidence('description', 'description', cve + ': ' + row['description'], row['description'], fp['description'])
        seen = set()
        for pair in row['affected_products_json']:
            require(pair['vendor_key'] == pair['vendor'].strip().casefold(), 'Vendor key mismatch')
            require(pair['product_key'] == pair['vendor_key'] + '::' + pair['product'].strip().casefold(), 'Product key mismatch')
            if pair['product_key'] in seen:
                raise ValueError('Duplicate product pair in ' + cve)
            seen.add(pair['product_key'])
            vendor = node('Vendor', pair['vendor_key'], pair['vendor'])
            product = node('Product', pair['product_key'], pair['product'] + ' [vendor: ' + pair['vendor'] + ']')
            provenance = {'field': fp['affected_products'], 'pair': pair}
            relation(cve, 'AFFECTS', product, provenance)
            relation(product, 'MADE_BY', vendor, provenance)
        for cwe in row['cwe_ids_json']:
            require(cwe.startswith('CWE-') and cwe[4:].isdigit(), 'Invalid CWE')
            relation(cve, 'HAS_WEAKNESS', node('CWE', cwe, cwe),
                {'field': fp['cwe_ids'], 'nvd_record': fp.get('nvd_record'),
                 'cna_raw_file': fp['description'].get('raw_file')})
        if row['cvss_score'] is not None:
            relation(cve, 'HAS_SEVERITY', node('Severity', row['severity'], row['severity']),
                {'field': fp['cvss'], 'nvd_record': fp.get('nvd_record'),
                 'cna_raw_file': fp['description'].get('raw_file')})
            value = {k: row[k] for k in ['cvss_score', 'cvss_version', 'cvss_vector', 'cvss_source']}
            evidence('property', 'cvss', cve + ' SELECTED_CVSS ' + stable(value), value, fp['cvss'])
        kev = {'kev_listed': row['kev_listed'], 'kev_date_added': row['kev_date_added']}
        evidence('property', 'kev', cve + ' KEV_SNAPSHOT_MEMBERSHIP ' + stable(kev), kev, fp['kev_listed'])
        evidence('property', 'published_date', cve + ' PUBLISHED_DATE ' + str(row['published_date']),
            row['published_date'], fp['published_date'])
        evidence('record_status', 'status', cve + ' SOURCE_STATUS unadjudicated structured metadata',
            {'conflict_flags': row['conflict_flags_json'], 'missing_fields': row['missing_fields_json']}, fp)
    require(len({u['evidence_id'] for u in units}) == len(units), 'Duplicate evidence IDs')
    return {'schema_version': 2, 'graph_kind': 'structured_source_development',
        'production_ready': False, 'llm_extraction_graph': False, 'human_gold': False,
        'source_conflicts_adjudicated': False,
        'identity_policy': 'Exact strip+casefold vendor keys; vendor-qualified product keys; no aliases.',
        'source_manifest': source_manifest, 'nodes': sorted(nodes.values(), key=lambda n: n['id']),
        'edges': sorted(edges.values(), key=lambda e: (e['subject'], e['predicate'], e['object'])),
        'evidence_units': sorted(units, key=lambda u: (u['cve_id'], u['evidence_id']))}


def documents(graph):
    """Both views use the same complete units, including provenance and flags."""
    result = []
    for cve in sorted(n['id'] for n in graph['nodes'] if n['type'] == 'CVE'):
        facts = [u for u in graph['evidence_units'] if u['cve_id'] == cve]
        result.append({'cve_id': cve, 'facts': facts,
            'text': '\n'.join('[' + u['evidence_id'] + '] ' + u['text'] for u in facts)})
    return result


def inspect(graph, cve):
    by_id = {u['evidence_id']: u for u in graph['evidence_units']}
    names = {n['id']: n['name'] for n in graph['nodes']}
    require(cve in names, 'CVE not present: ' + cve)
    paths = []
    for edge in graph['edges']:
        if edge['subject'] != cve:
            continue
        local = [eid for eid in edge['evidence_ids'] if by_id[eid]['cve_id'] == cve]
        paths.append({'nodes': [cve, names[edge['object']]], 'predicates': [edge['predicate']], 'evidence_ids': local})
        if edge['predicate'] == 'AFFECTS':
            for vendor in graph['edges']:
                if vendor['subject'] == edge['object'] and vendor['predicate'] == 'MADE_BY':
                    own = [eid for eid in vendor['evidence_ids'] if by_id[eid]['cve_id'] == cve]
                    if own:
                        paths.append({'nodes': [cve, names[edge['object']], names[vendor['object']]],
                            'predicates': ['AFFECTS', 'MADE_BY'], 'evidence_ids': local + own})
    return {'cve_id': cve, 'paths': paths,
        'evidence_units': [u for u in graph['evidence_units'] if u['cve_id'] == cve]}


def write(path, value):
    with path.open('x', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2); handle.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--expected-snapshot', default='cgqa-5495aa3949d0b789')
    parser.add_argument('--inspect-cve', default='CVE-2020-16009')
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        verified = audit(root, args.expected_snapshot)
        require(verified['input_sha256']['data/processed/cves.json'] ==
            '656a56ec884c39168cad87ab0ff10281ada2a747a5ddb2ecf76fe6fe9e60f319',
            'Canonical dataset differs from the verified Checkpoint 18 bytes')
        graph = assemble(read(root/'data/processed/cves.json'), verified)
        graph['builder_sha256'] = digest(Path(__file__))
        docs = documents(graph)
        flat = [f for d in docs for f in d['facts']]
        require(flat == graph['evidence_units'], 'Text/graph evidence parity failed')
        report = inspect(graph, args.inspect_cve)
        args.output_dir.mkdir(parents=True, exist_ok=False)
        write(args.output_dir/'graph.json', graph)
        with (args.output_dir/'text-documents.jsonl').open('x', encoding='utf-8') as handle:
            for doc in docs:
                handle.write(json.dumps(doc, ensure_ascii=False) + '\n')
        write(args.output_dir/'inspection.json', report)
        summary = {'schema_version': 1, 'status': 'built_and_parity_checked',
            'snapshot_id': args.expected_snapshot, 'records': len(docs),
            'node_counts': dict(Counter(n['type'] for n in graph['nodes'])),
            'edge_counts': dict(Counter(e['predicate'] for e in graph['edges'])),
            'evidence_units': len(flat), 'text_graph_units_identical': True,
            'model_requests_sent': 0, 'qa_experiment_run': False, 'llm_extraction_graph': False,
            'human_gold': False, 'source_conflicts_adjudicated': False,
            'input_sha256': verified['input_sha256'], 'builder_sha256': graph['builder_sha256'],
            'output_sha256': {name: digest(args.output_dir/name) for name in
                ['graph.json', 'text-documents.jsonl', 'inspection.json']},
            'retrieval_adapter_ready': False,
            'note': 'Schema 2 requires a new retrieval adapter and index. Do not use the literal pilot index.'}
        write(args.output_dir/'build-summary.json', summary)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, 'Full QA graph build stopped: ' + str(error) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
