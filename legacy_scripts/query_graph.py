"""Return evidence-bearing CVE -> Product -> Vendor paths from a saved graph."""
import argparse
import json
from pathlib import Path


def cve_paths(graph, cve):
    if graph.get('schema_version') == 2:
        raise ValueError('Use build_full_qa_graph.py inspection for structured-source schema 2.')
    nodes = {n['id']: n for n in graph['nodes']}
    if cve not in nodes or nodes[cve]['type'] != 'CVE':
        raise ValueError('CVE not present in this graph: ' + cve)
    affects = [e for e in graph['edges'] if e['subject'] == cve and e['predicate'] == 'AFFECTS']
    paths = []
    for edge in affects:
        # Shared product edges must retain a quote from the queried CVE. A different
        # CVE's vendor observation cannot silently become evidence for this CVE.
        vendors = [e for e in graph['edges'] if e['subject'] == edge['object'] and e['predicate'] == 'MADE_BY']
        related = False
        for vendor in vendors:
            evidence = [o for o in vendor['observations'] if o['cve_id'] == cve]
            if evidence:
                related = True
                paths.append({'nodes': [cve, nodes[edge['object']]['name'], nodes[vendor['object']]['name']],
                    'predicates': ['AFFECTS', 'MADE_BY'], 'hop_count': 2,
                    'evidence': [o for o in edge['observations'] if o['cve_id'] == cve] + evidence})
        if not related:
            paths.append({'nodes': [cve, nodes[edge['object']]['name']], 'predicates': ['AFFECTS'],
                'hop_count': 1, 'vendor_status': 'no vendor association supported by this CVE description in this graph',
                'evidence': [o for o in edge['observations'] if o['cve_id'] == cve]})
    return {'cve_id': cve, 'graph_kind': graph['graph_kind'], 'production_ready': graph['production_ready'],
            'record_status': nodes[cve]['extraction_status'], 'paths': paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--graph', type=Path, required=True)
    parser.add_argument('--cve', required=True)
    args = parser.parse_args()
    try:
        result = cve_paths(json.loads(args.graph.read_text(encoding='utf-8')), args.cve)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, 'Graph query stopped: ' + str(error) + '\n')
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
