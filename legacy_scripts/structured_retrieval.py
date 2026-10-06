"""Schema-2 corpus validation and exact-anchor typed-path development retrieval."""
import re
from collections import defaultdict


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(graph):
    require(graph.get('schema_version') == 2 and graph.get('graph_kind') == 'structured_source_development',
        'Unsupported structured graph')
    nodes = {n['id']: n for n in graph['nodes']}
    units = {u['evidence_id']: u for u in graph['evidence_units']}
    require(len(nodes) == len(graph['nodes']) and len(units) == len(graph['evidence_units']), 'Duplicate graph identities')
    cves = {k for k, n in nodes.items() if n['type'] == 'CVE'}
    for unit in units.values():
        require(unit['cve_id'] in cves and unit['snapshot_id'] == nodes[unit['cve_id']]['snapshot_id'], 'Unit source/snapshot mismatch')
        require(unit['origin'] == 'frozen_structured_sources' and unit['source_conflicts_adjudicated'] is False,
            'Structured source status changed')
    signatures = set(); covered = set(); affects = set()
    types = {'AFFECTS': ('CVE', 'Product'), 'MADE_BY': ('Product', 'Vendor'),
             'HAS_WEAKNESS': ('CVE', 'CWE'), 'HAS_SEVERITY': ('CVE', 'Severity')}
    for edge in graph['edges']:
        triple = (edge['subject'], edge['predicate'], edge['object'])
        require(triple not in signatures, 'Duplicate graph edge'); signatures.add(triple)
        require(edge['subject'] in nodes and edge['object'] in nodes and edge['predicate'] in types,
            'Invalid edge endpoint/predicate')
        require((nodes[edge['subject']]['type'], nodes[edge['object']]['type']) == types[edge['predicate']], 'Invalid typed edge')
        ids = edge['evidence_ids']
        require(bool(ids) and len(ids) == len(set(ids)), 'Empty/duplicate edge evidence')
        for eid in ids:
            require(eid in units, 'Unknown edge evidence')
            unit = units[eid]
            require(unit['kind'] == 'relation' and unit['value'] == {k: edge[k] for k in ['subject','predicate','object']},
                'Edge/evidence value mismatch')
            if edge['predicate'] != 'MADE_BY':
                require(unit['cve_id'] == edge['subject'], 'Borrowed CVE evidence')
            if edge['predicate'] == 'AFFECTS':
                affects.add((unit['cve_id'], edge['object']))
            covered.add(eid)
    require(covered == {k for k,u in units.items() if u['kind']=='relation'}, 'Orphan relation evidence')
    for edge in graph['edges']:
        if edge['predicate'] == 'MADE_BY':
            for eid in edge['evidence_ids']:
                require((units[eid]['cve_id'], edge['subject']) in affects, 'Ownership evidence is not source-local to an affected pair')
    return nodes, units


def corpus(graph):
    nodes, units = validate(graph)
    grouped = defaultdict(list)
    for unit in graph['evidence_units']:
        grouped[unit['cve_id']].append(unit)
    documents = {}
    for cve in sorted(k for k,n in nodes.items() if n['type']=='CVE'):
        facts = grouped[cve]
        require(any(f['kind']=='description' for f in facts), 'Missing CVE description unit')
        require(any(f['kind']=='record_status' for f in facts), 'Missing CVE status unit')
        documents[cve] = {'cve_id': cve, 'extraction_status': 'structured_source_unadjudicated',
            'facts': facts, 'text': '\n'.join(f['text'] for f in facts)}
    return documents


def mentions(question, label):
    return bool(re.search(r'(?<!\w)' + re.escape(label.strip()) + r'(?!\w)', question, re.I))


def rank(graph, question, top_k):
    require(top_k > 0 and bool(question.strip()), 'Invalid structured query')
    nodes, units = validate(graph)
    labels = {k: {n['name']} for k,n in nodes.items()}
    for unit in units.values():
        if unit['kind']=='relation' and unit['value']['predicate']=='AFFECTS':
            pair = unit['provenance']['pair']
            labels[unit['value']['object']].add(pair['product'])
    anchors = sorted((nodes[k] for k,names in labels.items() if any(mentions(question,name) for name in names)), key=lambda n:n['id'])
    anchor_ids = {n['id'] for n in anchors}
    named_cves = {n['id'] for n in anchors if n['type']=='CVE'}
    # An explicitly named CVE constrains the seed records. Otherwise exact
    # entity labels select candidate records. This is not semantic parsing of
    # negation, OR, joins, comparisons, or temporal conditions.
    seeds = named_cves or {k for k,n in nodes.items() if n['type']=='CVE'}
    outgoing = defaultdict(list)
    for edge in graph['edges']:
        outgoing[edge['subject']].append(edge)
    rows = []
    for cve in sorted(seeds):
        reasons = []
        if cve in anchor_ids:
            descriptions = [u['evidence_id'] for u in units.values() if u['cve_id']==cve and u['kind']=='description']
            reasons.append({'anchor_id':cve,'hop_count':0,'node_ids':[cve], 'nodes':[cve], 'evidence_ids':descriptions})
        for edge in outgoing[cve]:
            local = [e for e in edge['evidence_ids'] if units[e]['cve_id']==cve]
            if edge['object'] in anchor_ids and local:
                reasons.append({'anchor_id':edge['object'],'hop_count':1,
                    'node_ids':[cve,edge['object']], 'nodes':[cve,nodes[edge['object']]['name']],
                    'predicates':[edge['predicate']], 'evidence_ids':local})
            if edge['predicate'] == 'AFFECTS':
                for vendor in outgoing[edge['object']]:
                    own = [e for e in vendor['evidence_ids'] if units[e]['cve_id']==cve]
                    if vendor['predicate']=='MADE_BY' and vendor['object'] in anchor_ids and local and own:
                        reasons.append({'anchor_id':vendor['object'],'hop_count':2,
                            'node_ids':[cve,edge['object'],vendor['object']],
                            'nodes':[cve,nodes[edge['object']]['name'],nodes[vendor['object']]['name']],
                            'predicates':['AFFECTS','MADE_BY'], 'evidence_ids':local+own})
        if reasons:
            rows.append({'cve_id':cve,'score':len({r['anchor_id'] for r in reasons}),
                'selection':'structured_exact_anchor_typed_paths', 'support_paths':reasons})
    return sorted(rows,key=lambda r:(-r['score'],r['cve_id']))[:top_k], anchors
