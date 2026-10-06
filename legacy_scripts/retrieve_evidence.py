"""Development retrieval smoke test over equal-information text/graph views.

Lexical ranking is a plumbing adapter, not the planned FAISS benchmark baseline.
No generator, gold answers, or model calls are used. Schema 2 supports the
frozen structured-source graph through its explicit adapter.
"""
import argparse
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path

from query_graph import cve_paths


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def terms(text):
    return re.findall(r"cve-\d{4}-\d{4,}|[a-z0-9]+", text.casefold())


def corpus(graph):
    """Serialize exactly the graph's descriptions and observed relations for text.

    Observations, including duplicates from different sources, are retained in
    fact provenance. Failed CVEs retain descriptions and their failed status.
    """
    if graph.get('schema_version') == 2:
        from structured_retrieval import corpus as structured_corpus
        return structured_corpus(graph)
    nodes = {node['id']: node for node in graph['nodes']}
    documents = {}
    for node in sorted(nodes.values(), key=lambda x: x['id']):
        if node['type'] != 'CVE':
            continue
        cve = node['id']
        facts = [{'evidence_id': 'description:' + cve, 'kind': 'description',
                  'text': cve + ': ' + node['description'], 'cve_id': cve,
                  'source_description_sha256': hashlib.sha256(node['description'].encode()).hexdigest()}]
        for edge in graph['edges']:
            observations = [o for o in edge['observations'] if o['cve_id'] == cve]
            if not observations:
                continue
            fact_key = [cve, edge['subject'], edge['predicate'], edge['object']]
            facts.append({'evidence_id': 'fact:' + sha(fact_key)[:24], 'kind': 'relation',
                'cve_id': cve, 'subject': edge['subject'], 'predicate': edge['predicate'],
                'object': edge['object'], 'observations': observations,
                'text': nodes[edge['subject']]['name'] + ' ' + edge['predicate'] + ' ' + nodes[edge['object']]['name']})
        documents[cve] = {'cve_id': cve, 'extraction_status': node['extraction_status'],
                         'facts': facts, 'text': '\n'.join(f['text'] for f in facts)}
    return documents


def lexical_rank(documents, question, top_k):
    """TF-IDF cosine with fixed local vocabulary; development only."""
    query = Counter(terms(question))
    vectors = {cve: Counter(terms(doc['text'])) for cve, doc in documents.items()}
    df = Counter(term for vector in vectors.values() for term in vector)
    idf = {term: math.log((1 + len(vectors)) / (1 + count)) + 1 for term, count in df.items()}
    q = {t: n * idf[t] for t, n in query.items() if t in idf}
    qnorm = math.sqrt(sum(n*n for n in q.values()))
    ranked = []
    for cve, vector in vectors.items():
        weighted = {t: n * idf[t] for t, n in vector.items()}
        norm = math.sqrt(sum(n*n for n in weighted.values()))
        score = sum(q.get(t, 0)*n for t, n in weighted.items()) / (qnorm*norm) if qnorm and norm else 0
        if score > 0:
            ranked.append({'cve_id': cve, 'score': score, 'selection': 'lexical_tfidf'})
    return sorted(ranked, key=lambda r: (-r['score'], r['cve_id']))[:top_k]


def mentions(question, name):
    return bool(re.search(r'(?<!\w)' + re.escape(name.strip()) + r'(?!\w)', question, re.I))


def graph_rank(graph, question, top_k):
    """Exact named anchors and source-local typed paths; no question-specific rules."""
    if graph.get('schema_version') == 2:
        from structured_retrieval import rank
        return rank(graph, question, top_k)
    anchors = [n for n in graph['nodes'] if mentions(question, n['name'])]
    anchors = sorted(anchors, key=lambda n: n['id'])
    documents = corpus(graph)
    matches = []
    for cve in documents:
        paths = cve_paths(graph, cve)['paths']
        reasons = []
        for anchor in anchors:
            if anchor['type'] == 'CVE' and anchor['id'] == cve:
                reasons.append({'anchor_id': cve, 'hop_count': 0, 'nodes': [cve], 'evidence_ids': ['description:' + cve]})
            elif anchor['type'] in {'Product', 'Vendor'}:
                for path in paths:
                    position = 1 if anchor['type'] == 'Product' else 2
                    if len(path['nodes']) > position and path['nodes'][position].casefold() == anchor['name'].casefold():
                        # Keep the path's source-local observations, never use another
                        # CVE's ownership edge just because a product label is shared.
                        reasons.append({'anchor_id': anchor['id'], 'hop_count': position,
                            'nodes': path['nodes'][:position+1], 'path_evidence': path['evidence']})
        if reasons:
            matches.append({'cve_id': cve, 'score': len({r['anchor_id'] for r in reasons}),
                            'selection': 'exact_anchor_typed_paths', 'support_paths': reasons})
    return sorted(matches, key=lambda r: (-r['score'], r['cve_id']))[:top_k], anchors


def pack(ranked, documents, char_cap):
    """Pack complete evidence units; char cap is explicitly not a token budget."""
    facts, skipped, used, seen = [], [], 0, set()
    for row in ranked:
        for fact in documents[row['cve_id']]['facts']:
            if fact['evidence_id'] in seen:
                continue
            seen.add(fact['evidence_id'])
            block = '[' + fact['evidence_id'] + '] ' + fact['text'] + '\n'
            if used + len(block) > char_cap:
                skipped.append(fact['evidence_id'])
                continue
            facts.append(fact); used += len(block)
    return {'evidence': facts, 'context': ''.join('['+f['evidence_id']+'] '+f['text']+'\n' for f in facts),
            'context_characters': used, 'skipped_evidence_ids': skipped}


def pack_hybrid(text_rows, graph_rows, documents, char_cap):
    """Half per channel, deduplication, then unused-capacity reclamation."""
    first = pack(text_rows, documents, char_cap//2)
    second = pack(graph_rows, documents, char_cap//2)
    selected, ids = [], set()
    for fact in first['evidence'] + second['evidence']:
        if fact['evidence_id'] not in ids:
            selected.append(fact); ids.add(fact['evidence_id'])
    remainder = [f for r in text_rows + graph_rows for f in documents[r['cve_id']]['facts'] if f['evidence_id'] not in ids]
    return pack([{'cve_id': 'merged'}], {'merged': {'facts': selected + remainder}}, char_cap)


def retrieve(graph, question, mode, top_k=5, char_cap=6000):
    if mode not in {'llm-only', 'text', 'graph', 'hybrid'}:
        raise ValueError('Unknown retrieval mode')
    if top_k < 1 or char_cap < 1 or not question.strip():
        raise ValueError('Question, top-k, and character cap must be positive/nonempty')
    docs = corpus(graph)
    text_rows = lexical_rank(docs, question, top_k) if mode in {'text', 'hybrid'} else []
    graph_rows, anchors = graph_rank(graph, question, top_k) if mode in {'graph', 'hybrid'} else ([], [])
    if mode == 'hybrid':
        # Reserve half for each channel, then reclaim unused capacity. Do not
        # silently double the total context budget by concatenating two top-k's.
        packed = pack_hybrid(text_rows, graph_rows, docs, char_cap)
    else:
        packed = pack(text_rows + graph_rows, docs, char_cap)
    return {'schema_version': 1, 'development_diagnostic_only': True, 'qa_experiment_run': False,
        'generation_performed': False, 'mode': mode, 'question': question,
        'graph_kind': graph['graph_kind'], 'graph_sha256': sha(graph),
        'corpus_sha256': sha(docs), 'fact_access_policy': ('Same frozen structured-source evidence units, provenance, flags, and missing fields in all views; unadjudicated metadata.'
            if graph.get('schema_version') == 2 else 'Same descriptions and source-local observed relations in all retrieval views; no metadata added.'),
        'text_backend': 'lexical_tfidf_development_only' if mode in {'text', 'hybrid'} else None,
        'budget': {'unit': 'characters', 'cap': char_cap, 'generator_token_budget_enforced': False},
        'top_k_per_channel': top_k, 'anchors': [{'id': n['id'], 'name': n['name'], 'type': n['type']} for n in anchors],
        'text_candidates': text_rows, 'graph_candidates': graph_rows, **packed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--graph', type=Path, required=True)
    parser.add_argument('--question', required=True)
    parser.add_argument('--mode', choices=['llm-only', 'text', 'graph', 'hybrid'], required=True)
    parser.add_argument('--top-k', type=int, default=5)
    parser.add_argument('--char-cap', type=int, default=6000)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        graph = json.loads(args.graph.read_text(encoding='utf-8'))
        result = retrieve(graph, args.question, args.mode, args.top_k, args.char_cap)
        result['graph_file_sha256'] = hashlib.sha256(args.graph.read_bytes()).hexdigest()
        result['retriever_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False); handle.write('\n')
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, 'Retrieval stopped: ' + str(error) + '\n')
    print(json.dumps({'mode': args.mode, 'evidence_units': len(result['evidence']),
        'context_characters': result['context_characters'], 'qa_experiment_run': False,
        'output': str(args.output)}))


if __name__ == '__main__':
    main()
