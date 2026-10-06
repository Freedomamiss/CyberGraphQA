"""Run four development context modes with one persisted semantic ranker.

No answers, gold files, new corpus embeddings or model downloads are produced.
"""
import argparse
import json
from pathlib import Path

import retrieve_evidence as retrieval
import semantic_index as semantic


def compose_modes(graph, question, semantic_output, top_k=5, char_cap=6000):
    docs = retrieval.corpus(graph)
    if (semantic_output['graph_sha256'] != retrieval.sha(graph)
            or semantic_output['corpus_sha256'] != retrieval.sha(docs)
            or semantic_output['question'] != question):
        raise ValueError('Semantic output does not match graph/corpus/question')
    if semantic_output['text_backend'] != 'sentence_transformer_faiss' or semantic_output['index_rebuilt'] is not False:
        raise ValueError('A persisted semantic retrieval result is required')
    if semantic_output['top_k'] != top_k or semantic_output['budget']['cap'] != char_cap:
        raise ValueError('Semantic and graph retrieval configurations differ')
    rows = semantic_output['candidates']
    if len(rows) > top_k or len({r['cve_id'] for r in rows}) != len(rows) or any(r['cve_id'] not in docs for r in rows):
        raise ValueError('Semantic candidate coverage is invalid')
    results = {m: retrieval.retrieve(graph, question, m, top_k, char_cap) for m in ['llm-only', 'graph']}
    text = {**semantic_output, 'text_candidates': rows, 'graph_candidates': [], 'anchors': [], 'top_k_per_channel': top_k,
            'fact_access_policy': results['graph']['fact_access_policy']}
    # Repack from the canonical shared facts, never trust prepacked external text.
    text.update(retrieval.pack(rows, docs, char_cap))
    results['text'] = text
    hybrid = {**results['graph'], 'mode': 'hybrid', 'text_backend': 'sentence_transformer_faiss',
        'text_candidates': rows, **retrieval.pack_hybrid(rows, results['graph']['graph_candidates'], docs, char_cap)}
    for key in ['model_id', 'model_revision', 'index_manifest_sha256', 'query_script_sha256',
                'question_embedding_tokens', 'query_packages', 'index_rebuilt', 'model_loaded_locally', 'ranking_policy']:
        hybrid[key] = semantic_output[key]
    results['hybrid'] = hybrid
    valid_ids = {f['evidence_id'] for d in docs.values() for f in d['facts']}
    for mode, result in results.items():
        ids = [f['evidence_id'] for f in result['evidence']]
        if len(ids) != len(set(ids)) or not set(ids).issubset(valid_ids):
            raise ValueError('Evidence is duplicated or outside the corpus: ' + mode)
        if len(result['context']) > char_cap or result['corpus_sha256'] != retrieval.sha(docs):
            raise ValueError('Context cap or corpus identity mismatch: ' + mode)
    return {m: results[m] for m in ['llm-only', 'text', 'graph', 'hybrid']}


def run(graph_path, index_dir, question, output_dir, top_k=5, char_cap=6000):
    # Refuse to overwrite an earlier or partial run.
    output_dir.mkdir(parents=True, exist_ok=False)
    graph = json.loads(graph_path.read_text(encoding='utf-8'))
    semantic_output = semantic.semantic_result(graph_path, index_dir, question, top_k, char_cap)
    results = compose_modes(graph, question, semantic_output, top_k, char_cap)
    for mode, result in results.items():
        result['comparison_script_sha256'] = semantic.digest(__file__)
        result['packing_script_sha256'] = semantic.digest(retrieval.__file__)
        result['graph_file_sha256'] = semantic.digest(graph_path)
        semantic.write_json(output_dir/(mode+'.json'), result)
    manifest = {'schema_version': 1, 'status': 'complete', 'development_diagnostic_only': True,
        'qa_experiment_run': False, 'generation_performed': False,
        'question': question, 'graph_kind': graph['graph_kind'], 'graph_sha256': retrieval.sha(graph),
        'corpus_sha256': semantic_output['corpus_sha256'], 'model_id': semantic_output['model_id'],
        'model_revision': semantic_output['model_revision'], 'index_manifest_sha256': semantic_output['index_manifest_sha256'],
        'semantic_query_calls': 1, 'corpus_index_rebuilt': False,
        'top_k_per_channel': top_k, 'budget': {'unit': 'characters', 'cap': char_cap, 'generator_token_budget_enforced': False},
        'output_sha256': {m+'.json': semantic.digest(output_dir/(m+'.json')) for m in results}}
    semantic.write_json(output_dir/'comparison-manifest.json', manifest)
    return [{'mode': m, 'text_backend': r['text_backend'], 'evidence_units': len(r['evidence']),
             'context_characters': r['context_characters'], 'qa_experiment_run': False} for m, r in results.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--graph', type=Path, required=True)
    parser.add_argument('--index-dir', type=Path, required=True)
    parser.add_argument('--question', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--top-k', type=int, default=5)
    parser.add_argument('--char-cap', type=int, default=6000)
    args = parser.parse_args()
    try:
        result = run(args.graph, args.index_dir, args.question, args.output_dir, args.top_k, args.char_cap)
    except Exception as error:
        parser.exit(1, 'Retrieval comparison stopped (' + type(error).__name__ + '): ' + str(error) + '\n')
    for row in result:
        print(json.dumps(row))
    print('Results directory: ' + str(args.output_dir))


if __name__ == '__main__':
    main()
