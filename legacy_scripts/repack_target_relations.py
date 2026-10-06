"""Create a separate hybrid packing variant from verified Checkpoint 23 contexts."""
import argparse
import json
from pathlib import Path
from generate_structured_development import verify_suite, load_contexts, CASES
from run_structured_retrieval_smoke import verified_bundle
from retrieve_evidence import corpus
from pack_target_relations import pack_target_relations, VARIANT
from semantic_index import digest, write_json


def run(source_dir, graph_dir, output_dir):
    summary = verify_suite(source_dir, graph_dir)
    if summary.get('retrieval_variant'):
        raise ValueError('Use the preserved Checkpoint 23 baseline, not an already tuned variant')
    graph, _ = verified_bundle(graph_dir); docs = corpus(graph)
    prepared = []; cases = []
    for case, question in CASES:
        manifest, rows = load_contexts(source_dir/case)
        original_rows = dict(rows)
        old = rows['hybrid']
        packed = pack_target_relations(old['text_candidates'], old['graph_candidates'], docs, 6000, 'hybrid', question)
        if packed['context'] != old['context']:
            rows['hybrid'] = {**old, **packed, 'retrieval_variant': VARIANT,
                'tuned_after_checkpoint26_and_claude_review': True,
                'previous_packing_script_sha256': old['packing_script_sha256'],
                'packing_script_sha256': digest(Path(__file__).with_name('pack_target_relations.py')),
                'source_context_sha256': digest(source_dir/case/'hybrid.json')}
        if any(rows[m]['text_candidates'] != original_rows[m]['text_candidates'] or
               rows[m]['graph_candidates'] != original_rows[m]['graph_candidates'] for m in rows):
            raise ValueError('Packing changed candidate rankings')
        cases.append({'case': case, 'hybrid_context_changed': rows['hybrid']['context'] != old['context'],
            'before_characters': old['context_characters'], 'after_characters': rows['hybrid']['context_characters'],
            'target_relation_coverage': rows['hybrid'].get('target_relation_coverage'),
            'other_modes_unchanged': all(rows[m] == original_rows[m] for m in ['llm-only','text','graph'])})
        prepared.append((case, manifest, rows))
    output_dir.mkdir(parents=True, exist_ok=False)
    for case, manifest, rows in prepared:
        target = output_dir/case; target.mkdir()
        for mode, row in rows.items(): write_json(target/(mode+'.json'), row)
        write_json(target/'comparison-manifest.json', {**manifest, 'retrieval_variant': VARIANT,
            'tuned_after_checkpoint26_and_claude_review': True,
            'hybrid_packing_script_sha256': digest(Path(__file__).with_name('pack_target_relations.py')),
            'source_manifest_sha256': digest(source_dir/case/'comparison-manifest.json'),
            'output_sha256': {m+'.json': digest(target/(m+'.json')) for m in rows}})
    result = {**{k:v for k,v in summary.items() if k not in ['cases','output_sha256']},
        'retrieval_variant': VARIANT, 'tuned_after_checkpoint26_and_claude_review': True, 'cases': cases,
        'model_requests_sent': 0, 'generator_requests_sent': 0, 'semantic_query_calls': 0,
        'candidate_rankings_changed': False, 'corpus_changed': False, 'new_index_required': False,
        'human_gold': False, 'quality_scored': False, 'held_out_benchmark_run': False,
        'repacking_script_sha256': digest(Path(__file__)),
        'hybrid_packing_script_sha256': digest(Path(__file__).with_name('pack_target_relations.py')),
        'source_summary_sha256': digest(source_dir/'repacking-summary.json'),
        'output_sha256': {p.relative_to(output_dir).as_posix(): digest(p) for p in sorted(output_dir.rglob('*.json'))}}
    write_json(output_dir/'repacking-summary.json', result)
    verify_suite(output_dir, graph_dir)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--graph-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try: result = run(args.source_dir, args.graph_dir, args.output_dir)
    except Exception as error: parser.exit(1, 'Target relation repacking stopped: '+str(error)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'output_sha256'}, indent=2))
