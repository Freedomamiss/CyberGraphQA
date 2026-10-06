"""Repeated development comparison of old/new hybrid contexts; no prompt tuning."""
import argparse
import json
from pathlib import Path
import time
import generate_item_citations as gen
from pack_target_relations import VARIANT
from semantic_index import digest, write_json

CASES = ['named-cve', 'second-cve']
REPEATS = 3


def prepare(baseline, tuned, graph):
    old_summary = gen.verify_suite(baseline, graph)
    new_summary = gen.verify_suite(tuned, graph)
    if old_summary.get('retrieval_variant') or new_summary.get('retrieval_variant') != VARIANT:
        raise ValueError('Expected original Checkpoint 23 and Checkpoint 29 retrieval variant')
    if new_summary['source_summary_sha256'] != digest(baseline/'repacking-summary.json'):
        raise ValueError('Tuned contexts do not descend from the supplied baseline')
    contexts = {}
    for case, _ in gen.CASES:
        _, old = gen.load_contexts(baseline/case)
        _, new = gen.load_contexts(tuned/case)
        for mode in gen.MODES:
            if mode != 'hybrid' or case not in CASES:
                if old[mode] != new[mode]: raise ValueError('Unexpected change outside the two hybrid contexts')
            elif old[mode]['context'] == new[mode]['context']:
                raise ValueError('Expected the named-CVE hybrid packing change')
            if old[mode]['text_candidates'] != new[mode]['text_candidates'] or old[mode]['graph_candidates'] != new[mode]['graph_candidates']:
                raise ValueError('Candidate rankings changed')
        if case in CASES: contexts[case] = {'baseline': old['hybrid'], 'tuned': new['hybrid']}
    return contexts


def schedule():
    # Alternate order to reduce a fixed before/after ordering effect. This is
    # still a small development diagnostic, not a randomized held-out study.
    return [(case, repeat, variant) for repeat in range(1, REPEATS+1)
            for case in (CASES if repeat % 2 else list(reversed(CASES)))
            for variant in (['baseline','tuned'] if repeat % 2 else ['tuned','baseline'])]


def run(baseline, tuned, graph, output, dry_run=False, client=None):
    contexts = prepare(baseline, tuned, graph)
    output.mkdir(parents=True, exist_ok=False)
    plan = schedule()
    config = {'comparison_variant': 'hybrid-packing-paired-repeats-v1',
        'generation_variant': gen.VARIANT, 'retrieval_variant': VARIANT,
        'tuned_after_checkpoint26_and_claude_review': True, 'development_diagnostic_only': True,
        'model': gen.PINNED_MODEL, 'expected_digest': gen.PINNED_DIGEST,
        'options': gen.OPTIONS, 'system_prompt': gen.SYSTEM, 'answer_schema': gen.SCHEMA,
        'runner_sha256': digest(__file__), 'generator_sha256': digest(gen.__file__),
        'baseline_summary_sha256': digest(baseline/'repacking-summary.json'),
        'tuned_summary_sha256': digest(tuned/'repacking-summary.json'),
        'mode': 'hybrid', 'repetitions_per_case_per_variant': REPEATS,
        'planned_generation_requests': len(plan), 'call_order': plan, 'dry_run': dry_run,
        'retry_policy': 'No retries, output repair, or failure salvage; all planned outcomes retained.',
        'generation_settings_changed': False, 'human_gold': False, 'held_out_benchmark_run': False,
        'comparative_quality_scored': False, 'generator_token_budget_enforced': False}
    write_json(output/'comparison-config.json', config)
    for case, repeat, variant in plan:
        directory = output/case/('repeat-'+str(repeat))/variant; directory.mkdir(parents=True)
        row = contexts[case][variant]
        write_json(directory/'request.json', gen.request_body(gen.PINNED_MODEL, row))
        write_json(directory/'citation-map.json', gen.citation_map(row))
        write_json(directory/'context.json', row)
    statuses = []
    if not dry_run:
        client = client or gen.Ollama('http://localhost:11434')
        try:
            before = gen.snapshot(client, gen.PINNED_MODEL)
            write_json(output/'model-before.json', before)
            if before['digest'].removeprefix('sha256:') != gen.PINNED_DIGEST:
                raise ValueError('Model digest differs from the frozen generator')
            write_json(output/'model-show.json', client.call('/api/show', {'model': gen.PINNED_MODEL}))
            write_json(output/'ollama-version.json', client.call('/api/version'))
        except Exception as error:
            write_json(output/'preflight-error.json', {'error': str(error), 'model_requests_sent': 0})
            raise
        for case, repeat, variant in plan:
            directory = output/case/('repeat-'+str(repeat))/variant
            body = json.loads((directory/'request.json').read_text(encoding='utf-8'))
            status = {'case': case, 'repeat': repeat, 'variant': variant, 'mode': 'hybrid',
                'status': 'failed', 'model_request_started': False, 'model_response_received': False,
                'request_sha256': digest(directory/'request.json'), 'quality_scored': False}
            started = time.perf_counter()
            try:
                current = gen.snapshot(client, gen.PINNED_MODEL)
                write_json(directory/'model-before.json', current)
                if current['digest'].removeprefix('sha256:') != gen.PINNED_DIGEST:
                    raise ValueError('Model digest changed before call')
                print('Generating: '+case+' / repeat '+str(repeat)+' / '+variant, flush=True)
                status['model_request_started'] = True
                write_json(directory/'dispatch.json', {'model_request_started': True,
                    'request_sha256': status['request_sha256'], 'receipt_verified': False})
                response = client.call('/api/chat', body)
                write_json(directory/'response.json', response)
                status['model_response_received'] = True
                status['response_sha256'] = digest(directory/'response.json')
                for field in ['done_reason','prompt_eval_count','eval_count']: status[field] = response.get(field)
                if response.get('done') is not True or response.get('error'):
                    raise ValueError('Incomplete/error response')
                if response.get('model') != gen.PINNED_MODEL:
                    raise ValueError('Response model differs from requested model')
                if response.get('done_reason') == 'length':
                    raise ValueError('Output token limit reached; truncated response retained as failure')
                labels = gen.citation_map(contexts[case][variant])
                answer = gen.validate_answer(response['message']['content'], set(labels), 'hybrid')
                write_json(directory/'answer.json', answer)
                write_json(directory/'evidence-links.json', gen.evidence_links(answer, labels))
                status['status'] = 'item_citations_and_abstention_valid'
            except Exception as error:
                status['error_type'] = type(error).__name__; status['error'] = str(error)
            status['wall_seconds'] = time.perf_counter()-started
            write_json(directory/'status.json', status); statuses.append(status)
            print(json.dumps({k:status[k] for k in ['case','repeat','variant','status']}), flush=True)
        write_json(output/'statuses.json', statuses)
        try:
            after = gen.snapshot(client, gen.PINNED_MODEL); write_json(output/'model-after.json', after)
            stable = after['digest'].removeprefix('sha256:') == gen.PINNED_DIGEST and all(
                json.loads((output/case/('repeat-'+str(repeat))/variant/'model-before.json').read_text())['digest'].removeprefix('sha256:') == gen.PINNED_DIGEST
                for case, repeat, variant in plan)
        except Exception as error:
            stable = False; write_json(output/'model-after-error.json', {'error': str(error)})
    else:
        stable = None
    result = {'schema_version': 1, 'status': 'dry_run_complete' if dry_run else 'development_comparison_calls_finished',
        'comparison_variant': config['comparison_variant'], 'generation_variant': gen.VARIANT, 'retrieval_variant': VARIANT,
        'planned_requests': len(plan), 'completed_outcomes': len(statuses),
        'model_requests_started': sum(s['model_request_started'] for s in statuses),
        'model_responses_received': sum(s['model_response_received'] for s in statuses),
        'validated': sum(s['status'] == 'item_citations_and_abstention_valid' for s in statuses),
        'failed': sum(s['status'] == 'failed' for s in statuses), 'model_digest_stable': stable,
        'human_gold': False, 'held_out_benchmark_run': False, 'comparative_quality_scored': False,
        'semantic_review_complete': False,
        'request_count_note': 'Started records dispatch intent; a missing response does not establish server receipt.',
        'explanation': 'Protocol checks do not establish factual correctness, citation support, or comparative performance.',
        'output_sha256': {p.relative_to(output).as_posix(): digest(p) for p in sorted(output.rglob('*.json'))}}
    write_json(output/'comparison-summary.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ['baseline','tuned','graph-dir','output-dir']: parser.add_argument('--'+arg, type=Path, required=True)
    parser.add_argument('--dry-run', action='store_true'); args = parser.parse_args()
    try: result = run(args.baseline, args.tuned, args.graph_dir, args.output_dir, args.dry_run)
    except Exception as error: parser.exit(1, 'Packing comparison stopped: '+str(error)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'output_sha256'}))
