"""Audit saved paired packing calls without new generation or semantic scoring."""
import argparse
from collections import Counter
import json
from pathlib import Path
import generate_packing_comparison as comparison
import generate_item_citations as gen
from audit_item_generation import verify_hashes
from semantic_index import digest, write_json


def audit(run_dir, baseline, tuned, graph_dir, output_dir):
    contexts = comparison.prepare(baseline, tuned, graph_dir)
    result = json.loads((run_dir/'comparison-summary.json').read_text(encoding='utf-8'))
    if result['status'] != 'development_comparison_calls_finished':
        raise ValueError('Completed development comparison required')
    verify_hashes(run_dir, result['output_sha256'])
    config = json.loads((run_dir/'comparison-config.json').read_text(encoding='utf-8'))
    expected = {'runner_sha256': digest(comparison.__file__), 'generator_sha256': digest(gen.__file__),
        'baseline_summary_sha256': digest(baseline/'repacking-summary.json'),
        'tuned_summary_sha256': digest(tuned/'repacking-summary.json'),
        'model': gen.PINNED_MODEL, 'expected_digest': gen.PINNED_DIGEST,
        'options': gen.OPTIONS, 'system_prompt': gen.SYSTEM, 'answer_schema': gen.SCHEMA,
        'dry_run': False, 'planned_generation_requests': 12, 'call_order': [list(x) for x in comparison.schedule()]}
    for key, value in expected.items():
        if config.get(key) != value: raise ValueError('Comparison config mismatch: '+key)
    for filename in ['model-before.json','model-after.json']:
        if json.loads((run_dir/filename).read_text())['digest'].removeprefix('sha256:') != gen.PINNED_DIGEST:
            raise ValueError('Unexpected model digest')
    statuses = json.loads((run_dir/'statuses.json').read_text(encoding='utf-8'))
    if [(s['case'],s['repeat'],s['variant']) for s in statuses] != comparison.schedule():
        raise ValueError('Unexpected call accounting/order')
    ledger = []; groups = {}
    for status in statuses:
        case, repeat, variant = status['case'], status['repeat'], status['variant']
        directory = run_dir/case/('repeat-'+str(repeat))/variant
        def load(name): return json.loads((directory/name).read_text(encoding='utf-8'))
        row = contexts[case][variant]
        if load('context.json') != row or load('request.json') != gen.request_body(gen.PINNED_MODEL,row):
            raise ValueError('Request/context identity mismatch')
        labels = gen.citation_map(row)
        if load('citation-map.json') != labels or load('status.json') != status:
            raise ValueError('Status/citation map mismatch')
        if digest(directory/'request.json') != status['request_sha256']:
            raise ValueError('Request status hash mismatch')
        if load('model-before.json')['digest'].removeprefix('sha256:') != gen.PINNED_DIGEST:
            raise ValueError('Per-call model digest mismatch')
        if not status['model_response_received'] or not status['model_request_started']:
            raise ValueError('Incomplete request/response accounting')
        if digest(directory/'response.json') != status['response_sha256']:
            raise ValueError('Response hash mismatch')
        response = load('response.json'); raw = response['message']['content']
        error = None; answer = None
        try:
            if response.get('done') is not True or response.get('error') or response.get('model') != gen.PINNED_MODEL:
                raise ValueError('Incomplete/error/model response')
            if response.get('done_reason') == 'length':
                raise ValueError('Output token limit reached; truncated response retained as failure')
            answer = gen.validate_answer(raw,set(labels),'hybrid')
        except Exception as exc: error = str(exc)
        valid = error is None
        if valid != (status['status'] == 'item_citations_and_abstention_valid'):
            raise ValueError('Protocol result does not reproduce')
        for field in ['done_reason','prompt_eval_count','eval_count']:
            if status.get(field) != response.get(field): raise ValueError('Token/stop accounting mismatch')
        if valid and (answer != load('answer.json') or gen.evidence_links(answer,labels) != load('evidence-links.json')):
            raise ValueError('Answer/source link mismatch')
        facts = {f['evidence_id']:f for f in row['evidence']}
        ledger.append({'case':case,'repeat':repeat,'variant':variant,'protocol_status':status['status'],
            'semantic_review_performed_by_audit':False,'answer':answer,'protocol_error':error,
            'cited_evidence':[{'item_index':index,'claim':item['claim'],
                'citations':[{'label':label,'fact':facts[labels[label]]} for label in item['evidence_ids']]}
                for index,item in enumerate(answer['answer_items'])] if answer else []})
        groups.setdefault((case,variant),[]).append({'request':load('request.json'),'raw':raw,'answer':answer})
    variation=[]
    for (case,variant), rows in groups.items():
        encode=lambda value:json.dumps(value,sort_keys=True,ensure_ascii=False)
        variation.append({'case':case,'variant':variant,'repetitions':len(rows),
            'distinct_request_bodies':len({encode(r['request']) for r in rows}),
            'distinct_raw_answer_texts':len({r['raw'] for r in rows}),
            'distinct_parsed_answers':len({encode(r['answer']) for r in rows}),
            'distinct_claim_and_citation_lists':len({encode(r['answer']['answer_items']) if r['answer'] else 'failed' for r in rows})})
    summary={'status':'saved_comparison_audited','artifact_hashes_verified':len(result['output_sha256']),
        'requests_reconstructed':len(ledger),'protocol_counts':dict(Counter(r['protocol_status'] for r in ledger)),
        'variation':variation,'model_requests_sent':0,'human_gold':False,'held_out_benchmark_run':False,
        'semantic_quality_scored':False,'semantic_review_performed_by_audit':False,
        'source_comparison_summary_sha256':digest(run_dir/'comparison-summary.json')}
    output_dir.mkdir(parents=True,exist_ok=False)
    write_json(output_dir/'audit-summary.json',summary);write_json(output_dir/'evidence-ledger.json',ledger)
    return summary


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ['run-dir','baseline','tuned','graph-dir','output-dir']:p.add_argument('--'+arg,type=Path,required=True)
    a=p.parse_args()
    try:result=audit(a.run_dir,a.baseline,a.tuned,a.graph_dir,a.output_dir)
    except Exception as e:p.exit(1,'Comparison audit stopped: '+str(e)+'\n')
    print(json.dumps(result,indent=2))
