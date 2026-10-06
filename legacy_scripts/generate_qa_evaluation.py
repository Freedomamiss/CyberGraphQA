"""Generate the 80 frozen QA outcomes from verified saved retrieval contexts."""
import argparse
import json
from pathlib import Path
import generate_item_citations as gen
import retrieve_qa_evaluation as retrieval
from run_structured_retrieval_smoke import verified_bundle
from retrieve_evidence import sha
from semantic_index import digest, write_json
from verify_qa_evaluation import verify, verify_hashes


def verify_inputs(context_dir, packet_dir, graph_dir, preflight_dir):
    preflight=verify(packet_dir,graph_dir,preflight_dir)
    lock=json.loads((packet_dir/'protocol-lock.json').read_text(encoding='utf-8'))
    questions=json.loads((packet_dir/'questions.json').read_text(encoding='utf-8'))
    summary=json.loads((context_dir/'evaluation-retrieval-summary.json').read_text(encoding='utf-8'))
    if (summary['status']!='frozen_qa_retrieval_complete' or summary['questions']!=20
            or summary['saved_mode_contexts']!=80 or summary['generation_performed'] is not False):
        raise ValueError('Completed 20-question retrieval-only suite required')
    if summary['packet_manifest_sha256']!=preflight['packet_manifest_sha256']:
        raise ValueError('Retrieval packet identity differs')
    if summary['runner_sha256']!=digest(retrieval.__file__):raise ValueError('Retrieval runner differs')
    verify_hashes(context_dir,summary['output_sha256'])
    graph,_=verified_bundle(graph_dir)
    if summary['graph_canonical_sha256']!=sha(graph):raise ValueError('Retrieval graph differs')
    config=json.loads((context_dir/'retrieval-config.json').read_text(encoding='utf-8'))
    index=json.loads((context_dir/'index-manifest.json').read_text(encoding='utf-8'))
    if (config['index_manifest_sha256']!=summary['index_manifest_sha256'] or
            digest(context_dir/'index-manifest.json')!=summary['index_manifest_sha256'] or
            index['graph_sha256']!=sha(graph) or index['model_revision']!=lock['embedding_model_revision']):
        raise ValueError('Saved index identity differs')
    loaded={}
    for question in questions:
        directory=context_dir/question['question_id'];manifest,rows=gen.load_contexts(directory)
        if manifest['question']!=question['question']:raise ValueError('Question differs from frozen packet')
        semantic=json.loads((directory/'semantic-ranking.json').read_text(encoding='utf-8'))
        if semantic['index_manifest_sha256']!=summary['index_manifest_sha256']:
            raise ValueError('Question index identity differs')
        expected=retrieval.compose_frozen(graph,question,semantic,lock['character_cap'],lock['top_k_per_channel'])
        if rows!=expected:raise ValueError('Saved packing differs from reconstructed source context')
        loaded[question['question_id']]=rows
    return questions,loaded,summary


def run(context_dir, packet_dir, graph_dir, output_dir, dry_run=False, client=None):
    output_dir.mkdir(parents=True,exist_ok=False)
    questions,rows,retrieval_summary=verify_inputs(context_dir,packet_dir,graph_dir,output_dir/'packet-preflight')
    write_json(output_dir/'evaluation-config.json',{'protocol_id':'source-derived-qa-evaluation-v1',
        'generation_variant':gen.VARIANT,'questions':20,'planned_generation_requests':80,
        'model':gen.PINNED_MODEL,'expected_digest':gen.PINNED_DIGEST,'options':gen.OPTIONS,
        'system_prompt':gen.SYSTEM,'answer_schema':gen.SCHEMA,'mode_order':gen.MODES,
        'question_order':[q['question_id'] for q in questions],
        'runner_sha256':digest(__file__),'generator_sha256':digest(gen.__file__),
        'source_retrieval_summary_sha256':digest(context_dir/'evaluation-retrieval-summary.json'),
        'packet_manifest_sha256':retrieval_summary['packet_manifest_sha256'],
        'dry_run':dry_run,'human_gold':False,'held_out_benchmark':False,
        'source_reference_used_in_generator_messages':False,
        'retry_policy':'No automatic retries, response repair, or resume. Preserve all completed and partial artifacts.'})
    if not dry_run:
        client=client or gen.Ollama('http://localhost:11434')
        before=gen.snapshot(client,gen.PINNED_MODEL)
        write_json(output_dir/'model-before.json',before)
        if before['digest'].removeprefix('sha256:')!=gen.PINNED_DIGEST:
            raise ValueError('Local generator digest differs from frozen protocol')
    outcomes=[]
    for question in questions:
        qid=question['question_id'];print('Frozen QA question: '+qid,flush=True)
        # Reuse the unchanged request construction, validation and raw saving
        # code from the frozen generator. Only orchestration is new.
        result=gen.run(context_dir/qid,output_dir/qid,gen.PINNED_MODEL,gen.PINNED_DIGEST,dry_run,client)
        outcomes.append({'question_id':qid,**result})
    stable=None
    if not dry_run:
        try:
            after=gen.snapshot(client,gen.PINNED_MODEL);write_json(output_dir/'model-after.json',after)
            stable=after['digest'].removeprefix('sha256:')==gen.PINNED_DIGEST and all(x['model_digest_stable'] for x in outcomes)
        except Exception as error:
            stable=False;write_json(output_dir/'model-after-error.json',{'error':str(error)})
    summary={'schema_version':1,'status':'dry_run_complete' if dry_run else 'frozen_qa_generation_calls_finished',
        'protocol_id':'source-derived-qa-evaluation-v1','generation_variant':gen.VARIANT,
        'planned_generation_requests':80,'questions_completed':len(outcomes),
        'model_requests_started':sum(x['model_requests_sent'] for x in outcomes),
        'validated':sum(x.get('validated',0) for x in outcomes),
        'failed':sum(x.get('failed',0) for x in outcomes),
        'model_responses_received':len(list(output_dir.glob('*/*-response.json'))),
        'generation_performed':any(x['generation_performed'] for x in outcomes),
        'model_digest_stable':stable,'human_gold':False,'held_out_benchmark':False,
        'semantic_review_complete':False,'comparative_quality_scored':False,
        'source_retrieval_summary_sha256':digest(context_dir/'evaluation-retrieval-summary.json'),
        'cases':outcomes,'request_count_note':'Dispatch accounting does not prove server receipt without a response; raw response files are retained.',
        'explanation':'Protocol validity is not factual correctness, citation support, or answer completeness.',
        'output_sha256':{p.relative_to(output_dir).as_posix():digest(p) for p in sorted(output_dir.rglob('*.json'))}}
    write_json(output_dir/'evaluation-generation-summary.json',summary)
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['contexts','packet-dir','graph-dir','output-dir']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--dry-run',action='store_true');a=p.parse_args()
    try:r=run(a.contexts,a.packet_dir,a.graph_dir,a.output_dir,a.dry_run)
    except Exception as e:p.exit(1,'Frozen QA generation stopped: '+str(e)+'\n')
    print(json.dumps({k:v for k,v in r.items() if k not in ['cases','output_sha256']},indent=2))
