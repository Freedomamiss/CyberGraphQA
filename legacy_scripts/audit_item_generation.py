"""Audit saved development generation and export evidence for semantic review."""
import argparse
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import generate_item_citations as gen
from semantic_index import digest, write_json


def verify_hashes(root, manifest):
    for name, expected in manifest.items():
        relative=Path(name)
        posix=PurePosixPath(name)
        windows=PureWindowsPath(name)
        if (posix.anchor or windows.anchor or '..' in posix.parts or
            '..' in windows.parts or '\\' in name):
            raise ValueError('Unsafe manifest path')
        if digest(root/relative)!=expected:
            raise ValueError('Artifact hash mismatch: '+name)


def audit(run_dir, contexts, graph_dir, output_dir):
    gen.verify_suite(contexts,graph_dir)
    answers=run_dir/'answers'
    summary=json.loads((answers/'generation-summary.json').read_text(encoding='utf-8'))
    if summary.get('status')!='development_calls_finished':
        raise ValueError('A completed development answer run is required')
    verify_hashes(answers,summary['output_sha256'])
    config=json.loads((answers/'suite-config.json').read_text(encoding='utf-8'))
    if config['source_summary_sha256']!=digest(contexts/'repacking-summary.json'):
        raise ValueError('Source retrieval summary mismatch')
    if config.get('generation_variant')!=gen.VARIANT:
        raise ValueError('Unexpected generation variant')
    if config['expected_digest']!=gen.PINNED_DIGEST or config['model']!=gen.PINNED_MODEL or config['dry_run'] is not False:
        raise ValueError('Unexpected generator model/configuration')
    ledger=[]; valid=0; failed=0; sent=0
    for case,question in gen.CASES:
        directory=answers/case
        manifest,rows=gen.load_contexts(contexts/case)
        case_config=json.loads((directory/'config.json').read_text(encoding='utf-8'))
        if (case_config['options']!=gen.OPTIONS or case_config['system_prompt']!=gen.SYSTEM or
            case_config['answer_schema']!=gen.SCHEMA or case_config['runner_sha256']!=digest(gen.__file__) or
            case_config['context_manifest_sha256']!=digest(contexts/case/'comparison-manifest.json')):
            raise ValueError('Generation settings/source changed: '+case)
        for name in ['model-before.json','model-after.json']:
            model=json.loads((directory/name).read_text(encoding='utf-8'))
            if model['digest'].removeprefix('sha256:')!=gen.PINNED_DIGEST:
                raise ValueError('Unexpected model digest: '+case)
        statuses=json.loads((directory/'statuses.json').read_text(encoding='utf-8'))
        if [s['mode'] for s in statuses]!=gen.MODES:
            raise ValueError('Wrong status mode sequence')
        for status in statuses:
            mode=status['mode'];row=rows[mode]
            request_path=directory/(mode+'-request.json')
            request=json.loads(request_path.read_text(encoding='utf-8'))
            if request!=gen.request_body(gen.PINNED_MODEL,row) or status['request_sha256']!=digest(request_path):
                raise ValueError('Request differs from saved context/settings')
            labels=gen.citation_map(row)
            if json.loads((directory/(mode+'-citation-map.json')).read_text(encoding='utf-8'))!=labels:
                raise ValueError('Citation map mismatch')
            response_path=directory/(mode+'-response.json')
            response=json.loads(response_path.read_text(encoding='utf-8'))
            if status.get('model_request_sent') is not True or status['raw_response_sha256']!=digest(response_path):
                raise ValueError('Missing response or request accounting')
            sent+=1;error=None;answer=None
            try:
                if response.get('error') or response.get('done') is not True:
                    raise ValueError('Ollama did not complete the response')
                if response.get('done_reason')=='length':
                    raise ValueError('Output token limit reached; truncated result retained as failure')
                if response.get('model')!=gen.PINNED_MODEL:
                    raise ValueError('Response model differs from requested model')
                answer=gen.validate_answer(response['message']['content'],set(labels),mode)
            except (ValueError,KeyError,TypeError) as e:error=str(e)
            if error is None:
                valid+=1
                if status['status']!='item_citations_and_abstention_valid' or json.loads((directory/(mode+'-answer.json')).read_text(encoding='utf-8'))!=answer:
                    raise ValueError('Saved answer/status differs from raw response')
                links=gen.evidence_links(answer,labels)
                if json.loads((directory/(mode+'-evidence-links.json')).read_text(encoding='utf-8'))!=links:
                    raise ValueError('Saved evidence links mismatch')
            else:
                failed+=1
                if status['status']!='failed' or status['error']!=error:
                    raise ValueError('Failure status differs from validation')
            try: parsed=json.loads(response['message']['content'])
            except (ValueError,KeyError,TypeError):parsed=None
            facts={f['evidence_id']:f for f in row['evidence']}
            citations=[]
            if isinstance(parsed,dict) and isinstance(parsed.get('answer_items'),list):
                for index,item in enumerate(parsed['answer_items']):
                    if not isinstance(item,dict) or not isinstance(item.get('evidence_ids'),list):continue
                    for label in item['evidence_ids']:
                        if isinstance(label,str) and label in labels:
                            citations.append({'item_index':index,'claim':item.get('claim'),'label':label,'fact':facts[labels[label]]})
            ledger.append({'case':case,'question':question,'mode':mode,
                'structural_status':status['status'],'validation_error':error,
                'answer':parsed,'raw_answer_text':response['message']['content'] if error else None,'cited_facts':citations,'supplied_evidence_units':len(row['evidence']),
                'prompt_eval_count':response.get('prompt_eval_count'),'eval_count':response.get('eval_count'),
                'factual_correctness_reviewed':False,'claim_citation_support_verified':False})
    if (sent,valid,failed)!=(summary['model_requests_sent'],summary['validated'],summary['failed']) or summary['model_digest_stable'] is not True:
        raise ValueError('Generation summary differs from audited artifacts')
    output_dir.mkdir(parents=True,exist_ok=False)
    write_json(output_dir/'review-ledger.json',ledger)
    result={'schema_version':2,'generation_variant':gen.VARIANT,'status':'item_generation_artifacts_audited','cases':len(gen.CASES),
        'saved_answer_requests':sent,'structure_valid':valid,'structure_failed':failed,
        'artifact_hashes_verified':len(summary['output_sha256']),
        'request_contexts_and_citation_maps_verified':True,'model_digest_verified':gen.PINNED_DIGEST,
        'source_generation_summary_sha256':digest(answers/'generation-summary.json'),
        'source_retrieval_summary_sha256':digest(contexts/'repacking-summary.json'),
        'model_requests_sent_by_this_audit':0,'human_gold':False,'comparative_quality_scored':False,
        'semantic_review_complete':False,'held_out_benchmark_run':False,
        'note':'This audit verifies artifacts and exports citations. It does not judge factual correctness or citation entailment.',
        'output_sha256':{'review-ledger.json':digest(output_dir/'review-ledger.json')}}
    write_json(output_dir/'audit-summary.json',result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-dir',type=Path,required=True);p.add_argument('--contexts',type=Path,required=True)
    p.add_argument('--graph-dir',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
    a=p.parse_args()
    try:r=audit(a.run_dir,a.contexts,a.graph_dir,a.output_dir)
    except Exception as e:p.exit(1,'Generation audit stopped: '+str(e)+'\n')
    print(json.dumps(r))


if __name__=='__main__':main()
