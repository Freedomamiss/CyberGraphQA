"""Audit saved full-sample extraction and build a strictly unreviewed candidate graph."""
import argparse
from collections import Counter
import json
from pathlib import Path

import extract_cves as extraction
import extract_full_sample as full
from build_graph import from_run
from retrieve_evidence import corpus
from semantic_index import digest, write_json


def require(condition,message):
    if not condition:raise ValueError(message)


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def audit_run(directory, input_path):
    manifest=read(directory/'artifact-manifest.json')['file_sha256']
    actual={p.relative_to(directory).as_posix() for p in directory.rglob('*')
        if p.is_file() and p.suffix in ['.json','.bin'] and p.name!='artifact-manifest.json'}
    require(actual==set(manifest),'Artifact manifest coverage differs')
    for relative,expected in manifest.items():
        p=directory/relative
        require(p.resolve().is_relative_to(directory.resolve()),'Unsafe artifact path')
        require(digest(p)==expected,'Artifact hash mismatch: '+relative)
    rows=extraction.load_inputs(input_path);config=read(directory/'config.json');summary=read(directory/'summary.json')
    frozen=full.config_for(input_path,rows,full.MODEL,full.MODEL_DIGEST,False)
    require(config['frozen_config']==frozen and all(config.get(k)==v for k,v in frozen.items()),'Frozen configuration differs')
    require(summary['status']=='all_records_attempted' and summary['pending_records']==0,'Run is incomplete')
    require(summary['indeterminate_attempts']==0 and summary['model_digest_stable'] is True,'Interrupted or unstable model run')
    statuses=read(directory/'statuses.json')
    require([s['cve_id'] for s in statuses]==[r['cve_id'] for r in rows],'Status/input coverage differs')
    require(all(s.get('attempt_state')=='finished' for s in statuses),'Unfinished record')
    counts=Counter(s['status'] for s in statuses)
    require(set(counts)<={'validated','failed'},'Unsupported primary status')
    require(counts['validated']==summary['validated'] and counts['failed']==summary['failed'],'Summary status counts differ')
    provenance=read(directory/'model_provenance.json')
    require(provenance['model']['digest'].removeprefix('sha256:')==full.MODEL_DIGEST,'Model provenance digest differs')
    sessions=read(directory/'sessions.json')
    for session in sessions:
        if session.get('chat_requests_started',0):
            require(session['model_digest_stable'] is True,'Unverified session model')
            require(all(session[k]['digest'].removeprefix('sha256:')==full.MODEL_DIGEST for k in ['model_before','model_after']),
                'Session digest changed')
    errors=Counter();absent_vendor_records=[];empty_validated=[];token_limits=[]
    for row,status in zip(rows,statuses):
        cve=row['cve_id'];full.check_artifacts(directory,status,row)
        require(read(directory/'record_statuses'/(cve+'.json'))==status,'Record/aggregate status differs')
        require(status['model_digest_before'].removeprefix('sha256:')==full.MODEL_DIGEST,'Per-record model digest differs')
        payload=read(directory/'requests'/(cve+'.json'))
        require(payload==extraction.make_payload(row,full.MODEL,full.OPTIONS,full.TRACK),'Saved request differs from frozen description-only payload')
        response=read(directory/'raw'/(cve+'.json'))
        require(response.get('model')==full.MODEL,'API response model differs')
        if response.get('done_reason')=='length':token_limits.append(cve)
        if status['status']=='validated':
            require(response.get('done') is True and response.get('done_reason')!='length','Accepted response incomplete')
            assertion=json.loads(response['message']['content'])
            require(assertion==read(directory/'validated_assertions'/(cve+'.json')),'Accepted assertions differ from raw response')
            compiled=extraction.validate_assertions(assertion,row)
            require(compiled==read(directory/'validated'/(cve+'.json')),'Compiled graph differs')
            if not assertion['products']:empty_validated.append(cve)
        else:
            errors[status.get('error','unreported failure')]+=1
            require(not (directory/'validated'/(cve+'.json')).exists(),'Failed record has a validated graph')
        try:
            value=json.loads(response['message']['content'])
            if any(isinstance(v.get('name'),str) and v['name'] not in row['description']
                for p in value.get('products',[]) for v in p.get('vendors',[])):
                absent_vendor_records.append(cve)
        except (ValueError,KeyError,TypeError,AttributeError):pass
    require(summary['model_requests_started']==len(rows) and summary['completed_api_responses']==len(rows),
        'Complete API response coverage differs')
    return {'schema_version':1,'status':'saved_run_audit_passed','records':len(rows),
        'primary_validated':counts['validated'],'primary_failed':counts['failed'],
        'artifact_hashes_verified':len(manifest),'all_requests_description_only':True,
        'accepted_assertions_match_raw_responses':True,'model_digest_stable':True,
        'failure_counts':dict(errors),'output_token_limit_records':token_limits,
        'records_with_vendor_names_absent_from_description':absent_vendor_records,
        'empty_validated_records':empty_validated,
        'model_requests_sent_by_audit':0,'new_extraction_performed':False,
        'quality_metrics_scored':False,'human_gold':False,'semantic_review_complete':False,
        'source_run_config_sha256':digest(directory/'config.json'),
        'source_artifact_manifest_sha256':digest(directory/'artifact-manifest.json'),
        'input_sha256':digest(input_path),'auditor_sha256':digest(__file__),
        'note':'Primary record-level results are unchanged. Failed assertions are not salvaged or silently repaired.'}


def build(directory,input_path,output_dir):
    report=audit_run(directory,input_path)
    graph=from_run(directory,input_path)
    graph['semantic_review_complete']=False
    graph['audit_policy']='Strict primary record validation only; accepted outputs remain unreviewed model candidates. Failed CVEs retain descriptions without model relations.'
    docs=corpus(graph)
    require(len(docs)==report['records'],'Candidate graph lost source records')
    failed={s['cve_id'] for s in read(directory/'statuses.json') if s['status']=='failed'}
    require(all(len(docs[c]['facts'])==1 and docs[c]['facts'][0]['kind']=='description' for c in failed),
        'Failed model assertions entered the graph/text views')
    output_dir.mkdir(parents=True,exist_ok=False)
    write_json(output_dir/'audit.json',report)
    write_json(output_dir/'candidate-graph.json',graph)
    write_json(output_dir/'candidate-text-documents.json',docs)
    result={'schema_version':1,'status':'audited_candidate_graph_built','records':report['records'],
        'primary_validated':report['primary_validated'],'primary_failed':report['primary_failed'],
        'node_counts':dict(Counter(n['type'] for n in graph['nodes'])),
        'edge_counts':dict(Counter(e['predicate'] for e in graph['edges'])),
        'text_evidence_units':sum(len(d['facts']) for d in docs.values()),
        'failed_records_have_description_only':True,'text_graph_fact_access_equal':True,
        'graph_kind':graph['graph_kind'],'production_ready':False,'human_gold':False,
        'model_requests_sent':0,'qa_experiment_run':False,'quality_metrics_scored':False,
        'structured_metadata_fused':False,'semantic_review_complete':False,
        'output_sha256':{n:digest(output_dir/n) for n in ['audit.json','candidate-graph.json','candidate-text-documents.json']}}
    write_json(output_dir/'build-summary.json',result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-dir',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    args=p.parse_args()
    try:
        root=Path(__file__).resolve().parents[1]
        result=build(args.run_dir,root/'data/processed/extraction_inputs.jsonl',args.output_dir)
    except Exception as error:p.exit(1,'Extraction audit stopped: '+str(error)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
