"""Resumable description-only literal extraction, preserving every attempted call."""
import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.request

import extract_cves as extraction
from audit_frozen_dataset import audit

MODEL = 'llama3.1:8b'
MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
OPTIONS = {'temperature': 0, 'seed': 1337, 'num_ctx': 8192, 'num_predict': 2048}
TRACK = 'literal-facts'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write(path, value):
    extraction.save(path, value)


class RawAPIError(ValueError):
    def __init__(self, body, message):
        super().__init__(message); self.body = body


class LocalOllama:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, route, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request('http://127.0.0.1:11434'+route, data=body,
            headers={'Content-Type':'application/json'})
        try:
            with self.opener.open(request, timeout=600 if route=='/api/chat' else 30) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            raise RawAPIError(error.read(), 'Ollama HTTP error '+str(error.code)) from error


def api(client, route, payload=None):
    body = client.call(route, payload)
    try:
        return body, json.loads(body)
    except (ValueError, UnicodeError) as error:
        raise RawAPIError(body, 'API response is not valid JSON') from error


def model_snapshot(client, model, expected):
    _, tags = api(client, '/api/tags')
    matches = [m for m in tags.get('models',[]) if m.get('name')==model or m.get('model')==model]
    if len(matches)!=1 or matches[0].get('digest','').removeprefix('sha256:')!=expected:
        raise ValueError('Installed model differs from the frozen full digest')
    if matches[0].get('remote_host') or matches[0].get('remote_model'):
        raise ValueError('A locally installed model is required')
    return matches[0]


@contextmanager
def run_lock(directory):
    # OS locks release automatically after process termination. The small lock
    # file can remain; its mere presence never prevents a later resume.
    handle = (directory/'.run.lock').open('a+b')
    try:
        handle.seek(0,2)
        if handle.tell()==0: handle.write(b'0'); handle.flush()
        handle.seek(0)
        try:
            if __import__('os').name=='nt':
                import msvcrt
                msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as error:
            raise ValueError('Another process is using this extraction run') from error
        yield
    finally:
        handle.close()


def config_for(input_path, records, model, expected_digest, dry_run):
    version, prompt, schema = extraction.track_spec(TRACK)
    return {'schema_version':1,'input_sha256':digest(input_path),
        'selected_cve_ids':[r['cve_id'] for r in records], 'model_requested':model,
        'expected_model_digest':expected_digest,'options':OPTIONS,'extraction_track':TRACK,
        'model_output_representation':'product_assertions','prompt_version':version,
        'prompt_sha256':hashlib.sha256(prompt.encode()).hexdigest(),
        'schema_sha256':hashlib.sha256(json.dumps(schema,sort_keys=True).encode()).hexdigest(),
        'runner_sha256':digest(__file__),'extractor_sha256':digest(extraction.__file__),
        'dry_run':dry_run,'development_diagnostic_only':True,'held_out_benchmark_run':False,
        'retry_policy':'No automatic retries. Resume skips finished or indeterminate attempts; recover saved raw responses offline.',
        'validation_policy':'JSON, exact quote spans, names, and structural checks only. Product classification and vendor meaning need semantic review.',
        'quality_metrics_not_scored':True,'metadata_in_model_input':False}


def check_artifacts(directory, status, record):
    expected_record = hashlib.sha256(json.dumps(record,sort_keys=True).encode()).hexdigest()
    if status['record_sha256']!=expected_record:
        raise ValueError('Saved record differs from frozen input: '+record['cve_id'])
    if status.get('status') not in ['validated','failed'] or status.get('attempt_state') not in ['finished','in_flight','indeterminate']:
        raise ValueError('Unsupported saved record status')
    required={'requests/'+record['cve_id']+'.json'}
    if status['status']=='validated':
        required.update(folder+'/'+record['cve_id']+'.json' for folder in ['raw','validated_assertions','validated','normalized'])
    if not required.issubset(status.get('artifact_sha256',{})):
        raise ValueError('Saved artifact hash coverage is incomplete')
    for relative, expected in status.get('artifact_sha256',{}).items():
        path=directory/relative
        if not path.resolve().is_relative_to(directory.resolve()) or digest(path)!=expected:
            raise ValueError('Saved extraction artifact changed: '+relative)
    if status['status']=='validated':
        assertion=read(directory/'validated_assertions'/(record['cve_id']+'.json'))
        compiled=extraction.validate_assertions(assertion,record)
        if compiled!=read(directory/'validated'/(record['cve_id']+'.json')):
            raise ValueError('Saved compiled graph differs from assertions')


def finish(directory, record, status, response_body):
    cve=record['cve_id']; files=status.setdefault('artifact_sha256',{})
    raw=directory/'raw'/(cve+'.json')
    raw.parent.mkdir(parents=True,exist_ok=True)
    if raw.exists() and raw.read_bytes()!=response_body:
        raise ValueError('Refusing to overwrite a saved response')
    if not raw.exists(): raw.write_bytes(response_body)
    files['raw/'+cve+'.json']=digest(raw)
    write(directory/'record_statuses'/(cve+'.json'),status)
    try:
        response=json.loads(response_body)
        if response.get('error') or response.get('done') is not True or response.get('done_reason')=='length':
            raise ValueError('Generation incomplete, errored, or output token limit reached')
        if response.get('model')!=status['model_requested']:
            raise ValueError('Response model differs from requested model')
        assertions=json.loads(response['message']['content'])
        graph=extraction.validate_assertions(assertions,record)
        for folder, value in [('validated_assertions',assertions),('validated',graph),('normalized',extraction.normalize(graph))]:
            path=directory/folder/(cve+'.json'); write(path,value)
            files[folder+'/'+cve+'.json']=digest(path)
        status.update(status='validated',entity_count=len(graph['entities']),relationship_count=len(graph['relationships']))
        status.update(prompt_eval_count=response.get('prompt_eval_count'),eval_count=response.get('eval_count'))
    except (ValueError,KeyError,TypeError,UnicodeError) as error:
        status.update(status='failed',error_type=type(error).__name__,error=str(error))
    status['attempt_state']='finished'
    status['factual_correctness_reviewed']=False


def summarize(directory, records, sessions, dry_run=False):
    statuses=[]
    for record in records:
        p=directory/'record_statuses'/(record['cve_id']+'.json')
        if p.exists(): statuses.append(read(p))
    write(directory/'statuses.json',statuses)
    completed=len(statuses)
    sent_sessions=[s for s in sessions if s.get('chat_requests_started',0)>0]
    stable=bool(sent_sessions) and all(s.get('model_digest_stable') is True for s in sent_sessions)
    result={'schema_version':1,'status':('dry_run_complete' if dry_run else 'all_records_attempted' if completed==len(records) and stable else 'paused_or_stopped'),
        'requested_records':len(records),'attempted_records':completed,'pending_records':len(records)-completed,
        'validated':sum(s['status']=='validated' for s in statuses),
        'failed':sum(s['status']=='failed' for s in statuses),
        'indeterminate_attempts':sum(s.get('attempt_state') in ['in_flight','indeterminate'] for s in statuses),
        'model_requests_started':sum(s.get('model_request_started',False) for s in statuses),
        'completed_api_responses':sum('raw/'+s['cve_id']+'.json' in s.get('artifact_sha256',{}) for s in statuses),
        'model_digest_stable':stable,'dry_run':dry_run,'extraction_track':TRACK,
        'metadata_in_model_input':False,'quality_metrics_not_scored':True,'graph_ready':False,
        'held_out_benchmark_run':False,'semantic_review_performed':False,
        'request_count_note':'Started means dispatch was recorded before the call. After abrupt interruption, server receipt cannot be proved without a saved response.',
        'explanation':'Validated means structure and source spans passed; it does not establish correct products, vendor associations, completeness, or independent gold.'}
    write(directory/'summary.json',result)
    return result


def run(input_path, directory, model=MODEL, expected_digest=MODEL_DIGEST,
        dry_run=False, resume=False, max_records=None, client=None):
    records=extraction.load_inputs(input_path)
    if max_records is not None and max_records<1: raise ValueError('max-records must be positive')
    static=config_for(input_path,records,model,expected_digest,dry_run)
    if resume:
        if dry_run: raise ValueError('Dry runs cannot be resumed as live runs')
        if not directory.is_dir(): raise ValueError('Resume directory does not exist')
    else:
        directory.mkdir(parents=True,exist_ok=False)
    with run_lock(directory):
        if resume:
            saved=read(directory/'config.json')
            if saved['frozen_config']!=static or any(saved.get(k)!=v for k,v in static.items()):
                raise ValueError('Frozen run configuration/input/code changed')
        else:
            write(directory/'config.json',{'run_id':directory.name,'created_utc':extraction.utc(),
                'frozen_config':static, **static})
        if dry_run:
            for record in records:
                write(directory/'requests'/(record['cve_id']+'.json'),extraction.make_payload(record,model,OPTIONS,TRACK))
            return summarize(directory,records,[],True)
        # Check all earlier status/artifact pairs before contacting the model.
        for record in records:
            p=directory/'record_statuses'/(record['cve_id']+'.json')
            if p.exists():
                status=read(p); check_artifacts(directory,status,record)
                if status.get('attempt_state')=='in_flight':
                    raw=directory/'raw'/(record['cve_id']+'.json')
                    if raw.exists():
                        finish(directory,record,status,raw.read_bytes())
                        status['recovered_saved_response_offline']=True
                    else:
                        status.update(status='failed',attempt_state='indeterminate',
                            error_type='InterruptedAttempt',error='Interrupted call has no saved response; not retried automatically.')
                    write(p,status)
        sessions=read(directory/'sessions.json') if (directory/'sessions.json').exists() else []
        if all((directory/'record_statuses'/(r['cve_id']+'.json')).exists() for r in records):
            return summarize(directory,records,sessions)
        client=client or LocalOllama()
        session={'started_utc':extraction.utc(),'model_digest_stable':False,'chat_requests_started':0}
        sessions.append(session); write(directory/'sessions.json',sessions)
        stopped=None
        try:
            before=model_snapshot(client,model,expected_digest)
            _,show=api(client,'/api/show',{'model':model})
            _,version=api(client,'/api/version')
            if show.get('remote_host') or show.get('remote_model'): raise ValueError('Remote model is not allowed')
            provenance={'ollama_version':version,'model':before,'show':show}
            if (directory/'model_provenance.json').exists():
                old=read(directory/'model_provenance.json')
                if old['ollama_version']!=version or old['show']!=show:
                    raise ValueError('Ollama version or model configuration changed during resume')
            else: write(directory/'model_provenance.json',provenance)
            session.update(model_before=before,ollama_version=version)
            write(directory/'sessions.json',sessions)
            for record in records:
                cve=record['cve_id']; status_path=directory/'record_statuses'/(cve+'.json')
                if status_path.exists(): continue
                if max_records is not None and session['chat_requests_started']>=max_records: break
                current=model_snapshot(client,model,expected_digest)
                payload=extraction.make_payload(record,model,OPTIONS,TRACK)
                request_path=directory/'requests'/(cve+'.json')
                # A saved request without a dispatch marker was never marked as
                # initiated. Verify its contents, rather than overwriting it.
                if request_path.exists():
                    if read(request_path)!=payload: raise ValueError('Saved request differs from frozen payload')
                else: write(request_path,payload)
                status={'cve_id':cve,'status':'failed','attempt_state':'in_flight','model_requested':model,
                    'model_digest_before':current['digest'],'model_request_started':True,
                    'record_sha256':hashlib.sha256(json.dumps(record,sort_keys=True).encode()).hexdigest(),
                    'artifact_sha256':{'requests/'+cve+'.json':digest(request_path)},'started_utc':extraction.utc()}
                write(status_path,status)
                session['chat_requests_started']+=1; write(directory/'sessions.json',sessions)
                print('Extracting '+cve+' ('+str(sum((directory/'record_statuses'/(r['cve_id']+'.json')).exists() for r in records))+'/'+str(len(records))+')',flush=True)
                started=time.perf_counter(); transport_failed=False
                try:
                    body=client.call('/api/chat',payload)
                    finish(directory,record,status,body)
                except RawAPIError as error:
                    transport_failed=True
                    p=directory/'raw_errors'/(cve+'.bin');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(error.body)
                    status['artifact_sha256']['raw_errors/'+cve+'.bin']=digest(p)
                    status.update(status='failed',attempt_state='finished',error_type=type(error).__name__,error=str(error))
                except (OSError,ValueError,KeyError,TypeError,UnicodeError) as error:
                    transport_failed=isinstance(error,OSError)
                    status.update(status='failed',attempt_state='finished',error_type=type(error).__name__,error=str(error))
                status['runtime_seconds']=time.perf_counter()-started
                write(status_path,status); summarize(directory,records,sessions)
                print(cve+' '+status['status'],flush=True)
                if transport_failed:
                    raise ValueError('Transport or filesystem failure; progress saved and remaining records paused.')
        except KeyboardInterrupt:
            session['interrupted']=True; stopped='Interrupted by user; progress retained.'
        except Exception as error:
            session.update(error_type=type(error).__name__,error=str(error)); stopped=str(error)
            if isinstance(error,RawAPIError):
                p=directory/('session-'+str(len(sessions))+'-raw-error.bin');p.write_bytes(error.body)
        finally:
            try:
                after=model_snapshot(client,model,expected_digest)
                session['model_after']=after
                session['model_digest_stable']='model_before' in session and after['digest']==session['model_before']['digest']
            except Exception as error:
                session['postflight_error']=str(error)
            session['finished_utc']=extraction.utc(); write(directory/'sessions.json',sessions)
            result=summarize(directory,records,sessions)
        if stopped: print(stopped,flush=True)
        return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-dir',type=Path,required=True)
    p.add_argument('--resume',action='store_true')
    p.add_argument('--dry-run',action='store_true')
    p.add_argument('--max-records',type=int)
    args=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    try:
        verified=audit(root,'cgqa-5495aa3949d0b789')
        if verified['input_sha256']['data/processed/extraction_inputs.jsonl']!='4d74ed3c2f4efa0414a9abec881ab7a40c11fdee28b02fc0afb7c9e29ad6ae09':
            raise ValueError('Description-only inputs differ from the verified frozen bytes')
        result=run(root/'data/processed/extraction_inputs.jsonl',args.run_dir,
            dry_run=args.dry_run,resume=args.resume,max_records=args.max_records)
        audit_path=args.run_dir/'frozen-dataset-audit.json'
        if not audit_path.exists():write(audit_path,verified)
        manifest={f.relative_to(args.run_dir).as_posix():digest(f) for f in sorted(args.run_dir.rglob('*'))
            if f.is_file() and f.suffix in ['.json','.bin'] and f.name!='artifact-manifest.json'}
        write(args.run_dir/'artifact-manifest.json',{'schema_version':1,'file_sha256':manifest})
    except Exception as error:
        p.exit(1,'Full-sample extraction stopped: '+str(error)+'\n')
    print(json.dumps(result,indent=2))
    return 0 if result['status'] in ['all_records_attempted','dry_run_complete'] else 2


if __name__=='__main__':raise SystemExit(main())
