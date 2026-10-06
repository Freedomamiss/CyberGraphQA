"""Repack verified Checkpoint 20 rankings without embedding or generator calls."""
import argparse
import json
from pathlib import Path
from pack_support import pack_supported
from retrieve_evidence import corpus,sha
from run_structured_retrieval_smoke import verified_bundle,CASES
from semantic_index import digest,write_json


def run(source_dir,graph_dir,output_dir):
    summary=json.loads((source_dir/'retrieval-summary.json').read_text(encoding='utf-8'))
    if summary.get('status')!='retrieval_smoke_complete':raise ValueError('Completed retrieval smoke run required')
    for name,h in summary['output_sha256'].items():
        p=source_dir/name
        if not p.resolve().is_relative_to(source_dir.resolve()) or digest(p)!=h:raise ValueError('Source context hash/path mismatch: '+name)
    graph,_=verified_bundle(graph_dir);docs=corpus(graph);results=[];prepared=[]
    for label,question in CASES:
        rows={m:json.loads((source_dir/label/(m+'.json')).read_text(encoding='utf-8')) for m in ['llm-only','text','graph','hybrid']}
        manifest=json.loads((source_dir/label/'comparison-manifest.json').read_text(encoding='utf-8'))
        for mode,row in rows.items():
            if digest(source_dir/label/(mode+'.json'))!=manifest['output_sha256'][mode+'.json']:raise ValueError('Mode hash mismatch')
            if row['question']!=question or row['corpus_sha256']!=sha(docs) or row['graph_sha256']!=sha(graph):raise ValueError('Context source identity mismatch')
            for f in row['evidence']:
                if f not in docs[f['cve_id']]['facts']:raise ValueError('Noncanonical source evidence')
        changed={}
        for mode,row in rows.items():
            if mode=='llm-only':changed[mode]=row;continue
            packed=pack_supported(row['text_candidates'],row['graph_candidates'],docs,6000,mode)
            changed[mode]={**row,**packed,'repacking_only':True,'previous_packing_script_sha256':row['packing_script_sha256'],
                'packing_script_sha256':digest(Path(__file__).with_name('pack_support.py')),
                'source_context_sha256':digest(source_dir/label/(mode+'.json'))}
        prepared.append((label,changed))
        results.append({'case':label,'question':question,'modes':[{'mode':m,'evidence_units':len(r['evidence']),
            'context_characters':r['context_characters'],'preferred_bundles':r.get('packing_support',{}).get('preferred_bundles',0),
            'omitted_bundles':r.get('packing_support',{}).get('omitted_bundles',0)} for m,r in changed.items()]})
    output_dir.mkdir(parents=True,exist_ok=False)
    for label,rows in prepared:
        target=output_dir/label;target.mkdir()
        for mode,row in rows.items():write_json(target/(mode+'.json'),row)
        original=json.loads((source_dir/label/'comparison-manifest.json').read_text(encoding='utf-8'))
        manifest={**original,'repacking_only':True,'source_manifest_sha256':digest(source_dir/label/'comparison-manifest.json'),
            'semantic_query_calls':0,'output_sha256':{m+'.json':digest(target/(m+'.json')) for m in rows},
            'packing_script_sha256':digest(Path(__file__).with_name('pack_support.py'))}
        write_json(target/'comparison-manifest.json',manifest)
    result={'schema_version':1,'status':'support_repacking_complete','cases':results,
        'candidate_rankings_changed':False,'corpus_changed':False,'semantic_query_calls':0,'generator_requests_sent':0,
        'new_index_required':False,'budget':{'unit':'characters','cap':6000,'generator_token_budget_enforced':False},
        'quality_scored':False,'held_out_benchmark_run':False,'exhaustive_list_answers_supported':False,
        'structured_graph_only':True,'llm_candidate_graph_integrated':False,
        'source_summary_sha256':digest(source_dir/'retrieval-summary.json'),
        'output_sha256':{p.relative_to(output_dir).as_posix():digest(p) for p in sorted(output_dir.rglob('*.json'))}}
    write_json(output_dir/'repacking-summary.json',result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-dir',type=Path,required=True);p.add_argument('--graph-dir',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args()
    try:r=run(a.source_dir,a.graph_dir,a.output_dir)
    except Exception as e:p.exit(1,'Support repacking stopped: '+str(e)+'\n')
    for case in r['cases']:print(json.dumps(case))
    print(json.dumps({k:v for k,v in r.items() if k not in ['cases','output_sha256']}))


if __name__=='__main__':main()
