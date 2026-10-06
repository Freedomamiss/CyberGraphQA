"""Retrieve four frozen modes for 20 questions without generating answers."""
import argparse
import json
from pathlib import Path
from compare_retrieval import compose_modes
from generate_item_citations import load_contexts
from pack_support import pack_supported
from pack_target_relations import pack_target_relations
from retrieve_evidence import corpus, sha
from run_structured_retrieval_smoke import verified_bundle
from semantic_index import checked_manifest, digest, semantic_result, write_json
from verify_qa_evaluation import verify


def discover_index(root, graph, revision):
    """Select the newest identity-matching full index, then verify its bytes."""
    candidates=[]
    for path in root.rglob('manifest.json'):
        try: manifest=json.loads(path.read_text(encoding='utf-8'))
        except (ValueError,OSError): continue
        if (manifest.get('status')=='complete' and manifest.get('graph_sha256')==sha(graph)
                and manifest.get('model_revision')==revision and manifest.get('documents')==150
                and (path.parent/'model').is_dir()):
            candidates.append(path)
    if not candidates:
        raise ValueError('No matching full structured index with local model found under '+str(root)+'. No index rebuild or download was attempted.')
    chosen=sorted(candidates,key=lambda p:(-p.stat().st_mtime_ns,str(p)))[0]
    # A corrupted selected index must fail, not silently fall back to another.
    manifest=checked_manifest(chosen.parent,graph)
    return chosen.parent,manifest


def requested_units(graph, question):
    cve=question['cve_id'];local={u['evidence_id'] for u in graph['evidence_units'] if u['cve_id']==cve}
    affects=[e for e in graph['edges'] if e['subject']==cve and e['predicate']=='AFFECTS']
    products={e['object'] for e in affects}
    relevant=affects+[e for e in graph['edges'] if e['predicate']=='MADE_BY' and e['subject'] in products]
    kind=question['question_type']
    extra='HAS_WEAKNESS' if kind.endswith('weakness') else 'HAS_SEVERITY' if kind.endswith('severity') else None
    relevant += [e for e in graph['edges'] if e['subject']==cve and e['predicate']==extra]
    return {eid for edge in relevant for eid in edge['evidence_ids'] if eid in local}


def compose_frozen(graph, question, semantic, cap=6000, top_k=5):
    rows=compose_modes(graph,question['question'],semantic,top_k,cap)
    docs=corpus(graph)
    for mode,row in rows.items():
        if mode=='llm-only': continue
        packer=pack_target_relations if mode=='hybrid' else pack_supported
        args=[row['text_candidates'],row['graph_candidates'],docs,cap,mode]
        if mode=='hybrid': args.append(question['question'])
        packed=packer(*args)
        rows[mode]={**row,**packed,'repacking_only':True,
            'packing_script_sha256':digest(Path(__file__).with_name('pack_target_relations.py' if mode=='hybrid' else 'pack_support.py')),
            'retrieval_protocol':'source-derived-qa-evaluation-v1'}
    # Validate exact source preservation after packing, including empty mode.
    facts={f['evidence_id']:f for d in docs.values() for f in d['facts']}
    for mode,row in rows.items():
        if row['graph_sha256']!=sha(graph) or row['corpus_sha256']!=sha(docs):
            raise ValueError('Packed source identity changed')
        expected=''.join('['+f['evidence_id']+'] '+f['text']+'\n' for f in row['evidence'])
        if row['context']!=expected or row['context_characters']!=len(expected) or len(expected)>cap:
            raise ValueError('Packing context/budget mismatch')
        ids=[f['evidence_id'] for f in row['evidence']]
        if len(ids)!=len(set(ids)) or any(facts.get(f['evidence_id'])!=f for f in row['evidence']):
            raise ValueError('Duplicate or noncanonical evidence')
        if mode=='llm-only' and ids: raise ValueError('No-retrieval mode contains evidence')
    return rows


def run(packet_dir, graph_dir, output_dir, index_dir=None, index_root=None):
    output_dir.mkdir(parents=True,exist_ok=False)
    verify(packet_dir,graph_dir,output_dir/'packet-preflight')
    lock=json.loads((packet_dir/'protocol-lock.json').read_text(encoding='utf-8'))
    graph,_=verified_bundle(graph_dir)
    if index_dir is None:
        if index_root is None: raise ValueError('An index directory or root is required')
        index_dir,index=discover_index(index_root,graph,lock['embedding_model_revision'])
    else:
        index=checked_manifest(index_dir,graph)
    if index['model_revision']!=lock['embedding_model_revision'] or index['model_id']!='sentence-transformers/all-MiniLM-L6-v2':
        raise ValueError('Embedding model differs from frozen protocol')
    print('Reusing verified index: '+str(index_dir),flush=True)
    write_json(output_dir/'index-manifest.json',index)
    write_json(output_dir/'retrieval-config.json',{'protocol_id':lock['protocol_id'],
        'packet_manifest_sha256':digest(packet_dir/'packet-manifest.json'),
        'runner_sha256':digest(__file__),'index_directory':str(index_dir),
        'index_manifest_sha256':digest(index_dir/'manifest.json'),
        'index_selection_policy':'Explicit directory, or newest identity-matching complete index with local model; fail on selected index corruption.',
        'question_embedding_calls_planned':20,'generator_requests_planned':0,
        'character_cap':lock['character_cap'],'top_k_per_channel':lock['top_k_per_channel'],
        'source_reference_used_for_ranking_or_packing':False})
    questions=json.loads((packet_dir/'questions.json').read_text(encoding='utf-8'));cases=[]
    for question in questions:
        qid=question['question_id'];print('Retrieving '+qid+': '+question['question'],flush=True)
        directory=output_dir/qid;directory.mkdir()
        write_json(directory/'query-dispatch.json',{'question_embedding_started':True,'generation_requested':False})
        semantic=semantic_result(graph_dir/'graph.json',index_dir,question['question'],lock['top_k_per_channel'],lock['character_cap'])
        write_json(directory/'semantic-ranking.json',semantic)
        rows=compose_frozen(graph,question,semantic,lock['character_cap'],lock['top_k_per_channel'])
        for mode,row in rows.items():write_json(directory/(mode+'.json'),row)
        manifest={'schema_version':1,'status':'complete','protocol_id':lock['protocol_id'],
            'question_id':qid,'question':question['question'],'graph_sha256':sha(graph),
            'corpus_sha256':semantic['corpus_sha256'],'generation_performed':False,
            'semantic_query_calls':1,'index_rebuilt':False,'top_k_per_channel':lock['top_k_per_channel'],
            'budget':{'unit':'characters','cap':lock['character_cap'],'generator_token_budget_enforced':False},
            'output_sha256':{m+'.json':digest(directory/(m+'.json')) for m in rows}}
        write_json(directory/'comparison-manifest.json',manifest)
        load_contexts(directory)
        required=requested_units(graph,question)
        case={'question_id':qid,'cve_id':question['cve_id'],'modes':[]}
        for mode,row in rows.items():
            supplied={f['evidence_id'] for f in row['evidence']}
            case['modes'].append({'mode':mode,'evidence_units':len(supplied),
                'context_characters':row['context_characters'],
                'requested_relation_units_in_graph':len(required),
                'requested_relation_units_supplied':len(required & supplied),
                'target_record_supplied':any(f['cve_id']==question['cve_id'] for f in row['evidence']),
                'coverage_is_exact_source_unit_diagnostic_not_semantic_support':True})
        cases.append(case);write_json(directory/'retrieval-diagnostic.json',case)
    # Detect changes to the persisted index during the run.
    if checked_manifest(index_dir,graph)!=index: raise ValueError('Index changed during retrieval')
    summary={'schema_version':1,'status':'frozen_qa_retrieval_complete','protocol_id':lock['protocol_id'],
        'questions':len(questions),'saved_mode_contexts':sum(len(c['modes']) for c in cases),
        'question_embedding_calls':len(cases),'generator_requests_sent':0,'generation_performed':False,
        'new_index_required':False,'index_rebuilt':False,'model_download_performed':False,
        'human_gold':False,'held_out_benchmark':False,'quality_scored':False,
        'packet_manifest_sha256':digest(packet_dir/'packet-manifest.json'),
        'graph_canonical_sha256':sha(graph),'index_manifest_sha256':digest(index_dir/'manifest.json'),
        'runner_sha256':digest(__file__),'cases':cases,
        'output_sha256':{p.relative_to(output_dir).as_posix():digest(p) for p in sorted(output_dir.rglob('*.json'))}}
    write_json(output_dir/'evaluation-retrieval-summary.json',summary)
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['packet-dir','graph-dir','output-dir']:p.add_argument('--'+name,type=Path,required=True)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--index-dir',type=Path);group.add_argument('--index-root',type=Path)
    a=p.parse_args()
    try:r=run(a.packet_dir,a.graph_dir,a.output_dir,a.index_dir,a.index_root)
    except Exception as e:p.exit(1,'Frozen evaluation retrieval stopped: '+str(e)+'\n')
    print(json.dumps({k:v for k,v in r.items() if k not in ['cases','output_sha256']},indent=2))
