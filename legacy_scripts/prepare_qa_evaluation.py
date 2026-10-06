"""Freeze a source-derived 20-question QA packet before new generation."""
import argparse
import hashlib
import json
from pathlib import Path
from collections import defaultdict
from run_structured_retrieval_smoke import verified_bundle
from retrieve_evidence import sha
from semantic_index import digest, write_json
import generate_item_citations as gen

SEED = 'cgqa-source-derived-qa-v1'
RETIRED_QA_CVES = {'CVE-2020-16009', 'CVE-2025-20125'}
FREEZE_SCRIPTS = ['generate_item_citations.py','generate_structured_development.py',
    'retrieve_evidence.py','structured_retrieval.py','compare_retrieval.py','semantic_index.py',
    'pack_support.py','pack_target_relations.py','repack_target_relations.py',
    'build_full_qa_graph.py','query_graph.py','run_structured_retrieval_smoke.py']


def select(graph, excluded, count=20):
    nodes = {n['id']:n for n in graph['nodes']}; edges = graph['edges']
    units = {u['evidence_id']:u for u in graph['evidence_units']}
    makes = defaultdict(list)
    for edge in edges:
        if edge['predicate']=='MADE_BY': makes[edge['subject']].append(edge)
    groups = defaultdict(list); candidates = {}
    for cve in sorted(n['id'] for n in graph['nodes'] if n['type']=='CVE'):
        if cve in excluded: continue
        all_products = {e['object'] for e in edges if e['subject']==cve and e['predicate']=='AFFECTS'}
        if not 1 <= len(all_products) <= 5: continue
        paths = []
        for affects in edges:
            if affects['subject']!=cve or affects['predicate']!='AFFECTS': continue
            for maker in makes[affects['object']]:
                ids = [eid for eid in affects['evidence_ids']+maker['evidence_ids']
                       if units[eid]['cve_id']==cve]
                a_ids = [eid for eid in affects['evidence_ids'] if eid in ids]
                m_ids = [eid for eid in maker['evidence_ids'] if eid in ids]
                if not a_ids or not m_ids: continue
                paths.append({'nodes':[cve,affects['object'],maker['object']],
                    'predicates':['AFFECTS','MADE_BY'],'hop_count':2,
                    'affects_evidence_ids':a_ids,'made_by_evidence_ids':m_ids})
        if not paths or {p['nodes'][1] for p in paths} != all_products: continue
        candidates[cve]=paths
        # Assign multi-vendor CVEs once using their first sorted vendor key.
        vendor=min(nodes[path['nodes'][2]]['identity_key'] for path in paths)
        groups[vendor].append(cve)
    key=lambda cve:hashlib.sha256((SEED+'|'+cve).encode()).hexdigest()
    for vendor in groups: groups[vendor].sort(key=key)
    chosen=[]
    while len(chosen)<count:
        added=False
        for vendor in sorted(groups):
            if groups[vendor] and len(chosen)<count:
                chosen.append((vendor,groups[vendor].pop(0)));added=True
        if not added: raise ValueError('Insufficient eligible source records')
    return chosen,candidates


def build(graph, excluded):
    nodes={n['id']:n for n in graph['nodes']}; chosen,paths=select(graph,excluded)
    questions=[];reference=[]
    for index,(vendor,cve) in enumerate(chosen):
        kind=['products-vendors','products-vendors-weakness','products-vendors-severity'][(index+index//6)%3]
        question='Within the frozen dataset, which recorded products and vendors are linked to '+cve+'?'
        if kind.endswith('weakness'):question=question[:-1]+', and what weakness IDs are recorded for it?'
        if kind.endswith('severity'):question=question[:-1]+', and what selected severity is recorded for it?'
        qid='QA-'+str(index+1).zfill(3)
        questions.append({'question_id':qid,'question':question,'cve_id':cve,'question_type':kind,
            'vendor_stratum':vendor,'requires_product_vendor_path':True,'minimum_support_path_hops':2,
            'prior_source_exposure':True,'held_out':False,'generation_performed':False})
        local=[e for e in graph['edges'] if e['subject']==cve]
        claims=[]
        for node_id in sorted({p['nodes'][1] for p in paths[cve]}):
            ids=sorted({eid for p in paths[cve] if p['nodes'][1]==node_id for eid in p['affects_evidence_ids']})
            claims.append({'kind':'product','entity_id':node_id,'name':nodes[node_id]['name'],'support_evidence_ids':ids})
        for node_id in sorted({p['nodes'][2] for p in paths[cve]}):
            ids=sorted({eid for p in paths[cve] if p['nodes'][2]==node_id for eid in p['affects_evidence_ids']+p['made_by_evidence_ids']})
            claims.append({'kind':'vendor','entity_id':node_id,'name':nodes[node_id]['name'],'support_evidence_ids':ids})
        predicate='HAS_WEAKNESS' if kind.endswith('weakness') else 'HAS_SEVERITY' if kind.endswith('severity') else None
        extra=[e for e in local if e['predicate']==predicate]
        for edge in sorted(extra,key=lambda e:e['object']):
            claims.append({'kind':'weakness' if predicate=='HAS_WEAKNESS' else 'severity',
                'entity_id':edge['object'],'name':nodes[edge['object']]['name'],'support_evidence_ids':edge['evidence_ids']})
        source_units=[u for u in graph['evidence_units'] if u['cve_id']==cve]
        reference.append({'question_id':qid,'cve_id':cve,'expected_claims':claims,
            'support_paths':paths[cve],'requested_metadata_missing':bool(predicate and not extra),
            'conflict_flags':sorted({flag for u in source_units for flag in u['conflict_flags']}),
            'source_conflicts_adjudicated':False,'human_gold':False,'reference_kind':'frozen_structured_source_reference'})
    return questions,reference


def run(graph_dir,pilot_ids,output_dir):
    graph,summary=verified_bundle(graph_dir)
    pilot=json.loads(pilot_ids.read_text(encoding='utf-8'))['cve_ids']
    excluded=set(pilot)|RETIRED_QA_CVES
    questions,reference=build(graph,excluded)
    scripts=Path(__file__).parent
    lock={'schema_version':1,'protocol_id':'source-derived-qa-evaluation-v1','frozen':True,
        'selection_seed':SEED,'selection_policy':'One to five recorded products with same-CVE vendor support; SHA-256 ordering within source-vendor strata; round robin; no extraction outcome or QA result used',
        'excluded_cves':sorted(excluded),'questions':20,'modes':gen.MODES,
        'planned_generation_requests':80,'generation_requests_sent':0,
        'graph_canonical_sha256':sha(graph),'snapshot_id':graph['evidence_units'][0]['snapshot_id'],
        'model':gen.PINNED_MODEL,'model_digest':gen.PINNED_DIGEST,'generator_options':gen.OPTIONS,
        'system_prompt':gen.SYSTEM,'answer_schema':gen.SCHEMA,
        'embedding_model_revision':'1110a243fdf4706b3f48f1d95db1a4f5529b4d41',
        'top_k_per_channel':5,'character_cap':6000,'generator_token_budget_enforced':False,
        'retrieval_policy':'Checkpoint 23 support packing; Checkpoint 29 target-relation priority for eligible hybrid questions',
        'script_sha256':{name:digest(scripts/name) for name in FREEZE_SCRIPTS},
        'packet_builder_sha256':digest(__file__),'source_graph_build_summary_sha256':digest(graph_dir/'build-summary.json'),
        'human_gold':False,'held_out_benchmark':False,'source_conflicts_adjudicated':False,
        'exposure_disclosure':'All source records were used in development extraction and corpus building. Excluding pilot IDs does not establish blindness; newly composed questions are not a held-out source split.',
        'evaluation_status':'protocol_and_source_reference_frozen; retrieval_and_generation_pending',
        'scoring_policy_file':'SCORING_RULES.md'}
    output_dir.mkdir(parents=True,exist_ok=False)
    write_json(output_dir/'questions.json',questions);write_json(output_dir/'source-reference.json',reference)
    write_json(output_dir/'protocol-lock.json',lock)
    rules=Path(__file__).resolve().parents[1]/'QA_Evaluation_Scoring_Rules_v1.md'
    (output_dir/'SCORING_RULES.md').write_bytes(rules.read_bytes())
    hashes={p.name:digest(p) for p in sorted(output_dir.iterdir())}
    write_json(output_dir/'packet-manifest.json',{'protocol_id':lock['protocol_id'],'output_sha256':hashes,
        'model_requests_sent':0,'human_gold':False,'held_out_benchmark':False})
    return lock


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['graph-dir','pilot-ids','output-dir']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    try:result=run(a.graph_dir,a.pilot_ids,a.output_dir)
    except Exception as e:p.exit(1,'Evaluation packet stopped: '+str(e)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['script_sha256','system_prompt','answer_schema']},indent=2))
