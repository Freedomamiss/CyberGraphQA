"""Verify a frozen source-derived QA packet and installed code; no model calls."""
import argparse
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
from collections import Counter
from prepare_qa_evaluation import build, SEED, FREEZE_SCRIPTS
from run_structured_retrieval_smoke import verified_bundle
from retrieve_evidence import sha
from semantic_index import digest, write_json
import generate_item_citations as gen


def verify_hashes(root, manifest):
    """Verify packet bytes without depending on optional prior audit patches."""
    for name, expected in manifest.items():
        posix = PurePosixPath(name); windows = PureWindowsPath(name)
        if (posix.anchor or windows.anchor or '..' in posix.parts or
                '..' in windows.parts or '\\' in name):
            raise ValueError('Unsafe manifest path')
        path = root/name
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('Unsafe manifest path')
        if digest(path) != expected:
            raise ValueError('Packet artifact hash mismatch: '+name)


def verify(packet_dir, graph_dir, output):
    manifest=json.loads((packet_dir/'packet-manifest.json').read_text(encoding='utf-8'))
    if set(manifest['output_sha256'])!={'questions.json','source-reference.json','protocol-lock.json','SCORING_RULES.md'}:
        raise ValueError('Unexpected evaluation packet files')
    verify_hashes(packet_dir,manifest['output_sha256'])
    lock=json.loads((packet_dir/'protocol-lock.json').read_text(encoding='utf-8'))
    if lock['selection_seed']!=SEED or lock['human_gold'] is not False or lock['held_out_benchmark'] is not False:
        raise ValueError('Evaluation identity/disclosure differs')
    if set(lock['script_sha256'])!=set(FREEZE_SCRIPTS):raise ValueError('Code freeze coverage differs')
    scripts=Path(__file__).parent
    for name,h in lock['script_sha256'].items():
        if digest(scripts/name)!=h:raise ValueError('Frozen code differs: '+name)
    if digest(scripts/'prepare_qa_evaluation.py')!=lock['packet_builder_sha256']:
        raise ValueError('Packet builder differs')
    if lock['generator_options']!=gen.OPTIONS or lock['system_prompt']!=gen.SYSTEM or lock['answer_schema']!=gen.SCHEMA:
        raise ValueError('Generator protocol differs')
    if lock['model_digest']!=gen.PINNED_DIGEST or lock['model']!=gen.PINNED_MODEL:
        raise ValueError('Expected generator identity differs')
    graph,_=verified_bundle(graph_dir)
    if lock['graph_canonical_sha256']!=sha(graph) or lock['source_graph_build_summary_sha256']!=digest(graph_dir/'build-summary.json'):
        raise ValueError('Frozen graph bundle differs')
    expected_q,expected_r=build(graph,set(lock['excluded_cves']))
    questions=json.loads((packet_dir/'questions.json').read_text(encoding='utf-8'))
    reference=json.loads((packet_dir/'source-reference.json').read_text(encoding='utf-8'))
    if questions!=expected_q or reference!=expected_r:raise ValueError('Question/source reference reconstruction differs')
    if len(questions)!=20 or len({q['cve_id'] for q in questions})!=20:
        raise ValueError('Question coverage differs')
    result={'status':'frozen_qa_packet_verified','protocol_id':lock['protocol_id'],'questions':len(questions),
        'vendor_strata':dict(Counter(q['vendor_stratum'] for q in questions)),
        'question_types':dict(Counter(q['question_type'] for q in questions)),
        'multi_hop_support_paths':sum(len(r['support_paths']) for r in reference),
        'all_questions_have_two_edge_product_vendor_support':all(r['support_paths'] and all(p['hop_count']==2 for p in r['support_paths']) for r in reference),
        'frozen_code_files_verified':len(FREEZE_SCRIPTS)+1,'packet_hashes_verified':4,
        'expected_claims':sum(len(r['expected_claims']) for r in reference),
        'model_requests_sent':0,'retrieval_performed':False,'generation_performed':False,
        'human_gold':False,'held_out_benchmark':False,'quality_scored':False,
        'packet_manifest_sha256':digest(packet_dir/'packet-manifest.json')}
    output.mkdir(parents=True,exist_ok=False);write_json(output/'verification-summary.json',result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ['packet-dir','graph-dir','output-dir']:p.add_argument('--'+arg,type=Path,required=True)
    a=p.parse_args()
    try:result=verify(a.packet_dir,a.graph_dir,a.output_dir)
    except Exception as e:p.exit(1,'Evaluation packet verification stopped: '+str(e)+'\n')
    print(json.dumps(result,indent=2))
