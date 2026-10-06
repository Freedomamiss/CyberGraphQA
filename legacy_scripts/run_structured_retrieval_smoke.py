"""Verify the schema-2 graph/text bundle and run fixed development retrieval cases."""
import argparse
import json
from pathlib import Path

from build_full_qa_graph import documents
from compare_retrieval import run
from semantic_index import digest, write_json, checked_manifest
from structured_retrieval import validate

CASES = [
    ('named-cve', 'Which products and vendors are linked to CVE-2020-16009?'),
    ('vendor', 'Which CVEs are linked to Microsoft?'),
    ('weakness', 'Which CVEs have recorded weakness CWE-295?'),
    ('severity', 'Which CVEs have selected severity CRITICAL?'),
    ('product', 'Which CVEs affect Chrome?'),
    ('second-cve', 'Which products and vendors are linked to CVE-2025-20125?'),
    ('unrecognized-product', 'Which CVEs affect Unrepresented Example Product Zeta?'),
]


def verified_bundle(directory):
    summary = json.loads((directory/'build-summary.json').read_text(encoding='utf-8'))
    if summary.get('status') != 'built_and_parity_checked':
        raise ValueError('Structured graph build is not complete')
    for name in ['graph.json','text-documents.jsonl','inspection.json']:
        if digest(directory/name) != summary['output_sha256'][name]:
            raise ValueError('Graph bundle hash mismatch: '+name)
    graph = json.loads((directory/'graph.json').read_text(encoding='utf-8'))
    validate(graph)
    exported = [json.loads(line) for line in (directory/'text-documents.jsonl').read_text(encoding='utf-8').splitlines()]
    if exported != documents(graph):
        raise ValueError('Exported text differs from the canonical graph units')
    if len(exported) != 150 or len(graph['evidence_units']) != 2054:
        raise ValueError('Structured corpus coverage differs')
    if graph['source_manifest']['input_sha256'] != summary['input_sha256']:
        raise ValueError('Source hashes differ within bundle')
    return graph, summary


def smoke(graph_dir, index_dir, output_dir):
    graph, build = verified_bundle(graph_dir)
    index = checked_manifest(index_dir, graph)
    output_dir.mkdir(parents=True, exist_ok=False)
    reports=[]
    for label, question in CASES:
        print('Retrieval case: '+label, flush=True)
        target=output_dir/label
        rows=run(graph_dir/'graph.json',index_dir,question,target)
        modes={m:json.loads((target/(m+'.json')).read_text(encoding='utf-8')) for m in ['llm-only','text','graph','hybrid']}
        reports.append({'case':label,'question':question,'modes':rows,
            'text_candidate_cves':[r['cve_id'] for r in modes['text']['text_candidates']],
            'graph_candidate_cves':[r['cve_id'] for r in modes['graph']['graph_candidates']],
            'graph_anchor_types':sorted({n['type'] for n in modes['graph']['anchors']})})
    write_json(output_dir/'index-manifest.json',index)
    write_json(output_dir/'graph-build-summary.json',build)
    result={'schema_version':1,'status':'retrieval_smoke_complete','development_diagnostic_only':True,
        'cases':reports,'records':150,'evidence_units':2054,'graph_bundle_verified':True,
        'smoke_script_sha256':digest(Path(__file__)),
        'text_graph_units_identical':True,'embedding_model_revision':index['model_revision'],
        'corpus_embeddings_rebuilt':index.get('corpus_embeddings_rebuilt',False),
        'index_chunks':index['chunks'],'semantic_query_calls':len(CASES),'generator_requests_sent':0,
        'held_out_benchmark_run':False,'comparative_quality_scored':False,
        'source_conflicts_adjudicated':False,'llm_extraction_graph':False,
        'budget':{'unit':'characters','cap':6000,'generator_token_budget_enforced':False},
        'limitations':['Exact anchors and typed paths only; no general parsing of negation, OR, joins, comparisons, or time conditions.',
            'Top five CVEs per channel; no KEV predicate filter or gold-answer scoring.',
            'Candidates and packed context are diagnostics, not evidence of factual answer quality.'],
        'output_sha256':{p.relative_to(output_dir).as_posix():digest(p) for p in sorted(output_dir.rglob('*.json'))}}
    write_json(output_dir/'retrieval-summary.json',result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--graph-dir',type=Path,required=True)
    p.add_argument('--index-dir',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    args=p.parse_args()
    try:
        result=smoke(args.graph_dir,args.index_dir,args.output_dir)
    except Exception as error:
        p.exit(1,'Structured retrieval smoke stopped: '+str(error)+'\n')
    for case in result['cases']:
        print(json.dumps(case))
    print(json.dumps({k:v for k,v in result.items() if k not in ['cases','output_sha256']}))


if __name__=='__main__':main()
