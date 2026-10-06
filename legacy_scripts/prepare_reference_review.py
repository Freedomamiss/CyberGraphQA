"""Prepare source-only pending annotations; never fabricate reviewed gold."""
import argparse
import hashlib
import json
from pathlib import Path
from semantic_index import digest,write_json

SELECTION_SEED='cgqa-independent-reference-v1'


def prepare(project,output):
    inputs=project/'data/processed/extraction_inputs.jsonl'
    rows=[json.loads(line) for line in inputs.read_text(encoding='utf-8').splitlines()]
    metadata=json.loads((project/'data/processed/cves.json').read_text(encoding='utf-8'))
    excluded={r['cve_id'] for r in json.loads((project/'data/extraction/pilot_reference_ai_reviewed.json').read_text(encoding='utf-8'))['records']}
    descriptions={r['cve_id']:r['description'] for r in rows}
    if len(rows)!=150 or len(descriptions)!=150 or set(descriptions)!={r['cve_id'] for r in metadata}:
        raise ValueError('Frozen sample coverage differs')
    selected=[]
    for listed,count in [(True,24),(False,6)]:
        pool=[r for r in metadata if r['kev_listed'] is listed and r['cve_id'] not in excluded]
        pool.sort(key=lambda r:hashlib.sha256((SELECTION_SEED+':'+r['cve_id']).encode()).hexdigest())
        if len(pool)<count:raise ValueError('Insufficient records for review stratum')
        selected.extend(pool[:count])
    selected.sort(key=lambda r:r['cve_id'])
    records=[{'cve_id':r['cve_id'],'description':descriptions[r['cve_id']],
              'annotation_status':'pending','reviewer':None,'review_date':None,
              'reviewer_exposed_to_model_outputs_for_this_record':None,
              'products':None,'ambiguity_notes':None} for r in selected]
    output.mkdir(parents=True,exist_ok=False)
    write_json(output/'pending-reference.json',{'schema_version':1,
        'reference_kind':'pending_source_only_annotation','human_reviewed':False,
        'independent_review_complete':False,'records':records})
    text='# Source-only literal extraction review\n\n'
    text+='Complete using only each description and the accompanying guide. Blank annotations are pending, not zero-fact gold.\n\n'
    for index,r in enumerate(records,1):
        text+=f"## {index}. {r['cve_id']}\n\n{r['description']}\n\n"
        text+='Reviewer: \n\nDate: \n\nHave you seen model outputs for this CVE? Yes / No / Unsure: \n\n'
        text+='Products/components and exact supporting quotes: \n\nExplicit vendors for each product and exact supporting quotes: \n\nAliases, ambiguity, or no supported facts: \n\n'
    (output/'Source_Only_Reference_Worksheet.md').write_text(text,encoding='utf-8')
    guide='''# Review instructions

This packet contains source descriptions and blank annotations, not model answers. Prefer a reviewer who has not seen model outputs for these records. Record exposure honestly; a source-only packet does not prove reviewer independence.

This task creates literal product/vendor extraction references. It does not create QA answers, adjudicate structured metadata, or establish a held-out benchmark. All descriptions were already available to the development extraction model.

For each record:

1. Identify explicitly named affected software and named components. Do not annotate generic interfaces, protocols, algorithms, or content as software products.
2. Use source product names without version numbers. Record clear aliases together and explain ambiguity rather than guessing.
3. Copy exact contiguous supporting quotes from the description. Do not rewrite quotes.
4. Add a vendor only when explicit product branding supports it. Do not infer Microsoft from Windows, Apple from iOS, or a component's vendor from a containing product. Do not look up outside facts or add structured metadata.
5. Identify every named affected component/product according to this policy. Distinguish affected versions from fixed versions; this packet does not ask for version ranges.
6. Record reviewer name/date, whether you have seen model outputs for this CVE, and ambiguities. An empty reviewed list means no qualifying fact; a blank field means pending.

You may fill in the Markdown worksheet instead of editing JSON. For JSON, products is a list of objects with name, evidence, and vendors; vendors is a list of objects with name and evidence. Set annotation_status to reviewed only after finishing. Use products=[] only for an intentionally reviewed no-fact record. Do not change descriptions or CVE IDs.

Return the completed worksheet or JSON. References must be checked for exact quotes, policy consistency, and completeness before scoring. Flag disputed cases for adjudication. No score or human-gold status is established by creating this packet.
'''
    (output/'REVIEW_GUIDE.md').write_text(guide,encoding='utf-8')
    result={'schema_version':1,'status':'pending_review_packet_prepared','records':30,
        'kev_listed':24,'not_listed_in_snapshot':6,'selection_seed':SELECTION_SEED,
        'selection_method':'Stratified hash order; excludes all pilot AI-reference IDs; no model outcomes used in selection.',
        'excluded_pilot_ids':sorted(excluded),'selected_ids':[r['cve_id'] for r in selected],
        'input_sha256':{'extraction_inputs.jsonl':digest(inputs),'cves.json':digest(project/'data/processed/cves.json')},
        'human_reviewed':False,'independent_review_complete':False,'model_requests_sent':0,
        'qa_gold':False,'held_out_benchmark_run':False,
        'output_sha256':{f.name:digest(f) for f in sorted(output.iterdir())}}
    write_json(output/'packet-manifest.json',result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--project',type=Path,default=Path('.'))
    p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args()
    try:r=prepare(a.project,a.output_dir)
    except Exception as e:p.exit(1,'Review preparation stopped: '+str(e)+'\n')
    print(json.dumps(r))


if __name__=='__main__':main()
