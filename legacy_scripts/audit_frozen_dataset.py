"""Read-only audit of the frozen dataset before full QA graph construction."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def audit(root, expected_snapshot):
    paths={name:root/name for name in ['data/processed/cves.json','data/processed/cves.csv',
        'data/processed/extraction_inputs.jsonl','data/raw/full/selection.json','data/raw/pilot/kev.json']}
    rows=read(paths['data/processed/cves.json']); selection=read(paths['data/raw/full/selection.json'])
    require(selection['snapshot_id']==expected_snapshot,'Frozen snapshot ID changed')
    ids=[r['cve_id'] for r in rows]
    require(len(ids)==150 and len(set(ids))==150,'Dataset must contain 150 unique CVEs')
    require(sorted(ids)==selection['cve_ids'],'Selection IDs differ from canonical data')
    require(all(r['snapshot_id']==expected_snapshot for r in rows),'Mixed snapshot IDs')
    require(Counter(r['kev_listed'] for r in rows)=={True:120,False:30},'KEV cohort counts changed')
    catalog=read(paths['data/raw/pilot/kev.json'])
    kev={r['cveID'] for r in catalog['vulnerabilities']}
    require(len(kev)==catalog['count'],'KEV count mismatch')
    require(all(type(r['kev_listed']) is bool and r['kev_listed']==(r['cve_id'] in kev) for r in rows),'KEV membership differs')
    hashes=0
    for base in [root/'data/raw/pilot',root/'data/raw/full']:
        for meta_path in base.rglob('*.provenance.json'):
            original=meta_path.with_name(meta_path.name.replace('.provenance.json','.json'))
            require(digest(original)==read(meta_path)['sha256'],'Source hash mismatch: '+str(original))
            hashes+=1
    require(hashes>0,'No source hash records found')
    inputs=[json.loads(line) for line in paths['data/processed/extraction_inputs.jsonl'].read_text(encoding='utf-8-sig').splitlines()]
    require(len(inputs)==len(rows),'Extraction row count differs')
    for item,row in zip(inputs,rows):
        require(set(item)=={'cve_id','description'},'Extraction input includes unauthorized keys')
        require(item['cve_id']==row['cve_id'] and item['description']==row['description'],'Extraction source text differs')
    with paths['data/processed/cves.csv'].open(encoding='utf-8-sig',newline='') as handle:
        flat=list(csv.DictReader(handle))
    require(len(flat)==len(rows),'CSV row count differs')
    flags=Counter(); sources=Counter(); products=set(); vendors=set(); cwes=set()
    for row,csv_row in zip(rows,flat):
        require(csv_row['cve_id']==row['cve_id'] and csv_row['description']==row['description'],'CSV record differs')
        for key in row:
            if key.endswith('_json'):
                require(json.loads(csv_row[key])==row[key],'CSV JSON field differs: '+key)
        require(csv_row['kev_listed']==str(row['kev_listed']),'CSV membership differs')
        flags.update(row['conflict_flags_json'])
        sources.update([row['field_provenance_json']['affected_products']['source']])
        for pair in row['affected_products_json']:
            require(pair['product_key']==pair['vendor_key']+'::'+pair['product'].strip().casefold(),'Product identity is not vendor-qualified')
            products.add(pair['product_key']); vendors.add(pair['vendor_key'])
        for cwe in row['cwe_ids_json']:
            require(cwe.startswith('CWE-') and cwe[4:].isdigit(),'Placeholder/invalid CWE in canonical data')
            cwes.add(cwe)
        if row['cvss_score'] is not None:
            score=row['cvss_score']; severity='NONE' if score==0 else 'LOW' if score<4 else 'MEDIUM' if score<7 else 'HIGH' if score<9 else 'CRITICAL'
            require(row['cvss_version'] in ['3.0','3.1'] and 0<=score<=10 and row['severity']==severity,'CVSS/severity inconsistency')
    return {'schema_version':1, 'status':'audit_passed', 'snapshot_id':expected_snapshot,
        'records':len(rows),'kev_listed':120,'not_listed_in_snapshot':30,'source_hashes_verified':hashes,
        'extraction_input_isolated':True,'canonical_csv_json_fields_match':True,
        'unique_vendor_qualified_products':len(products),'unique_vendor_keys':len(vendors),'unique_cwes':len(cwes),
        'records_missing_cwe':sum(not r['cwe_ids_json'] for r in rows),
        'records_missing_cvss':sum(r['cvss_score'] is None for r in rows),
        'records_with_flags_or_missing_fields':sum(bool(r['conflict_flags_json'] or r['missing_fields_json']) for r in rows),
        'affected_pair_source_counts':dict(sources),'conflict_flag_counts':dict(flags),
        'input_sha256':{name:digest(path) for name,path in paths.items()},
        'audit_script_sha256':digest(Path(__file__)), 'model_requests_sent':0,
        'source_conflicts_adjudicated':False,'full_qa_graph_built':False,
        'note':'Checks frozen inputs and recorded hashes only; does not prove source claims correct or report whether other project model runs occurred.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-snapshot',default='cgqa-5495aa3949d0b789')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        result=audit(Path(__file__).resolve().parents[1],args.expected_snapshot)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('x',encoding='utf-8') as handle:
            json.dump(result,handle,indent=2);handle.write('\n')
    except Exception as error:
        parser.exit(1,'Frozen dataset audit stopped: '+str(error)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
