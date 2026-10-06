"""Validate frozen sources, dataset consistency and extraction-input isolation."""
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
from acquire_dataset import ALIASES, COLS
from acquire_pilot import write_json

root=Path(__file__).resolve().parents[1]
rows=json.loads((root/'data/processed/cves.json').read_text(encoding='utf-8'))
selection=json.loads((root/'data/raw/full/selection.json').read_text(encoding='utf-8'))
catalog=json.loads((root/'data/raw/pilot/kev.json').read_text(encoding='utf-8'))
kev={r['cveID'] for r in catalog['vulnerabilities']}
assert len(kev)==catalog['count']
assert len(rows)==150 and len({r['cve_id'] for r in rows})==150
assert sorted(r['cve_id'] for r in rows)==selection['cve_ids']
assert Counter(r['kev_listed'] for r in rows)=={True:120,False:30}
assert all(set(r)==set(COLS) for r in rows)
assert all(r['snapshot_id']==selection['snapshot_id'] for r in rows)
hashes=0
for base in (root/'data/raw/pilot',root/'data/raw/full'):
    for p in base.rglob('*.provenance.json'):
        original=p.with_name(p.name.replace('.provenance.json','.json'))
        meta=json.loads(p.read_text(encoding='utf-8'))
        assert hashlib.sha256(original.read_bytes()).hexdigest()==meta['sha256'], str(original)
        hashes+=1
pools={}
by_cwe=defaultdict(set)
by_vendor=defaultdict(set)
normalized_products=set()
for r in rows:
    identifier=r['cve_id']
    assert isinstance(r['kev_listed'],bool) and r['kev_listed']==(identifier in kev)
    assert r['description'] and '2020' <= r['published_date'][:4] <= '2025'
    if not r['kev_listed']:
        assert '2025-01-01' <= r['published_date'][:10] <= '2025-04-30'
    prov=r['field_provenance_json']
    source=json.loads((root/prov['description']['raw_file']).read_text(encoding='utf-8'))
    assert source['cveMetadata']['cveId']==identifier and source['cveMetadata']['state']=='PUBLISHED'
    raw_pairs={(str(p.get('vendor','')).strip().casefold(),str(p.get('product','')).strip().casefold()) for p in source['containers']['cna'].get('affected',[])}
    if prov['affected_products']['source']=='CISA KEV':
        entry=next(e for e in catalog['vulnerabilities'] if e['cveID']==identifier)
        raw_pairs={(entry['vendorProject'].strip().casefold(),entry['product'].strip().casefold())}
    for pair in r['affected_products_json']:
        assert (pair['vendor'].strip().casefold(),pair['product'].strip().casefold()) in raw_pairs
        assert pair['product_key']==pair['vendor_key']+'::'+pair['product'].strip().casefold()
        normalized_products.add(pair['product_key'])
        by_vendor[pair['vendor_key']].add(identifier)
    nvd_ref=prov['nvd_record']
    if nvd_ref['raw_file'] not in pools:
        pools[nvd_ref['raw_file']]=json.loads((root/nvd_ref['raw_file']).read_text(encoding='utf-8'))
    idx=int(nvd_ref['field_path'].split('[')[1].split(']')[0])
    assert pools[nvd_ref['raw_file']]['vulnerabilities'][idx]['cve']['id']==identifier
    for c in r['cwe_ids_json']:
        assert c.startswith('CWE-') and c[4:].isdigit()
        by_cwe[c].add(identifier)
    if r['cvss_score'] is not None:
        assert r['cvss_version'] in ('3.0','3.1') and 0 <= r['cvss_score'] <= 10
        score=r['cvss_score']
        expected='NONE' if score==0 else 'LOW' if score<4 else 'MEDIUM' if score<7 else 'HIGH' if score<9 else 'CRITICAL'
        assert r['severity']==expected,(identifier,score,r['severity'])
extraction=[json.loads(line) for line in (root/'data/processed/extraction_inputs.jsonl').read_text(encoding='utf-8').splitlines()]
assert len(extraction)==150
for item,row in zip(extraction,rows):
    assert set(item)=={'cve_id','description'}
    assert item['cve_id']==row['cve_id'] and item['description']==row['description']
with (root/'data/processed/cves.csv').open(encoding='utf-8',newline='') as f:
    reader=csv.DictReader(f)
    assert reader.fieldnames==COLS
    csv_rows=list(reader)
assert len(csv_rows)==150
for flat,row in zip(csv_rows,rows):
    assert flat['cve_id']==row['cve_id'] and flat['description']==row['description']
    for key in COLS:
        if key.endswith('_json'):
            assert json.loads(flat[key])==row[key]
    assert flat['kev_listed']==str(row['kev_listed'])
summary=json.loads((root/'outputs/dataset/summary.json').read_text(encoding='utf-8'))
assert all(v==20 if k.endswith('_listed') else v==5 for k,v in summary['vendor_strata'].items())
result={'snapshot_id':selection['snapshot_id'],'records_verified':150,'source_hashes_verified':hashes,
        'kev_membership_verified':True,'raw_source_pair_identity_verified':True,'nvd_record_locators_verified':True,
        'cvss_severity_consistency_verified':True,'extraction_input_keys':['cve_id','description'],
        'extraction_rows_verified':150,'csv_json_roundtrip_verified':True,
        'raw_case_normalized_product_nodes':len(normalized_products),'raw_case_normalized_vendor_nodes':len(by_vendor),
        'unique_cwes':len(by_cwe),'cwes_shared_by_multiple_cves':sum(len(v)>1 for v in by_cwe.values()),
        'cwes_spanning_multiple_vendors':sum(len({vendor for vendor,ids in by_vendor.items() if ids & members})>1 for members in by_cwe.values()),
        'no_model_experiment_run':True}
write_json(root/'outputs/dataset/validation.json',result)
print(json.dumps(result,indent=2))
