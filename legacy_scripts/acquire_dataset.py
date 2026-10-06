"""Acquire the 150-CVE dataset from frozen KEV/CVE revisions and cached NVD pools.

No third-party dependencies. Selection is fixed before any model experiments.
The comparison pool is intentionally bounded to Jan-Apr 2025; see decisions.
"""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import json
from pathlib import Path
import random
import re
import time
import urllib.parse
from acquire_pilot import fetch, inspect_record, utc, write_json

ROOT = Path(__file__).resolve().parents[1]
API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
ALIASES = {'Microsoft': {'microsoft', 'microsoft corporation'}, 'Apple': {'apple', 'apple inc.'},
           'Google': {'google', 'google inc.', 'google llc'}, 'Cisco': {'cisco', 'cisco systems, inc.'},
           'Ivanti': {'ivanti', 'ivanti inc.'}, 'VMware': {'vmware', 'vmware, inc.', 'vmware inc.'}}
COLS = ['cve_id','description','description_source','affected_products_json','cwe_ids_json',
        'cvss_score','cvss_version','cvss_vector','cvss_source','severity','kev_listed',
        'kev_date_added','kev_vendor_raw','kev_product_raw','published_date','source_urls_json',
        'field_provenance_json','missing_fields_json','conflict_flags_json','snapshot_id']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=ROOT)
    ap.add_argument('--offline', action='store_true')
    args = ap.parse_args()
    root = args.root
    raw, processed, out = root/'data/raw/full', root/'data/processed', root/'outputs/dataset'
    pilot = root/'data/raw/pilot'
    errors, exclusions = [], []
    pool_refs = {}
    last_nvd = [0.0]
    def get(url, path):
        if args.offline and not path.exists():
            raise ValueError(f'Offline cache missing: {path}')
        if 'services.nvd.nist.gov' in url and not path.exists():
            time.sleep(max(0, 6.1-(time.monotonic()-last_nvd[0])))
            last_nvd[0] = time.monotonic()
        return fetch(url, path, 120)[0]
    catalog = get('cached',pilot/'kev.json')
    kev = {v['cveID']:v for v in catalog['vulnerabilities']}
    assert len(kev) == catalog['count']
    kev_sha = get('cached',pilot/'kev_revision.json')['sha']
    cve_sha = get('cached',pilot/'cve_revision.json')['sha']
    def pool(url, path):
        data = get(url,path)
        result = {v['cve']['id']:v['cve'] for v in data['vulnerabilities']}
        if len(result) != data['totalResults']:
            raise ValueError(f'Incomplete pool requires pagination: {path}')
        for index,item in enumerate(data['vulnerabilities']):
            pool_refs[(path.name,item['cve']['id'])] = {'raw_file':str(path.relative_to(root)),
                                                      'field_path':f'vulnerabilities[{index}].cve'}
        return result
    kev_pool = pool(API+'?hasKev&resultsPerPage=2000',raw/'nvd_kev_pool.json')
    def eligible(n):
        return n.get('vulnStatus') != 'Rejected' and '2020' <= n.get('published','')[:4] <= '2025' and any(d.get('lang')=='en' for d in n.get('descriptions',[]))
    groups = defaultdict(list)
    for identifier, nvd in kev_pool.items():
        if identifier in kev and eligible(nvd):
            groups[kev[identifier]['vendorProject']].append(identifier)
    vendors = sorted(groups, key=lambda v:(-len(groups[v]),v))[:6]
    if any(len(groups[v]) < 20 for v in vendors):
        raise ValueError('Insufficient KEV strata; sampling design revision required.')
    if any(v not in ALIASES for v in vendors):
        raise ValueError(f'Unreviewed vendor matching: {vendors}')
    decision_path = raw/'sampling_decisions.json'
    decisions = {
        'recorded_utc':utc(), 'seed':1337, 'vendors':vendors, 'eligible_nvd_kev_counts':{v:len(groups[v]) for v in vendors},
        'kev_sha':kev_sha,'cve_sha':cve_sha,
        'listed_selection':'Seeded shuffle of sorted IDs within six strata; verify CNA publication and English description before accepting first 20.',
        'comparison_selection':'Five per vendor from NVD keyword-search pool published 2025-01-01 through 2025-04-30; seeded shuffle; verify CNA vendor and eligibility.',
        'bounded_comparison_pool_reason':'Manageable, reproducible acquisition within project timeline; comparisons are vendor-matched, not publication-year-matched. Report resulting time imbalance.',
        'no_missing_cwe_or_cvss_exclusions':True, 'vendor_aliases':{k:sorted(v) for k,v in ALIASES.items()},
        'nvd_kev_pool_count':len(kev_pool),'frozen_kev_ids_absent_from_nvd_pool':sorted(set(kev)-set(kev_pool))}
    if not decision_path.exists():
        write_json(decision_path,decisions)
    else:
        saved = json.loads(decision_path.read_text())
        if {k:v for k,v in saved.items() if k!='recorded_utc'} != {k:v for k,v in decisions.items() if k!='recorded_utc'}:
            raise ValueError('Sampling decisions changed; use a new snapshot directory.')
    comparison = {}
    comparison_ref_names = {}
    for vendor in vendors:
        query = urllib.parse.urlencode({'keywordSearch':vendor,'pubStartDate':'2025-01-01T00:00:00.000','pubEndDate':'2025-04-30T23:59:59.999','resultsPerPage':2000})
        comparison[vendor] = pool(API+'?'+query,raw/f'nvd_comparison_{vendor}.json')
        comparison_ref_names.update({(vendor,identifier):f'nvd_comparison_{vendor}.json' for identifier in comparison[vendor]})
        print('Comparison pool:',vendor,len(comparison[vendor]),flush=True)
    amendment_path = raw/'sampling_amendments.json'
    if not amendment_path.exists():
        write_json(amendment_path,{'recorded_utc':utc(), 'reason':'Apple keyword search provided only four verified non-listed affected-vendor matches.',
                                  'change':'Union Apple keyword pool with Apple CNA sourceIdentifier pool in the same Jan-Apr 2025 window.',
                                  'sourceIdentifier':'product-security@apple.com','no_model_experiment_run':True})
    apple_query = urllib.parse.urlencode({'sourceIdentifier':'product-security@apple.com','pubStartDate':'2025-01-01T00:00:00.000','pubEndDate':'2025-04-30T23:59:59.999','resultsPerPage':2000})
    apple_extra = pool(API+'?'+apple_query,raw/'nvd_comparison_Apple_CNA.json')
    for identifier,record in apple_extra.items():
        if identifier not in comparison['Apple']:
            comparison['Apple'][identifier] = record
            comparison_ref_names[('Apple',identifier)] = 'nvd_comparison_Apple_CNA.json'
    print('Supplemented Apple pool:',len(comparison['Apple']),flush=True)
    rng = random.Random(1337)
    order = {}
    for vendor in vendors:
        listed = sorted(groups[vendor]); rng.shuffle(listed)
        unlisted = sorted(i for i,n in comparison[vendor].items() if i not in kev and eligible(n)); rng.shuffle(unlisted)
        order[vendor] = {'listed':listed,'unlisted':unlisted}
    write_json(raw/'candidate_order.json',order)
    def download(identifier):
        year, number = identifier.split('-')[1:]
        url = f'https://raw.githubusercontent.com/CVEProject/cvelistV5/{cve_sha}/cves/{year}/{number[:-3]}xxx/{identifier}.json'
        p = raw/'cna'/f'{identifier}.json'
        if (pilot/'cna'/f'{identifier}.json').exists():
            p = pilot/'cna'/f'{identifier}.json'
        try:
            return identifier, get(url,p), p
        except Exception as e:
            return identifier, {'error':str(e)}, p
    chosen = []
    chosen_nvd = {}
    sources = {}
    for vendor in vendors:
        for cohort, target in [('listed',20),('unlisted',5)]:
            accepted = 0
            ids = order[vendor][cohort]
            # Download bounded batches. Reserves are logged; they are never chosen on QA performance.
            offset = 0
            while accepted < target and offset < len(ids):
                batch = ids[offset:offset+max(5,target-accepted)]
                offset += len(batch)
                with ThreadPoolExecutor(max_workers=6) as ex:
                    downloaded = list(ex.map(download,batch))
                for identifier,cna,path in downloaded:
                    if accepted == target:
                        break
                    if 'error' in cna:
                        errors.append({'cve_id':identifier,'error':cna['error']})
                        write_json(out/'acquisition_errors.json',errors)
                        raise RuntimeError('Candidate download failed; rerun to retry. Do not substitute for network failures.')
                    nvd = kev_pool[identifier] if cohort=='listed' else comparison[vendor][identifier]
                    record = inspect_record(identifier,cna,{'vulnerabilities':[{'cve':nvd}]},kev)
                    reason = None
                    if record['state'] != 'PUBLISHED': reason = 'CNA state is not PUBLISHED'
                    elif not record['publication_in_window']: reason = 'CNA publication date outside 2020-2025'
                    elif not record['description']: reason = 'No English description'
                    elif cohort == 'unlisted' and not '2025-01-01' <= record['published_date'][:10] <= '2025-04-30':
                        reason = 'CNA publication date outside comparison-pool window'
                    elif cohort == 'unlisted' and not any(p['vendor'].strip().casefold() in ALIASES[vendor] for p in record['valid_affected_pairs']):
                        reason = 'CNA affected vendor does not match stratum'
                    if reason:
                        exclusions.append({'cve_id':identifier,'cohort':cohort,'vendor':vendor,'reason':reason})
                        continue
                    record['sampling_vendor'] = vendor
                    record['sampling_cohort'] = cohort
                    chosen.append(record); chosen_nvd[identifier] = nvd
                    sources[identifier] = str(path.relative_to(root))
                    accepted += 1
                print('Accepted:',vendor,cohort,accepted,'/',target,flush=True)
            if accepted != target:
                write_json(out/'exclusions.json',exclusions)
                raise ValueError(f'Insufficient verified comparison records for {vendor}; revise pool explicitly.')
    chosen.sort(key=lambda r:r['cve_id'])
    fusion_path = raw/'structured_fusion_decision.json'
    if not fusion_path.exists():
        write_json(fusion_path,{'recorded_utc':utc(),'reason':'25 selected CNA records lack usable paired affected vendor/product fields.',
                                'policy':'Use CNA valid pairs first; when none are usable, use the exact paired vendorProject/product labels from the frozen KEV entry if listed.',
                                'limitations':'KEV product labels may be broader than CNA labels; preserve source and do not infer versions or split combined products.',
                                'missing_cwe_policy':'Keep absent numeric CWE mappings missing; do not infer from descriptions.', 'no_model_experiment_run':True})
    ids = [r['cve_id'] for r in chosen]
    assert len(ids)==150 and len(set(ids))==150
    assert sum(r['kev_listed'] for r in chosen)==120
    assert all(r['kev_listed']==(r['cve_id'] in kev) for r in chosen)
    snapshot_material = {'kev_sha':kev_sha,'cve_sha':cve_sha,'ids':ids,'pool_hashes':{p.name:json.loads(p.read_text())['sha256'] for p in raw.glob('nvd*.provenance.json')}}
    snapshot_id = 'cgqa-'+hashlib.sha256(json.dumps(snapshot_material,sort_keys=True).encode()).hexdigest()[:16]
    selection = {'snapshot_id':snapshot_id,'cve_ids':ids,'seed':1337,'strata':dict(Counter((r['sampling_vendor']+'_'+r['sampling_cohort']) for r in chosen)),**snapshot_material}
    selected_path = raw/'selection.json'
    if selected_path.exists() and json.loads(selected_path.read_text()) != selection:
        raise ValueError('Frozen selection changed; use a new snapshot directory.')
    write_json(selected_path,selection)
    rows = []
    for r in chosen:
        identifier = r['cve_id']; nvd = chosen_nvd[identifier]; m = r['provisional_selected_cvss'] or {}
        pairs = []
        seen = set()
        for p in r['valid_affected_pairs']:
            key = (p['vendor'].strip().casefold(),p['product'].strip().casefold())
            if key in seen: continue
            seen.add(key)
            pairs.append({**p,'vendor_key':key[0],'product_key':key[0]+'::'+key[1]})
        pair_source = 'CNA'
        pair_raw_file = sources[identifier]
        pair_field_path = 'containers.cna.affected'
        if not pairs and identifier in kev:
            entry = kev[identifier]
            vendor_raw, product_raw = entry.get('vendorProject'), entry.get('product')
            if vendor_raw and product_raw:
                pair_source = 'CISA KEV'
                pair_raw_file = 'data/raw/pilot/kev.json'
                pair_field_path = f"vulnerabilities[{next(i for i,e in enumerate(catalog['vulnerabilities']) if e['cveID']==identifier)}]"
                pairs = [{'vendor':vendor_raw,'product':product_raw,'source':pair_source,'field_path':pair_field_path,
                          'vendor_key':vendor_raw.strip().casefold(),'product_key':vendor_raw.strip().casefold()+'::'+product_raw.strip().casefold()}]
        flags = []
        cwe_sets = {source:sorted({c['id'] for c in r['cwe_candidates'] if c['source_role']==source}) for source in ('NVD','CNA','CISA-ADP')}
        if len({tuple(s) for s in cwe_sets.values() if s}) > 1: flags.append('cwe_source_disagreement')
        if len({(str(c.get('version')),c.get('baseScore')) for c in r['cvss_candidates']}) > 1: flags.append('cvss_source_or_version_disagreement')
        if r['kev_vendor_raw'] and r['valid_affected_pairs'] and not any(p['vendor'].strip().casefold() in ALIASES[r['sampling_vendor']] for p in r['valid_affected_pairs']): flags.append('kev_cna_vendor_disagreement')
        if pair_source == 'CISA KEV': flags.append('kev_pair_used_for_missing_cna_pair')
        if any('22h3' in p['product'].casefold() for p in pairs): flags.append('product_spelling_review_22H3')
        if r['published_date'][:10] != nvd.get('published','')[:10]: flags.append('publication_date_disagreement')
        if len(r['valid_affected_pairs']) != len(r['affected_pairs']): flags.append('placeholder_affected_pairs_omitted')
        missing = [name for name,value in [('affected_products',pairs),('cwe_ids',r['selected_cwe_ids']),('cvss_score',m.get('baseScore')),('severity',m.get('baseSeverity'))] if value is None or value==[]]
        nvd_url = API+'?cveId='+identifier
        nvd_ref = pool_refs[('nvd_kev_pool.json' if r['sampling_cohort']=='listed' else comparison_ref_names[(r['sampling_vendor'],identifier)],identifier)]
        cna_url = json.loads((root/sources[identifier]).with_suffix('.provenance.json').read_text())['requested_url']
        evidence = {'nvd_record':nvd_ref,
                    'description':{'source':r['description_source'],'raw_file':sources[identifier] if r['description_source']=='CNA' else nvd_ref['raw_file'],'field_path':'containers.cna.descriptions' if r['description_source']=='CNA' else nvd_ref['field_path']+'.descriptions'},
                    'affected_products':{'source':pair_source,'raw_file':pair_raw_file,'field_path':pair_field_path,'normalization':'casefold, whitespace trim; vendor-qualified product; exact deduplication'},
                    'cwe_ids':{'accepted_ids':r['selected_cwe_ids'],'candidate_sources':r['cwe_candidates']},
                    'cvss':{'selected':m,'candidate_sources':r['cvss_candidates']},
                    'kev_listed':{'source':'CISA KEV','raw_file':'data/raw/pilot/kev.json','revision':kev_sha},
                    'published_date':{'source':'CVE metadata (fallback NVD)','raw_file':sources[identifier],'field_path':'cveMetadata.datePublished'}}
        row = {'cve_id':identifier,'description':r['description'],'description_source':r['description_source'],
               'affected_products_json':pairs,'cwe_ids_json':r['selected_cwe_ids'],'cvss_score':m.get('baseScore'),
               'cvss_version':m.get('version'),'cvss_vector':m.get('vectorString'),'cvss_source':m.get('source'),
               'severity':m.get('baseSeverity'),'kev_listed':r['kev_listed'],'kev_date_added':kev.get(identifier,{}).get('dateAdded'),
               'kev_vendor_raw':r['kev_vendor_raw'],'kev_product_raw':r['kev_product_raw'],'published_date':r['published_date'],
               'source_urls_json':[cna_url,nvd_url,'https://github.com/cisagov/kev-data/tree/'+kev_sha],
               'field_provenance_json':evidence,'missing_fields_json':missing,'conflict_flags_json':flags,'snapshot_id':snapshot_id}
        rows.append(row)
    processed.mkdir(parents=True,exist_ok=True)
    write_json(processed/'cves.json',rows)
    # CSV is a machine-readable pipeline export, not a presentation workbook.
    with (processed/'cves.csv').open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=COLS);writer.writeheader()
        for row in rows:
            writer.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(list,dict)) else ('' if v is None else v) for k,v in row.items()})
    with (processed/'extraction_inputs.jsonl').open('w',encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps({'cve_id':row['cve_id'],'description':row['description']},ensure_ascii=False)+'\n')
    write_json(out/'source_candidates.json',chosen)
    write_json(out/'exclusions.json',exclusions)
    write_json(out/'acquisition_errors.json',errors)
    summary={'snapshot_id':snapshot_id,'records':len(rows),'kev_listed':sum(r['kev_listed'] for r in rows),'not_kev_listed':sum(not r['kev_listed'] for r in rows),
             'vendor_strata':selection['strata'],'missing_fields':dict(Counter(f for r in rows for f in r['missing_fields_json'])),
             'conflict_flags':dict(Counter(f for r in rows for f in r['conflict_flags_json'])),
             'cwe_mapped':sum(bool(r['cwe_ids_json']) for r in rows),'cvss3_scored':sum(r['cvss_score'] is not None for r in rows),
             'publication_years_by_cohort':{cohort:dict(Counter(r['published_date'][:4] for r in chosen if r['sampling_cohort']==cohort)) for cohort in ('listed','unlisted')},
             'excluded_ineligible_candidates':len(exclusions),'no_model_experiment_run':True}
    write_json(out/'summary.json',summary)
    manifests=[]
    for source_root in (pilot,raw):
        for p in sorted(source_root.rglob('*.provenance.json')):
            manifests.append({'provenance_file':str(p.relative_to(root)),**json.loads(p.read_text())})
    write_json(raw/'manifest.json',{'snapshot_id':snapshot_id,'generated_utc':utc(),'sources':manifests,'selection_file':'data/raw/full/selection.json'})
    print(json.dumps(summary,indent=2),flush=True)


if __name__=='__main__':
    main()
