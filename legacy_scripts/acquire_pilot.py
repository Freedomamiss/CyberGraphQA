"""Freeze a 10-CVE acquisition pilot. Python 3.10+, standard library only.

Pilot selection uses CVE identifier year as a candidate filter; publication dates
are audited afterward. This is NOT the final 150-record sampling implementation.
"""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import re
import time
import urllib.request


def utc():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    temp.replace(path)


def fetch(url, path, timeout):
    """Immutable cache with request provenance and verified cache hashes."""
    meta_path = path.with_suffix('.provenance.json')
    if path.exists():
        if not meta_path.exists():
            raise ValueError(f'Untracked cache: {path}')
        body = path.read_bytes()
        meta = json.loads(meta_path.read_text(encoding='utf-8'))
        if hashlib.sha256(body).hexdigest() != meta['sha256']:
            raise ValueError(f'Cache hash mismatch: {path}')
        return json.loads(body), meta
    request = urllib.request.Request(url, headers={'User-Agent': 'CyberGraphQA-acquisition/0.1', 'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
        value = json.loads(body)
        meta = {'requested_url': url, 'resolved_url': response.url,
                'retrieved_utc': utc(), 'sha256': hashlib.sha256(body).hexdigest(),
                'bytes': len(body), 'http_status': response.status,
                'etag': response.headers.get('ETag'), 'last_modified': response.headers.get('Last-Modified')}
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(meta_path, meta)
    temp = path.with_suffix('.tmp')
    temp.write_bytes(body)
    temp.replace(path)
    return value, meta


def inspect_record(cve_id, cna, nvd, kev):
    container = cna.get('containers', {}).get('cna', {})
    cna_org = container.get('providerMetadata', {}).get('orgId')
    nvd_source_identifier = (nvd or {}).get('vulnerabilities', [{}])[0].get('cve', {}).get('sourceIdentifier')
    cisa_orgs = {a.get('providerMetadata', {}).get('orgId') for a in cna.get('containers', {}).get('adp', [])
                 if a.get('providerMetadata', {}).get('shortName') == 'CISA-ADP'}
    def source_role(source):
        if source == 'nvd@nist.gov':
            return 'NVD'
        if source == 'CNA' or source == cna_org or (nvd_source_identifier and source == nvd_source_identifier):
            return 'CNA'
        if source in cisa_orgs or 'cisa' in str(source).lower():
            return 'CISA-ADP'
        return 'unclassified'
    descriptions = [d['value'] for d in container.get('descriptions', []) if d.get('lang', '').lower().startswith('en')]
    affected = [{'vendor': p.get('vendor'), 'product': p.get('product'), 'source': 'CNA',
                 'field_path': f'containers.cna.affected[{i}]'} for i, p in enumerate(container.get('affected', []))]
    cwe_candidates = []
    metric_candidates = []
    for name, cont in [('CNA', container)] + [('ADP:' + a.get('providerMetadata', {}).get('shortName', 'unknown'), a) for a in cna.get('containers', {}).get('adp', [])]:
        for problem in cont.get('problemTypes', []):
            for item in problem.get('descriptions', []):
                ids = re.findall(r'\bCWE-\d+\b', item.get('cweId', '') + ' ' + item.get('description', ''))
                for identifier in sorted(set(ids)):
                    cwe_candidates.append({'id': identifier, 'source': name})
        for metric in cont.get('metrics', []):
            for key in ('cvssV3_1', 'cvssV3_0'):
                if key in metric:
                    metric_candidates.append({'source': name, **metric[key]})
    nvd_record = None
    if nvd:
        matches = [v['cve'] for v in nvd.get('vulnerabilities', []) if v.get('cve', {}).get('id') == cve_id]
        if len(matches) != 1:
            raise ValueError(f'NVD identity/count mismatch: {cve_id}')
        nvd_record = matches[0]
        for weakness in nvd_record.get('weaknesses', []):
            for desc in weakness.get('description', []):
                for identifier in re.findall(r'\bCWE-\d+\b', desc.get('value', '')):
                    cwe_candidates.append({'id': identifier, 'source': weakness.get('source'), 'type': weakness.get('type'), 'container': 'NVD'})
        for key in ('cvssMetricV31', 'cvssMetricV30'):
            for metric in nvd_record.get('metrics', {}).get(key, []):
                metric_candidates.append({'source': metric.get('source'), 'type': metric.get('type'), 'container': 'NVD', **metric['cvssData']})
        if not descriptions:
            descriptions = [d['value'] for d in nvd_record.get('descriptions', []) if d.get('lang') == 'en']
    if cna.get('cveMetadata', {}).get('cveId') != cve_id:
        raise ValueError(f'CNA identity mismatch: {cve_id}')
    invalid = {'n/a', 'na', 'unknown', 'unspecified', ''}
    valid_pairs = [p for p in affected if str(p['vendor'] or '').lower() not in invalid and str(p['product'] or '').lower() not in invalid]
    def rank_metric(m):
        version_rank = 0 if m.get('version') == '3.1' else 1
        source = str(m.get('source', '')).lower()
        source_rank = {'NVD': 0, 'CNA': 1, 'CISA-ADP': 2}.get(m['source_role'], 3)
        return version_rank, source_rank, source, m.get('vectorString', '')
    for candidate in metric_candidates + cwe_candidates:
        candidate['source_role'] = source_role(candidate.get('source'))
    eligible_metrics = [m for m in metric_candidates if m['source_role'] != 'unclassified']
    selected = sorted(eligible_metrics, key=rank_metric)[0] if eligible_metrics else None
    # Selection remains provisional pending review of source disagreements.
    nvd_cwes = sorted({c['id'] for c in cwe_candidates if c.get('source') == 'nvd@nist.gov'})
    cna_cwes = sorted({c['id'] for c in cwe_candidates if c.get('source') == 'CNA'})
    cisa_cwes = sorted({c['id'] for c in cwe_candidates if c['source_role'] == 'CISA-ADP'})
    selected_cwes = nvd_cwes or cna_cwes or cisa_cwes
    pub = cna.get('cveMetadata', {}).get('datePublished') or (nvd_record or {}).get('published')
    return {'cve_id': cve_id, 'state': cna.get('cveMetadata', {}).get('state'),
            'description': descriptions[0] if descriptions else None,
            'description_source': 'CNA' if any(d.get('lang', '').lower().startswith('en') for d in container.get('descriptions', [])) else 'NVD',
            'published_date': pub, 'publication_in_window': bool(pub and '2020' <= pub[:4] <= '2025'),
            'kev_listed': cve_id in kev, 'kev_vendor_raw': kev.get(cve_id, {}).get('vendorProject'),
            'kev_product_raw': kev.get(cve_id, {}).get('product'), 'affected_pairs': affected,
            'valid_affected_pairs': valid_pairs, 'cwe_candidates': cwe_candidates,
            'selected_cwe_ids': selected_cwes, 'cvss_candidates': metric_candidates,
            'provisional_selected_cvss': selected, 'nvd_available': nvd_record is not None,
            'review_required': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--offline', action='store_true', help='Reinspect cached sources without any network access.')
    args = parser.parse_args()
    raw, out = args.root / 'data' / 'raw' / 'pilot', args.root / 'outputs' / 'pilot'
    errors = []
    def get(url, path):
        if args.offline and not path.exists():
            raise ValueError(f'Missing offline source: {path}')
        return fetch(url, path, args.timeout)
    revision, _ = get('https://api.github.com/repos/cisagov/kev-data/commits/develop', raw / 'kev_revision.json')
    kev_sha = revision['sha']
    catalog, catalog_meta = get(f'https://raw.githubusercontent.com/cisagov/kev-data/{kev_sha}/known_exploited_vulnerabilities.json', raw / 'kev.json')
    entries = catalog['vulnerabilities']
    kev = {v['cveID']: v for v in entries}
    if len(kev) != len(entries) or catalog.get('count') != len(entries):
        raise ValueError('KEV duplicate/count mismatch')
    cve_revision, _ = get('https://api.github.com/repos/CVEProject/cvelistV5/commits/main', raw / 'cve_revision.json')
    cve_sha = cve_revision['sha']
    selection_path = raw / 'selection.json'
    if selection_path.exists():
        selection = json.loads(selection_path.read_text(encoding='utf-8'))
    else:
        groups = defaultdict(list)
        for v in entries:
            if 2020 <= int(v['cveID'].split('-')[1]) <= 2025:
                groups[v['vendorProject']].append(v['cveID'])
        vendors = sorted(groups, key=lambda v: (-len(groups[v]), v))[:5]
        rng = random.Random(1337)
        ids = [i for v in vendors for i in sorted(rng.sample(sorted(groups[v]), 2))]
        selection = {'purpose': '10-record acquisition pilot; not final sample', 'seed': 1337,
                     'candidate_filter': 'CVE ID year 2020-2025; publication date audited after acquisition',
                     'kev_sha': kev_sha, 'cve_sha': cve_sha, 'vendor_candidate_counts': {v:len(groups[v]) for v in vendors}, 'cve_ids': ids}
        write_json(selection_path, selection)
    if selection['kev_sha'] != kev_sha or selection['cve_sha'] != cve_sha:
        raise ValueError('Selection/source revision mismatch')
    ids = selection['cve_ids']
    print('Frozen KEV:', catalog.get('catalogVersion'), 'records:', len(entries), flush=True)
    print('Pilot IDs:', ', '.join(ids), flush=True)
    def acquire_cna(identifier):
        year, number = identifier.split('-')[1:]
        bucket = number[:-3] + 'xxx'
        url = f'https://raw.githubusercontent.com/CVEProject/cvelistV5/{cve_sha}/cves/{year}/{bucket}/{identifier}.json'
        try:
            return identifier, get(url, raw / 'cna' / f'{identifier}.json')[0]
        except Exception as exc:
            return identifier, {'acquisition_error': str(exc), 'url': url}
    with ThreadPoolExecutor(max_workers=3) as pool:
        cnas = dict(pool.map(acquire_cna, ids))
    records = []
    for identifier in ids:
        nvd_path = raw / 'nvd' / f'{identifier}.json'
        if not nvd_path.exists() and not args.offline:
            time.sleep(6.1)  # Respect conservative no-key NVD pacing.
        try:
            nvd = get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={identifier}', nvd_path)[0]
        except Exception as exc:
            nvd = None
            errors.append({'cve_id': identifier, 'stage': 'nvd', 'error': str(exc)})
        try:
            if 'acquisition_error' in cnas[identifier]:
                raise ValueError(cnas[identifier]['acquisition_error'])
            records.append(inspect_record(identifier, cnas[identifier], nvd, kev))
            print('Inspected:', identifier, flush=True)
        except Exception as exc:
            errors.append({'cve_id': identifier, 'stage': 'cna_or_inspection', 'error': str(exc)})
    manifest = {'generated_utc': utc(), 'kev_revision': kev_sha, 'cve_revision': cve_sha,
                'catalog_version': catalog.get('catalogVersion'), 'catalog_count': len(entries),
                'catalog_date_released': catalog.get('dateReleased'), 'sources': []}
    for path in sorted(raw.rglob('*.provenance.json')):
        manifest['sources'].append({'provenance_path': str(path.relative_to(args.root)), **json.loads(path.read_text(encoding='utf-8'))})
    summary = {'requested': len(ids), 'inspected': len(records), 'with_nvd': sum(r['nvd_available'] for r in records),
               'with_valid_affected_pairs': sum(bool(r['valid_affected_pairs']) for r in records),
               'with_selected_cwe': sum(bool(r['selected_cwe_ids']) for r in records),
               'with_cvss3': sum(bool(r['provisional_selected_cvss']) for r in records),
               'publication_in_window': sum(r['publication_in_window'] for r in records),
               'errors': len(errors), 'no_extraction_or_qa_experiment_run': True}
    write_json(raw / 'manifest.json', manifest)
    write_json(out / 'inspected_records.json', records)
    write_json(out / 'acquisition_errors.json', errors)
    write_json(out / 'summary.json', summary)
    print(json.dumps(summary, indent=2), flush=True)
    return 0 if len(records) == len(ids) and not errors else 2


if __name__ == '__main__':
    raise SystemExit(main())
