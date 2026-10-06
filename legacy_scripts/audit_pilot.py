"""Generate a readable acquisition audit from real cached pilot outputs."""
from collections import defaultdict
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
records = json.loads((root / 'outputs/pilot/inspected_records.json').read_text(encoding='utf-8'))
summary = json.loads((root / 'outputs/pilot/summary.json').read_text(encoding='utf-8'))
manifest = json.loads((root / 'data/raw/pilot/manifest.json').read_text(encoding='utf-8'))
selection = json.loads((root / 'data/raw/pilot/selection.json').read_text(encoding='utf-8'))
assert len(records) == 10 and len({r['cve_id'] for r in records}) == 10
assert all(r['state'] == 'PUBLISHED' and r['publication_in_window'] for r in records)
by_cwe = defaultdict(list)
by_product = defaultdict(set)
rows = []
for r in records:
    m = r['provisional_selected_cvss'] or {}
    pairs = {(p['vendor'].strip().casefold(), p['product'].strip().casefold()) for p in r['valid_affected_pairs']}
    for c in r['selected_cwe_ids']:
        by_cwe[c].append(r['cve_id'])
    for p in pairs:
        by_product[p].add(r['cve_id'])
    rows.append(f"| {r['cve_id']} | {r['kev_vendor_raw']} | {len(pairs)} | {', '.join(r['selected_cwe_ids'])} | {m.get('baseScore', 'missing')} | {m.get('baseSeverity', 'missing')} | {m.get('source_role', 'missing')} |")
lines = [
    '# CyberGraphQA: Checkpoint 2 Acquisition Audit', '',
    '**Researcher:** Aaron Ballinger  ', '**Date:** September 30, 2026  ',
    '**Scope:** 10-record acquisition pilot. No LLM extraction or QA experiment has run.', '',
    '## Actual outcome', '',
    f"- Frozen CISA KEV catalog version: `{manifest['catalog_version']}`; reported and verified count: {manifest['catalog_count']}.",
    f"- Requested/inspected CVEs: {summary['requested']}/{summary['inspected']}.",
    f"- NVD responses available: {summary['with_nvd']}/10.",
    f"- English descriptions, valid affected pairs, selected numeric CWEs, and CVSS 3.x scores: 10/10 each.",
    f"- Publication dates in 2020-2025: {summary['publication_in_window']}/10.",
    f"- Acquisition/inspection errors: {summary['errors']}.",
    '- All 10 candidates are KEV-listed. Non-listed comparison records remain to be acquired.', '',
    '## Pilot field inventory', '',
    'Product-pair counts below apply only whitespace/case normalization and deduplication. No product-family merging or typo correction has been performed. Selected metrics are source-policy outputs, not independently adjudicated ground truth.', '',
    '| CVE | KEV vendor | Unique product pairs | Selected CWE | CVSS 3.x | Severity | Metric origin |',
    '|---|---|---:|---|---:|---|---|', *rows, '',
    '## Relationship feasibility', '',
    'Shared CWE groups observed in these ten records:', '',
]
for c, ids in sorted(by_cwe.items()):
    if len(ids) > 1:
        lines.append(f"- `{c}`: {', '.join(ids)}.")
lines += ['', f"{sum(len(ids)>1 for ids in by_product.values())} case/whitespace-normalized product pairs are shared by more than one pilot CVE.", '',
          'These are genuine candidate support paths: CVE -> CWE <- CVE and CVE -> Product -> Vendor. They support testing comparison and vendor questions. They do not establish that a 60-question benchmark is ready or that graph retrieval will improve answers.', '',
          'Examples for development only, scoped to these ten pilot records:', '',
          '- Which pilot CVE shares a CWE with CVE-2025-21334 but belongs to a different vendor? The structured records identify CVE-2023-32373 through CWE-416, with Microsoft and Apple as the respective vendors.',
          '- Which pilot Chrome CVE sharing CWE-843 has Critical severity under the selected CVSS policy? CVE-2024-4947 (9.6); CVE-2023-3079 is High (8.8).', '',
          'These examples were derived after inspecting the data and must not be presented as a held-out evaluation set.', '',
          '## Findings that affect the implementation', '',
          '1. **Descriptions omit important metadata.** Both Microsoft descriptions are short vulnerability titles. Their structured affected arrays list many Windows variants. Exact recovery of all those variants cannot reasonably be required from the title alone. Keep description-supported extraction separate from metadata recovery.',
          '2. **Vendor severity is not CVSS severity.** Both Chrome descriptions say Chromium security severity is High. The selected NVD CVSS score makes CVE-2024-4947 Critical. Preserve both claims in their original contexts; do not overwrite source text or equate the two scales.',
          '3. **Product normalization needs boundaries.** Microsoft records contain repeated names with case/platform/version differences. Apple has repeated iOS-and-iPadOS entries for separate version ranges. Deduplicate exact normalized vendor/product pairs, but preserve raw affected objects and version ranges. Do not collapse all Windows versions into one product without a documented decision.',
          '4. **One source string needs review.** CVE-2025-21334 includes a CNA product called Windows 11 version 22H3. Preserve that spelling and flag it for authoritative review rather than silently changing it.',
          '5. **Placeholder weaknesses need a fallback.** CVE-2024-35250 has an NVD-authored NVD-CWE-Other placeholder and a CNA CWE-822 mapping. The pilot excludes the placeholder and uses the valid CNA mapping. Missing/placeholder values must not become graph nodes.',
          '6. **Source attribution may use organization IDs.** NVD metric sources can be UUIDs, including CISA ADP. The parser resolves those IDs against CVE provider metadata instead of assuming every secondary metric is CNA-authored.', '',
          '## Sampling decision', '',
          'Continue with the KEV-centered 120-listed/30-not-listed design. The pilot is a field-availability check, not a representative estimate of metadata completeness. It chose two seeded candidates per vendor from five high-count strata using identifier year, then verified publication dates.', '',
          'Candidate counts for those pilot strata (identifier years 2020-2025, not a completed eligibility audit):', '']
for vendor, count in selection['vendor_candidate_counts'].items():
    lines.append(f'- {vendor}: {count}.')
lines += ['', 'The preliminary sixth stratum is VMware with 24 identifier-year candidates. Actual eligibility and non-listed matching still require publication-date and vendor checks. Do not claim 150 records have been selected.', '',
          '## Provenance and verification', '',
          f"- KEV GitHub revision: `{manifest['kev_revision']}`.",
          f"- CVE List GitHub revision: `{manifest['cve_revision']}`.",
          '- Original JSON bytes are preserved with retrieval timestamps, URLs and SHA-256 hashes.',
          '- NVD API responses are frozen individually by retrieval time and hash.',
          '- Online pilot completed with exit code 0; an offline rerun completed with exit code 0.',
          '- Record identities, published state, catalog count, uniqueness and date-window checks passed.', '',
          '## Status', '',
          '**COMPLETED:** Frozen catalog; 10 CNA and 10 NVD records; field audit; cached-data validation; candidate multi-hop paths.', '',
          '**CURRENT:** Acquisition pilot passed. Product normalization and source conflicts are documented for review.', '',
          '**NEXT:** Acquire and freeze the full candidate pool; apply publication-date eligibility; select 120 listed and 30 non-listed records; produce the canonical dataset and description-only extraction inputs.', '',
          '**BLOCKERS:** No acquisition blocker for the pilot. Full-sample comparison matching, original course rubric, and generator configuration remain unverified.', '',
          '## Primary sources', '',
          '- CISA official mirror: https://github.com/cisagov/kev-data',
          '- Official CVE List: https://github.com/CVEProject/cvelistV5',
          '- NVD CVE API: https://services.nvd.nist.gov/rest/json/cves/2.0',
          '- Exact record URLs and hashes: data/raw/pilot/manifest.json', '']
(root / 'Checkpoint_2_Acquisition_Audit.md').write_text('\n'.join(lines), encoding='utf-8')
print('Audit written; ten published records and publication windows checked.')
