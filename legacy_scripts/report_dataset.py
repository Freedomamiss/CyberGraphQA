"""Write Checkpoint 3 report and a source-conflict review queue."""
from collections import Counter
import hashlib
import json
from pathlib import Path
from acquire_pilot import write_json

root=Path(__file__).resolve().parents[1]
summary=json.loads((root/'outputs/dataset/summary.json').read_text(encoding='utf-8'))
validation=json.loads((root/'outputs/dataset/validation.json').read_text(encoding='utf-8'))
rows=json.loads((root/'data/processed/cves.json').read_text(encoding='utf-8'))
selection=json.loads((root/'data/raw/full/selection.json').read_text(encoding='utf-8'))
review=[]
for r in rows:
    if r['missing_fields_json'] or r['conflict_flags_json']:
        review.append({'cve_id':r['cve_id'],'missing_fields':r['missing_fields_json'],'flags':r['conflict_flags_json'],
                       'selected_cwe_ids':r['cwe_ids_json'],'selected_cvss_score':r['cvss_score'],
                       'evidence':r['field_provenance_json'],'review_status':'not_adjudicated','reviewer':None,'decision':None})
write_json(root/'outputs/dataset/review_queue.json',review)
lines=['# CyberGraphQA: Checkpoint 3 Dataset Audit','',
       '**Researcher:** Aaron Ballinger  ', '**Date:** September 30, 2026 (America/Chicago)  ',
       f"**Snapshot:** `{summary['snapshot_id']}`  ",
       '**Status:** Dataset acquired, selection frozen and engineering checks passed. Source disagreements remain queued for review. No model extraction or QA experiment has run.','',
       '## Dataset inventory','',
       '| Measure | Actual value |','|---|---:|',
       f"| Unique CVEs | {summary['records']} |",f"| Listed in the frozen KEV catalog | {summary['kev_listed']} |",
       f"| Not listed in that catalog | {summary['not_kev_listed']} |",f"| Numeric CWE mapping available | {summary['cwe_mapped']} |",
       f"| Numeric CWE mapping missing | {150-summary['cwe_mapped']} |",f"| Selected CVSS 3.x score available | {summary['cvss3_scored']} |",
       '| CVEs with a sourced vendor/product pair after KEV fallback | 150 |',
       f"| Source hashes independently checked | {validation['source_hashes_verified']} |",'',
       '## Vendor strata','',
       '| Vendor | KEV-listed | Not listed | Total |','|---|---:|---:|---:|']
for vendor in ('Microsoft','Apple','Google','Cisco','Ivanti','VMware'):
    a=summary['vendor_strata'][vendor+'_listed'];b=summary['vendor_strata'][vendor+'_unlisted']
    lines.append(f'| {vendor} | {a} | {b} | {a+b} |')
lines += ['', 'The sample is deliberately balanced across six vendors. It does not reproduce the vendor distribution of the full CVE population or KEV catalog. Non-membership means not listed in the frozen catalog, not never exploited.','',
          '## Sources and selection','',
          '- Retained the pilot\'s frozen CISA KEV and CVE List GitHub revisions.',
          '- Retrieved an NVD KEV pool containing all 1,730 entries in the frozen catalog, with no missing catalog IDs.',
          '- Ranked vendors by eligible NVD-published CVEs in 2020-2025; selected the six leading strata.',
          '- Used seed 1337 and sorted-ID lists to create a reproducible candidate order. Confirmed CNA publication state, English description availability and publication window before accepting 20 listed records per vendor.',
          '- Retrieved comparison pools published January 1 through April 30, 2025. Confirmed affected-vendor pairs against the CNA record and non-membership against the entire frozen KEV catalog before accepting five per vendor.',
          '- Keyword search alone produced only four eligible Apple comparisons. Supplemented the Apple pool with the verified Apple CNA source identifier, product-security@apple.com, in the same date window. The initial candidate order and exclusions are retained.',
          f"- The final selection excluded {summary['excluded_ineligible_candidates']} ineligible candidates. Download failures do not trigger replacement: the script stops and permits retry instead.",
          '- Missing CWE or CVSS fields were not grounds for exclusion.', '',
          '### Publication-year distribution','',
          '| Publication year | Listed cohort | Non-listed cohort |','|---|---:|---:|']
for year in map(str,range(2020,2026)):
    lines.append(f"| {year} | {summary['publication_years_by_cohort']['listed'].get(year,0)} | {summary['publication_years_by_cohort']['unlisted'].get(year,0)} |")
lines += ['', 'The cohorts are vendor-matched, but not time-matched. This limits exploitation-status or temporal comparisons. The main experiment compares retrieval methods on the same frozen questions and corpus; it does not estimate the causes of exploitation.','',
          '## Structured source fusion','',
          'Twenty-five selected CNA records have placeholder affected-vendor/product fields. Their known vendor/product pair exists in the KEV catalog. For those records only, the canonical dataset uses the exact frozen KEV vendorProject/product pair and records CISA KEV as the source. CNA pairs take priority whenever usable.',
          '', 'This is structured metadata fusion, not LLM extraction and not a guessed correction. KEV labels may be broader than CNA product names. Combined product labels and source spelling remain intact. No versions are inferred. Original CNA objects remain available in raw records.',
          '', 'The 13 missing numeric CWE mappings remain missing. Placeholder values such as NVD-CWE-Other are not graph entities. The 150 CVSS scores use the documented v3.1/v3.0 source policy; alternate metrics remain available.', '',
          '## Issues recorded for review','',
          '| Issue | Records carrying flag |','|---|---:|']
for flag,count in summary['conflict_flags'].items():lines.append(f'| {flag} | {count} |')
lines += ['', 'Flags can overlap. A source disagreement is not automatically an incorrect record. CVSS flags include differences between metric versions as well as scores. Product-spelling flags preserve Windows 11 version 22H3 rather than silently correcting it.',
          '', f"The review queue contains {len(review)} records with missing fields or flags. It includes selected values, source evidence, and blank reviewer/decision fields. These are source-policy selections; source disagreements have not been independently adjudicated. Avoid gold questions that depend on unresolved ambiguous product names, and explicitly handle missing mappings.", '',
          '## Relationship feasibility','',
          f"- {validation['unique_cwes']} distinct numeric CWE identifiers.",
          f"- {validation['cwes_shared_by_multiple_cves']} CWEs shared by multiple CVEs.",
          f"- {validation['cwes_spanning_multiple_vendors']} CWEs spanning multiple affected vendors.",
          f"- {validation['raw_case_normalized_product_nodes']} distinct vendor-qualified product keys after basic case/whitespace normalization.",
          '', 'These counts come from the canonical metadata. They establish available relations for benchmark construction, not QA performance. The graph, held-out benchmark, Node2Vec model, and retrieval conditions have not been built or evaluated at this checkpoint.', '',
          '## Extraction boundary','',
          '`data/processed/extraction_inputs.jsonl` has 150 rows. Each has exactly two keys: `cve_id` and `description`. Each description matches the selected source description. Vendor, product, CWE, severity, CVSS, dates, catalog status, provenance and gold answers are excluded from the extraction file.',
          '', 'Facts naturally present in the original description remain there. Later evaluation must distinguish description-supported extraction from recovery of metadata that was never stated.', '',
          '## Verification performed','',
          '- Verified 150 unique IDs, the 120/30 split and the 20/5 counts in each vendor stratum.',
          '- Verified published state, dates, KEV membership, sourced vendor/product pairs and raw NVD record locators.',
          '- Independently checked all 232 raw source hashes.',
          '- Checked selected CVSS score ranges and severity consistency.',
          '- Verified all JSONL rows have only the authorized extraction keys.',
          '- Verified all 150 CSV rows round-trip JSON-valued columns and preserve description text.',
          '- Completed an offline dataset rebuild and checked that canonical JSON, CSV and extraction-input bytes remained unchanged.', '',
          '## Reproduce on Windows','',
          'Extract the project folder and run:', '', '```powershell',
          "Set-Location 'C:\\Hacking_Projects\\CyberGraphQA'", 'py -3 scripts\\acquire_dataset.py --offline',
          'py -3 scripts\\validate_dataset.py','py -3 scripts\\report_dataset.py','```','',
          'The archive contains the original source bytes, pool responses, source revisions, hashes, decision records, scripts, canonical dataset and extraction inputs. Do not refresh raw sources during scored experiments. Acquisition without --offline retries missing files using the documented source policies.', '',
          '## Status','', '**COMPLETED:** Full source acquisition, 150-record frozen selection, canonical JSON/CSV, isolated extraction inputs, provenance and engineering checks.', '',
          '**CURRENT:** Source conflict and missing-field review queue. No extraction or QA scores exist.', '',
          '**NEXT:** Define the description-supported extraction rubric, implement the fixed-schema extractor, and run a small model pilot before extracting all 150 descriptions.', '',
          '**BLOCKERS:** Generator access/configuration and original course rubric remain unverified. No data-acquisition blocker remains.', '',
          '## Source references','',
          f"- CISA mirror revision: https://github.com/cisagov/kev-data/tree/{selection['kev_sha']}",
          f"- Official CVE List revision: https://github.com/CVEProject/cvelistV5/tree/{selection['cve_sha']}",
          '- NVD CVE API: https://services.nvd.nist.gov/rest/json/cves/2.0',
          '- Exact pool URLs, timestamps and hashes: data/raw/full/manifest.json.', '']
lines=[line.replace(chr(92)*2,chr(92)) for line in lines]
(root/'Checkpoint_3_Dataset_Audit.md').write_text('\n'.join(lines),encoding='utf-8')
hashes={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [root/'data/processed/cves.json',root/'data/processed/cves.csv',root/'data/processed/extraction_inputs.jsonl',*sorted((root/'scripts').glob('*.py'))]}
write_json(root/'outputs/dataset/artifact_hashes.json',hashes)
print(f'Report and review queue written; {len(review)} flagged/incomplete records preserved.')
