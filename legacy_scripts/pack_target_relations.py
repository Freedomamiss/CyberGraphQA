"""Development hybrid variant: reserve whole named-CVE product/vendor bundles."""
import re
from pack_support import pack_supported

VARIANT = 'hybrid-named-cve-product-vendor-v1'


def pack_target_relations(text_rows, graph_rows, documents, char_cap, mode, question):
    baseline = pack_supported(text_rows, graph_rows, documents, char_cap, mode)
    mentioned = set(re.findall(r'\bCVE-\d{4}-\d{4,}\b', question.upper()))
    requested = bool(re.search(r'\bproducts?\b', question, re.I) and re.search(r'\bvendors?\b', question, re.I))
    targets = sorted({r['cve_id'] for r in graph_rows if r['cve_id'] in mentioned and
                      any(p['anchor_id'] == r['cve_id'] for p in r['support_paths'])})
    if mode != 'hybrid' or not requested or not targets:
        return baseline
    facts = {f['evidence_id']: f for d in documents.values() for f in d['facts']}
    def block(eid):
        return '[' + eid + '] ' + facts[eid]['text'] + '\n'
    bundles = []
    for cve in targets:
        relations = [f for f in documents[cve]['facts'] if f['kind'] == 'relation']
        products = sorted({f['value']['object'] for f in relations
                           if f['value']['predicate'] == 'AFFECTS' and f['value']['subject'] == cve})
        for product in products:
            ids = [f['evidence_id'] for f in relations if
                   (f['value']['predicate'] == 'AFFECTS' and f['value']['subject'] == cve and f['value']['object'] == product) or
                   (f['value']['predicate'] == 'MADE_BY' and f['value']['subject'] == product)]
            bundles.append({'cve_id': cve, 'product_id': product, 'evidence_ids': list(dict.fromkeys(ids))})
    selected = []; seen = set(); used = 0; withheld = set(); retained = []; omitted = []
    for bundle in bundles:
        extra = [eid for eid in bundle['evidence_ids'] if eid not in seen]
        cost = sum(len(block(eid)) for eid in extra)
        if used + cost > char_cap:
            omitted.append(bundle); withheld.update(extra)
            continue
        retained.append(bundle)
        selected.extend(facts[eid] for eid in extra); seen.update(extra); used += cost
    # Keep source wording after requested relations. A long description must
    # not consume the space needed for the affected-product/vendor chain.
    for cve in targets:
        for fact in documents[cve]['facts']:
            if fact['kind'] != 'description': continue
            eid = fact['evidence_id']; cost = len(block(eid))
            if eid not in seen and used + cost <= char_cap:
                selected.append(fact); seen.add(eid); used += cost
    # Continue with the previous deterministic packing order. Do not admit a
    # lone relation from a target bundle that exceeded the character budget.
    preferred = baseline['packing_support']['retained'] + baseline['packing_support']['omitted']
    for bundle in preferred:
        extra = [eid for eid in bundle['evidence_ids'] if eid not in seen]
        if set(extra) & withheld: continue
        cost = sum(len(block(eid)) for eid in extra)
        if used + cost <= char_cap:
            selected.extend(facts[eid] for eid in extra); seen.update(extra); used += cost
        else:
            withheld.update(extra)
    for fact in baseline['evidence']:
        eid = fact['evidence_id']; cost = len(block(eid))
        if eid not in seen and eid not in withheld and used + cost <= char_cap:
            selected.append(fact); seen.add(eid); used += cost
    kept = [b for b in preferred if set(b['evidence_ids']).issubset(seen)]
    missing = [b for b in preferred if not set(b['evidence_ids']).issubset(seen)]
    support = {**baseline['packing_support'], 'retained': kept, 'omitted': missing,
               'retained_bundles': len(kept), 'omitted_bundles': len(missing)}
    all_ids = {eid for b in bundles for eid in b['evidence_ids']}
    context = ''.join(block(f['evidence_id']) for f in selected)
    cves = set(targets) | {r['cve_id'] for r in graph_rows + text_rows}
    return {**baseline, 'evidence': selected, 'context': context, 'context_characters': len(context),
            'packing_policy': VARIANT + '; whole target relation bundles, then descriptions, then previous support order',
            'packing_support': support,
            'skipped_evidence_ids': [f['evidence_id'] for c in sorted(cves) for f in documents[c]['facts'] if f['evidence_id'] not in seen],
            'target_relation_coverage': {'target_cves': targets, 'required_relation_units': len(all_ids),
                'retained_relation_units': len(all_ids & seen), 'all_requested_source_relations_retained': all_ids.issubset(seen),
                'retained_product_bundles': retained, 'omitted_product_bundles': omitted,
                'semantic_correctness_verified': False, 'exhaustive_dataset_answer_supported': False}}
