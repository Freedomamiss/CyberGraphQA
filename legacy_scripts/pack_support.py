"""Pack schema-2 matched facts first, keeping representative graph paths together."""
from collections import defaultdict


def pack_supported(text_rows,graph_rows,documents,char_cap,mode):
    if mode not in ['text','graph','hybrid'] or char_cap<1:raise ValueError('Invalid packing mode/cap')
    facts={f['evidence_id']:f for d in documents.values() for f in d['facts']}
    def block(eid):return '['+eid+'] '+facts[eid]['text']+'\n'
    def bundle(cve,ids,channel,anchor=None):
        ids=list(dict.fromkeys(ids))
        if not ids or any(e not in facts or facts[e]['cve_id']!=cve for e in ids):
            raise ValueError('Support evidence is absent or outside the candidate CVE')
        return {'cve_id':cve,'channel':channel,'anchor_id':anchor,'evidence_ids':ids}
    text=[];graph=[]
    if mode in ['text','hybrid']:
        for row in text_rows:
            if row['cve_id'] not in documents:raise ValueError('Unknown text candidate')
            text.append(bundle(row['cve_id'],[row['matched_evidence_id']],'text'))
    if mode in ['graph','hybrid']:
        for row in graph_rows:
            by_anchor=defaultdict(list)
            for path in row['support_paths']:by_anchor[path['anchor_id']].append(path)
            for anchor in sorted(by_anchor):
                # One representative path per matched anchor/CVE. Do not imply
                # that all affected-product variants fit the generator context.
                path=min(by_anchor[anchor],key=lambda p:(p['hop_count'],tuple(p['node_ids']),tuple(p['evidence_ids'])))
                graph.append(bundle(row['cve_id'],path['evidence_ids'],'graph',anchor))
    selected=[];seen=set();used=0;admitted=[]
    def admit(item,limit):
        nonlocal used
        extra=[e for e in item['evidence_ids'] if e not in seen]
        cost=sum(len(block(e)) for e in extra)
        if used+cost>limit:return False
        for e in extra:selected.append(facts[e]);seen.add(e)
        used+=cost
        admitted.append(item)
        return True
    deferred=[]
    if mode=='hybrid':
        # Equal initial reservations. Account each channel independently, then
        # merge with deduplication before reclaiming unused total capacity.
        for items in [graph,text]:
            before=used;limit=before+char_cap//2
            for item in items:
                if not admit(item,limit):deferred.append(item)
    else:
        for item in graph+text:
            if not admit(item,char_cap):deferred.append(item)
    for item in deferred:
        if item not in admitted:admit(item,char_cap)
    preferred=graph+text
    withheld={e for item in preferred if not set(item['evidence_ids']).issubset(seen) for e in item['evidence_ids']}
    # Fill remaining room fairly across candidate records. Never fill a lone
    # fragment of a preferred path that could not be admitted as a bundle.
    cves=list(dict.fromkeys(r['cve_id'] for r in (graph_rows if mode=='graph' else text_rows if mode=='text' else graph_rows+text_rows)))
    for ordinal in range(max((len(documents[c]['facts']) for c in cves),default=0)):
        for cve in cves:
            if ordinal>=len(documents[cve]['facts']):continue
            fact=documents[cve]['facts'][ordinal];eid=fact['evidence_id']
            if eid in seen or eid in withheld:continue
            cost=len(block(eid))
            if used+cost<=char_cap:selected.append(fact);seen.add(eid);used+=cost
    retained=[item for item in preferred if set(item['evidence_ids']).issubset(seen)]
    omitted=[item for item in preferred if not set(item['evidence_ids']).issubset(seen)]
    context=''.join(block(f['evidence_id']) for f in selected)
    return {'evidence':selected,'context':context,'context_characters':len(context),
        'skipped_evidence_ids':[f['evidence_id'] for c in cves for f in documents[c]['facts'] if f['evidence_id'] not in seen],
        'packing_policy':'matched_evidence_first; one representative whole path per graph anchor/CVE; half per hybrid channel then reclamation; round-robin remaining facts',
        'packing_support':{'preferred_bundles':len(preferred),'retained_bundles':len(retained),
            'omitted_bundles':len(omitted),'retained':retained,'omitted':omitted,
            'exhaustive_answer_supported':False,'generator_token_budget_enforced':False}}
