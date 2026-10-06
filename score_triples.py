"""Exact triple scorer with CVE scope; AI reference is not human gold.
Prediction format: {"triples": [{"cve_id","subject","predicate","object"}, ...]}.
Include only accepted extraction triples; rejected outputs remain empty.
"""
import argparse,json
from pathlib import Path

def key(t):
    return tuple(' '.join(str(t[k]).casefold().split()) for k in ['cve_id','subject','predicate','object'])
def score(reference,prediction):
    ref_ids={t['cve_id'] for t in reference['triples']}
    if any(t['cve_id'] not in ref_ids for t in prediction['triples']):raise ValueError('Prediction CVE outside benchmark')
    r={key(t) for t in reference['triples']};p={key(t) for t in prediction['triples']}
    tp=len(r&p);fp=len(p-r);fn=len(r-p)
    return {'TP':tp,'FP':fp,'FN':fn,'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,
            'F1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,'human_gold':reference.get('human_gold',False),
            'reference_kind':reference['reference_kind'],'scope':'exact description-only triples; no alias repair'}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--gold',type=Path,default=Path('benchmarks/gold_triples.json'));p.add_argument('--predictions',type=Path,required=True);a=p.parse_args()
    print(json.dumps(score(json.loads(a.gold.read_text()),json.loads(a.predictions.read_text())),indent=2))
