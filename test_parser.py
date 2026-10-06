"""Offline parser checks against source-only assertions; no LLM calls."""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent/'legacy_scripts'))
from extract_cves import validate_assertions

def parse(raw,record):return validate_assertions(json.loads(raw),record)
if __name__=='__main__':
    data=json.loads(Path('prompts/few_shot_examples.json').read_text())
    for ex in data['examples']:parse(json.dumps(ex['output']),ex['input'])
    print(json.dumps({'status':'parser_examples_valid','examples':len(data['examples']),'synthetic':True,'model_requests_sent':0}))
