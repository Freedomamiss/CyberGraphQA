"""Initialize a constrained NetworkX graph from the preserved schema-2 bundle."""
import argparse,json
from pathlib import Path
import networkx as nx
from cgqa_design.models import Entity,Relation,GraphChunk

def load(path):
    raw=json.loads(Path(path).read_text(encoding='utf-8'))
    nodes=[Entity(id=x['id'],name=x['name'],type=x['type'],attributes={k:v for k,v in x.items() if k not in ['id','name','type']}) for x in raw['nodes']]
    edges=[Relation.model_validate(x) for x in raw['edges']]
    snapshot=raw['nodes'][0]['snapshot_id']
    chunk=GraphChunk(snapshot_id=snapshot,origin='frozen_structured_sources',nodes=nodes,edges=edges)
    evidence={e['evidence_id']:e for e in raw['evidence_units']}
    if len(evidence)!=len(raw['evidence_units']):raise ValueError('Duplicate source evidence ID')
    for edge in chunk.edges:
        if not set(edge.evidence_ids)<=evidence.keys():raise ValueError('Missing provenance unit')
    graph=nx.MultiDiGraph(snapshot_id=snapshot,graph_kind=raw['graph_kind'],human_gold=False)
    by_name={};by_type={}
    for node in chunk.nodes:
        graph.add_node(node.id,**node.model_dump())
        by_name.setdefault(' '.join(node.name.casefold().split()),[]).append(node.id)
        by_type.setdefault(node.type,[]).append(node.id)
    for edge in chunk.edges:graph.add_edge(edge.subject,edge.object,key=edge.predicate,**edge.model_dump())
    return graph,{'name':by_name,'type':by_type},evidence

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--graph',type=Path,default=Path('data/qa/graph.json'));p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    graph,indexes,_=load(a.graph)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x',encoding='utf-8') as f:json.dump({'nodes':list(graph.nodes.values()),'edges':[d for _,_,_,d in graph.edges(keys=True,data=True)],'indexes':indexes,'snapshot_id':graph.graph['snapshot_id']},f,indent=2)
    print(json.dumps({'nodes':graph.number_of_nodes(),'edges':graph.number_of_edges(),'status':'initialized','model_requests_sent':0}))
