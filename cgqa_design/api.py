"""FastAPI design scaffold; retrieval/generation adapters are not wired yet."""
from pathlib import Path
from fastapi import FastAPI,HTTPException
from cgqa_design.models import QueryPayload,RetrievalResponse,QAResponse,GraphChunk
import schema
app=FastAPI(title='CyberGraphQA Milestone 2',version='design-v1')
app.state.engine=None
@app.get('/health')
def health():return {'status':'design_scaffold','engine_ready':app.state.engine is not None,'generation_enabled':app.state.engine is not None}
@app.get('/schema')
def contracts():return {'graph':GraphChunk.model_json_schema(),'query':QueryPayload.model_json_schema()}
@app.get('/graph/{cve_id}')
def inspect_graph(cve_id:str):
    graph,_,evidence=schema.load(Path(__file__).resolve().parents[1]/'data/qa/graph.json')
    if cve_id not in graph or graph.nodes[cve_id]['type']!='CVE':raise HTTPException(404,'CVE not in snapshot')
    affected=[v for _,v,k in graph.out_edges(cve_id,keys=True) if k=='AFFECTS']
    nodes={cve_id,*affected};edges=[]
    for u,v,k,d in graph.edges(keys=True,data=True):
        if u==cve_id or (u in affected and k=='MADE_BY'):
            nodes.add(v);edges.append(d)
    return {'snapshot_id':graph.graph['snapshot_id'],'nodes':[graph.nodes[n] for n in sorted(nodes)],'edges':edges,'exhaustive_dataset_query':False}
@app.post('/retrieve',response_model=RetrievalResponse)
def retrieve(payload:QueryPayload):
    if app.state.engine is None:raise HTTPException(503,'Retrieval adapter not implemented in this design scaffold')
    return app.state.engine.retrieve(payload)
@app.post('/qa',response_model=QAResponse)
def qa(payload:QueryPayload):
    if app.state.engine is None:raise HTTPException(503,'QA adapter not implemented in this design scaffold')
    return app.state.engine.answer(payload)
