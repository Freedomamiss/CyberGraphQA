import copy,json,unittest
from pathlib import Path
import networkx as nx
from pydantic import ValidationError
from cgqa_design.models import GraphChunk,QueryPayload,QAResponse
from cgqa_design.embedding_design import transition_weights,walk
from score_triples import score
from test_parser import parse
import schema
ROOT=Path(__file__).resolve().parents[1]
class CheckpointTests(unittest.TestCase):
    def test_frozen_graph_initializes_with_exact_counts(self):
        graph,lookup,ev=schema.load(ROOT/'data/qa/graph.json')
        self.assertEqual((graph.number_of_nodes(),graph.number_of_edges(),len(ev)),(373,960,2054))
        self.assertEqual(len(lookup['type']['CVE']),150)
    def test_invalid_graph_endpoints_cannot_be_implicitly_created(self):
        with self.assertRaisesRegex(ValidationError,'Dangling'):
            GraphChunk(snapshot_id='x',origin='frozen_structured_sources',nodes=[],edges=[{'subject':'a','predicate':'AFFECTS','object':'b','evidence_ids':['e']}])
    def test_endpoint_types_rejected(self):
        with self.assertRaisesRegex(ValidationError,'typed'):
            GraphChunk(snapshot_id='x',origin='frozen_structured_sources',nodes=[{'id':'a','name':'a','type':'Vendor'},{'id':'b','name':'b','type':'CVE'}],edges=[{'subject':'a','predicate':'AFFECTS','object':'b','evidence_ids':['e']}])
    def test_parser_rejects_vendor_not_in_quote(self):
        record={'cve_id':'CVE-2099-10001','description':'ParserZ crashes.'}
        with self.assertRaises(ValueError):parse(json.dumps({'cve_id':record['cve_id'],'products':[{'name':'ParserZ','evidence':'ParserZ','vendors':[{'name':'ExampleCo','evidence':'ParserZ'}]}]}),record)
    def test_benchmarks_have_real_source_spans_and_paths(self):
        gold=json.loads((ROOT/'benchmarks/gold_triples.json').read_text());self.assertEqual(len(gold['triples']),88);self.assertFalse(gold['human_gold'])
        for t in gold['triples']:self.assertIn(t['evidence'],t['description'])
        qs=json.loads((ROOT/'benchmarks/eval_queries.json').read_text())['queries'];self.assertEqual(len(qs),20)
        for q in qs:self.assertTrue(q['support_paths']);self.assertTrue(all(p['hop_count']==2 for p in q['support_paths']))
    def test_triple_scoring_keeps_wrong_cve_and_failed_omissions(self):
        ref={'human_gold':False,'reference_kind':'ai','triples':[{'cve_id':'a','subject':'a','predicate':'AFFECTS','object':'x'},{'cve_id':'b','subject':'b','predicate':'AFFECTS','object':'y'}]}
        pred={'triples':[{'cve_id':'a','subject':'a','predicate':'AFFECTS','object':'y'}]};r=score(ref,pred)
        self.assertEqual((r['TP'],r['FP'],r['FN']),(0,1,2))
    def test_query_limits_and_abstention_contract(self):
        with self.assertRaises(ValidationError):QueryPayload(question='x',max_hops=3)
        with self.assertRaises(ValidationError):QAResponse(answer_items=[{'claim':'x','evidence_ids':[]}],explanation='x',abstain=True,answer_basis='prior_knowledge')
    def test_node2vec_kernel_and_seed(self):
        graph=nx.Graph([('a','b'),('b','c'),('b','d'),('a','c')]);choices,w=transition_weights(graph,'a','b',p=2,q=.5)
        self.assertEqual(dict(zip(choices,w)),{'a':.5,'c':1.,'d':2.})
        self.assertEqual(walk(graph,'a'),walk(graph,'a'))
    def test_api_schema_and_unwired_routes_are_explicit(self):
        from cgqa_design.api import health,contracts,retrieve
        from fastapi import HTTPException
        self.assertFalse(health()['engine_ready']);self.assertIn('graph',contracts())
        with self.assertRaises(HTTPException) as cm:retrieve(QueryPayload(question='x'))
        self.assertEqual(cm.exception.status_code,503)
if __name__=='__main__':unittest.main()
