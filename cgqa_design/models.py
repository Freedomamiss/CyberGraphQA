"""Milestone 2 boundary contracts. These do not change frozen experiment files."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

NodeType=Literal['CVE','Product','Vendor','CWE','Severity']
Predicate=Literal['AFFECTS','MADE_BY','HAS_WEAKNESS','HAS_SEVERITY']
SourceKind=Literal['frozen_structured_sources','model_candidate_development']
class Contract(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
class Entity(Contract):
    id: str=Field(min_length=1)
    name: str=Field(min_length=1)
    type: NodeType
    attributes: dict=Field(default_factory=dict)
class Relation(Contract):
    subject: str
    predicate: Predicate
    object: str
    evidence_ids: list[str]=Field(min_length=1)
class GraphChunk(Contract):
    snapshot_id: str
    origin: SourceKind
    nodes: list[Entity]
    edges: list[Relation]
    @model_validator(mode='after')
    def references(self):
        ids={n.id for n in self.nodes}
        if len(ids)!=len(self.nodes):raise ValueError('Duplicate node ID')
        kinds={n.id:n.type for n in self.nodes}
        allowed={'AFFECTS':('CVE','Product'),'MADE_BY':('Product','Vendor'),
                 'HAS_WEAKNESS':('CVE','CWE'),'HAS_SEVERITY':('CVE','Severity')}
        seen=set()
        for e in self.edges:
            if e.subject not in ids or e.object not in ids:raise ValueError('Dangling endpoint')
            if (kinds[e.subject],kinds[e.object])!=allowed[e.predicate]:raise ValueError('Invalid typed relation')
            key=(e.subject,e.predicate,e.object)
            if key in seen:raise ValueError('Duplicate relation')
            if len(e.evidence_ids)!=len(set(e.evidence_ids)):raise ValueError('Duplicate evidence ID')
            seen.add(key)
        return self
class QueryPayload(Contract):
    question: str=Field(min_length=1,max_length=2000)
    mode: Literal['llm-only','text','graph','hybrid']='hybrid'
    snapshot_id: str='cgqa-5495aa3949d0b789'
    max_hops: int=Field(default=2,ge=1,le=2)
    character_cap: int=Field(default=6000,ge=1,le=6000)
class Evidence(Contract):
    label: str
    evidence_id: str
    cve_id: str
    text: str
class RetrievalResponse(Contract):
    snapshot_id: str
    evidence: list[Evidence]
    corpus_sha256: str
    exhaustive: bool=False
class AnswerItem(Contract):
    claim: str=Field(min_length=1)
    evidence_ids: list[str]
class QAResponse(Contract):
    answer_items: list[AnswerItem]
    explanation: str
    abstain: bool
    answer_basis: Literal['supplied_evidence','prior_knowledge','insufficient_evidence']
    @model_validator(mode='after')
    def abstention(self):
        if self.abstain and (self.answer_items or self.answer_basis!='insufficient_evidence'):
            raise ValueError('Abstention requires empty items and insufficient_evidence')
        if not self.abstain and not self.answer_items:raise ValueError('Nonabstention requires items')
        return self
