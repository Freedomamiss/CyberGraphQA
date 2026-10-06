from pathlib import Path
import json,textwrap,html
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,Preformatted
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing,Rect,String,Line,Polygon
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
ROOT=Path(__file__).resolve().parents[1]
FONT='/usr/share/fonts/truetype/dejavu/'
for name,file in [('Body','DejaVuSans.ttf'),('Bold','DejaVuSans-Bold.ttf'),('Mono','DejaVuSansMono.ttf')]:pdfmetrics.registerFont(TTFont(name,FONT+file))
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='B',fontName='Body',fontSize=10,leading=13,spaceAfter=7))
styles.add(ParagraphStyle(name='SmallX',fontName='Body',fontSize=8.5,leading=11,spaceAfter=5))
styles.add(ParagraphStyle(name='H',fontName='Bold',fontSize=15,leading=19,spaceAfter=10,textColor=colors.HexColor('#153C52')))
styles.add(ParagraphStyle(name='Sub',fontName='Bold',fontSize=11,leading=14,spaceBefore=6,spaceAfter=5,textColor=colors.HexColor('#153C52')))
styles.add(ParagraphStyle(name='CodeX',fontName='Mono',fontSize=7.9,leading=9.5,spaceAfter=7))
story=[]
def P(t,small=False):story.append(Paragraph(t,styles['SmallX' if small else 'B']))
def H(t):story.append(Paragraph(t,styles['H']))
def S(t):story.append(Paragraph(t,styles['Sub']))
def CODE(s,wrap=96):
    lines=[]
    for l in s.splitlines():lines.extend(textwrap.wrap(l,width=wrap,replace_whitespace=False,drop_whitespace=False) if len(l)>wrap else [l])
    story.append(Preformatted('\n'.join(lines),styles['CodeX']))
def T(rows,widths):
    formatted=[[Paragraph(html.escape(str(v)),styles['SmallX']) for v in row] for row in rows]
    t=Table(formatted,colWidths=widths,hAlign='LEFT',repeatRows=1)
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#DCEAF1')),('VALIGN',(0,0),(-1,-1),'TOP'),('GRID',(0,0),(-1,-1),.35,colors.HexColor('#BACBD4')),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),4)]))
    story.append(t);story.append(Spacer(1,8))
def PAGE():story.append(PageBreak())
def diagram(kind):
    d=Drawing(504,200 if kind=='architecture' else 135)
    def box(x,y,w,h,label,sub=''):
        d.add(Rect(x,y,w,h,rx=4,ry=4,fillColor=colors.HexColor('#EAF2F6'),strokeColor=colors.HexColor('#4D7487')))
        for j,line in enumerate(label.split('|')):d.add(String(x+w/2,y+h-17-j*12,line,textAnchor='middle',fontName='Bold',fontSize=9))
        if sub:d.add(String(x+w/2,y+8,sub,textAnchor='middle',fontName='Body',fontSize=7))
    def arrow(x,y,a,b):
        d.add(Line(x,y,a,b,strokeColor=colors.HexColor('#41677B'),strokeWidth=1))
        import math
        angle=math.atan2(b-y,a-x);pts=[a,b,a-6*math.cos(angle-.45),b-6*math.sin(angle-.45),a-6*math.cos(angle+.45),b-6*math.sin(angle+.45)]
        d.add(Polygon(pts,fillColor=colors.HexColor('#41677B'),strokeColor=None))
    if kind=='architecture':
        for x,label,sub in [(0,'Source ingestion','CVE / KEV / NVD'),(170,'LLM extractor','description-only JSON'),(340,'Resolver + graph','typed directed facts')]:box(x,136,150,53,label,sub)
        arrow(150,162,170,162);arrow(320,162,340,162)
        box(340,49,150,53,'Graph embedder','Node2Vec planned');arrow(415,136,415,102)
        box(170,49,150,53,'Hybrid vector stores','384-D text / 64-D graph');arrow(340,76,320,76)
        box(0,49,150,53,'Multi-hop QA','pack → generate → check');arrow(170,76,150,76)
        box(0,0,150,32,'Frontend');arrow(75,49,75,32)
        arrow(415,136,150,98)
        d.add(String(233,119,'typed traversal / source fusion',fontName='Body',fontSize=7))
        arrow(75,136,210,102);d.add(String(68,115,'text chunks',fontName='Body',fontSize=7))
    else:
        box(0,80,145,47,'Entity','id / type / attributes');box(175,80,145,47,'Relation','typed endpoints / evidence');box(350,80,145,47,'GraphChunk','nodes[] / edges[]')
        arrow(350,105,320,105);arrow(350,85,145,85)
        box(0,0,145,46,'QueryPayload','question / mode / budget');box(175,0,145,46,'QAEngine protocol','retrieve() / answer()');box(350,0,145,46,'QAResponse','items / basis / abstain')
        arrow(145,23,175,23);arrow(320,23,350,23);arrow(420,80,248,46)
    story.append(d);story.append(Spacer(1,7))
# PAGE 1
H('1. Executive Summary & System Requirements')
P('<b>CyberGraphQA — CS 6338 Milestone 2</b><br/>Prepared by Aaron Ballinger · October 5, 2026 · System Architecture &amp; Design Document')
P('CyberGraphQA is a vulnerability-focused GraphRAG chatbot for a security analyst who needs to connect a CVE to affected products, vendors, weakness IDs, and recorded severity. The analyst should be able to inspect the supporting facts, not just accept a confident sentence. Assigning the wrong product to a CVE could send remediation work toward the wrong system.')
P('This blueprint builds on the current prototype. The frozen sample has 150 CVEs: 120 KEV-listed and 30 not listed in that catalog snapshot. “Not listed” is a catalog membership statement, not evidence that exploitation never happened. Source records and SHA-256 hashes remain fixed during evaluation.')
S('Functional requirements and acceptance checks')
T([['ID','Requirement','Acceptance evidence'],['F1','Extract description-only product/vendor assertions.','Schema and exact-span parser; retain failures.'],['F2','Resolve typed entities and fuse attributed metadata.','No dangling edges or cross-vendor product merges.'],['F3','Retrieve bounded multi-hop subgraphs and text.','CVE → product → vendor paths; four modes.'],['F4','Generate cited items and allow abstention.','Per-item label-to-source map; semantic support review.'],['F5','Expose inspection and QA through a UI/API boundary.','Validated request/response contracts; no silent fallback.'],['F6','Evaluate extraction and QA independently.','88 reference triples; 20 QA pairs; reproducible metrics.']],[30,231,243])
S('Non-functional targets, not measured claims')
P('For a warm local service, target retrieval p95 ≤ 3 seconds and graph inspection p95 ≤ 0.5 seconds over 100 timed requests. Target full QA p95 ≤ 60 seconds on Aaron’s Windows machine; local LLM inference is reported separately. These targets have not been demonstrated. The design favors one active generation job, cached evidence/embeddings, and a fixed request budget over unbounded concurrency.')
P('Cache keys include snapshot hash, query, mode, model digest, prompt version, and budget. A changed dependency invalidates the cache. Persist raw responses and failed validations. Evidence is untrusted input; source text cannot instruct the system to browse, run tools, or change policy. Bind the demo API to localhost and allow only configured frontend origins.')
P('<b>Status:</b> ingestion, extraction runs, source fusion, text indexing, four-mode retrieval, and a development QA audit exist. This checkpoint adds tested schema/API contracts. Node2Vec training, structural-vector indexing, RAGAS execution, and a full frontend remain specified work. This is a design document grounded in a prototype, not a backdated claim that the design preceded every experiment.',True)
PAGE()
# PAGE 2
H('2. End-to-End System Architecture')
P('The design keeps extraction candidates separate from source-selected facts. That separation matters: an extraction that passes a parser is not automatically a correct fact. The current QA graph is built from structured source metadata; the model candidate graph has not been integrated into QA.')
diagram('architecture')
T([['Connection','Input → output','Protocol / invariant'],['Ingestion → extractor','{cve_id, description} → assertions','UTF-8 JSON; no metadata or answer leakage.'],['Extractor → resolver','Accepted assertions → stable IDs / triples','Exact quotes; rejected response stored unchanged.'],['Resolver / fusion → graph','Typed nodes / edges + provenance','Versioned JSON; immutable snapshot and evidence IDs.'],['Graph → embedder','Undirected projection → 64-D vectors','Offline job; retain directed graph for reasoning.'],['Text / graph → indexes','Text / node summaries → vectors','Separate 384-D and 64-D FAISS spaces.'],['Indexes + graph → QA','Candidates + support paths → context','Bounded hops; deduplicate; preserve complete bundles.'],['QA → UI / audit','Items, citations, uncertainty, status','HTTP JSON/Pydantic; raw answer retained.']],[115,185,204])
S('Execution boundaries')
P('Offline jobs freeze source bytes, compile the graph, fit embeddings, and persist index manifests. Online requests load verified artifacts, identify anchors, retrieve support, synthesize context, and call the generator. No online query modifies the graph. Reindexing is a new offline artifact, not an automatic repair during a scored run.')
P('Each artifact records schema version, snapshot ID, code hash, source hash, and model revision. A mismatch stops the request. The graph-to-QA path can operate before structural embeddings exist; the graph-embedding channel is enabled only in a separately named ablation. A frontend receives evidence and status, not hidden gold answers.')
PAGE()
# PAGE 3
H('3. Graph Extraction & Schema Engineering Pipeline')
S('Domain schema and identities')
T([['Node type','Identity / required attributes'],['CVE','Exact CVE ID; description; snapshot; KEV membership; field provenance.'],['Product','Vendor-qualified normalized key. Unknown-vendor extraction products remain record-local. Preserve raw name and component ambiguity.'],['Vendor','Casefolded organization key; raw spelling; supported aliases.'],['CWE','Validated CWE identifier; mapping source and alternatives.'],['Severity','Selected CVSS 3.x category: LOW, MEDIUM, HIGH, CRITICAL.']],[85,419])
T([['Predicate','Allowed direction','Edge attributes'],['AFFECTS','CVE → Product','Evidence IDs, source, source-field path, review status.'],['MADE_BY','Product → Vendor','Same-CVE supporting pair provenance for QA.'],['HAS_WEAKNESS','CVE → CWE','Selected mapping; retained disagreements.'],['HAS_SEVERITY','CVE → Severity','Selected CVSS vector/version/source; alternatives retained.']],[108,145,251])
P('No dangling endpoints, duplicate node IDs, unsupported predicates, or incorrectly typed relationships are allowed. Product names are not joined to every vendor named in a record. MADE_BY does not imply that a component inherits its containing product’s vendor. Missing fields remain missing; placeholders do not become nodes.')
S('Resolution and deduplication algorithm')
P('First trim and collapse whitespace, then casefold for exact lookup. Preserve the original display name. Structured products use vendor_key + product_key, which keeps identically named products from different vendors separate. Exact typed keys merge; their supporting evidence is unioned without dropping source attribution.')
P('For nonexact spellings, generate candidates only within the same type and vendor scope. Proposed thresholds are normalized edit similarity ≥ 0.90 or node-summary cosine ≥ 0.90. These are review triggers, not merge decisions or calibrated probabilities. A reviewer must identify explicit source support before a versioned alias is accepted. Do not remove product versions or merge components automatically. Store old ID, canonical ID, rationale, source quote, reviewer, and date in the merge log.')
P('The current snapshot has 164 vendor-qualified products and six vendor keys. The design adds a typed NetworkX adapter; it does not rewrite that snapshot’s IDs. The separate extraction reference retains 14 records with unresolved annotation questions, including product granularity and vendor scope. Their uncertainty must survive scoring.')
PAGE()
# PAGE 4
H('3. Extraction Prompts, Chunking & Failure Policy')
P('Historical extraction used one complete description per CVE, with no overlap. The design intake limit is 4,000 characters. Longer descriptions use a new variant with 4,000-character windows and 200-character overlap, preserving source offsets; exact duplicate assertions are collapsed. That long-record branch has not been used in the frozen extraction run. Text indexing separately enforces the encoder’s 256-token limit, with zero overlap and complete character coverage.')
S('Exact implemented system prompt: literal-product-assertions-v1')
CODE((ROOT/'prompts/extraction_system.txt').read_text().strip(),wrap=100)
S('Output contract, examples, and gates')
CODE('{"cve_id":"CVE-2099-10001","products":[\n {"name":"ExampleCo Widget","evidence":"ExampleCo Widget",\n  "vendors":[{"name":"ExampleCo","evidence":"ExampleCo Widget"}]}]}')
P('The example is synthetic. A second example extracts ParserZ with vendors=[] when the organization is not stated. Both are stored in few_shot_examples.json for a future prompt variant; neither was used in the frozen run. The strict JSON schema forbids extra keys. The parser checks CVE identity, exact contiguous spans, names within quotes, and duplicate assertions.',True)
P('Acceptance is a deterministic gate: schema + identity + span + duplicate checks must all pass (gate score 1; otherwise 0). This is not a model confidence probability. Self-reported confidence is not used. Store malformed or truncated output as failed, retain raw bytes, and do not repair it silently. Semantic review follows mechanical acceptance.',True)
PAGE()
# PAGE 5
H('4. Graph Storage, Enhancement & Reasoning Engine')
P('NetworkX is sufficient for the curated 150-CVE design. The existing system persists directed typed facts as JSON. schema.py now initializes a MultiDiGraph through Pydantic validation, with predicate keys and explicit evidence references. NetworkX allows parallel edges, so application-level constraints are essential [1]. No Neo4j server or real-time Cypher execution is claimed.')
CODE('graph, lookup, evidence = schema.load("data/qa/graph.json")\n# Validate IDs, endpoint types and evidence before add_edge().\n# lookup["name"][normalized_name] -> candidate IDs\n# lookup["type"][node_type] -> IDs\n# graph.out_edges(cve_id, keys=True, data=True) -> typed facts')
P('Uniqueness is node ID and (subject, predicate, object). Name lookup returns a list, because a name can be ambiguous. Reject dangling endpoints before insertion; NetworkX must not create them implicitly. Initialization is idempotent as a pure load into a fresh graph. Output serialization uses exclusive creation so a checkpoint cannot overwrite another run.')
S('Reasoning layer: attributed structured-data fusion')
P('The required reasoning/enhancement layer is data fusion. CNA affected vendor/product pairs are selected first; KEV pairs are a documented fallback when CNA pairs are unusable. Never construct a Cartesian product of vendor and product lists. Keep description-only extraction separate from later source metadata. CWE selection uses the recorded source precedence; CVSS prefers an eligible v3.1 metric, then v3.0, with source attribution. Retain alternatives and disagreement flags rather than pretending they were resolved.')
P('The audit verified 232 source hashes. The structured graph contains 373 nodes and 960 edges: 508 AFFECTS, 164 MADE_BY, 138 HAS_WEAKNESS, and 150 HAS_SEVERITY. Thirteen records lack a selected CWE mapping; 77 contain flags or missing fields. These are source-data limitations, not a reason to fill blanks from model memory.')
S('Triple reference and automated verification')
P('benchmarks/gold_triples.json contains 88 description-only triples: 70 AFFECTS and 18 MADE_BY, compiled from the frozen Claude source-only reference. It carries human_gold=false, reviewer identity, reference hash, quotes, and unresolved notes. The assignment’s filename is retained, but this is an AI-reviewed reference, not human-adjudicated ground truth.')
CODE('K(t) = (cve_id, normalized_subject, predicate, normalized_object)\nTP = |prediction ∩ reference|; FP = |prediction - reference|\nFN = |reference - prediction|\nP = TP/(TP+FP); R = TP/(TP+FN); F1 = 2TP/(2TP+FP+FN)')
P('score_triples.py uses CVE-scoped set matching, exact names, and deduplication. Failed extractions contribute no accepted triples but retain their expected omissions. Empty prediction precision is N/A. Report per-predicate and end-to-end counts; alias sensitivity is separate. The historical 150-record run had 70 parser-accepted and 80 failed records, which is not an extraction-accuracy result. A human reference review must create a new version if required for course gold.',True)
PAGE()
# PAGE 6
H('5. Featurization, Embedding & Hybrid Vector Indexing')
S('Implemented semantic channel')
P('Each source evidence unit is independently chunked by tokenizer offsets. Every original character remains covered; oversized fragments split again instead of silently truncating. The frozen all-MiniLM-L6-v2 revision is 1110a243fdf4706b3f48f1d95db1a4f5529b4d41. Normalize 384-dimensional vectors and use FAISS IndexFlatIP so inner product equals cosine. The persisted source index has 2,055 chunks. A CVE candidate’s score is its maximum chunk score, with stable ID tie-breaking.')
S('Specified structural channel: Node2Vec')
P('Use a simple undirected projection of the typed graph only for random walks; retain directions and predicates in the reasoning graph. With previous node t, current node v, and candidate neighbor x, the transition is proportional to α(t,x)w(v,x), normalized over neighbors. α is 1/p for returning to t, 1 when t and x are adjacent, and 1/q otherwise [2].')
CODE('Pr(x | t,v) = α_pq(t,x) w(v,x) / Σ_y α_pq(t,y) w(v,y)\nmaximize Σ_u Σ_n∈N(u) log Pr(n | z_u)\nPr(n | z_u) ∝ exp(z_n · z_u)   # skip-gram neighborhood objective')
T([['Hyperparameter','Design choice'],['Dimensions / walks','64 dimensions; 10 walks per node; length 40.'],['Bias / training','p=1, q=0.5; unit edge weights; context window 5.'],['Optimization','5 negative samples; 5 epochs; initial learning rate 0.025.'],['Reproducibility','Seed 1337; one worker; sorted IDs/neighbors; record backend/version.']],[132,372])
P('The biased transition kernel is tested; embedding training has not run. Monitor vendor/CWE hubs and compare against p=q=1 before attributing improvements to walk bias. Structural neighbors indicate proximity, not a new factual relationship or evidence of exploitation. Record node order, projection hash, parameters, vectors, and backend version.')
S('Three indexes, one retrieval contract')
P('Persist separate FAISS indexes: (1) evidence-text vectors, 384-D; (2) source-backed node summaries encoded by the same text model, 384-D; and (3) normalized Node2Vec entity vectors, 64-D. Manifests bind dimensions, model/projection hashes, node/evidence order, and snapshot. Text and structural vectors are never concatenated or compared directly.')
P('For a natural-language query, the semantic node-summary index proposes anchor IDs. Average their 64-D structural vectors to form a structural query, normalize it, and search the 64-D index. If no anchor has a vector, skip that channel explicitly. Structural candidates must recover real typed paths and source evidence before generation. The current evaluation used semantic text plus typed traversal, not this planned structural-vector channel. Node2Vec is a separate ablation.')
PAGE()
# PAGE 7
H('6. Hybrid GraphRAG QA Engine & Retrieval Logic')
P('The generator should receive enough evidence to answer the requested relationship. More context is not automatically better context. The frozen evaluation showed that graph retrieval could retain the right facts while generation still produced nonanswers or unsupported transfers.')
S('Implemented four-mode retrieval')
P('1. Validate query, snapshot, mode, and budget. LLM-only receives no evidence. For retrieval modes, extract explicit CVE IDs and recognized entity names; ambiguous names remain candidates, not automatic resolutions.')
P('2. Text retrieves top-five CVE candidates by maximum chunk cosine score. Graph uses exact anchors and typed paths up to two edges, including CVE → product → vendor; predicate filters select requested weakness or severity facts. Reject cross-CVE evidence inheritance.')
P('3. Text and graph support are packed separately. Hybrid unions source IDs and reserves complete named-CVE product/vendor bundles before baseline filling. Deduplicate facts. The frozen budget is 6,000 characters, not a verified generator-token cap. Do not split a required relationship bundle into an apparently complete fragment.')
P('4. Give each selected unit a request-local E001-style label. Persist the label map, packed context, skipped IDs, ranking, and configuration. Generate one fresh response using the exact templates on page 8; validate structure, labels, and abstention. Then review semantic support and completeness separately.')
S('Specified improvements, outside the frozen protocol')
P('A new fair-routing variant will apply exact CVE filtering to both text and graph before ranking. It will reserve every requested predicate, including HAS_WEAKNESS and HAS_SEVERITY, not only product/vendor bundles. The original text baseline and all saved scores remain unchanged. This is important because the frozen text condition missed all target source records.')
CODE('text_hits = text_index.search(query_vector, top_k=5)\nanchors = exact_ids + semantic_node_index.search(query_vector)\ngraph_hits = typed_paths(anchors, max_hops=2)\nstructural_hits = node2vec_neighbors(anchors)  # optional ablation\nscore(id) = Σ_channel 1 / (60 + rank_channel(id))\nsupport = recover_attributed_paths(ranked_union)\ncontext = pack_requested_bundles(support, cap=6000)')
P('Reciprocal rank fusion avoids treating unrelated semantic and structural scores as a common calibrated scale. Use stable IDs for tie-breaking and at most five anchors per channel. If a complete requested bundle cannot fit, return explicit omission metadata and a partial-answer warning. Never infer an exhaustive list from a selected subgraph.')
S('Generator limits and operational behavior')
P('The pinned local generator is llama3.1:8b, temperature 0, seed 1337, num_ctx 8192, num_predict 512, top_p 1, top_k 40, repeat_penalty 1.1. The full digest is recorded in the repository protocol lock. A digest mismatch stops the run. No automatic repair or retries occur in evaluation. A missing citation, wrong label, contradictory abstention, or output-limit stop is a retained failure. Evidence-label validity does not establish factual support.')
PAGE()
# PAGE 8
H('6. Exact Context Synthesis & Generator Templates')
P('The following system text is copied from the current item-citations-abstention-v2 generator. Line wrapping is for print; prompts/qa_system.txt is the authoritative text. It is intentionally shown rather than described as an unspecified “grounded prompt.”')
CODE((ROOT/'prompts/qa_system.txt').read_text().strip(),wrap=100)
S('User message template and evidence format')
CODE('Answer policy:\n{policy}\n\nQuestion:\n{question}\n\nEvidence:\n[E001] {source_fact_text_1}\n[E002] {source_fact_text_2}')
P('Retrieval policy is exactly: “Retrieval mode: answer only from supplied evidence. Abstain if it does not support the requested relationship.” For LLM-only, it is: “No-retrieval baseline: prior knowledge is permitted, but dataset membership and grounding cannot be verified. Citations must be empty.”',True)
P('Ollama receives messages, the strict JSON answer schema through format, stream=false, the pinned options, and keep_alive=5m. answer_items contains claim/evidence_ids; explanation contains limitations; answer_basis is supplied_evidence, prior_knowledge, or insufficient_evidence. Retrieval citation values are restricted to actual request labels. Empty retrieval fixes items=[] and abstain=true. A future entity-typed answer schema is a new variant, not a retroactive repair.',True)
PAGE()
# PAGE 9
H('7. Evaluation Pipeline & Benchmark Protocol')
P('The repository contains 20 source-derived QA pairs, with seven product/vendor, seven product/vendor/weakness, and six product/vendor/severity questions. Vendor strata are Apple 4, Cisco 4, and Google, Ivanti, Microsoft, VMware 3 each. Each question has at least one documented two-edge product/vendor path; there are 33 paths and 65 expected claims. IDs and sources are frozen before an evaluation run.')
P('For example, QA-002 asks for the recorded products, vendors, and weakness IDs of CVE-2022-20708. Complete questions, source answers, and support paths are in eval_queries.json.',True)
S('Automated metrics and framework configuration')
P('Primary correctness is per-question atomic set precision, recall, and F1; macro recall/F1 use all 20 questions per mode. Report micro counts, protocol failures, supplied-evidence completeness, citation support, and retrieval versus generation omissions. Wrong-CVE claims are false positives; failed protocol outputs have no accepted claims. Preserve strict names and source-supported alias sensitivity separately.')
P('The planned RAGAS 0.2.14 job uses Faithfulness, ResponseRelevancy, and LLMContextRecall [3]. Supply user_input, the accepted response, retrieved_contexts, and the source reference. Faithfulness tests context support; relevance tests responsiveness; context recall tests coverage of reference claims. These judge scores supplement, not replace, scoped source-reference scoring. LLM-only faithfulness is N/A without supplied context.')
CODE('metrics = build_metrics(pinned_local_judge, pinned_embeddings)\n# config/evaluation.json: temperature=0; max_workers=1\n# timeout=180s; retry budget=0; metric-call cap=6/case\n# Cache by judge digest + metric prompt + input + version.\n# Deferred: adapt Ollama and run evaluate() in a separate job.')
P('RAGAS and its judge adapter have not been executed. Before running, lock judge digest, framework/adapters, metric prompts, and embeddings; log each judge call and NaN/error rather than dropping cases. Do not treat another AI model as a human or claim independence merely because its name differs.')
S('Human testing protocol: one disclosed author rater')
T([['Axis','1 — major failure','3 — partial','5 — complete'],['Factuality','Wrong target/entities.','Some correct; material errors.','All requested claims match reference.'],['Completeness','No useful requested answer.','Several required claims omitted.','All requested claims or valid missingness disclosure.'],['Coherence','Contradictory/unusable.','Understandable but unclear.','Clear, consistent, usable.']],[78,142,140,144])
P('Aaron will rate all 20 questions × four anonymized modes (80 outputs), in randomized order, using the reference and evidence. Scores 2 and 4 lie between anchors. Save factuality/completeness/coherence, rationale, timestamp, missingness, and reference disputes. No second human is assumed; report single-author review and prior exposure. Do not compute inter-rater agreement with one rater. Human ratings have not been performed.')
P('The existing development audit retained 80 responses: 72 protocol-valid, eight failed. Exact macro F1 was 0.0% LLM-only, 2.4% text, 69.4% graph, and 41.7% hybrid. These are AI-reviewed source-reference results, not human-gold or held-out results. Graph used exact CVE routing while text used semantic ranking, so this comparison cannot isolate graph representation from identifier matching. Keep that confound visible.',True)
PAGE()
# PAGE 10
H('8. Software Interfaces, Data Models & Class Diagrams')
P('Strict Pydantic contracts define module boundaries [4]. FastAPI validates request bodies and response models [5]. The full models include endpoint/type checks and evidence references; the excerpt shows the core shapes. Legacy data is adapted explicitly, not accepted through permissive extra fields.')
CODE('class Contract(BaseModel):\n    model_config = ConfigDict(extra="forbid", strict=True)\nclass Entity(Contract):\n    id: str; name: str; type: NodeType\n    attributes: dict = Field(default_factory=dict)\nclass Relation(Contract):\n    subject: str; predicate: Predicate; object: str\n    evidence_ids: list[str] = Field(min_length=1)\nclass GraphChunk(Contract):\n    snapshot_id: str; origin: SourceKind\n    nodes: list[Entity]; edges: list[Relation]\nclass QueryPayload(Contract):\n    question: str = Field(min_length=1, max_length=2000)\n    mode: Literal["llm-only","text","graph","hybrid"]\n    max_hops: int = Field(default=2, ge=1, le=2)')
diagram('classes')
T([['Route','Contract / behavior'],['GET /health; GET /schema','Readiness flags; JSON schemas; no model calls.'],['GET /graph/{cve_id}','Read-only typed neighborhood; 404 if ID absent.'],['POST /retrieve','QueryPayload → RetrievalResponse; 422 bad payload, 503 unwired.'],['POST /qa','QueryPayload → QAResponse; 503 until engine adapter is supplied.']],[180,324])
P('Streamlit is the planned frontend: question box, mode selector, answer items, cited evidence, two-edge path view, and missing-support warnings. It calls localhost FastAPI over HTTP JSON. Do not expose arbitrary Python or Cypher execution. QAEngine is an interface here; the API scaffold deliberately returns 503 instead of fabricating answers.',True)
P('<b>Checkpoint:</b> schema.py, exact prompts/parser, 88 triples, 20 QA pairs, Pydantic schemas, and nine passing tests are packaged. Node2Vec/RAGAS training or judging and frontend integration remain specified. The required hosted repository URL must be attached after this isolated checkpoint is uploaded. Human-adjudicated gold requires a separate review if the instructor requires it; its absence is not concealed by the gold_triples.json filename.',True)
P('<b>Technical references</b> (official documentation / original paper; accessed October 5, 2026):<br/>[1] NetworkX, MultiDiGraph. networkx.org/documentation/stable/reference/classes/multidigraph.html<br/>[2] Grover &amp; Leskovec (2016), <i>node2vec</i>. arxiv.org/abs/1607.00653<br/>[3] RAGAS 0.2.14, metrics and evaluate(). docs.ragas.io/en/v0.2.14/references/metrics/<br/>[4] Pydantic, models/configuration. docs.pydantic.dev/latest/concepts/models/<br/>[5] FastAPI, request bodies/response models. fastapi.tiangolo.com/tutorial/body/<br/>Project evidence: frozen source audit and graph bundle, Claude_Reference_v1, protocol-lock.json, and Checkpoint 35 review. Source repositories: github.com/CVEProject/cvelistV5; github.com/cisagov/kev-data; nvd.nist.gov.',True)
# Source data for editable, page-structured design text.
md=[]
for f in story:
 if isinstance(f,Paragraph):md.append(f.getPlainText())
 elif isinstance(f,Preformatted):md.append('```\n'+'\n'.join(f.lines)+'\n```')
 elif isinstance(f,PageBreak):md.append('\n---\n')
 elif isinstance(f,Table):md.extend(' | '.join(c.getPlainText() if hasattr(c,'getPlainText') else str(c) for c in row) for row in f._cellvalues)
(ROOT/'docs/DesignDoc_Source.md').write_text('\n\n'.join(md)+'\n')
def chrome(canvas,doc):
    canvas.saveState();canvas.setStrokeColor(colors.HexColor('#B1C8D3'));canvas.line(44,753,568,753)
    canvas.setFont('Body',8);canvas.setFillColor(colors.HexColor('#486578'));canvas.drawString(44,765,'CyberGraphQA  |  CS 6338  |  Milestone 2')
    canvas.drawRightString(568,27,f'{doc.page}');canvas.drawString(44,27,'Aaron Ballinger  ·  Architecture & Design  ·  October 5, 2026');canvas.restoreState()
path=ROOT/'docs/CyberGraphQA_GraphRAG_DesignDoc.pdf'
doc=SimpleDocTemplate(str(path),pagesize=(612,792),leftMargin=54,rightMargin=54,topMargin=53,bottomMargin=46,title='CyberGraphQA System Architecture and Design — Milestone 2',author='Aaron Ballinger')
doc.build(story,onFirstPage=chrome,onLaterPages=chrome)
print(path)
