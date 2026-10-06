# CyberGraphQA

This is an isolated architecture/design checkpoint based on the existing CyberGraphQA prototype. It does not replace frozen experiments. The ten-page PDF is `docs/CyberGraphQA_GraphRAG_DesignDoc.pdf`.

## Required files

- `schema.py`: NetworkX initialization and typed constraints; `cgqa_design/models.py`: Pydantic boundary schemas.
- `prompts/extraction_system.txt`, `extraction_schema.json`, `few_shot_examples.json`, and `test_parser.py`: exact extraction prompt/parser plus synthetic design examples. Few-shot examples were not in the historical run.
- `benchmarks/gold_triples.json`: **88 AI-reviewed, description-only triples** (70 AFFECTS, 18 MADE_BY) from the frozen Claude source-only reference. `human_gold=false`; ambiguity notes preserved. The filename follows the assignment, not a claim of human adjudication.
- `benchmarks/eval_queries.json`: 20 source-derived multi-hop QA pairs with 33 two-edge support paths; not human gold or a held-out source benchmark.
- `score_triples.py`: exact triple P/R/F1 with CVE scope and failed-output omissions.
- `config/node2vec.json` and `cgqa_design/embedding_design.py`: graph embedding specification and tested transition kernel. Embedding training and index building have **not** run.
- `config/evaluation.json` and `cgqa_design/ragas_design.py`: deferred RAGAS evaluator specification. No RAGAS judge calls or human ratings have been performed.
- `cgqa_design/api.py`: tested FastAPI contracts/scaffold. Retrieval and QA return 503 until a backend adapter is supplied. No full frontend is claimed.
- `legacy_scripts/`: unchanged current project scripts. `data/qa/`: the frozen structured-source bundle. Benchmarks and prompts contain no private credentials.

## Check this checkpoint (PowerShell)

```powershell
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements-checkpoint.txt
& .\.venv\Scripts\python.exe -m unittest discover -s tests -v
& .\.venv\Scripts\python.exe test_parser.py
& .\.venv\Scripts\python.exe schema.py --output outputs\initialized-graph.json
```

Expected graph: 373 nodes, 960 edges, 2,054 evidence units. A new output file is required. These commands send no model requests.

## Submission and honest limits

Submit the PDF and a link to a GitHub/GitLab checkpoint containing this folder. Nine design-checkpoint tests passed locally. Preserve the original references and unresolved annotations; do not change AI labels to human gold. If the instructor requires human-adjudicated gold, review the triples under the provided rubric and create a new reference version before making that claim. The supplied design requires human testing as a **protocol**; no second human is assumed. Aaron can perform a disclosed single-author review later.

Repository checkpoint: https://github.com/Freedomamiss/CyberGraphQA. Submit this URL with `docs/CyberGraphQA_GraphRAG_DesignDoc.pdf`. `Publish-Checkpoint.ps1` is retained as the original helper for publishing to an empty repository; it is not needed for this hosted checkpoint.
