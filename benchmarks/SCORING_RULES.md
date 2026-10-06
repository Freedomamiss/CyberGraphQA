# QA evaluation scoring rules v1

Freeze these rules before retrieval or answer generation for this packet. They apply equally to LLM-only, text, graph, and hybrid. References are derived from the frozen structured-source graph, not human gold. This is a broader development evaluation, not a held-out benchmark.

## Question scope

Each question asks for recorded product/vendor entities of a named CVE, with some also asking for recorded weakness IDs or selected severity. Product/vendor answers require a documented CVE → product → vendor path. Components mentioned only in descriptions are outside the requested recorded-product entity set. A description component is not silently promoted into a structured product node.

Twenty source records are selected by fixed hash ordering and round-robin source-vendor strata, excluding the 12 extraction-pilot CVEs. Eligibility requires one to five recorded products, each with a same-CVE supported vendor path, to bound enumeration size under the fixed output limit. This excludes high-cardinality records and limits generalization. Selection does not inspect accepted/failed extraction status or answer quality. Question types rotate across vendor strata so a vendor is not assigned only one type. All source records have already been exposed during development; this is not a blind source split. Do not claim course requirements verified solely because there are 20 questions with two-edge support paths.

## Separate outcomes

1. **Protocol validity:** JSON structure, item citations, answer basis, and abstention constraints. Failed outputs remain failures and are retained without repair. Report failures for all planned calls; do not drop them from comparison.
2. **Requested-claim correctness against the source reference:** each atomic product, vendor, requested weakness, or selected-severity claim must concern the requested CVE. Split composite sentences into atomic claims for review. Unsupported extra claims are false positives; expected claims omitted from the answer are false negatives. Wrong-CVE claims count as extra claims and do not satisfy the target reference.
3. **Citation support:** judge each returned item against its cited evidence, including CVE scope. Labels merely existing is insufficient. A cited AFFECTS unit with explicit vendor qualification may support a vendor claim; a two-edge path may require multiple units. Mark each citation supported, irrelevant, or insufficient, and each item's collective support supported, partial, or unsupported. A correct uncited item in LLM-only can match the reference but has no supplied-evidence grounding.
4. **Answer completeness relative to supplied evidence:** count expected source-reference claims for which adequate support was actually available in that mode's packed context, then measure how many the answer returned. This distinguishes generation omissions from retrieval omissions.
5. **Answer completeness relative to the frozen corpus:** compare returned atomic claims with the full source-reference set, even if retrieval omitted their support. This is an end-to-end outcome. Report both completeness measures; the source-reference set is not external factual truth.
6. **Abstention and uncertainty:** record whether the supplied context supported any requested claim. Empty or unrelated retrieved context warrants abstention, but missing retrieval does not prove a CVE/product absent. If some claims are supported, partial answers should identify omissions or source uncertainty. Missing recorded metadata may be stated as missing in the snapshot; this is not proof that the vulnerability has no weakness or severity.
7. **Explanation accuracy:** check extra factual claims and completeness/direct-path assertions in explanations separately. Do not hide unsupported explanation claims because item claims passed.

## Matching and aggregation

Use case-insensitive names with collapsed whitespace for exact matches. Do not infer aliases from general knowledge or merge separately recorded products. An explicitly supported alternative spelling/brand name may be marked as an AI-review alias decision with its cited source and rationale; report exact and reviewed matches separately. Do not silently change expected entities after seeing answers. Any reference correction requires a new version, change log, preserved original, and sensitivity analysis.

When the reference marks requested metadata as missing, a supported statement that the snapshot contains no recorded value is an absence disclosure, not an invented entity or false positive. Review it under uncertainty/explanation accuracy; it adds no entity TP. Distinguish missing values from unsupported global claims such as "this vulnerability has no weakness."

For requested atomic claims, report TP/FP/FN, precision, recall, and F1 per question and mode. If an answer has no claims, precision is not applicable; it has zero recall when expected claims are nonempty. Failed protocol outputs receive no accepted claims for end-to-end scoring, so expected claims remain omissions. Any raw-failure semantic inspection is a separately labeled diagnostic and is not salvaged into the primary result.

Primary comparisons use macro averages across the 20 questions, with the same denominator per mode. Also report micro counts, protocol failures, abstention counts, partial-list rates, citation support, and retrieval-versus-generation omissions. Do not turn the four modes or repeated calls into independent question samples. Do not compute uncertainty intervals that assume all outputs are independent.

The source reference records exact graph support units, but alternative description evidence may also support an expected claim. A semantic reviewer must assess that evidence rather than restricting support to an exact evidence-ID intersection. Do not label automated span/name checks as entailment.

## Review disclosure and stopping rule

Codex and Claude reviews are AI reviews with exposure disclosures, not human gold or established reviewer independence. No second human reviewer is assumed. Preserve disagreements and policy ambiguities. Prior development results motivated the packing intervention and these question types; disclose that tuning history.

Run each frozen question once per mode under the locked settings, without automatic retries or response repair. Save all 80 planned outcomes, including request accounting and truncated/API failures. No generator or retrieval tuning is allowed within this protocol version. Any subsequent fix becomes a separate development variant; it must not overwrite this run.

Protocol freezing does not mean generation has run, semantic scoring is complete, source conflicts are resolved, or GraphRAG superiority is established.
