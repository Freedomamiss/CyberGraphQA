"""Deferred framework configuration. This factory alone sends no judge calls.
Requires ragas==0.2.14 and separately constructed local judge/embedding adapters.
Do not use the current experimental generator silently as an independent judge.
"""
def build_metrics(judge,embeddings):
    from ragas.metrics import Faithfulness,ResponseRelevancy,LLMContextRecall
    return [Faithfulness(llm=judge),ResponseRelevancy(llm=judge,embeddings=embeddings,strictness=3),LLMContextRecall(llm=judge)]
