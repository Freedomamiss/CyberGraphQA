"""Persist a pinned SentenceTransformer/FAISS pilot index, then query locally."""
import argparse
import hashlib
import json
from importlib.metadata import version
from pathlib import Path
import shutil

from retrieve_evidence import corpus, sha, pack

MODEL = 'sentence-transformers/all-MiniLM-L6-v2'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False); handle.write('\n')


def chunk_text(text, tokenizer, max_length):
    """Use offsets into the original text; every character remains covered."""
    capacity = max_length - tokenizer.num_special_tokens_to_add(pair=False)
    if capacity < 1:
        raise ValueError('Model token capacity is invalid')
    offsets = tokenizer(text, add_special_tokens=False, truncation=False,
                        return_offsets_mapping=True)['offset_mapping']
    if not offsets:
        raise ValueError('Cannot embed empty/tokenless text')
    # Some tokenizers can re-tokenize boundary fragments differently. Validate
    # actual fragment lengths and split further if necessary instead of relying
    # on the tokenizer/model to truncate a long input silently.
    starts = [0] + [offsets[i][0] for i in range(capacity, len(offsets), capacity)]
    ends = starts[1:] + [len(text)]
    result = []

    def append(start, end):
        fragment = text[start:end]
        count = len(tokenizer(fragment, add_special_tokens=True, truncation=False)['input_ids'])
        if count <= max_length:
            result.append({'start': start, 'end': end, 'text': fragment, 'token_count': count})
        elif end-start > 1:
            middle = start + (end-start)//2
            append(start, middle); append(middle, end)
        else:
            raise ValueError('Cannot fit a text fragment within model length')
    for start, end in zip(starts, ends):
        append(start, end)
    if ''.join(c['text'] for c in result) != text:
        raise ValueError('Chunk coverage failed')
    return result


def make_chunks(documents, tokenizer, max_length):
    chunks = []
    for cve, document in sorted(documents.items()):
        for fact in document['facts']:
            for ordinal, chunk in enumerate(chunk_text(fact['text'], tokenizer, max_length)):
                chunks.append({'chunk_id': fact['evidence_id'] + ':' + str(ordinal),
                    'cve_id': cve, 'evidence_id': fact['evidence_id'], **chunk})
    return chunks


def normalized_vectors(vectors, count):
    import numpy as np
    values = np.asarray(vectors, dtype='float32')
    if values.ndim != 2 or values.shape[0] != count or values.shape[1] < 1 or not np.isfinite(values).all():
        raise ValueError('Invalid embedding shape or non-finite values')
    norms = np.linalg.norm(values, axis=1, keepdims=True)
    if (norms <= 0).any():
        raise ValueError('Zero-length embedding')
    return np.ascontiguousarray(values/norms, dtype='float32')


def rank_chunks(scores, indices, chunks, top_k):
    """Collapse exact chunk search to CVEs by maximum chunk cosine score."""
    if top_k < 1:
        raise ValueError('top-k must be positive')
    best = {}
    for score, index in zip(scores, indices):
        if int(index) < 0:
            continue
        chunk = chunks[int(index)]
        row = {'cve_id': chunk['cve_id'], 'score': float(score),
               'matched_chunk_id': chunk['chunk_id'], 'matched_evidence_id': chunk['evidence_id'],
               'selection': 'sentence_transformer_faiss_max_chunk_cosine'}
        old = best.get(row['cve_id'])
        if old is None or row['score'] > old['score'] or (
            row['score'] == old['score'] and row['matched_chunk_id'] < old['matched_chunk_id']):
            best[row['cve_id']] = row
    return sorted(best.values(), key=lambda r: (-r['score'], r['cve_id']))[:top_k]


def checked_manifest(directory, graph):
    manifest = json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('status') != 'complete' or manifest['schema_version'] != 1:
        raise ValueError('Index is not complete/supported')
    if manifest['graph_sha256'] != sha(graph) or manifest['corpus_sha256'] != sha(corpus(graph)):
        raise ValueError('Graph/corpus differs from the indexed source')
    for relative, expected in manifest['file_sha256'].items():
        path = directory/relative
        if not path.resolve().is_relative_to(directory.resolve()):
            raise ValueError('Unsafe index file path')
        if digest(path) != expected:
            raise ValueError('Index/model file hash mismatch: ' + relative)
    return manifest


def reuse_model(source_index, destination):
    """Copy only verified model files, never reuse another corpus's vectors."""
    manifest = json.loads((source_index/'manifest.json').read_text(encoding='utf-8'))
    if (manifest.get('status') != 'complete' or manifest.get('schema_version') != 1
            or manifest.get('model_id') != MODEL
            or manifest.get('model_revision') != '1110a243fdf4706b3f48f1d95db1a4f5529b4d41'):
        raise ValueError('Reusable index does not contain the verified embedding model revision')
    files = {k:v for k,v in manifest['file_sha256'].items() if k.startswith('model/')}
    if not {'model/config.json','model/modules.json','model/model.safetensors'}.issubset(files):
        raise ValueError('Reusable model manifest is incomplete')
    actual = {p.relative_to(source_index).as_posix() for p in (source_index/'model').rglob('*')
              if p.is_file() and '.cache' not in p.relative_to(source_index/'model').parts}
    if actual != set(files):
        raise ValueError('Reusable model file coverage differs')
    # Verify every model file before copying any of them.
    for relative, expected in files.items():
        path = source_index/relative
        if not path.resolve().is_relative_to(source_index.resolve()) or digest(path) != expected:
            raise ValueError('Reusable model hash/path mismatch: ' + relative)
    for relative in sorted(files):
        target = destination/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_index/relative, target)
    return manifest['model_revision'], digest(source_index/'manifest.json')


def build(graph_path, directory, reuse_model_index=None):
    import numpy as np
    import faiss
    import torch
    from huggingface_hub import HfApi, snapshot_download
    from sentence_transformers import SentenceTransformer

    graph = json.loads(graph_path.read_text(encoding='utf-8'))
    documents = corpus(graph)
    if not documents:
        raise ValueError('No CVE documents')
    directory.mkdir(parents=True, exist_ok=False)
    # A failed partial directory deliberately has no complete manifest. Retrying
    # uses a new directory, never silently overwrites earlier artifacts.
    reused_manifest = None
    if reuse_model_index is not None:
        revision, reused_manifest = reuse_model(reuse_model_index, directory)
        print('Reusing verified local embedding model revision: ' + revision, flush=True)
    else:
        revision = HfApi().model_info(MODEL).sha
        if not revision:
            raise ValueError('Could not resolve a model revision')
        print('Downloading pinned embedding model revision: ' + revision, flush=True)
        snapshot_download(repo_id=MODEL, revision=revision, local_dir=str(directory/'model'),
            allow_patterns=['*.json', '*.txt', '*.safetensors'],
            ignore_patterns=['onnx/*', 'openvino/*'], token=False)
    torch.manual_seed(1337); torch.set_num_threads(1)
    model = SentenceTransformer(str(directory/'model'), device='cpu', local_files_only=True,
                                trust_remote_code=False)
    if any(model.prompts.values()):
        raise ValueError('Unexpected model prompts; chunk lengths need explicit prompt handling')
    chunks = make_chunks(documents, model.tokenizer, int(model.max_seq_length))
    if not chunks:
        raise ValueError('No indexable chunks')
    print('Encoding ' + str(len(chunks)) + ' evidence chunks on CPU.', flush=True)
    vectors = normalized_vectors(model.encode([c['text'] for c in chunks], batch_size=16, prompt='',
        convert_to_numpy=True, normalize_embeddings=True, show_progress_bar=True), len(chunks))
    index = faiss.IndexFlatIP(vectors.shape[1]); index.add(vectors)
    faiss.write_index(index, str(directory/'index.faiss'))
    with (directory/'embeddings.npy').open('xb') as handle:
        np.save(handle, vectors, allow_pickle=False)
    write_json(directory/'chunks.json', chunks)
    write_json(directory/'documents.json', documents)
    paths = [directory/'index.faiss', directory/'embeddings.npy', directory/'chunks.json', directory/'documents.json']
    paths += sorted(p for p in (directory/'model').rglob('*') if p.is_file() and '.cache' not in p.relative_to(directory/'model').parts)
    manifest = {'schema_version': 1, 'status': 'complete', 'development_diagnostic_only': True,
        'qa_experiment_run': False, 'graph_kind': graph['graph_kind'],
        'graph_sha256': sha(graph), 'graph_file_sha256': digest(graph_path), 'corpus_sha256': sha(documents),
        'model_id': MODEL, 'model_revision': revision, 'model_reused_from_index_manifest_sha256': reused_manifest,
        'model_download_performed': reuse_model_index is None, 'corpus_embeddings_rebuilt': True, 'device': 'cpu', 'seed': 1337, 'torch_threads': 1, 'embedding_prompt': '',
        'max_seq_length': int(model.max_seq_length), 'chunk_policy': 'Each evidence unit split by tokenizer offsets; original character coverage and fragment token lengths checked; no overlap.',
        'ranking_policy': 'Exact normalized inner-product chunk search; CVE score is max chunk score; stable CVE and chunk-ID tie breaks.',
        'index_type': 'IndexFlatIP', 'normalized_embeddings': True,
        'documents': len(documents), 'chunks': len(chunks), 'dimensions': vectors.shape[1],
        'packages': {p: version(p) for p in ['numpy', 'torch', 'sentence-transformers', 'faiss-cpu', 'huggingface-hub', 'transformers']},
        'builder_sha256': digest(__file__),
        'file_sha256': {p.relative_to(directory).as_posix(): digest(p) for p in paths}}
    write_json(directory/'manifest.json', manifest)
    return {k: manifest[k] for k in ['status', 'documents', 'chunks', 'dimensions', 'model_revision', 'qa_experiment_run']}


def semantic_result(graph_path, directory, question, top_k=5, char_cap=6000):
    import faiss
    import torch
    from sentence_transformers import SentenceTransformer

    if not question.strip() or top_k < 1 or char_cap < 1:
        raise ValueError('Invalid question/top-k/character cap')
    graph = json.loads(graph_path.read_text(encoding='utf-8'))
    manifest = checked_manifest(directory, graph)
    documents = json.loads((directory/'documents.json').read_text(encoding='utf-8'))
    if sha(documents) != manifest['corpus_sha256']:
        raise ValueError('Saved corpus identity mismatch')
    chunks = json.loads((directory/'chunks.json').read_text(encoding='utf-8'))
    torch.manual_seed(manifest['seed']); torch.set_num_threads(manifest['torch_threads'])
    model = SentenceTransformer(str(directory/'model'), device='cpu', local_files_only=True,
                                trust_remote_code=False)
    if int(model.max_seq_length) != manifest['max_seq_length']:
        raise ValueError('Model context length changed')
    token_count = len(model.tokenizer(question, add_special_tokens=True, truncation=False)['input_ids'])
    if token_count > manifest['max_seq_length']:
        raise ValueError('Question exceeds embedding model limit; refusing silent truncation')
    vector = normalized_vectors(model.encode([question], prompt='', convert_to_numpy=True, normalize_embeddings=True), 1)
    index = faiss.read_index(str(directory/'index.faiss'))
    if index.ntotal != len(chunks) or index.d != manifest['dimensions'] or vector.shape[1] != index.d:
        raise ValueError('Index/chunk/model dimensions mismatch')
    # Exact all-chunk search at pilot scale avoids dropping CVEs because several
    # top chunks belong to one record. It uses the persisted FAISS vectors.
    scores, indices = index.search(vector, index.ntotal)
    ranked = rank_chunks(scores[0], indices[0], chunks, top_k)
    result = {'schema_version': 1, 'development_diagnostic_only': True, 'qa_experiment_run': False,
        'generation_performed': False, 'mode': 'text', 'text_backend': 'sentence_transformer_faiss',
        'question': question, 'question_embedding_tokens': token_count,
        'graph_kind': graph['graph_kind'], 'graph_sha256': sha(graph), 'corpus_sha256': manifest['corpus_sha256'],
        'model_id': manifest['model_id'], 'model_revision': manifest['model_revision'],
        'index_manifest_sha256': digest(directory/'manifest.json'), 'query_script_sha256': digest(__file__),
        'query_packages': {p: version(p) for p in manifest['packages']},
        'index_rebuilt': False, 'model_loaded_locally': True, 'top_k': top_k,
        'ranking_policy': manifest['ranking_policy'], 'candidates': ranked,
        'budget': {'unit': 'characters', 'cap': char_cap, 'generator_token_budget_enforced': False},
        **pack(ranked, documents, char_cap)}
    return result


def query(graph_path, directory, question, output, top_k=5, char_cap=6000):
    result = semantic_result(graph_path, directory, question, top_k, char_cap)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, result)
    return {'mode': 'text', 'text_backend': result['text_backend'], 'candidate_cves': [r['cve_id'] for r in result['candidates']],
        'evidence_units': len(result['evidence']), 'context_characters': result['context_characters'],
        'index_rebuilt': False, 'qa_experiment_run': False, 'output': str(output)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    builder = sub.add_parser('build'); search = sub.add_parser('query')
    for p in [builder, search]:
        p.add_argument('--graph', type=Path, required=True)
        p.add_argument('--index-dir', type=Path, required=True)
    builder.add_argument('--reuse-model-index', type=Path)
    search.add_argument('--question', required=True)
    search.add_argument('--output', type=Path, required=True)
    search.add_argument('--top-k', type=int, default=5)
    search.add_argument('--char-cap', type=int, default=6000)
    args = parser.parse_args()
    try:
        result = build(args.graph, args.index_dir, args.reuse_model_index) if args.command == 'build' else query(
            args.graph, args.index_dir, args.question, args.output, args.top_k, args.char_cap)
    except Exception as error:
        parser.exit(1, 'Semantic index stopped (' + type(error).__name__ + '): ' + str(error) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
