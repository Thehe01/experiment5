"""CPU relational encoders, common decoder/loss and fail-closed checkpoints."""
import collections
import copy
import importlib.metadata
import os
import platform
import random
from pathlib import Path
import torch
from torch import nn
from torch.nn import functional as F
from chapter5.core import RELATIONS, TYPES, ENDPOINTS, digest, filtered_rank, summarize_ranks, training_edges
from chapter5.io import atomic_json, append_event, read_json, sha_file

ABLATIONS = {'distmult': (), 'rgcn': (), 'rgcn_without_product': ('affects',),
             'rgcn_without_cwe': ('instantiates',), 'rgcn_without_tactic_phase': ('implies', 'belongs_to_phase')}


def code_binding():
    root = Path(__file__).parent
    return {p.name: sha_file(p) for p in sorted(root.glob('*.py')) if not p.name.startswith('test_')}


class Graph:
    def __init__(self, graph, remove=()):
        self.graph = graph
        ordered = sorted(graph['nodes'], key=lambda n: n['id'])
        self.names = [n['id'] for n in ordered]
        if len(set(self.names)) != len(self.names):
            raise ValueError('duplicate graph node')
        self.ids = {n: i for i, n in enumerate(self.names)}
        self.node_types = [TYPES.index(n['type']) for n in ordered]
        self.pools = {t: torch.tensor([i for i, v in enumerate(self.node_types) if v == t], dtype=torch.long) for t in range(len(TYPES))}
        self.known = set()
        for e in graph['edges']:
            r = RELATIONS.index(e['relation'])
            h, t = self.ids[e['head']], self.ids[e['tail']]
            a, b = ENDPOINTS[e['relation']]
            if (self.node_types[h], self.node_types[t]) != (a, b):
                raise ValueError('edge endpoint type mismatch: '+str(e))
            self.known.add((h, r, t))
        edges = training_edges(graph['edges'], graph['split'], remove)
        triples = sorted({(self.ids[e['head']], RELATIONS.index(e['relation']), self.ids[e['tail']]) for e in edges})
        if not any(r == 2 for h, r, t in triples):
            raise ValueError('no training target edges')
        self.positive = torch.tensor(triples, dtype=torch.long)
        self.by_relation = {r: self.positive[self.positive[:, 1] == r] for r in range(len(RELATIONS))}
        self.message_edges = [(h, t, r) for h, r, t in triples] + [(t, h, r+len(RELATIONS)) for h, r, t in triples]
        self.adjacency = []
        for r in range(2*len(RELATIONS)):
            pairs = [(s, d) for s, d, k in self.message_edges if k == r]
            src = torch.tensor([s for s, d in pairs], dtype=torch.long)
            dst = torch.tensor([d for s, d in pairs], dtype=torch.long)
            degree = torch.bincount(dst, minlength=len(self.names)).clamp_min(1)
            scale = (1./degree[dst].float()).unsqueeze(1)
            self.adjacency.append((src, dst, scale))
        self.candidate_names = sorted(graph['techniques'])
        if len(set(self.candidate_names)) != len(self.candidate_names):
            raise ValueError('duplicate technique candidates')
        self.candidates = torch.tensor([self.ids[t] for t in self.candidate_names], dtype=torch.long)
        if any(self.node_types[i] != 3 for i in self.candidates):
            raise ValueError('non-technique target candidate')
        self.truth = collections.defaultdict(set)
        for e in graph.get('evaluation_targets', graph['edges']):
            if e['relation'] == 'exploited_by':
                if e['tail'] not in self.candidate_names:
                    raise ValueError('positive outside frozen candidate domain')
                self.truth[e['head']].add(e['tail'])
                self.known.add((self.ids[e['head']], 2, self.ids[e['tail']]))

    def negative_samples(self, count):
        out = []
        for h, r, t in self.positive.tolist():
            a, b = ENDPOINTS[RELATIONS[r]]
            for _ in range(count):
                for attempt in range(100):
                    # Target heads stay in Train. Only auxiliary relations corrupt either endpoint.
                    corrupt_head = r != 2 and bool(torch.randint(2, ()).item())
                    pool = self.pools[a if corrupt_head else b]
                    value = pool[torch.randint(len(pool), ())].item()
                    negative = (value, r, t) if corrupt_head else (h, r, value)
                    if negative not in self.known:
                        out.append(negative)
                        break
                else:
                    legal = [(h, r, int(x)) for x in self.pools[b] if (h, r, int(x)) not in self.known]
                    if r != 2:
                        legal += [(int(x), r, t) for x in self.pools[a] if (int(x), r, t) not in self.known]
                    if not legal:
                        raise ValueError('relation has no legal typed negative for positive '+str((h, r, t)))
                    out.append(legal[torch.randint(len(legal), ())])
        return torch.tensor(out, dtype=torch.long)


class RGCNLayer(nn.Module):
    def __init__(self, dimension, bases):
        super().__init__()
        self.bases = nn.Parameter(torch.empty(bases, dimension, dimension))
        self.coefficients = nn.Parameter(torch.empty(2*len(RELATIONS), bases))
        self.self_weight = nn.Parameter(torch.empty(dimension, dimension))
        nn.init.xavier_uniform_(self.bases)
        nn.init.xavier_uniform_(self.coefficients)
        nn.init.xavier_uniform_(self.self_weight)

    def forward(self, x, adjacency):
        weights = torch.einsum('rb,bij->rij', self.coefficients, self.bases)
        output = x @ self.self_weight
        for r, (src, dst, scale) in enumerate(adjacency):
            if len(src):
                output.index_add_(0, dst, (x[src] @ weights[r]) * scale)
        return output


class Predictor(nn.Module):
    def __init__(self, graph, arm, params, cfg):
        super().__init__()
        d = params['dimension']
        self.entity = nn.Embedding(len(graph.names), d)
        self.types = nn.Embedding(len(TYPES), d)
        self.relation = nn.Embedding(len(RELATIONS), d)
        self.register_buffer('type_ids', torch.tensor(graph.node_types, dtype=torch.long))
        self.layers = nn.ModuleList([RGCNLayer(d, cfg['bases']) for _ in range(cfg['layers'])] if arm != 'distmult' else [])
        self.dropout = params['dropout']
        for embedding in (self.entity, self.types, self.relation):
            nn.init.xavier_uniform_(embedding.weight)

    def encode(self, graph):
        x = self.entity.weight + self.types(self.type_ids)
        for layer in self.layers:
            x = F.dropout(F.relu(layer(x, graph.adjacency)), self.dropout, self.training)
        if not self.layers:
            x = F.dropout(x, self.dropout, self.training)
        return x

    def score(self, embeddings, triples):
        return (embeddings[triples[:, 0]] * self.relation(triples[:, 1]) * embeddings[triples[:, 2]]).sum(1)

    def objective(self, graph, cfg):
        embeddings = self.encode(graph)
        negatives = graph.negative_samples(cfg['negatives_per_positive'])
        loss = embeddings.sum()*0
        parts = {}
        for r in range(len(RELATIONS)):
            positives = graph.by_relation[r]
            if not len(positives):
                continue
            neg = negatives[negatives[:, 1] == r]
            value = .5*(F.softplus(-self.score(embeddings, positives)).mean()+F.softplus(self.score(embeddings, neg)).mean())
            parts[RELATIONS[r]] = float(value.detach())
            loss = loss + value*(1. if r == 2 else cfg['auxiliary_weight']/4.)
        return loss, parts


def scores_by_head(model, graph, heads):
    model.eval()
    with torch.no_grad():
        embeddings = model.encode(graph)
        tails = embeddings[graph.candidates]
        relation = model.relation.weight[2]
        values = (embeddings[torch.tensor([graph.ids[h] for h in heads])] * relation) @ tails.T
    if not torch.isfinite(values).all():
        raise ValueError('nonfinite ranking scores')
    return {h: dict(zip(graph.candidate_names, row.tolist())) for h, row in zip(heads, values)}


def evaluate(model, graph, role):
    heads = graph.graph['split'][role]
    scores = scores_by_head(model, graph, heads)
    rows = [{'head': h, 'tail': t, 'rank': filtered_rank(scores[h], graph.truth[h], t)}
            for h in heads for t in sorted(graph.truth[h])]
    return summarize_ranks(rows), rows


def binding(graph, arm, params, cfg, seed):
    dependencies = {p: importlib.metadata.version(p) for p in ('torch','sympy','mpmath','filelock','typing_extensions','networkx','Jinja2','fsspec','MarkupSafe')}
    return digest({'graph': graph, 'arm': arm, 'params': params, 'config': cfg, 'seed': seed,
                   'code': code_binding(), 'python': platform.python_version(), 'torch': torch.__version__,
                   'dependencies': dependencies, 'torch_build': digest(torch.__config__.show())})


def save_checkpoint(path, state):
    temp = path.with_name(path.name+'.tmp')
    with temp.open('wb') as stream:
        torch.save(state, stream); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, path)
    atomic_json(path.with_name(path.name+'.receipt.json'), {'sha256': sha_file(path), 'binding': state['binding'], 'epoch': state['epoch']})


def load_state(path, signature):
    receipt = read_json(path.with_name(path.name+'.receipt.json'))
    if receipt['sha256'] != sha_file(path) or receipt['binding'] != signature:
        raise ValueError('checkpoint byte/binding mismatch')
    state = torch.load(path, map_location='cpu', weights_only=False)
    if state.get('binding') != signature:
        raise ValueError('checkpoint input/code/runtime binding mismatch')
    required = ('model','best_model','optimizer','epoch','patience_count','python_rng','torch_rng','best_dev','best_score')
    if any(k not in state for k in required):
        raise ValueError('incomplete checkpoint')
    return state


def train(graph, arm, params, cfg, seed, directory, stop_after_epochs=None):
    if arm not in ABLATIONS:
        raise ValueError('unknown experimental arm')
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    signature = binding(graph, arm, params, cfg, seed)
    checkpoint, final = directory/'checkpoint.pt', directory/'result.json'
    torch.set_num_threads(cfg['threads']); torch.use_deterministic_algorithms(True)
    random.seed(seed); torch.manual_seed(seed)
    g = Graph(graph, ABLATIONS[arm])
    net = Predictor(g, arm, params, cfg)
    optimizer = torch.optim.Adam(net.parameters(), lr=params['learning_rate'], weight_decay=cfg['weight_decay'])
    if checkpoint.exists():
        state = load_state(checkpoint, signature)
        net.load_state_dict(state['model']); optimizer.load_state_dict(state['optimizer'])
        random.setstate(state['python_rng']); torch.set_rng_state(state['torch_rng'])
    else:
        if final.exists() or (directory/'epochs.jsonl').exists():
            raise ValueError('training state missing checkpoint; refuse to reset budget')
        state = {'binding': signature, 'epoch': 0, 'patience_count': 0, 'best_score': -1., 'best_model': None, 'best_dev': None}
        state.update(model=net.state_dict(), optimizer=optimizer.state_dict(), python_rng=random.getstate(), torch_rng=torch.get_rng_state())
        save_checkpoint(checkpoint, state)
    if final.exists():
        result = read_json(final)
        if result['binding'] != signature or result['epoch'] != state['epoch']:
            raise ValueError('completed result binding mismatch')
        return result
    while state['epoch'] < cfg['max_epochs'] and state['patience_count'] < cfg['patience']:
        net.train(); optimizer.zero_grad(set_to_none=True)
        loss, parts = net.objective(g, cfg)
        if not torch.isfinite(loss):
            raise ValueError('nonfinite training loss')
        loss.backward(); optimizer.step()
        state['epoch'] += 1
        metrics, _ = evaluate(net, g, 'dev')
        if metrics['mrr'] > state['best_score'] + cfg['min_improvement']:
            state['best_score'] = metrics['mrr']; state['best_dev'] = metrics
            state['best_model'] = copy.deepcopy(net.state_dict()); state['patience_count'] = 0
            state['best_epoch'] = state['epoch']
        else:
            state['patience_count'] += 1
        state.update(model=net.state_dict(), optimizer=optimizer.state_dict(), python_rng=random.getstate(), torch_rng=torch.get_rng_state())
        save_checkpoint(checkpoint, state)
        append_event(directory/'epochs.jsonl', {'epoch': state['epoch'], 'loss': float(loss.detach()), 'components': parts,
                                             'dev_mrr': metrics['mrr'], 'best_dev_mrr': state['best_score'], 'patience': state['patience_count']})
        if stop_after_epochs is not None and state['epoch'] >= stop_after_epochs:
            return {'status': 'checkpointed', 'epoch': state['epoch'], 'binding': signature}
    result = {'status': 'trained', 'arm': arm, 'seed': seed, 'params': params, 'binding': signature,
              'epoch': state['epoch'], 'best_epoch': state['best_epoch'], 'dev': state['best_dev'],
              'stopping_reason': 'patience' if state['patience_count'] >= cfg['patience'] else 'max_epochs'}
    atomic_json(final, result)
    return result


def restore_best(graph, arm, params, cfg, seed, directory):
    signature = binding(graph, arm, params, cfg, seed)
    g = Graph(graph, ABLATIONS[arm])
    net = Predictor(g, arm, params, cfg)
    state = load_state(Path(directory)/'checkpoint.pt', signature)
    if not (Path(directory)/'result.json').exists():
        raise ValueError('cannot evaluate Test from unfinished training')
    net.load_state_dict(state['best_model'])
    return net, g
