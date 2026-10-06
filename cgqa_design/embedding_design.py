"""Testable Node2Vec transition kernel; model training remains a planned module."""
import random

def transition_weights(graph,previous,current,p=1.0,q=0.5):
    if p<=0 or q<=0:raise ValueError('p and q must be positive')
    candidates=sorted(graph.neighbors(current))
    weights=[1/p if x==previous else 1.0 if graph.has_edge(previous,x) else 1/q for x in candidates]
    return candidates,weights

def walk(graph,start,length=40,seed=1337,p=1.0,q=0.5):
    rng=random.Random(seed);path=[start]
    while len(path)<length:
        current=path[-1];choices=sorted(graph.neighbors(current))
        if not choices:break
        if len(path)==1:next_node=rng.choice(choices)
        else:
            choices,weights=transition_weights(graph,path[-2],current,p,q)
            next_node=rng.choices(choices,weights=weights,k=1)[0]
        path.append(next_node)
    return path
