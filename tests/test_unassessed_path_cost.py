import networkx as nx
from attack_path import _path_record

def test_unknown_intermediate_uses_placeholder_but_terminal_is_not_charged():
    graph=nx.DiGraph()
    graph.add_node('known',risk_score=5,top_cve_id='CVE-2020-1234')
    graph.add_node('unknown',risk_score=0,top_cve_id=None)
    graph.add_node('target',risk_score=7,top_cve_id='CVE-2020-5678')
    graph.add_edge('known','unknown',weight=.2)
    graph.add_edge('unknown','target',weight=100)
    route=_path_record(graph,'known','target',['known','unknown','target'],100.2)
    assert route['cost']==100.2 and route['cost_placeholder_sources']==['unknown']
    terminal=_path_record(graph,'known','unknown',['known','unknown'],.2)
    assert terminal['cost']==.2 and terminal['cost_placeholder_sources']==[]
    assert terminal['unassessed_nodes']==['unknown']
