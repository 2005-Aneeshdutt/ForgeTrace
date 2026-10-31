import random

import networkx as nx

from forgetrace.reach.reach import search


def test_toy_graph_max_product():
    G = nx.DiGraph()
    G.add_edge("account:a", "group:g", weight=0.7)
    G.add_edge("group:g", "host:h1", weight=0.7)
    G.add_edge("account:a", "host:h2", weight=1.0)
    G.add_edge("host:h2", "account:b", weight=0.5)
    G.add_edge("account:b", "host:h1", weight=1.0)
    best = search(G, {"account:a": {"weight": 1.0}}, 4)
    assert abs(best["host:h1"]["reach"] - 0.5) < 1e-9 and best["host:h1"]["hops"] == 3  # 0.5 > 0.49
    assert best["host:h2"]["hops"] == 1
    assert "host:h1" not in search(G, {"account:a": {"weight": 1.0}}, 1)


def test_removal_is_monotone():
    rnd = random.Random(3)
    for _ in range(30):
        G = nx.gnp_random_graph(12, 0.25, seed=rnd.randint(0, 9999), directed=True)
        G = nx.relabel_nodes(G, {i: f"n{i}" for i in G})
        for u, v in G.edges:
            G[u][v]["weight"] = rnd.choice([0.5, 0.7, 1.0])
        C = {"n0": {"weight": 1.0}}
        before = {k for k, v in search(G, C, 4).items() if v["reach"] >= 0.3}
        H = G.copy()
        H.remove_node(f"n{rnd.randint(1, 11)}")
        after = {k for k, v in search(H, C, 4).items() if v["reach"] >= 0.3}
        assert after <= before


def test_incident_reachability_has_evidence(sample):
    inc = next(i for i in sample["incidents"] if "Exfiltration" in i["tactics"])
    r = inc["inferred"]["reachability"]
    assert r["compromised"] and r["reachable"] and r["mode"] == "observed+configured"
    for a in r["reachable"]:
        assert a["start"] and a["hops"] >= 1 and a["explanation"] and a["path_edges"]
        for e in a["path_edges"]:
            assert e["kind"] in ("observed", "configured", "inferred")
            assert e["evidence"].get("event_ids") or e["evidence"].get("fixture")


def test_containment_simulation(sample):
    from datetime import datetime

    from forgetrace import store
    from forgetrace.reach.reach import simulate
    inc = next(i for i in sample["incidents"] if "Exfiltration" in i["tactics"])
    gid = {}
    for n in inc["observed"]["nodes"]:
        n = dict(n, ts_first=datetime.fromisoformat(n["ts_first"][:-1]), ts_last=datetime.fromisoformat(n["ts_last"][:-1]))
        gid[n["group_id"]] = n
    con = store.connect(sample["out"], read_only=True)
    internal = {"group_ids": inc["group_ids"], "ts_last": datetime.fromisoformat(inc["ts_last"][:-1])}
    best = inc["inferred"]["containment_candidates"][0]
    r = simulate(con, internal, gid, [best["action"]])
    assert r["after_critical_reachable"] <= r["before_critical_reachable"]
    assert r["before_critical_reachable"] == best["before"] and r["after_critical_reachable"] == best["after"]
    assert r["removed_relationships"]
    assert r["disclaimer"] == (
        "Based on observed telemetry and configured asset relationships, this action reduces modelled reachable "
        f"critical assets from {r['before_critical_reachable']} to {r['after_critical_reachable']}. "
        "This is a reachability estimate, not a guarantee of prevention.")
