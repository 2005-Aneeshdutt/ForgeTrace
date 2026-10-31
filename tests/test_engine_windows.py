"""The linear-time threshold windows, follower match and duplicate marking return exactly what the
Phase 1 quadratic code returned (reference copies below, verbatim logic from commit e6d64a3)."""
from __future__ import annotations

from datetime import datetime, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from forgetrace.rules.engine import _duplicates, first_follower, merge_windows

T0 = datetime(2026, 10, 1)


# ----------------------------------------------------------------------------- Phase 1 reference
def ref_windows(evs, n, W):
    cur, windows = None, []
    for i, (ts, eid, cnt) in enumerate(evs):
        if cnt >= n:
            lo = ts.timestamp() - W
            mem = [(t, e) for t, e, _ in evs[: i + 1] if t.timestamp() >= lo]
            if cur and mem[0][0].timestamp() <= cur[-1][0].timestamp() + W:
                cur.extend(m for m in mem if m not in cur)
            else:
                if cur:
                    windows.append(cur)
                cur = list(mem)
    if cur:
        windows.append(cur)
    for w in windows:
        w.sort()
    return windows


def ref_follower(win, followers, n, lim, wlink):
    members = [e for _, e in win]
    for t, e, flink in followers:
        if e in members:
            continue
        pre = [(wt, we) for wt, we in win if 0 <= t.timestamp() - wt.timestamp() <= lim
               and (wlink is None or wlink[we] == flink)]
        if len(pre) >= n:
            return (t, e), pre
    return None, []


def ref_duplicates(rows):
    by_tech = {}
    for r in rows:
        r["duplicate_of"] = None
        by_tech.setdefault(r["technique_id"], []).append(r)
    for group in by_tech.values():
        for r in group:
            ms = set(r["member_event_ids"])
            for o in group:
                if o is r:
                    continue
                stronger = (o["severity"], -o["label_priority"], o["detection_id"]) > \
                           (r["severity"], -r["label_priority"], r["detection_id"])
                if stronger and ms <= set(o["member_event_ids"]):
                    r["duplicate_of"] = o["detection_id"]
                    break


# ----------------------------------------------------------------------------- generators
def _events(offsets, W):
    """Sorted (ts, eid, win_count) like the SQL: count of events in [ts - W, ts]."""
    offs = sorted(offsets)
    ts = [T0 + timedelta(seconds=o) for o in offs]
    out = []
    for i, t in enumerate(ts):
        cnt = sum(1 for u in ts[: i + 1] if u.timestamp() >= t.timestamp() - W)
        out.append((t, 1000 + i, cnt))
    return out


@settings(max_examples=400, deadline=None)
@given(st.lists(st.integers(0, 4000), max_size=60), st.integers(1, 6), st.sampled_from([30, 300, 600, 1800]))
def test_windows_match_phase1(offsets, n, W):
    evs = _events(offsets, W)
    assert merge_windows(evs, n, W) == ref_windows(evs, n, W)


@settings(max_examples=300, deadline=None)
@given(st.lists(st.integers(0, 3000), min_size=1, max_size=40), st.lists(st.integers(0, 4000), max_size=15),
       st.integers(1, 5), st.sampled_from([60, 600, 1800]), st.booleans(), st.integers(0, 2))
def test_followers_match_phase1(win_offs, fol_offs, n, lim, use_link, seed):
    win = [(T0 + timedelta(seconds=o), 1000 + i) for i, o in enumerate(sorted(win_offs))]
    fol = [(T0 + timedelta(seconds=o), 5000 + i, (f"p{(i + seed) % 2}",)) for i, o in enumerate(sorted(fol_offs))]
    if fol and win:
        fol.insert(0, (win[0][0], win[0][1], ("p0",)))  # a follower that is itself a member is skipped
    wlink = {e: (f"p{(e + seed) % 2}",) for _, e in win} if use_link else None
    assert first_follower(win, fol, n, lim, wlink) == ref_follower(win, fol, n, lim, wlink)


@settings(max_examples=300, deadline=None)
@given(st.lists(st.tuples(st.sampled_from(["T1", "T2"]), st.integers(1, 4), st.integers(10, 40),
                          st.sets(st.integers(0, 12), min_size=1, max_size=6)), max_size=25))
def test_duplicates_match_phase1(specs):
    def rows():
        return [{"detection_id": f"R{i:02d}", "technique_id": t, "severity": sev, "label_priority": lp,
                 "member_event_ids": sorted(m)} for i, (t, sev, lp, m) in enumerate(specs)]
    a, b = rows(), rows()
    _duplicates(a)
    ref_duplicates(b)
    assert [r["duplicate_of"] for r in a] == [r["duplicate_of"] for r in b]


def test_dense_key_is_linear():
    """A user launching Office every 20 s for 10 days (43k events, one merged window) stays fast."""
    import time
    evs = [(T0 + timedelta(seconds=20 * i), i, 1) for i in range(43_200)]
    t = time.perf_counter()
    w = merge_windows(evs, 1, 600)
    assert len(w) == 1 and len(w[0]) == 43_200 and time.perf_counter() - t < 1.0
