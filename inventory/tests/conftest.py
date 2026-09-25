import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import pytest  # noqa: E402

from pqcinv import classify, probe  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


def assess_fixture(name, targets=None):
    """Parse a recorded probe run and assess every endpoint in it."""
    _, results = probe.parse_output(load(name))
    by = {}
    for r in results:
        by.setdefault((r.host, r.port), {})[r.profile] = r
    targets = targets or [probe.Target(h, p, "lab") for (h, p) in by]
    return {t.endpoint: classify.assess_endpoint(t, by.get((t.host, t.port), {})) for t in targets}


@pytest.fixture
def lab():
    return assess_fixture("lab-local.txt")
