"""Start one process-per-hospital P2P network on localhost (ports 5001-5004).

Usage:  python3 run_network.py            # all four hospitals in one command
        python3 run_network.py --node chennai --port 5001 [--bootstrap http://127.0.0.1:5002]
"""
import argparse
import json
import threading
import time
from pathlib import Path

from hospital_p2p.node import Node
from hospital_p2p.seed import HOSPITALS, PATIENTS
from setup_consortium import provision

DATA = Path("data")
PORTS = {slug: 5001 + i for i, slug in enumerate(HOSPITALS)}


def make_node(slug, port, bootstrap):
    ident = json.loads((DATA / f"{slug}.identity.json").read_text())
    ca_pub = json.loads((DATA / "consortium.json").read_text())["ca_pub"]
    return Node(ident, ca_pub, port, PATIENTS[slug], bootstrap=bootstrap).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", choices=list(HOSPITALS))
    ap.add_argument("--port", type=int)
    ap.add_argument("--bootstrap", nargs="*", default=[])
    a = ap.parse_args()
    if not (DATA / "consortium.json").exists():
        provision(DATA)
    if a.node:
        nodes = [make_node(a.node, a.port or PORTS[a.node], a.bootstrap)]
    else:
        # ring bootstrap: each hospital only knows ONE neighbour; gossip does the rest
        slugs = list(HOSPITALS)
        nodes = [make_node(s, PORTS[s], [f"http://127.0.0.1:{PORTS[slugs[(i + 1) % len(slugs)]]}"])
                 for i, s in enumerate(slugs)]
    for n in nodes:
        print(f"  {n.id.name:28s} dashboard -> {n.url}")
    print("Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
