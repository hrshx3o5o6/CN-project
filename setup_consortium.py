"""One-time setup: create the consortium CA and enrol the hospitals (keys + certificates)."""
import json
import sys
from pathlib import Path

from hospital_p2p.crypto import issue_identity, new_ca
from hospital_p2p.seed import HOSPITALS


def provision(out: Path, hospitals=HOSPITALS) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    ca = new_ca()
    (out / "consortium.json").write_text(json.dumps({"ca_pub": ca["ca_pub"]}, indent=2))
    (out / "ca_private.json").write_text(json.dumps(ca))  # held by consortium admin only
    for slug, name in hospitals.items():
        (out / f"{slug}.identity.json").write_text(json.dumps(issue_identity(ca["ca_priv"], name), indent=2))
    return ca


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "data")
    provision(target)
    print(f"Consortium CA + {len(HOSPITALS)} hospital identities written to {target}/")
