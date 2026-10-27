# MedMesh — A Decentralized P2P Framework for Secure Inter-Hospital Medical Data Exchange

BCSE308P Computer Networks Lab project. Hospitals exchange patient records **directly, peer-to-peer**,
with no central server that stores or relays medical data.

## What it does
| Feature | How |
|---|---|
| **No central server** | Every hospital runs a node (HTTP server + client). Records live only on the owning node. |
| **Peer discovery (gossip)** | A node needs just one bootstrap peer; peers exchange peer lists + certificates, so the full mesh forms automatically. |
| **Trusted membership** | A consortium CA signs each hospital's certificate (Ed25519). Nodes reject anyone without a valid cert. |
| **Authentic, replay-safe messages** | Every P2P message is a signed envelope (cert + timestamp + nonce). Tampered, stale, or replayed messages are refused. |
| **Privacy-preserving lookup** | "Who holds patient X?" is asked using a salted hash of the ID; no data moves. |
| **Consent-based exchange** | Holder's doctor must explicitly *Approve* each request. |
| **End-to-end encryption** | Approved record is sealed with the requester's X25519 key (HKDF-SHA256 + AES-256-GCM); integrity hash verified on receipt. |
| **Tamper-evident audit trail** | Each hospital keeps a signed hash-chain of events; all peers replicate every chain. "Verify" detects edits; "heal" restores from peers. Only pseudonymous patient hashes are logged. |

## Requirements
- Python 3.10+ (tested 3.14), `pip install -r requirements.txt` (only `cryptography`, ~4 MB). No other dependencies; the dashboard is plain HTML/JS.

## Run
```bash
pip install -r requirements.txt
python3 run_network.py            # creates keys on first run, starts 4 hospitals
```
Open the dashboards:
- Chennai General Hospital — http://127.0.0.1:5001
- Vellore Medical Centre — http://127.0.0.1:5002
- Bengaluru Heart Institute — http://127.0.0.1:5003
- Delhi Central Hospital — http://127.0.0.1:5004

Run one node per machine instead: `python3 run_network.py --node vellore --port 5002 --bootstrap http://<other-host>:5001`
(copy `data/consortium.json` and that hospital's `*.identity.json` to the machine).

## Demo walkthrough (expected results)
1. Open Vellore (5002). *Consortium peers* shows 3 peers **online** (discovered via gossip from a single bootstrap).
2. In *Find & request*, search `P-1001` → "Chennai General Hospital holds P-1001". Choose **Emergency** → *Request record*.
3. Open Chennai (5001) → *Incoming requests* shows the request → **Approve & send encrypted**.
4. Back on Vellore: *My requests* shows the decrypted record (Arjun Menon, T2DM, penicillin allergy).
5. The *Audit ledger* on every node lists REQUEST_SENT → REQUEST_RECEIVED → ACCESS_GRANTED → RECORD_RECEIVED.
6. Click **Demo: tamper** then **Verify chains** → one hospital's chain turns red (TAMPERED); **Verify & heal** restores it from peers.
7. Rogue node: a node holding a cert from a different CA gets HTTP 403 and shows under *Security events* (see `tests`).

Screenshots: `screenshots/`. Test log: `docs/test_results.txt`.

## Tests
```bash
python3 -m unittest discover -s tests -t . -v
```
10 tests: crypto (seal/open, envelope forgery/replay), ledger tamper detection, 3-node network (gossip
discovery, hashed lookup, approve→encrypted delivery, deny, replication+heal, rogue node, replay).

## Layout
```
hospital_p2p/   crypto.py ledger.py node.py seed.py dashboard.html
run_network.py  setup_consortium.py  tests/  simulation/ (Packet Tracer topology + configs)  docs/  screenshots/
```
## Security notes / limits (honest scope)
- Dashboard API binds to 127.0.0.1 and has no login (a real system needs clinician auth/RBAC).
- Transport is plain HTTP; confidentiality of records relies on the application-layer sealed box (a production deployment would add mutual TLS).
- Data is synthetic and held in memory; a restart resets records/ledger. Persistence is future work.
- `data/` contains demo private keys; never commit real keys.