"""A hospital node: HTTP server + peer-to-peer protocol + dashboard backend."""
import json
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .crypto import (CryptoError, Identity, canon, make_envelope, pid_hash, seal, sha256_hex,
                     verify_envelope)
from .ledger import Ledger

DASHBOARD = Path(__file__).with_name("dashboard.html")


class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


class Node:
    def __init__(self, identity: dict, ca_pub: str, port: int, patients: list,
                 bootstrap=(), host="127.0.0.1", sync_interval=2.0):
        self.id = Identity(identity)
        self.ca_pub, self.port, self.host = ca_pub, port, host
        self.url = f"http://{host}:{port}"
        self.patients = {p["patient_id"]: p for p in patients}
        self.urls = set(bootstrap) - {self.url}
        self.peers: dict[str, dict] = {}        # node_id -> {url, cert, online, last_seen}
        self.incoming: dict[str, dict] = {}     # requests other hospitals made to us
        self.outgoing: dict[str, dict] = {}     # requests we made (+ received records)
        self.security: list = []                # rejected envelopes etc.
        self.nonces: dict = {}
        self.ledger = Ledger()
        self.lock = threading.RLock()
        self.sync_interval = sync_interval
        self._stop = threading.Event()
        self.httpd = None
        self.ledger.append(self.id, "NODE_JOINED", {"hospital": self.id.name, "records": len(self.patients)})

    # ------------------------------------------------------------ lifecycle
    def start(self):
        node = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def _send(self, code, body, ctype="application/json"):
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                if self.path in ("/", "/index.html"):
                    return self._send(200, DASHBOARD.read_bytes(), "text/html; charset=utf-8")
                if self.path == "/api/ui/state":
                    return self._send(200, node.state())
                self._send(404, {"error": "not found"})

            def do_POST(self):
                try:
                    body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                    if self.path.startswith("/api/peer/"):
                        out = node.handle_peer(self.path[len("/api/peer/"):], body)
                    elif self.path.startswith("/api/ui/"):
                        out = node.handle_ui(self.path[len("/api/ui/"):], body)
                    else:
                        raise ApiError("not found", 404)
                    self._send(200, out)
                except ApiError as e:
                    self._send(e.code, {"error": str(e)})
                except Exception as e:  # keep server alive
                    self._send(500, {"error": f"{type(e).__name__}: {e}"})

        self.httpd = ThreadingHTTPServer((self.host, self.port), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://{self.host}:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        threading.Thread(target=self._sync_loop, daemon=True).start()
        return self

    def stop(self):
        self._stop.set()
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()

    # ------------------------------------------------------------ outbound
    def _post(self, url, route, payload, timeout=4):
        env = make_envelope(self.id, payload)
        req = urllib.request.Request(f"{url}/api/peer/{route}", canon(env), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read())
        cert = verify_envelope(resp, self.ca_pub, self.nonces)
        return cert, resp["payload"]

    def _hello_payload(self):
        with self.lock:
            certs = [p["cert"] for p in self.peers.values()] + [self.id.cert]
            return {"url": self.url, "urls": sorted(self.urls | {self.url}),
                    "certs": certs, "heads": self.ledger.heads()}

    def _sync_loop(self):
        while not self._stop.wait(self.sync_interval):
            for url in list(self.urls):
                try:
                    self.sync_with(url)
                except Exception:
                    with self.lock:
                        for p in self.peers.values():
                            if p["url"] == url:
                                p["online"] = False

    def sync_with(self, url):
        cert, resp = self._post(url, "hello", self._hello_payload())
        self._learn(cert, resp, url)
        self._pull(cert, url, resp.get("heads", {}))

    def _learn(self, cert, payload, url):
        with self.lock:
            if cert["node_id"] != self.id.node_id:
                self.peers[cert["node_id"]] = {"url": url, "cert": cert, "online": True, "last_seen": time.time()}
            for u in payload.get("urls", []):
                if u != self.url:
                    self.urls.add(u)
            for c in payload.get("certs", []):  # only CA-issued certs are kept
                from .crypto import verify_cert
                if verify_cert(self.ca_pub, c) and c["node_id"] != self.id.node_id and c["node_id"] not in self.peers:
                    self.peers[c["node_id"]] = {"url": None, "cert": c, "online": False, "last_seen": 0}

    def _pub_of(self, node_id):
        if node_id == self.id.node_id:
            return self.id.cert["sign_pub"]
        p = self.peers.get(node_id)
        return p["cert"]["sign_pub"] if p else None

    def _pull(self, cert, url, remote_heads):
        mine = self.ledger.heads()
        for author, n in remote_heads.items():
            pub = self._pub_of(author)
            if author == self.id.node_id or not pub or n <= mine.get(author, 0):
                continue
            _, r = self._post(url, "ledger", {"author": author, "start": mine.get(author, 0)})
            name = self.peers.get(author, {}).get("cert", {}).get("name", "")
            self.ledger.accept(author, r["blocks"], pub, name)

    # ------------------------------------------------------------ inbound (peer protocol)
    def handle_peer(self, route, env):
        try:
            with self.lock:
                cert = verify_envelope(env, self.ca_pub, self.nonces)
        except CryptoError as e:
            with self.lock:
                self.security.append({"ts": time.time(), "event": "REJECTED_PEER_MESSAGE", "detail": str(e),
                                      "claimed": (env.get("cert") or {}).get("name", "unknown") if isinstance(env, dict) else "?"})
            raise ApiError(f"rejected: {e}", 403)
        fn = getattr(self, "_peer_" + route, None)
        if not fn:
            raise ApiError("unknown route", 404)
        out = fn(cert, env["payload"])
        return make_envelope(self.id, out)

    def _peer_hello(self, cert, p):
        self._learn(cert, p, p.get("url") or "")
        if p.get("url"):
            self.urls.add(p["url"])
        return self._hello_payload()

    def _peer_ledger(self, cert, p):
        return {"blocks": self.ledger.blocks(p["author"], int(p.get("start", 0)))}

    def _peer_locate(self, cert, p):
        mine = {pid_hash(pid) for pid in self.patients}
        return {"holds": p["pid_hash"] in mine}

    def _peer_request(self, cert, p):
        pid = next((i for i in self.patients if pid_hash(i) == p["pid_hash"]), None)
        if not pid:
            return {"ok": False, "error": "no such record"}
        with self.lock:
            self.incoming[p["req_id"]] = {"req_id": p["req_id"], "patient_id": pid, "purpose": p["purpose"],
                                          "from_id": cert["node_id"], "from_name": cert["name"],
                                          "from_cert": cert, "ts": time.time(), "status": "pending"}
        self.ledger.append(self.id, "REQUEST_RECEIVED", {"req": p["req_id"], "patient": p["pid_hash"],
                                                          "from": cert["name"], "purpose": p["purpose"]})
        return {"ok": True}

    def _peer_denied(self, cert, p):
        with self.lock:
            r = self.outgoing.get(p["req_id"])
            if r and r["to_id"] == cert["node_id"]:
                r["status"] = "denied"
        return {"ok": True}

    def _peer_deliver(self, cert, p):
        with self.lock:
            r = self.outgoing.get(p["req_id"])
            if not r or r["to_id"] != cert["node_id"] or r["status"] != "sent":
                raise ApiError("unexpected delivery", 403)
        raw = self.id.open(p["box"], p["req_id"].encode())  # raises CryptoError if tampered/misaddressed
        if sha256_hex(raw) != p["record_hash"]:
            raise ApiError("record hash mismatch", 400)
        with self.lock:
            r["record"], r["status"] = json.loads(raw), "received"
        self.ledger.append(self.id, "RECORD_RECEIVED", {"req": p["req_id"], "patient": r["pid_hash"],
                                                         "from": cert["name"], "sha256": p["record_hash"][:16]})
        return {"ok": True}

    # ------------------------------------------------------------ dashboard (local UI) API
    def handle_ui(self, route, b):
        fn = getattr(self, "_ui_" + route, None)
        if not fn:
            raise ApiError("unknown route", 404)
        return fn(b)

    def _online_peers(self):
        with self.lock:
            return [(i, p) for i, p in self.peers.items() if p["url"] and p["online"]]

    def _ui_connect(self, b):
        url = b["url"].rstrip("/")
        self.sync_with(url)
        self.urls.add(url)
        return {"ok": True}

    def _ui_locate(self, b):
        h, found = pid_hash(b["patient_id"].strip()), []
        for nid, p in self._online_peers():
            try:
                _, r = self._post(p["url"], "locate", {"pid_hash": h})
                if r["holds"]:
                    found.append({"node_id": nid, "name": p["cert"]["name"]})
            except Exception:
                pass
        return {"patient_id": b["patient_id"], "holders": found}

    def _ui_request(self, b):
        with self.lock:
            peer = self.peers.get(b["node_id"])
        if not peer or not peer["url"]:
            raise ApiError("unknown peer")
        rid, h = uuid.uuid4().hex[:10], pid_hash(b["patient_id"])
        _, r = self._post(peer["url"], "request", {"req_id": rid, "pid_hash": h, "purpose": b.get("purpose", "Treatment")})
        if not r.get("ok"):
            raise ApiError(r.get("error", "request failed"))
        with self.lock:
            self.outgoing[rid] = {"req_id": rid, "patient_id": b["patient_id"], "pid_hash": h, "to_id": b["node_id"],
                                  "to_name": peer["cert"]["name"], "purpose": b.get("purpose", "Treatment"),
                                  "ts": time.time(), "status": "sent", "record": None}
        self.ledger.append(self.id, "REQUEST_SENT", {"req": rid, "patient": h, "to": peer["cert"]["name"],
                                                      "purpose": b.get("purpose", "Treatment")})
        return {"ok": True, "req_id": rid}

    def _ui_decision(self, b):
        with self.lock:
            r = self.incoming.get(b["req_id"])
            if not r or r["status"] != "pending":
                raise ApiError("no pending request")
        h = pid_hash(r["patient_id"])
        if b["approve"]:
            raw = canon(self.patients[r["patient_id"]])
            box = seal(r["from_cert"]["enc_pub"], raw, r["req_id"].encode())
            self._post(self._url_of(r["from_id"]), "deliver",
                       {"req_id": r["req_id"], "box": box, "record_hash": sha256_hex(raw)})
            r["status"] = "approved"
            self.ledger.append(self.id, "ACCESS_GRANTED", {"req": r["req_id"], "patient": h, "to": r["from_name"],
                                                            "encrypted": "X25519+AES-256-GCM"})
        else:
            self._post(self._url_of(r["from_id"]), "denied", {"req_id": r["req_id"]})
            r["status"] = "denied"
            self.ledger.append(self.id, "ACCESS_DENIED", {"req": r["req_id"], "patient": h, "to": r["from_name"]})
        return {"ok": True}

    def _url_of(self, node_id):
        p = self.peers.get(node_id)
        if not p or not p["url"]:
            raise ApiError("requester unreachable")
        return p["url"]

    def _pubs(self):
        with self.lock:
            d = {i: p["cert"]["sign_pub"] for i, p in self.peers.items()}
        d[self.id.node_id] = self.id.cert["sign_pub"]
        return d

    def _ui_audit(self, b):
        """Verify every replicated chain; optionally heal broken ones from peers."""
        res = self.ledger.audit(self._pubs())
        if b.get("heal"):
            for author, st in res.items():
                if st["ok"] or author == self.id.node_id:
                    continue
                for nid, p in self._online_peers():
                    try:
                        _, r = self._post(p["url"], "ledger", {"author": author, "start": 0})
                        if self.ledger.replace(author, r["blocks"], self._pubs()[author]):
                            break
                    except Exception:
                        continue
            res = self.ledger.audit(self._pubs())
        return res

    def _ui_tamper(self, b):
        """DEMO ONLY: corrupt a block in our local replica of another hospital's chain."""
        with self.ledger.lock:
            for a, chain in self.ledger.chains.items():
                if a != self.id.node_id and len(chain) > 1:
                    chain[1]["data"] = dict(chain[1]["data"], tampered=True)
                    return {"ok": True, "author": a}
        raise ApiError("nothing to tamper with yet")

    def state(self):
        with self.lock:
            peers = [{"node_id": i, "name": p["cert"]["name"], "url": p["url"], "online": p["online"]}
                     for i, p in self.peers.items()]
            inc = [{k: v for k, v in r.items() if k != "from_cert"} for r in self.incoming.values()]
            return {"me": {"name": self.id.name, "node_id": self.id.node_id, "url": self.url},
                    "patients": list(self.patients.values()), "peers": peers,
                    "incoming": sorted(inc, key=lambda r: -r["ts"]),
                    "outgoing": sorted(self.outgoing.values(), key=lambda r: -r["ts"]),
                    "ledger": self.ledger.flat(80), "heads": self.ledger.heads(),
                    "security": self.security[-20:], "now": time.time()}
