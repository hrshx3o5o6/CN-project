import json
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from hospital_p2p import crypto
from hospital_p2p.ledger import Ledger, verify_chain
from hospital_p2p.node import Node
from hospital_p2p.seed import PATIENTS
from setup_consortium import provision

NAMES = {"chennai": "Chennai General Hospital", "vellore": "Vellore Medical Centre", "delhi": "Delhi Central Hospital"}


def call(url, path, body=None):
    req = urllib.request.Request(url + path, json.dumps(body or {}).encode())
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def wait(cond, t=10):
    end = time.time() + t
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.ca = crypto.new_ca()
        self.a = crypto.Identity(crypto.issue_identity(self.ca["ca_priv"], "A"))
        self.b = crypto.Identity(crypto.issue_identity(self.ca["ca_priv"], "B"))

    def test_seal_roundtrip_and_wrong_recipient(self):
        box = crypto.seal(self.b.cert["enc_pub"], b"secret", b"aad")
        self.assertEqual(self.b.open(box, b"aad"), b"secret")
        with self.assertRaises(crypto.CryptoError):
            self.a.open(box, b"aad")
        with self.assertRaises(crypto.CryptoError):
            self.b.open(box, b"other")

    def test_envelope_checks(self):
        env = crypto.make_envelope(self.a, {"x": 1})
        seen = {}
        self.assertEqual(crypto.verify_envelope(env, self.ca["ca_pub"], seen)["name"], "A")
        with self.assertRaises(crypto.CryptoError):  # replay
            crypto.verify_envelope(env, self.ca["ca_pub"], seen)
        env2 = crypto.make_envelope(self.a, {"x": 1}); env2["payload"]["x"] = 2
        with self.assertRaises(crypto.CryptoError):  # tampered payload
            crypto.verify_envelope(env2, self.ca["ca_pub"])
        rogue = crypto.issue_identity(crypto.new_ca()["ca_priv"], "Rogue")
        with self.assertRaises(crypto.CryptoError):  # foreign CA
            crypto.verify_envelope(crypto.make_envelope(crypto.Identity(rogue), {}), self.ca["ca_pub"])

    def test_ledger_detects_tamper(self):
        led = Ledger()
        for i in range(3):
            led.append(self.a, "E", {"i": i})
        pub = self.a.cert["sign_pub"]
        self.assertTrue(verify_chain(led.blocks(self.a.node_id), pub)[0])
        led.chains[self.a.node_id][1]["data"]["i"] = 99
        self.assertEqual(verify_chain(led.blocks(self.a.node_id), pub), (False, 1))


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        ca = provision(Path(cls.tmp.name), NAMES)
        cls.ca = ca
        load = lambda s: json.loads((Path(cls.tmp.name) / f"{s}.identity.json").read_text())
        mk = lambda s, boot=(): Node(load(s), ca["ca_pub"], 0, PATIENTS[s], boot, sync_interval=0.3).start()
        cls.chn = mk("chennai")
        cls.vel = mk("vellore", [cls.chn.url])   # only knows chennai
        cls.del_ = mk("delhi", [cls.vel.url])    # only knows vellore -> must discover chennai via gossip
        cls.nodes = [cls.chn, cls.vel, cls.del_]
        assert wait(lambda: all(len(n.peers) == 2 and all(p["online"] for p in n.peers.values()) for n in cls.nodes))

    @classmethod
    def tearDownClass(cls):
        for n in cls.nodes:
            n.stop()
        cls.tmp.cleanup()

    def test_1_gossip_discovery(self):
        self.assertIn(self.chn.id.node_id, self.del_.peers)

    def test_2_locate_uses_hash_only(self):
        r = call(self.vel.url, "/api/ui/locate", {"patient_id": "P-1001"})[1]
        self.assertEqual([h["name"] for h in r["holders"]], [NAMES["chennai"]])
        self.assertEqual(call(self.vel.url, "/api/ui/locate", {"patient_id": "P-9999"})[1]["holders"], [])

    def test_3_request_approve_encrypted_delivery(self):
        rid = call(self.vel.url, "/api/ui/request", {"node_id": self.chn.id.node_id, "patient_id": "P-1001", "purpose": "Emergency"})[1]["req_id"]
        self.assertEqual(self.chn.incoming[rid]["status"], "pending")
        self.assertIsNone(self.vel.outgoing[rid]["record"])
        self.assertEqual(call(self.chn.url, "/api/ui/decision", {"req_id": rid, "approve": True})[0], 200)
        rec = self.vel.outgoing[rid]
        self.assertEqual(rec["status"], "received")
        self.assertEqual(rec["record"]["name"], "Arjun Menon")
        # raw patient ID never written to ledger
        self.assertNotIn("P-1001", json.dumps(self.vel.ledger.flat()))

    def test_4_deny(self):
        rid = call(self.del_.url, "/api/ui/request", {"node_id": self.vel.id.node_id, "patient_id": "P-2001"})[1]["req_id"]
        call(self.vel.url, "/api/ui/decision", {"req_id": rid, "approve": False})
        self.assertEqual(self.del_.outgoing[rid]["status"], "denied")
        self.assertIsNone(self.del_.outgoing[rid]["record"])

    def test_5_ledger_replicates_and_heals(self):
        self.assertTrue(wait(lambda: self.del_.ledger.heads() == self.chn.ledger.heads() == self.vel.ledger.heads()))
        self.assertTrue(all(v["ok"] for v in call(self.del_.url, "/api/ui/audit")[1].values()))
        call(self.del_.url, "/api/ui/tamper")
        self.assertFalse(all(v["ok"] for v in call(self.del_.url, "/api/ui/audit")[1].values()))
        self.assertTrue(all(v["ok"] for v in call(self.del_.url, "/api/ui/audit", {"heal": True})[1].values()))

    def test_6_rogue_node_rejected(self):
        rogue = crypto.Identity(crypto.issue_identity(crypto.new_ca()["ca_priv"], "Evil Clinic"))
        env = crypto.make_envelope(rogue, {"pid_hash": crypto.pid_hash("P-1001")})
        code, body = call(self.chn.url, "/api/peer/locate", env)
        self.assertEqual(code, 403)
        self.assertTrue(any(e["claimed"] == "Evil Clinic" for e in self.chn.security))

    def test_7_replayed_message_rejected(self):
        env = crypto.make_envelope(self.vel.id, {"pid_hash": crypto.pid_hash("P-1001")})
        self.assertEqual(call(self.chn.url, "/api/peer/locate", env)[0], 200)
        self.assertEqual(call(self.chn.url, "/api/peer/locate", env)[0], 403)


if __name__ == "__main__":
    unittest.main()
