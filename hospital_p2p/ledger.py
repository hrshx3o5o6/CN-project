"""Tamper-evident audit ledger: one signed hash-chain per hospital, replicated to every peer.

Each hospital appends events (requests, approvals, deliveries) to ITS OWN chain, signing every
block. Peers replicate all chains, so no hospital can silently rewrite history: altering a block
breaks its hash link and signature on every honest replica.
"""
import threading
import time

from .crypto import canon, sha256_hex, verify_sig

GENESIS = "0" * 64
FIELDS = ("author", "index", "ts", "event", "data", "prev")


def block_hash(b: dict) -> str:
    return sha256_hex(canon({k: b[k] for k in FIELDS}))


def check_block(b: dict, prev_hash: str, index: int, sign_pub: str) -> bool:
    try:
        return (b["index"] == index and b["prev"] == prev_hash and b["hash"] == block_hash(b)
                and verify_sig(sign_pub, b["hash"].encode(), b["sig"]))
    except (KeyError, TypeError):
        return False


def verify_chain(blocks: list, sign_pub: str):
    """-> (ok, index_of_first_bad_block or None)"""
    prev = GENESIS
    for i, b in enumerate(blocks):
        if not check_block(b, prev, i, sign_pub):
            return False, i
        prev = b["hash"]
    return True, None


class Ledger:
    def __init__(self):
        self.chains: dict[str, list] = {}
        self.names: dict[str, str] = {}
        self.lock = threading.RLock()

    def append(self, identity, event: str, data: dict) -> dict:
        with self.lock:
            chain = self.chains.setdefault(identity.node_id, [])
            self.names[identity.node_id] = identity.name
            b = {"author": identity.node_id, "index": len(chain), "ts": time.time(),
                 "event": event, "data": data, "prev": chain[-1]["hash"] if chain else GENESIS}
            b["hash"] = block_hash(b)
            b["sig"] = identity.sign(b["hash"].encode())
            chain.append(b)
            return b

    def heads(self) -> dict:
        with self.lock:
            return {a: len(c) for a, c in self.chains.items()}

    def blocks(self, author: str, start: int = 0) -> list:
        with self.lock:
            return list(self.chains.get(author, [])[start:])

    def accept(self, author: str, blocks: list, sign_pub: str, name: str = "") -> int:
        """Extend our replica of `author`'s chain with verified blocks. Returns #added."""
        added = 0
        with self.lock:
            chain = self.chains.setdefault(author, [])
            if name:
                self.names[author] = name
            for b in blocks:
                if b.get("index", -1) < len(chain):
                    continue  # already have it
                prev = chain[-1]["hash"] if chain else GENESIS
                if b.get("author") != author or not check_block(b, prev, len(chain), sign_pub):
                    break
                chain.append(b)
                added += 1
        return added

    def audit(self, pubs: dict) -> dict:
        with self.lock:
            out = {}
            for a, chain in self.chains.items():
                pub = pubs.get(a)
                ok, bad = verify_chain(chain, pub) if pub else (False, 0)
                out[a] = {"name": self.names.get(a, a), "length": len(chain), "ok": ok, "bad": bad}
            return out

    def replace(self, author: str, blocks: list, sign_pub: str) -> bool:
        ok, _ = verify_chain(blocks, sign_pub)
        if ok:
            with self.lock:
                self.chains[author] = list(blocks)
        return ok

    def flat(self, limit: int = 200) -> list:
        with self.lock:
            allb = [b for c in self.chains.values() for b in c]
        return sorted(allb, key=lambda b: b["ts"])[-limit:]
