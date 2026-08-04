"""
SS7 Security Research Framework — simulator.py

Simulated network nodes for laboratory testing.
No real operator connectivity — loopback only.

Classes
-------
SubscriberDB      — synthetic subscriber database
SimulatedHLR      — asyncio HLR server
SimulatedVLR      — stub VLR
SimulatedMSC      — stub MSC
SimulatedSMSC     — stub SMSC
NetworkSimulator  — orchestrates all nodes
"""
from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from protocols import (
    MAPCodec, MAPErr, MAPOp, MAPMessage,
    ParseError, validate_host, validate_port,
)

log = logging.getLogger("ss7simulator")

# Wire protocol: 4-byte big-endian length prefix + raw MAP bytes
# (Simplified — real SS7 uses SCTP/M3UA/SCCP/TCAP stack)
_PREFIX = 4


# ============================================================
# Subscriber record
# ============================================================

@dataclass
class Subscriber:
    msisdn:      str
    imsi:        str
    msc_address: str = "127.0.0.3"
    vlr_address: str = "127.0.0.2"
    smsc_address:str = "127.0.0.4"
    roaming:     bool = False
    active:      bool = True
    lac:         str  = ""

    @classmethod
    def synthetic(cls, msisdn: str) -> "Subscriber":
        msin = "".join(str(random.randint(0, 9)) for _ in range(9))
        return cls(
            msisdn=msisdn,
            imsi=f"310260{msin}",
            roaming=random.choice([True, False]),
            lac=f"LAC{random.randint(1000,9999)}",
        )

    def to_dict(self) -> dict:
        return {"msisdn":self.msisdn,"imsi":self.imsi,
                "roaming":self.roaming,"lac":self.lac,"active":self.active}


# ============================================================
# Subscriber database
# ============================================================

class SubscriberDB:
    def __init__(self) -> None:
        self._db: Dict[str, Subscriber] = {}
        self._log: List[Dict] = []

    def populate(self, count: int) -> None:
        for _ in range(count):
            msisdn = f"1310{random.randint(1_000_000, 9_999_999)}"
            self._db[msisdn] = Subscriber.synthetic(msisdn)
        log.info(f"DB: {count} synthetic subscribers loaded")

    def add(self, sub: Subscriber) -> None:
        self._db[sub.msisdn] = sub

    def lookup(self, msisdn: str) -> Optional[Subscriber]:
        return self._db.get(msisdn)

    def audit(self, op: str, msisdn: str, src: str, suspicious: bool = False) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(),
                 "op": op, "msisdn": msisdn, "src": src, "suspicious": suspicious}
        self._log.append(entry)
        level = log.warning if suspicious else log.info
        level(f"DB AUDIT {'[SUSPICIOUS] ' if suspicious else ''}"
              f"{op} msisdn={msisdn} src={src}")

    def query_log(self) -> List[dict]:
        return list(self._log)

    def suspicious(self) -> List[dict]:
        return [e for e in self._log if e["suspicious"]]


# ============================================================
# Simulated HLR
# ============================================================

class SimulatedHLR:
    """
    Asyncio HLR server.

    Handles SRI (returns IMSI + MSC) and rejects ISD (marks suspicious).
    """

    def __init__(self, host: str, port: int, db: SubscriberDB) -> None:
        self.host = validate_host(host)
        self.port = validate_port(port)
        self._db   = db
        self._codec= MAPCodec()
        self._srv: Optional[asyncio.Server] = None

    # ---- public handlers (testable without network) ------------------

    def handle_sri(self, msisdn: str, src: str, iid: int) -> bytes:
        self._db.audit("SRI", msisdn, src)
        sub = self._db.lookup(msisdn)
        if sub and sub.active:
            log.info(f"HLR SRI hit: {msisdn}")
            map_resp = self._codec.encode_sri_response(iid, sub.imsi, "12700000001")
        else:
            log.info(f"HLR SRI miss: {msisdn}")
            map_resp = self._codec.encode_error(iid, MAPErr.UNKNOWN_SUBSCRIBER)
        from protocols import TCAPEncoder
        return TCAPEncoder().end(map_resp, b"\x00\x00\x00\x01")

    def handle_isd(self, msisdn: str, src: str, iid: int) -> bytes:
        self._db.audit("ISD", msisdn, src, suspicious=True)
        log.warning(f"HLR ISD from {src} for {msisdn} — SUSPICIOUS — rejecting")
        map_resp = self._codec.encode_error(iid, MAPErr.UNEXPECTED_DATA_VALUE)
        from protocols import TCAPEncoder
        return TCAPEncoder().end(map_resp, b"\x00\x00\x00\x02")

    # ---- asyncio server ----------------------------------------------

    async def start(self) -> None:
        self._srv = await asyncio.start_server(self._handle, self.host, self.port)
        log.info(f"Simulated HLR on {self.host}:{self.port}")
        async with self._srv:
            await self._srv.serve_forever()

    async def _handle(
        self, r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        addr = w.get_extra_info("peername", ("?", 0))
        src  = addr[0]
        try:
            while True:
                hdr = await asyncio.wait_for(r.readexactly(_PREFIX), timeout=30.0)
                n   = int.from_bytes(hdr, "big")
                if n == 0 or n > 65535: break
                data = await asyncio.wait_for(r.readexactly(n), timeout=30.0)
                resp = self._dispatch(data, src)
                if resp:
                    w.write(len(resp).to_bytes(_PREFIX, "big") + resp)
                    await w.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            log.error(f"HLR conn error {src}: {exc}")
        finally:
            w.close()

    def _dispatch(self, data: bytes, src: str) -> Optional[bytes]:
        try:
            msg = self._codec.decode(data)
        except ParseError:
            return None
        op = msg.operation_code
        msisdn = self._msisdn_from(msg) or "unknown"
        if op == int(MAPOp.SEND_ROUTING_INFO):
            return self.handle_sri(msisdn, src, msg.invoke_id)
        if op == int(MAPOp.INSERT_SUBSCRIBER_DATA):
            return self.handle_isd(msisdn, src, msg.invoke_id)
        return None

    @staticmethod
    def _msisdn_from(msg: MAPMessage) -> Optional[str]:
        from protocols import ISDNAddress, ParseError as PE
        for k in ("msisdn", "ctx_0", "ctx_1"):
            v = msg.parameters.get(k)
            if isinstance(v, str): return v
            if isinstance(v, dict) and "hex" in v:
                try: return ISDNAddress.decode(bytes.fromhex(v["hex"])).digits
                except PE: pass
        return None


# ============================================================
# Stub nodes (VLR / MSC / SMSC)
# ============================================================

class SimulatedVLR:
    """Minimal VLR — logs location updates."""

    def __init__(self, port: int, db: SubscriberDB) -> None:
        self.port = port; self._db = db

    def handle_update_location(self, imsi: str, msc: str, src: str) -> dict:
        self._db.audit("UPDATE_LOC", imsi, src)
        return {"status": "acknowledged", "imsi": imsi, "msc": msc}


class SimulatedMSC:
    """Minimal MSC — handles roaming number provision."""

    def __init__(self, port: int) -> None:
        self.port = port
        self._roaming_numbers: Dict[str, str] = {}

    def provide_roaming_number(self, imsi: str) -> str:
        rn = f"1555{random.randint(1000000,9999999)}"
        self._roaming_numbers[imsi] = rn
        return rn


class SimulatedSMSC:
    """Minimal SMSC — logs short message routing."""

    def __init__(self, port: int) -> None:
        self.port = port
        self._messages: List[dict] = []

    def route_sms(self, msisdn: str, imsi: str, msc_addr: str) -> dict:
        entry = {"ts": datetime.now(timezone.utc).isoformat(),
                 "msisdn": msisdn, "imsi": imsi, "msc": msc_addr}
        self._messages.append(entry)
        log.info(f"SMSC route SMS for {msisdn}")
        return entry

    def message_log(self) -> List[dict]:
        return list(self._messages)


# ============================================================
# NetworkSimulator  — orchestrator
# ============================================================

class NetworkSimulator:
    """
    Starts all simulated SS7 network nodes.
    Provides a shared subscriber database.
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        sc         = cfg.get("simulator", {})
        self._cfg  = sc
        self.db    = SubscriberDB()
        host       = sc.get("hlr_host", "127.0.0.1")
        self.hlr   = SimulatedHLR(host, sc.get("hlr_port",  2905), self.db)
        self.vlr   = SimulatedVLR(sc.get("vlr_port", 2906), self.db)
        self.msc   = SimulatedMSC(sc.get("msc_port", 2907))
        self.smsc  = SimulatedSMSC(sc.get("smsc_port", 2908))

    def populate(self, count: Optional[int] = None) -> None:
        n = count or self._cfg.get("subscribers", 100)
        self.db.populate(n)

    async def start_all(self) -> None:
        self.populate()
        log.info(f"Starting simulated network nodes…")
        await asyncio.gather(self.hlr.start())

    def add_subscriber(self, sub: Subscriber) -> None:
        self.db.add(sub)

    def query_log(self) -> List[dict]:
        return self.db.query_log()

    def suspicious_events(self) -> List[dict]:
        return self.db.suspicious()
