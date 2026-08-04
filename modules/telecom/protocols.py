"""
SS7 Protocol Stack — ss7-security-framework/protocols.py

Sections
--------
1. Exceptions
2. ASN.1 BER codec (X.690)
3. SCTP parser  (RFC 4960)
4. M3UA layer   (RFC 4666)
5. SCCP layer   (ITU-T Q.711-714)
6. TCAP layer   (ITU-T Q.771)
7. MAP layer    (3GPP TS 29.002)
8. PCAP reader  (legacy format)

All encoding uses real TLV / BER — no plaintext protocol strings.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple


# ============================================================
# 1. Exceptions
# ============================================================

class ProtocolError(Exception):
    """Any protocol-layer failure."""

class ParseError(ProtocolError):
    """Could not decode message bytes."""

class ValidationError(ProtocolError):
    """Input value failed validation."""


# ============================================================
# 2. ASN.1 BER  (X.690)
# ============================================================

class _TC(IntEnum):          # Tag Class
    UNIVERSAL        = 0x00
    APPLICATION      = 0x40
    CONTEXT_SPECIFIC = 0x80
    PRIVATE          = 0xC0


@dataclass
class BERElement:
    tag_class:   _TC
    constructed: bool
    tag_number:  int
    length:      int
    value:       bytes
    children:    List["BERElement"] = field(default_factory=list)

    @property
    def label(self) -> str:
        cls = {_TC.UNIVERSAL:"U", _TC.APPLICATION:"A",
               _TC.CONTEXT_SPECIFIC:"C", _TC.PRIVATE:"P"}.get(self.tag_class,"?")
        f = "c" if self.constructed else "p"
        return f"[{cls}/{f}/{self.tag_number}]"

    def to_dict(self) -> dict:
        d: dict = {"tag": self.label, "len": self.length}
        if self.constructed:
            d["children"] = [c.to_dict() for c in self.children]
        else:
            d["hex"] = self.value.hex()
        return d


class BERCodec:
    """Encode and decode ASN.1 BER TLV structures."""

    # ---- decode ----

    def decode(self, data: bytes, off: int = 0) -> Tuple[BERElement, int]:
        if not data or off >= len(data):
            raise ParseError("Empty / out-of-range BER data")
        start = off

        b0 = data[off]; off += 1
        tc = _TC(b0 & 0xC0); cons = bool(b0 & 0x20); tn = b0 & 0x1F
        if tn == 0x1F:
            tn = 0
            while off < len(data):
                b = data[off]; off += 1
                tn = (tn << 7) | (b & 0x7F)
                if not (b & 0x80): break

        if off >= len(data): raise ParseError("Truncated: no length byte")
        lb = data[off]; off += 1
        if lb & 0x80:
            n = lb & 0x7F
            if n == 0: raise ParseError("Indefinite length not supported")
            if off + n > len(data): raise ParseError("Truncated length bytes")
            length = int.from_bytes(data[off:off+n], "big"); off += n
        else:
            length = lb

        if off + length > len(data):
            raise ParseError(f"Truncated value: need {length}, have {len(data)-off}")
        value = data[off:off+length]; end = off + length

        children: List[BERElement] = []
        if cons:
            ci = 0
            while ci < len(value):
                try:
                    child, ci = self.decode(value, ci)
                    children.append(child)
                except ParseError:
                    break

        return BERElement(tc, cons, tn, length, value, children), end

    def decode_all(self, data: bytes) -> List[BERElement]:
        elems: List[BERElement] = []
        off = 0
        while off < len(data):
            e, off = self.decode(data, off); elems.append(e)
        return elems

    @staticmethod
    def to_int(v: bytes) -> int:
        return int.from_bytes(v, "big", signed=True) if v else 0

    @staticmethod
    def to_tbcd(v: bytes) -> str:
        d: List[str] = []
        for b in v:
            lo, hi = b & 0xF, (b >> 4) & 0xF
            if lo != 0xF: d.append(str(lo))
            if hi != 0xF: d.append(str(hi))
        return "".join(d)

    # ---- encode ----

    def _tag(self, tc: _TC, cons: bool, tn: int) -> bytes:
        b0 = int(tc) | (0x20 if cons else 0)
        if tn < 0x1F: return bytes([b0 | tn])
        parts = [b0 | 0x1F]; enc: List[int] = []
        n = tn
        enc.append(n & 0x7F); n >>= 7
        while n: enc.append(0x80 | (n & 0x7F)); n >>= 7
        return bytes(parts) + bytes(reversed(enc))

    def _len(self, n: int) -> bytes:
        if n < 0x80: return bytes([n])
        if n < 0x100: return bytes([0x81, n])
        if n < 0x10000: return bytes([0x82]) + n.to_bytes(2, "big")
        return bytes([0x83]) + n.to_bytes(3, "big")

    def tlv(self, tc: _TC, cons: bool, tn: int, val: bytes) -> bytes:
        return self._tag(tc, cons, tn) + self._len(len(val)) + val

    def encode_int(self, v: int, tn: int = 0x02) -> bytes:
        vb = b"\x00" if v == 0 else v.to_bytes((v.bit_length() + 8) // 8, "big", signed=True)
        return bytes([int(_TC.UNIVERSAL) | tn]) + self._len(len(vb)) + vb

    def encode_oct(self, v: bytes, tn: int = 0x04) -> bytes:
        return bytes([int(_TC.UNIVERSAL) | tn]) + self._len(len(v)) + v

    def encode_seq(self, parts: List[bytes]) -> bytes:
        c = b"".join(parts)
        return bytes([int(_TC.UNIVERSAL) | 0x20 | 0x10]) + self._len(len(c)) + c

    def encode_ctx(self, tn: int, val: bytes, cons: bool = False) -> bytes:
        b = int(_TC.CONTEXT_SPECIFIC) | (0x20 if cons else 0) | (tn & 0x1F)
        return bytes([b]) + self._len(len(val)) + val

    def encode_tbcd(self, digits: str) -> bytes:
        s = digits if len(digits) % 2 == 0 else digits + "F"
        return bytes(
            (0x0F if s[i]=="F" else int(s[i])) |
            ((0x0F if s[i+1]=="F" else int(s[i+1])) << 4)
            for i in range(0, len(s), 2)
        )


_ber = BERCodec()      # module-level singleton for internal use


# ============================================================
# 3. SCTP parser  (RFC 4960)
# ============================================================

class ChunkType(IntEnum):
    DATA=0x00; INIT=0x01; INIT_ACK=0x02; SACK=0x03
    HEARTBEAT=0x04; HEARTBEAT_ACK=0x05; ABORT=0x06
    SHUTDOWN=0x07; SHUTDOWN_ACK=0x08; ERROR=0x09
    COOKIE_ECHO=0x0A; COOKIE_ACK=0x0B; SHUTDOWN_COMPLETE=0x0E

_SIGTRAN_PORTS = frozenset({2905, 2906, 2907, 2908, 2909, 2910, 14001})


@dataclass
class SCTPPacket:
    src_port: int; dst_port: int; vtag: int; checksum: int
    chunks: List[dict] = field(default_factory=list)
    raw: Optional[bytes] = None

    @property
    def is_sigtran(self) -> bool:
        return self.src_port in _SIGTRAN_PORTS or self.dst_port in _SIGTRAN_PORTS

    def data_payloads(self) -> List[bytes]:
        """Return user data from all DATA chunks (skip 12-byte DATA header)."""
        out = []
        for c in self.chunks:
            if c.get("type") == "DATA" and len(c.get("data", b"")) >= 12:
                out.append(c["data"][12:])
        return out

    def to_dict(self) -> dict:
        return {"src":self.src_port,"dst":self.dst_port,
                "vtag":f"0x{self.vtag:08x}","sigtran":self.is_sigtran,
                "chunks":[{k:v.hex() if isinstance(v,bytes) else v
                           for k,v in c.items()} for c in self.chunks]}


def parse_sctp(data: bytes) -> SCTPPacket:
    if len(data) < 12:
        raise ParseError(f"SCTP too short: {len(data)}")
    src, dst, vtag, csum = struct.unpack_from("!HHII", data)
    chunks: List[dict] = []
    off = 12
    while off + 4 <= len(data):
        ct, fl, clen = struct.unpack_from("!BBH", data, off)
        if clen < 4: break
        cdata = data[off+4: off+clen]
        try:
            ctype = ChunkType(ct).name
        except ValueError:
            ctype = f"0x{ct:02x}"
        chunks.append({"type": ctype, "flags": fl, "data": cdata})
        off += (clen + 3) & ~3
    return SCTPPacket(src, dst, vtag, csum, chunks, data)


# ============================================================
# 4. M3UA layer  (RFC 4666)
# ============================================================

_SI_NAMES = {0:"SNMM", 1:"STH", 3:"SCCP", 4:"TUP", 5:"ISUP"}


@dataclass
class ProtocolData:
    """MTP3 routing header + SS7 payload."""
    opc: int; dpc: int; si: int; ni: int; mp: int; sls: int; data: bytes

    @property
    def service(self) -> str:
        return _SI_NAMES.get(self.si, f"SI_{self.si}")

    def to_dict(self) -> dict:
        return {"opc":self.opc,"dpc":self.dpc,"si":self.si,
                "service":self.service,"ni":self.ni,"sls":self.sls,
                "data_hex":self.data.hex()}


@dataclass
class M3UAMessage:
    version: int; msg_class: int; msg_type: int; length: int
    params: Dict[int, bytes] = field(default_factory=dict)
    protocol_data: Optional[ProtocolData] = None; raw: Optional[bytes] = None

    def to_dict(self) -> dict:
        return {"version":self.version,"class":self.msg_class,
                "type":self.msg_type,"length":self.length,
                "protocol_data": self.protocol_data.to_dict() if self.protocol_data else None}


def parse_m3ua(data: bytes) -> M3UAMessage:
    if len(data) < 8: raise ParseError(f"M3UA too short: {len(data)}")
    ver, _, mc, mt, length = struct.unpack_from("!BBBBI", data)
    params: Dict[int, bytes] = {}; pd: Optional[ProtocolData] = None
    off = 8
    while off + 4 <= length:
        tag, plen = struct.unpack_from("!HH", data, off); off += 4
        if plen < 4: break
        val = data[off:off+plen-4]; off += plen - 4 + ((4-plen%4)%4)
        params[tag] = val
        if tag == 0x0210 and len(val) >= 12:   # PROTOCOL_DATA
            o, d, si, ni, mp, sls = struct.unpack_from("!IIBBBB", val)
            pd = ProtocolData(o&0xFFFFFF, d&0xFFFFFF, si, ni, mp, sls, val[12:])
    return M3UAMessage(ver, mc, mt, length, params, pd, data)


def build_m3ua_data(pd: ProtocolData, routing_context: Optional[int] = None) -> bytes:
    """Encode an M3UA DATA message (class=1, type=1)."""
    raw_pd = struct.pack("!IIBBBB", pd.opc, pd.dpc, pd.si, pd.ni, pd.mp, pd.sls) + pd.data
    plen = 4 + len(raw_pd); pad = (4-len(raw_pd)%4)%4
    pd_param = struct.pack("!HH", 0x0210, plen) + raw_pd + bytes(pad)
    body = b""
    if routing_context is not None:
        body += struct.pack("!HHI", 0x0006, 8, routing_context)
    body += pd_param
    return struct.pack("!BBBBI", 1, 0, 1, 1, 8+len(body)) + body


# ============================================================
# 5. SCCP layer  (ITU-T Q.711-714)
# ============================================================

class SSN(IntEnum):
    BSSAP=254; TCAP=145; MAP=147; CAMEL=146; RANAP=142


@dataclass
class SCCPAddress:
    ssn: Optional[int] = None
    point_code: Optional[int] = None
    global_title: Optional[bytes] = None
    routing_ind: int = 0

    @property
    def ssn_name(self) -> str:
        try: return SSN(self.ssn).name
        except: return f"SSN_{self.ssn}" if self.ssn is not None else "NONE"

    def to_dict(self) -> dict:
        return {"ssn":self.ssn,"ssn_name":self.ssn_name,
                "point_code":self.point_code,
                "gt":self.global_title.hex() if self.global_title else None}


@dataclass
class SCCPMessage:
    msg_type: int; protocol_class: int = 0
    called: Optional[SCCPAddress] = None
    calling: Optional[SCCPAddress] = None
    data: Optional[bytes] = None; raw: Optional[bytes] = None

    def to_dict(self) -> dict:
        names = {0x09:"UDT",0x11:"XUDT",0x0A:"UDTS",0x12:"XUDTS"}
        return {"type":names.get(self.msg_type,f"0x{self.msg_type:02x}"),
                "class":self.protocol_class,
                "called":self.called.to_dict() if self.called else None,
                "calling":self.calling.to_dict() if self.calling else None,
                "data_hex":self.data.hex() if self.data else None}


def _decode_sccp_addr(data: bytes, off: int) -> SCCPAddress:
    if off >= len(data): return SCCPAddress()
    ln = data[off]; off += 1
    if ln == 0 or off+ln > len(data): return SCCPAddress()
    ad = data[off:off+ln]; ai = ad[0]
    has_pc = bool(ai & 1); has_ssn = bool(ai & 2)
    gt_ind = (ai >> 2) & 0xF; p = 1
    pc = ssn = gt = None
    if has_pc and p+2 <= len(ad):
        pc = int.from_bytes(ad[p:p+2],"little") & 0x3FFF; p += 2
    if has_ssn and p < len(ad):
        ssn = ad[p]; p += 1
    if gt_ind and p < len(ad):
        gt = ad[p:]
    return SCCPAddress(ssn, pc, gt, int(bool(ai & 0x40)))


def parse_sccp(data: bytes) -> SCCPMessage:
    if not data: raise ParseError("Empty SCCP data")
    mt = data[0]
    if mt not in (0x09, 0x11, 0x0A, 0x12):
        return SCCPMessage(mt, raw=data)
    if len(data) < 5: raise ParseError("SCCP UDT too short")
    pc = data[1] & 0xF; off = 2
    p1 = data[off]+off; off+=1
    p2 = data[off]+off; off+=1
    p3 = data[off]+off; off+=1
    called  = _decode_sccp_addr(data, p1)
    calling = _decode_sccp_addr(data, p2)
    payload = data[p3+1:p3+1+data[p3]] if p3 < len(data) else None
    return SCCPMessage(mt, pc, called, calling, payload, data)


def build_sccp_udt(
    payload: bytes,
    called: SCCPAddress,
    calling: SCCPAddress,
    protocol_class: int = 0,
) -> bytes:
    def _enc_addr(a: SCCPAddress) -> bytes:
        ai = 0; body = bytearray()
        if a.point_code is not None:
            ai |= 1; body += a.point_code.to_bytes(2,"little")
        if a.ssn is not None:
            ai |= 2; body += bytes([a.ssn])
        if a.global_title is not None:
            ai |= (4 << 2); body += a.global_title
        full = bytes([ai]) + bytes(body)
        return bytes([len(full)]) + full
    cb = _enc_addr(called); kb = _enc_addr(calling)
    # Pointers relative to their own byte position
    # Header: [type][class][p1@2][p2@3][p3@4] then variable part starts at 5
    msg = bytes([0x09, protocol_class, 3, 2+len(cb), 1+len(cb)+len(kb)])
    msg += cb + kb + bytes([len(payload)]) + payload
    return msg


# ============================================================
# 6. TCAP layer  (ITU-T Q.771)
# ============================================================

class TCAPType(IntEnum):
    UNI=0x01; BEGIN=0x02; END=0x04; CONTINUE=0x05; ABORT=0x07


@dataclass
class TCAPMessage:
    msg_type: TCAPType; otid: Optional[bytes] = None
    dtid: Optional[bytes] = None; components: List[bytes] = field(default_factory=list)
    raw: Optional[bytes] = None

    def to_dict(self) -> dict:
        return {"type":self.msg_type.name,
                "otid":self.otid.hex() if self.otid else None,
                "dtid":self.dtid.hex() if self.dtid else None,
                "components":len(self.components)}


def parse_tcap(data: bytes) -> TCAPMessage:
    if not data: raise ParseError("Empty TCAP data")
    try: mt = TCAPType(data[0] & 0x1F)
    except ValueError: raise ParseError(f"Unknown TCAP type: 0x{data[0]:02x}")
    elem, _ = _ber.decode(data)
    otid = dtid = None; components: List[bytes] = []
    for c in elem.children:
        if c.tag_class == _TC.APPLICATION:
            if c.tag_number == 8: otid = c.value
            elif c.tag_number == 9: dtid = c.value
            elif c.tag_number == 11: components = [ch.value for ch in c.children]
    return TCAPMessage(mt, otid, dtid, components, data)


class TCAPEncoder:
    _n = 0
    def _tid(self) -> bytes:
        TCAPEncoder._n = (TCAPEncoder._n + 1) & 0xFFFFFFFF
        return TCAPEncoder._n.to_bytes(4,"big")

    def _tlv(self, tag: int, val: bytes) -> bytes:
        return bytes([tag, len(val)]) + val

    def begin(self, component: bytes, otid: Optional[bytes] = None) -> bytes:
        body = self._tlv(0x48, otid or self._tid()) + self._tlv(0x6B, component)
        return bytes([0x62, len(body)]) + body

    def end(self, component: bytes, dtid: bytes) -> bytes:
        body = self._tlv(0x49, dtid) + self._tlv(0x6B, component)
        return bytes([0x64, len(body)]) + body

    def cont(self, component: bytes, otid: bytes, dtid: bytes) -> bytes:
        body = self._tlv(0x48,otid)+self._tlv(0x49,dtid)+self._tlv(0x6B,component)
        return bytes([0x65, len(body)]) + body


# ============================================================
# 7. MAP layer  (3GPP TS 29.002)
# ============================================================

class MAPOp(IntEnum):
    """MAP operation codes (3GPP TS 29.002 §17.7.4)."""
    UPDATE_LOCATION         = 2
    CANCEL_LOCATION         = 3
    PROVIDE_ROAMING_NUMBER  = 4
    INSERT_SUBSCRIBER_DATA  = 7
    DELETE_SUBSCRIBER_DATA  = 8
    PURGE_MS                = 67
    SEND_ROUTING_INFO       = 22
    UPDATE_GPRS_LOCATION    = 23
    SEND_ROUTING_INFO_GPRS  = 24
    SEND_IDENTIFICATION     = 55
    SEND_AUTH_INFO          = 56
    REGISTER_SS             = 10
    ACTIVATE_SS             = 12
    DEACTIVATE_SS           = 13
    INTERROGATE_SS          = 14
    PROCESS_USS_REQUEST     = 59
    ROUTING_INFO_FOR_SM     = 45
    FORWARD_SHORT_MESSAGE   = 46
    SEND_END_SIGNAL         = 29

    @classmethod
    def name_of(cls, code: int) -> str:
        try: return cls(code).name
        except ValueError: return f"UNKNOWN_OP_{code}"

    @classmethod
    def risk(cls, code: int) -> str:
        HIGH = {cls.SEND_ROUTING_INFO, cls.ROUTING_INFO_FOR_SM,
                cls.INSERT_SUBSCRIBER_DATA, cls.DELETE_SUBSCRIBER_DATA,
                cls.PROVIDE_ROAMING_NUMBER, cls.CANCEL_LOCATION,
                cls.SEND_AUTH_INFO, cls.PURGE_MS}
        MEDIUM = {cls.UPDATE_LOCATION, cls.REGISTER_SS,
                  cls.ACTIVATE_SS, cls.DEACTIVATE_SS, cls.INTERROGATE_SS}
        try:
            op = cls(code)
            if op in HIGH: return "HIGH"
            if op in MEDIUM: return "MEDIUM"
        except ValueError: return "UNKNOWN"
        return "LOW"


class MAPErr(IntEnum):
    UNKNOWN_SUBSCRIBER    = 1
    ILLEGAL_SUBSCRIBER    = 9
    ILLEGAL_EQUIPMENT     = 15
    SYSTEM_FAILURE        = 34
    DATA_MISSING          = 35
    UNEXPECTED_DATA_VALUE = 36
    ABSENT_SUBSCRIBER     = 27


@dataclass
class ISDNAddress:
    """E.164 ISDN address (MSISDN / MSC number)."""
    digits: str; ton: int = 1; npi: int = 1

    def encode(self) -> bytes:
        ton_npi = 0x80 | ((self.ton & 7) << 4) | (self.npi & 0xF)
        return bytes([ton_npi]) + _ber.encode_tbcd(self.digits)

    @classmethod
    def decode(cls, data: bytes) -> "ISDNAddress":
        if not data: raise ParseError("Empty ISDN address")
        return cls(_ber.to_tbcd(data[1:]), (data[0]>>4)&7, data[0]&0xF)


@dataclass
class MAPMessage:
    """Decoded MAP component."""
    operation_code: int; invoke_id: int
    parameters: Dict[str, Any] = field(default_factory=dict)
    error_code: Optional[int] = None; is_response: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw: Optional[bytes] = None

    @property
    def operation_name(self) -> str: return MAPOp.name_of(self.operation_code)
    @property
    def risk_level(self) -> str: return MAPOp.risk(self.operation_code)

    def to_dict(self) -> dict:
        return {"op":self.operation_code,"op_name":self.operation_name,
                "invoke_id":self.invoke_id,"risk":self.risk_level,
                "is_response":self.is_response,"params":self.parameters,
                "error":self.error_code,"ts":self.timestamp.isoformat()}


class MAPCodec:
    """Encode and decode MAP messages using real BER."""

    _iid = 0

    def _next_iid(self) -> int:
        MAPCodec._iid = (MAPCodec._iid + 1) % 256
        return MAPCodec._iid

    # ---- encode helpers ----

    def _invoke(self, iid: int, op: int, params: bytes) -> bytes:
        op_b = _ber.encode_int(op)
        body = bytes([0x02, 0x01, iid]) + op_b + params
        return bytes([0xA1, len(body)]) + body

    def _ret_result(self, iid: int, result: bytes) -> bytes:
        body = bytes([0x02, 0x01, iid]) + result
        return bytes([0xA2, len(body)]) + body

    def _ret_error(self, iid: int, err: int) -> bytes:
        err_b = _ber.encode_int(err)
        body  = bytes([0x02, 0x01, iid]) + err_b
        return bytes([0xA3, len(body)]) + body

    # ---- public encode ----

    def encode_sri(self, msisdn: str, iid: Optional[int] = None) -> bytes:
        """SendRoutingInfo [22] request."""
        i = iid if iid is not None else self._next_iid()
        addr = ISDNAddress(msisdn).encode()
        params = bytes([0x80, len(addr)]) + addr
        return self._invoke(i, MAPOp.SEND_ROUTING_INFO, params)

    def encode_sri_response(self, iid: int, imsi: str, msc: str) -> bytes:
        tbcd  = _ber.encode_tbcd(imsi)
        i_tlv = bytes([0x04, len(tbcd)]) + tbcd
        m_enc = ISDNAddress(msc).encode()
        m_tlv = bytes([0x80, len(m_enc)]) + m_enc
        seq   = bytes([0x30, len(i_tlv)+len(m_tlv)]) + i_tlv + m_tlv
        return self._ret_result(iid, seq)

    def encode_isd(self, imsi: str, msisdn: str, iid: Optional[int] = None) -> bytes:
        """InsertSubscriberData [7] request."""
        i     = iid if iid is not None else self._next_iid()
        itbcd = _ber.encode_tbcd(imsi)
        i_tlv = bytes([0x04, len(itbcd)]) + itbcd
        addr  = ISDNAddress(msisdn).encode()
        m_tlv = bytes([0x81, len(addr)]) + addr
        params= bytes([0x30, len(i_tlv)+len(m_tlv)]) + i_tlv + m_tlv
        return self._invoke(i, MAPOp.INSERT_SUBSCRIBER_DATA, params)

    def encode_error(self, iid: int, err: MAPErr) -> bytes:
        return self._ret_error(iid, int(err))

    # ---- decode ----

    def decode(self, data: bytes) -> MAPMessage:
        if not data: raise ParseError("Empty MAP data")
        elems = _ber.decode_all(data)
        if not elems: raise ParseError("No BER elements")
        e = elems[0]
        tag = e.tag_number; is_resp = tag in (2, 3, 4)
        iid = op = 0; err: Optional[int] = None
        params: Dict[str, Any] = {}
        for ch in e.children:
            if ch.tag_class == _TC.UNIVERSAL and ch.tag_number == 0x02:
                v = _ber.to_int(ch.value)
                if iid == 0: iid = v
                elif op == 0: op = v
                else: err = v
            elif ch.tag_class == _TC.CONTEXT_SPECIFIC:
                params[f"ctx_{ch.tag_number}"] = {"hex":ch.value.hex()}
            elif ch.tag_class == _TC.UNIVERSAL and ch.tag_number == 0x10:
                params["seq"] = {"children":[c.to_dict() for c in ch.children]}
        return MAPMessage(op, iid, params, err, is_resp, datetime.now(timezone.utc), data)


# ============================================================
# 8. PCAP reader  (legacy format, no external libs)
# ============================================================

@dataclass
class RawPacket:
    timestamp: float; data: bytes; link_type: int; number: int

    def sctp_payload(self) -> Optional[bytes]:
        ip = self._ip()
        return self._sctp_from_ip(ip) if ip else None

    def _ip(self) -> Optional[bytes]:
        lt = self.link_type
        if lt == 1:   # Ethernet
            if len(self.data) < 14: return None
            et = struct.unpack_from("!H", self.data, 12)[0]
            return self.data[18 if et == 0x8100 else 14:]
        if lt == 113: # Linux SLL
            return self.data[16:] if len(self.data) >= 16 else None
        if lt == 12:  # Raw IPv4
            return self.data
        return None

    @staticmethod
    def _sctp_from_ip(data: bytes) -> Optional[bytes]:
        if not data: return None
        v = (data[0] >> 4) & 0xF
        if v == 4:
            if len(data) < 20 or data[9] != 132: return None
            return data[(data[0]&0xF)*4:]
        if v == 6:
            if len(data) < 40 or data[6] != 132: return None
            return data[40:]
        return None


def read_pcap(filepath: str) -> Iterator[RawPacket]:
    """Yield RawPacket objects from a PCAP legacy file."""
    path = Path(filepath)
    if not path.exists(): raise ParseError(f"File not found: {filepath}")
    with path.open("rb") as fh:
        magic = struct.unpack("<I", fh.read(4))[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D): bo = "<"; ns = (magic==0xA1B23C4D)
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1): bo = ">"; ns = (magic==0x4D3CB2A1)
        else: raise ParseError(f"Not a PCAP file (magic=0x{magic:08x})")
        hdr = struct.Struct(f"{bo}HHIIII")
        _, _, _, _, _, lt = hdr.unpack(fh.read(20))
        ph = struct.Struct(f"{bo}IIII")
        n = 0
        while True:
            raw = fh.read(16)
            if len(raw) < 16: break
            ts, tf, incl, _ = ph.unpack(raw)
            dat = fh.read(incl)
            if len(dat) < incl: break
            n += 1
            yield RawPacket(ts + tf/(1e9 if ns else 1e6), dat, lt, n)


# ============================================================
# Validators  (inline, no separate file needed)
# ============================================================

def validate_msisdn(raw: str) -> str:
    import re
    if not isinstance(raw, str): raise ValidationError("MSISDN must be a string")
    c = raw.strip().lstrip("+")
    if not c.isdigit(): raise ValidationError(f"Non-digit MSISDN: {raw!r}")
    if not (7 <= len(c) <= 15): raise ValidationError(f"MSISDN length invalid: {raw!r}")
    if c[0] == "0": raise ValidationError(f"Leading 0 in MSISDN: {raw!r}")
    return c

def validate_host(raw: str) -> str:
    import re
    if not re.match(r'^[a-zA-Z0-9.\-:]+$', raw.strip()):
        raise ValidationError(f"Unsafe host value: {raw!r}")
    return raw.strip()

def validate_port(p: object) -> int:
    try: n = int(p)  # type: ignore
    except: raise ValidationError(f"Port must be integer: {p!r}")
    if not (1 <= n <= 65535): raise ValidationError(f"Port out of range: {p}")
    return n
