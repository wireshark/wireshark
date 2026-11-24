# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers of the H.248 coverage generators: BER, H.248 message
builders, the package tables (pkgdb.py, extracted from the dissector
sources by pkgparse.py), parameter value encoders and the pcapng/UDP/TCP
framing. Everything is built with struct; nothing comes from a network.
Copied into every h248*-coverage directory."""
import random
import socket
import struct

from pkgdb import PKGS

# packages of annex E that are not registered by the dissector
UNREGISTERED = (0x0002, 0x0006)


# ---------------------------------------------------------------- BER

def L(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, *parts):
    c = b''.join(parts)
    if isinstance(tag, int):
        tag = bytes([tag])
    return tag + L(len(c)) + c


def ber_int(v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def u32(v):
    return v.to_bytes(4, 'big')


# ------------------------------------------------- package value encoders

IMPL_FALSE = ('&implicit', '&h248_e_implicit')

BCTP_IPBCP = (b'\x01\x20v=0\r\no=- 7 7 IN IP4 198.51.100.1\r\ns=-\r\n'
              b'c=IN IP4 198.51.100.1\r\nt=0 0\r\na=ipbcp:1 Request\r\n'
              b'm=audio 5004 RTP/AVP 0\r\n')

CODECS = [b'\x01\x01', b'\x01\x08\x03', b'\x01\x0a\x01', b'\x02\x01', b'\x02\x02\x81', b'\x02\x03\x81\x82',
          b'\x02\x04\x81\x82\x43', b'\x01\x0b\x02', b'\x01\x06', b'\x01\x0c\x04']
# codec lists hold only ITU-T codecs without configuration data
CODEC_LIST = b'\x01\x01\x01\x02\x01\x03\x01\x05\x01\x06\x01\x07'
# a Q.931 bearer capability content (information transfer capability, rate)
USI = [b'\x80\x90\xa3', b'\x88\x90', b'\x04\x03\x80\x90\xa3']
NSAPS = [b'\x39\x84\x0f\x00\x07\x88\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x02\x03\x04\x00',
         b'\x47\x00\x79\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00',
         b'\x45\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10']
SDP_TEXT = [b'0', b'- 25678 753849 IN IP4 192.0.2.1', b'Call', b'info', b'http://example.invalid/',
            b'mgc@example.invalid', b'+1 555 0100', b'IN IP4 192.0.2.7', b'AS:64', b'0 0', b'prompt:abc',
            b'rtpmap:0 PCMU/8000', b'0 0', b'2 3']
INTS = [1, 0, 2, 3, 100, 5, 1000, 70000, 255, 16]


def value(func, data, pid, k=0, ft=None):
    """Content of the OCTET STRING that carries one signal/event/property
    parameter value, for the table entry's dissector function."""
    if func in ('NULL', None):
        return tlv(4, bytes([k % 256]))
    if func == 'h248_param_ber_integer':
        return tlv(2, ber_int(INTS[k % len(INTS)]))
    if func == 'h248_param_ber_octetstring':
        n = {'FT_UINT8': 1, 'FT_UINT16': 2, 'FT_UINT24': 3, 'FT_UINT32': 4, 'FT_IPv4': 4, 'FT_IPv6': 16}.get(ft)
        if n:
            return tlv(4, bytes((0x20 + k + i) & 0xff for i in range(n)))
        if ft == 'FT_STRING':
            return tlv(4, [b'abcd', b'text', b'x'][k % 3])
        return tlv(4, [b'\x01\x02\x03', b'abcd', b'\x00', b'\xde\xad\xbe\xef\x01\x02\x03\x04'][k % 4])
    if func == 'h248_param_ber_boolean':
        return tlv(1, [b'\xff', b'\x00'][k % 2])
    if func == 'h248_param_PkgdName':
        return tlv(4, struct.pack('>HH', *[(0x0001, 0), (0x0003, 1), (0x0005, 2), (0x7777, 0), (0x0004, 1)][k % 5]))
    if func == 'dissect_h248_annexc_acodec':
        return tlv(4, CODECS[k % len(CODECS)])
    if func == 'dissect_h248_annexc_BIR':
        return tlv(4, bytes([0x10 + k % 200, 2, 3, 4]))
    if func == 'dissect_h248_annexc_NSAP':
        return tlv(4, NSAPS[k % len(NSAPS)])
    if func == 'dissect_h248_annexc_vpvc':
        return struct.pack('>HH', 1 + k % 100, 32 + k % 100)
    if func == 'dissect_h248_annexc_USI':
        return tlv(4, USI[k % len(USI)])
    if func == 'dissect_h248_annexc_SDP':
        return tlv(0x16, SDP_TEXT[(pid + k) % len(SDP_TEXT)])
    if func == 'dissect_h248_annexc_SDP_C':
        return tlv(0x16, [b'IN IP4 192.0.2.1', b'IN IP6 2001:db8::1'][k % 2])
    if func == 'dissect_h248_annexc_SDP_M':
        return tlv(0x16, [b'audio 5004 RTP/AVP 0 8', b'video 49170 RTP/AVP 31', b'audio x RTP/AVP 0',
                          b'audio', b'audio 5004', b'audio 5004 '][k % 6])
    if func in ('dissect_3GTFO_codec_list', 'dissect_3GTFO_codec_mode'):
        if k % 3 == 2:
            return b'\x30\x02\x00\x01'           # not an OCTET STRING
        return tlv(4, CODEC_LIST[:2 * (1 + k % 6)] if func.endswith('list') else CODECS[k % len(CODECS)])
    if func == 'dissect_3gcsd_plmnbc':
        return tlv(4, [b'\x04\x06\x60\x04\x02\x01\x00\x00', b'\x00\x01\x02\x03\x04\x05\x06\x07',
                       b'\x06\x00\x00\x00\x04'][k % 3])
    if func == 'dissect_bt_tunneled_proto':
        if k % 3 == 2:
            return b'\x30\x01\x00'               # not an OCTET STRING
        return tlv(4, BCTP_IPBCP if k % 3 == 0 else b'\x00\x01\x02\x03')
    raise KeyError(func)


# ------------------------------------------------------------- messages

def term_id(tid=b'\x01\x02', wild=None):
    """TerminationID ::= SEQUENCE { wildcard [0] SEQUENCE OF WildcardField,
    id [1] OCTET STRING }"""
    w = tlv(0xA0, *[tlv(0x04, x) for x in (wild or [])])
    return tlv(0x30, w, tlv(0x81, tid))


def term_list(*terms):
    return tlv(0xA0, *terms)          # terminationID [0] SEQUENCE OF TerminationID


def prop_parm(pkg, item, vals, extra=b''):
    """PropertyParm { name [0] PkgdName, value [1] SEQUENCE OF PropertyID }"""
    return tlv(0x30, tlv(0x80, struct.pack('>HH', pkg, item)), tlv(0xA1, *[tlv(0x04, v) for v in vals]), extra)


def media_desc(*props, tsd=True):
    """mediaDescriptor [0] { termStateDescr [1]? ...}: here the
    termStateDescr [1] holds propertyParms [0]; also reachable through
    the local control descriptor of a stream (see stream_desc)."""
    return tlv(0xA0, tlv(0xA1, tlv(0xA0, *props)))


def stream_desc(sid, lcd_props, local=None, remote=None):
    lcd = tlv(0xA1, tlv(0x80, b'\x02'), tlv(0xA3, *lcd_props)) if lcd_props else b''
    return tlv(0xA0, tlv(0xA3, tlv(0x30, tlv(0x80, bytes([sid])), lcd)))


def amm(kind, terms, descs):
    """AmmRequest { terminationID [0], descriptors [1] SEQUENCE OF AmmDescriptor }"""
    return tlv(kind, term_list(*terms), tlv(0xA1, *descs))


def cmd_req(cmdtag, body):
    """CommandRequest { command [0] Command }, Command CHOICE tagged cmdtag"""
    return tlv(0x30, tlv(0xA0, tlv(cmdtag, *body)))


def action(ctx, cmds, ctx_req=b'', audit=b''):
    return tlv(0x30, tlv(0x80, ber_int(ctx) if ctx < 0x80000000 else u32(ctx)),
               ctx_req, audit, tlv(0xA3, *cmds))


def trx_req(tid, actions):
    return tlv(0xA0, tlv(0x80, ber_int(tid) if tid < 0x80000000 else u32(tid)), tlv(0xA1, *actions))


def megaco(transactions, version=2, mid=None, auth=None):
    mid = mid if mid is not None else MID_DOM
    # mId [1] MId: ip4Address [0], ip6 [1], domainName [2], deviceName [3], mtpAddress [4]
    body = tlv(0xA2, tlv(0xA1, *transactions))
    msg = tlv(0xA1, tlv(0x80, bytes([version])), mid, body)
    return tlv(0x30, auth or b'', msg)


MID_DOM = tlv(0xA1, tlv(0xA2, tlv(0x80, b'mg.example.invalid'), tlv(0x81, b'\x0b\x80')))
MID_IP4 = tlv(0xA1, tlv(0xA0, tlv(0x80, bytes([192, 0, 2, 1])), tlv(0x81, b'\x0b\x81')))


# ------------------------------------------------- generic message generator

class Sweep:
    """Queues of package table entries still to be put in a message, and
    the entry the last name hook chose (the hooks for the parameter names
    and values follow it, in the order the dissector reads them)."""

    def __init__(self, pkgs=None, seed=5):
        self.rnd = random.Random(seed)
        self.pkgs = pkgs if pkgs is not None else sorted(p for p in PKGS if p not in UNREGISTERED)
        self.q = {'prop': [], 'sig': [], 'evt': [], 'stat': []}
        self.k = 0
        self.cur = None              # (kind, pkg, item, [(param id, func, data)], chosen param or None)
        self.par = None
        self.version = 2
        self.fill()

    def fill(self):
        for pid in self.pkgs:
            for d in PKGS[pid]:
                for it, f, dat, ft in d['props']:
                    self.q['prop'].append((pid, it, f, dat, ft))
                for kind, key in (('sig', 'sigs'), ('evt', 'evts'), ('stat', 'stats')):
                    for it, params in d[key]:
                        if not params:
                            self.q[kind].append((pid, it, None))
                        for p in params:
                            self.q[kind].append((pid, it, p))

    def pending(self):
        return sum(len(v) for v in self.q.values())

    def pick(self, kind):
        if self.q[kind]:
            return self.q[kind].pop(0)
        # nothing left: a random entry of any package, or an unknown one
        pid = self.rnd.choice(self.pkgs + [0x7777])
        ds = PKGS.get(pid, [])
        if kind == 'prop':
            ents = [(pid, it, f, dat, ft) for d in ds for it, f, dat, ft in d['props']]
        else:
            key = {'sig': 'sigs', 'evt': 'evts', 'stat': 'stats'}[kind]
            ents = [(pid, it, (ps[0] if ps else None)) for d in ds for it, ps in d[key] for _ in [0]]
        if not ents:
            return (pid, self.rnd.choice([0, 1, 9]), None) if kind != 'prop' else (pid, 1, 'NULL', 'NULL', None)
        return self.rnd.choice(ents)

    def nextk(self):
        self.k += 1
        return self.k


def install_hooks(g, sw, mids=None):
    rnd = sw.rnd

    def b4(pid, it):
        return struct.pack('>HH', pid, it)

    def pkgd(gg):
        name = gg.path[-1] if gg.path else ''
        if name == 'propertyName':
            e = sw.pick('prop')
            sw.cur = ('prop', e[0], e[1], e[2:], None)
            return b4(e[0], e[1])
        if name == 'statName':
            e = sw.pick('stat')
            sw.cur = ('stat', e[0], e[1], e[2], None)
            return b4(e[0], e[1])
        kind = 'evt' if name in ('pkgdName', 'eventName') else 'sig' if name == 'signalName' else 'stat'
        e = sw.pick(kind)
        return b4(e[0], e[1])

    def evtname(gg):
        e = sw.pick('evt')
        sw.cur = ('evt', e[0], e[1], e[2], None)
        return b4(e[0], e[1])

    def signame(gg):
        e = sw.pick('sig')
        sw.cur = ('sig', e[0], e[1], e[2], None)
        return b4(e[0], e[1])

    def parname(gg):
        c = sw.cur
        pid = 0xffff
        if c and c[3]:
            pid = c[3][0]
        n = [2, 1, 4, 3][sw.nextk() % 4]
        return pid.to_bytes(n, 'big') if pid < (1 << (8 * n)) else pid.to_bytes(4, 'big')

    def parvalue(gg):
        c = sw.cur
        if c and c[3]:
            return value(c[3][1], c[3][2], c[3][0], sw.nextk(), c[3][3])
        return tlv(4, b'\x01\x02')

    def propvalue(gg):
        c = sw.cur
        if c and c[0] == 'prop' and c[3] and c[3][0] not in ('NULL',):
            return value(c[3][0], c[3][1], c[2], sw.nextk(), c[3][2])
        return tlv(4, b'\x05')

    gh = g.type_hooks
    gh['PkgdName'] = pkgd
    gh['EventName'] = evtname
    gh['SignalName'] = signame
    gh['SigParameterName'] = parname
    gh['EventParameterName'] = parname
    gh['SigParamValue'] = parvalue
    gh['EventParamValue'] = parvalue
    gh['PropertyID'] = propvalue
    gh['SCreasonValueOctetStr'] = lambda gg: tlv(0x16, rnd.choice([b'900', b'Service Restored', b'MG restart']))
    gh['WildcardField'] = lambda gg: bytes([rnd.choice([0x00, 0x40, 0x80, 0xc0, 0x81, 0x43])])
    gh['MtpAddress'] = lambda gg: bytes(rnd.choice([(1, 2), (0x12, 0x34), (0, 1, 2, 3), (0x20, 0x44, 0x21)]))
    ih = g.int_hooks
    ih['version'] = lambda gg: sw.version
    ih['transactionId'] = lambda gg: rnd.choice([1, 2, 3, 7, 0x1234, 0xfffffff0])
    ih['firstAck'] = ih['lastAck'] = ih['transactionId']
    ih['contextId'] = lambda gg: rnd.choice([0, 1, 5, 0xfffffffe, 0xffffffff, 0x7fffff00])
    ih['errorCode'] = lambda gg: rnd.choice([400, 411, 430, 500, 903, 999, 0])
    ih['portNumber'] = lambda gg: rnd.choice([2944, 2945, 49152])
    return g


# ------------------------------------------------------------- framing

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return socket.inet_aton(s)


IDENT = [0]


def ethip(proto, payload, src, dst):
    IDENT[0] += 1
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IDENT[0] & 0xffff, 0x4000, 64, proto, 0,
                      ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return b'\x02\x00' + ip4(dst) + b'\x02\x00' + ip4(src) + b'\x08\x00' + hdr + payload


def udp(payload, src='192.0.2.1', sport=2945, dst='192.0.2.2', dport=2945):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    return (0, ethip(17, u, src, dst))


class TCP:
    def __init__(self, cli='192.0.2.1', cport=40000, srv='192.0.2.2', sport=2945):
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.cseq, self.sseq = 1000, 5000

    def seg(self, payload, to_server, flags=0x18):
        if to_server:
            src, sp, dst, dp, s, a = self.cli, self.cport, self.srv, self.sport, self.cseq, self.sseq
        else:
            src, sp, dst, dp, s, a = self.srv, self.sport, self.cli, self.cport, self.sseq, self.cseq
        opts = b''
        if flags & 0x02:
            opts = b'\x02\x04\x05\xb4'
            if not flags & 0x10:
                a = 0
        t = struct.pack('!HHIIBBHHH', sp, dp, s, a, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return (0, ethip(6, t, src, dst))

    def handshake(self):
        f = [self.seg(b'', True, 0x02)]
        self.cseq += 1
        f.append(self.seg(b'', False, 0x12))
        self.sseq += 1
        f.append(self.seg(b'', True, 0x10))
        return f

    def c2s(self, payload):
        f = self.seg(payload, True)
        self.cseq += len(payload)
        return f

    def s2c(self, payload):
        f = self.seg(payload, False)
        self.sseq += len(payload)
        return f


def tpkt(payload):
    return struct.pack('>BBH', 3, 0, 4 + len(payload)) + payload


LT_ETH, LT_MTP3, LT_EXPPDU = 1, 141, 252


def pcapng(path, frames):
    """frames: list of (interface, bytes); interface 0 Ethernet, 1 MTP3,
    2 Exported PDU."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', LT_ETH, 0, 262144))
    out += block(1, struct.pack('<HHI', LT_MTP3, 0, 262144))
    out += block(1, struct.pack('<HHI', LT_EXPPDU, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def mtp3(payload, si=14, opc=0x1234, dpc=0x0567, sls=0, ni=2):
    """ITU 14 bit point codes: SIO, then the routing label (32 bits)."""
    sio = (ni << 6) | si
    label = (dpc & 0x3fff) | ((opc & 0x3fff) << 14) | ((sls & 0xf) << 28)
    return (1, bytes([sio]) + struct.pack('<I', label) + payload)


def v1_text(text, v1text):
    """The H.248 v3 module with the version 1 types (h248v1support.asn)
    in place of EventParameter, SigParameter and AuditReply."""
    body = v1text[v1text.index('BEGIN') + 5:v1text.rindex('END')]
    text = text.replace('SEQUENCE OF EventParameter', 'SEQUENCE OF EventParameterV1')
    text = text.replace('SEQUENCE OF SigParameter', 'SEQUENCE OF SigParameterV1')
    text = text.replace('[4] AuditReply,', '[4] AuditReplyV1,').replace('[5] AuditReply,', '[5] AuditReplyV1,')
    i = text.rindex('END')
    return text[:i] + body + text[i:]


def udp6(payload, src='2001:db8::1', sport=2945, dst='2001:db8::2', dport=2945):
    s, d = socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = s + d + struct.pack('!IBBBB', len(u), 0, 0, 0, 17)
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    ip = struct.pack('!IHBB', 0x60000000, len(u), 17, 64) + s + d
    return (0, b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x86\xdd' + ip + u)


def exported_pdu(proto_name, payload):
    """Exported PDU: the dissector name tag, then the PDU; no addresses."""
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('!HH', 0, 0)
    return (2, tags + payload)
