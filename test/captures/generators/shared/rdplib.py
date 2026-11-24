# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared helpers for the RDP family coverage generators (batch 33).
# Copied into every <name>-coverage directory.  Builds Ethernet/IPv4 frames
# (TCP and UDP), TPKT/COTP, T.125 (MCS) and the RDP connection setup.
import struct

MAC_C = bytes.fromhex('020000000002')
MAC_S = bytes.fromhex('020000000001')
IP_C = bytes([192, 0, 2, 2])
IP_S = bytes([192, 0, 2, 1])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    """pcapng writer: interface 0 is Ethernet, interface 1 is Exported PDU (252)."""

    def __init__(self):
        self.frames = []
        self.t = 1700000000.0

    def add(self, data, lt=1):
        self.t += 0.001
        self.frames.append((self.t, data, lt))
        return len(self.frames)

    def exp(self, proto, payload, c2s=True, sport=50000, dport=3389, heur=False, pt=2, tags=None):
        """An Exported PDU frame: `proto` is a dissector name (or a heuristic
        dissector name when heur is true)."""
        a, b = (IP_C, IP_S) if c2s else (IP_S, IP_C)
        sp, dp = (sport, dport) if c2s else (dport, sport)
        t = tlv(13 if heur else 12, proto.encode())
        t += tlv(20, a) + tlv(21, b) + tlv(24, struct.pack('>I', pt))
        t += tlv(25, struct.pack('>I', sp)) + tlv(26, struct.pack('>I', dp))
        if tags:
            t += tags
        t += struct.pack('>HH', 0, 0)
        return self.add(t + payload, 252)

    def write(self, name):
        def block(typ, body):
            body += b'\0' * (-len(body) % 4)
            return struct.pack('<II', typ, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += block(1, struct.pack('<HHI', 1, 0, 262144))
        out += block(1, struct.pack('<HHI', 252, 0, 262144))
        for t, p, lt in self.frames:
            us = int(round(t * 1e6))
            body = struct.pack('<IIIII', 0 if lt == 1 else 1, us >> 32, us & 0xffffffff, len(p), len(p)) + p
            out += block(6, body)
        with open(name, 'wb') as f:
            f.write(out)


def tlv(t, v):
    return struct.pack('>HH', t, len(v)) + v


def ip4(src, dst, proto, payload, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def eth(src, dst, payload):
    return dst + src + b'\x08\x00' + payload


class Tcp:
    """One TCP connection client -> server (port 3389 by default)."""

    def __init__(self, cap, sport=50000, dport=3389, mss=1400):
        self.cap = cap
        self.sport, self.dport = sport, dport
        self.cseq, self.sseq = 1000, 5000
        self.ident = 1
        self.mss = mss

    def _seg(self, c2s, flags, payload=b'', seq=None, ack=None, opts=b''):
        if c2s:
            s, d, sp, dp, mac_s, mac_d = IP_C, IP_S, self.sport, self.dport, MAC_C, MAC_S
            sq, ak = self.cseq, self.sseq
        else:
            s, d, sp, dp, mac_s, mac_d = IP_S, IP_C, self.dport, self.sport, MAC_S, MAC_C
            sq, ak = self.sseq, self.cseq
        if seq is not None:
            sq = seq
        if ack is not None:
            ak = ack
        th = struct.pack('>HHIIBBHHH', sp, dp, sq & 0xffffffff, ak & 0xffffffff, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        ph = s + d + struct.pack('>BBH', 0, 6, len(th) + len(payload))
        ck = csum(ph + th + payload)
        th = th[:16] + struct.pack('>H', ck) + th[18:]
        self.ident += 1
        return self.cap.add(eth(mac_s, mac_d, ip4(s, d, 6, th + payload, self.ident)))

    def open(self):
        mss = b'\x02\x04\x05\xb4'
        self._seg(True, 0x02, ack=0, opts=mss)
        self.cseq += 1
        self._seg(False, 0x12, opts=mss)
        self.sseq += 1
        self._seg(True, 0x10)

    def send(self, c2s, payload, retrans_of=None):
        n = None
        for i in range(0, max(len(payload), 1), self.mss):
            chunk = payload[i:i + self.mss]
            n = self._seg(c2s, 0x18, chunk)
            if c2s:
                self.cseq += len(chunk)
            else:
                self.sseq += len(chunk)
        return n

    def raw_segment(self, c2s, payload, seq):
        """A segment at an explicit sequence number (does not move the state)."""
        return self._seg(c2s, 0x18, payload, seq=seq)


def udp(cap, c2s, payload, sport=50000, dport=3389, ident=1):
    if c2s:
        s, d, sp, dp, ms, md = IP_C, IP_S, sport, dport, MAC_C, MAC_S
    else:
        s, d, sp, dp, ms, md = IP_S, IP_C, dport, sport, MAC_S, MAC_C
    uh = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0)
    return cap.add(eth(ms, md, ip4(s, d, 17, uh + payload, ident)))


# ---------------------------------------------------------------- TPKT / COTP
def tpkt(payload):
    return b'\x03\x00' + struct.pack('>H', len(payload) + 4) + payload


def cotp_cr(user_data, dst_ref=0, src_ref=0x1234):
    body = struct.pack('>HHB', dst_ref, src_ref, 0) + user_data
    return tpkt(bytes([len(body) + 1, 0xe0]) + body)


def cotp_cc(user_data, dst_ref=0x1234, src_ref=0x4321):
    body = struct.pack('>HHB', dst_ref, src_ref, 0) + user_data
    return tpkt(bytes([len(body) + 1, 0xd0]) + body)


def cotp_dt(data):
    return tpkt(b'\x02\xf0\x80' + data)


def neg_req(proto=1, flags=0, extra=b''):
    return struct.pack('<BBHI', 1, flags, 8, proto) + extra


def neg_rsp(proto=1, flags=0):
    return struct.pack('<BBHI', 2, flags, 8, proto)


def neg_fail(code=2):
    return struct.pack('<BBHI', 3, 0, 8, code)


# ---------------------------------------------------------------- BER / PER
def ber_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xff])


def ber(tag, body):
    return tag + ber_len(len(body)) + body


def per_len(n):
    if n < 0x80:
        return bytes([n])
    assert n < 0x4000
    return bytes([0x80 | (n >> 8), n & 0xff])


def domparams():
    return ber(b'\x30', b''.join(ber(b'\x02', bytes([v])) for v in (34, 2, 0, 1, 0, 1, 0xff, 2)))


def connect_initial(blocks):
    cd = b''.join(blocks)
    gcc = b'\x00\x08\x00\x10\x00\x01\xc0\x00Duca' + per_len(len(cd)) + cd
    ud = b'\x00\x05\x00\x14\x7c\x00\x01' + per_len(len(gcc)) + gcc
    body = ber(b'\x04', b'\x01') + ber(b'\x04', b'\x01') + ber(b'\x01', b'\xff')
    body += domparams() * 3 + ber(b'\x04', ud)
    return ber(b'\x7f\x65', body)


def connect_response(blocks):
    sd = b''.join(blocks)
    gcc = b'\x14\x76\x0a\x01\x01\x00\x01\xc0\x00McDn' + per_len(len(sd)) + sd
    ud = b'\x00\x05\x00\x14\x7c\x00\x01' + per_len(len(gcc)) + gcc
    body = ber(b'\x0a', b'\x00') + ber(b'\x02', b'\x00') + domparams() + ber(b'\x04', ud)
    return ber(b'\x7f\x66', body)


def mcs_erect():
    return b'\x04\x01\x00\x01\x00'


def mcs_attach_req():
    return b'\x28'


def mcs_attach_conf(user=1001):
    return b'\x2e\x00' + struct.pack('>H', user - 1001)


def mcs_join_req(chan, user=1001):
    return b'\x38' + struct.pack('>HH', user - 1001, chan)


def mcs_join_conf(chan, user=1001):
    return b'\x3e\x00' + struct.pack('>HHH', user - 1001, chan, chan)


def send_data_req(chan, data, user=1001):
    return b'\x64' + struct.pack('>HH', user - 1001, chan) + b'\x70' + per_len(len(data)) + data


def send_data_ind(chan, data, user=1002):
    return b'\x68' + struct.pack('>HH', user - 1001, chan) + b'\x70' + per_len(len(data)) + data


# ---------------------------------------------------------------- GCC blocks
def blk(t, body):
    return struct.pack('<HH', t, len(body) + 4) + body


def cs_core(optional=99, name='CLIENT', width=1024, height=768, build=19041):
    b = struct.pack('<HHHHHHII', 4, 8, width, height, 0xca01, 0xaa03, 0x409, build)
    b += name.encode('utf-16le').ljust(32, b'\0')
    b += struct.pack('<III', 4, 0, 12) + b'\0' * 64
    opt = [struct.pack('<H', 0xca01), struct.pack('<H', 1), struct.pack('<I', 0x1234),
           struct.pack('<H', 24), struct.pack('<H', 0x0f), struct.pack('<H', 0x0001),
           ('DIGPRODID').encode('utf-16le').ljust(64, b'\0'), b'\x07', b'\0', struct.pack('<I', 3)]
    n = 0
    for o in opt:
        if n >= optional:
            break
        b += o
        n += 1
    return blk(0xC001, b)


def cs_security(enc=0x1b, ext=0):
    return blk(0xC002, struct.pack('<II', enc, ext))


def cs_net(channels, opts=0xc0a00000):
    net = struct.pack('<I', len(channels))
    for name in channels:
        if isinstance(name, tuple):
            name, o = name
        else:
            o = opts
        net += name.encode().ljust(8, b'\0') + struct.pack('<I', o)
    return blk(0xC003, net)


def cs_cluster(flags=0x0d, session=7):
    return blk(0xC004, struct.pack('<II', flags, session))


def cs_monitor(mons):
    b = struct.pack('<II', 0, len(mons))
    for m in mons:
        b += struct.pack('<iiiiI', *m)
    return blk(0xC005, b)


def cs_msgchannel(flags=0):
    return blk(0xC006, struct.pack('<I', flags))


def cs_monitor_ex(n=1):
    return blk(0xC008, struct.pack('<III', 0, 20, n))


def cs_multitransport(flags=0x305):
    return blk(0xC00A, struct.pack('<I', flags))


def sc_core(version=0x80004, req=3, early=0x0001):
    return blk(0x0C01, struct.pack('<IIH', version, req, early))


def sc_security(method=0, level=0, rnd=b'', cert=b''):
    b = struct.pack('<II', method, level)
    if method or level:
        b += struct.pack('<II', len(rnd), len(cert)) + rnd + cert
    return blk(0x0C02, b)


def sc_net(mcs_id, ids):
    b = struct.pack('<HH', mcs_id, len(ids)) + b''.join(struct.pack('<H', i) for i in ids)
    if len(ids) % 2:
        b += b'\0\0'
    return blk(0x0C03, b)


def sc_msgchannel(chan):
    return blk(0x0C04, struct.pack('<H', chan))


def sc_multitransport(flags=0x305):
    return blk(0x0C08, struct.pack('<I', flags))


# ---------------------------------------------------------------- RDP PDUs
def sec_hdr(flags, hi=0):
    return struct.pack('<HH', flags, hi)


def share_ctrl(pdutype, body, source=1002, ver=0x10):
    return struct.pack('<HHH', len(body) + 6, pdutype | ver, source) + body


def share_data(pdutype2, body, share=0x103ea, stream=1, ctype=0, clen=0):
    h = struct.pack('<IBBHBBH', share, 0, stream, len(body) + 4, pdutype2, ctype, clen)
    return share_ctrl(7, h + body)


def chan_pdu(length, flags, payload):
    return struct.pack('<II', length, flags) + payload


def chan_single(payload, flags=3):
    return chan_pdu(len(payload), flags, payload)


# ---------------------------------------------------------------- sessions
MCSCHAN = 1003
MSGCHAN = 1011


def lic_alert():
    return struct.pack('<BBH', 0xff, 3, 16) + struct.pack('<IIHH', 7, 2, 1, 4) + b'\0\0\0\0'


class Session:
    """A TCP connection (port 3389) carrying an RDP session without
    encryption up to the point where static channel PDUs can flow."""

    def __init__(self, cap, sport, channels, first_id=1004, msgchan=False, cs_extra=(), sc_extra=()):
        self.cap = cap
        self.t = Tcp(cap, sport=sport)
        self.sport = sport
        self.ids = [first_id + i for i in range(len(channels))]
        self.names = list(channels)
        t = self.t
        t.open()
        t.send(True, cotp_cr(neg_req(0, 0)))
        t.send(False, cotp_cc(neg_rsp(0, 0)))
        cb = [cs_core(), cs_security(0x1b, 0), cs_net(channels)] + list(cs_extra)
        t.send(True, cotp_dt(connect_initial(cb)))
        sb = [sc_core(), sc_security(0, 0), sc_net(MCSCHAN, self.ids)]
        if msgchan:
            sb.append(sc_msgchannel(MSGCHAN))
        t.send(False, cotp_dt(connect_response(sb + list(sc_extra))))
        t.send(True, cotp_dt(mcs_erect()))
        t.send(True, cotp_dt(mcs_attach_req()))
        t.send(False, cotp_dt(mcs_attach_conf(1001)))
        t.send(False, cotp_dt(send_data_ind(MCSCHAN, sec_hdr(0x0080) + lic_alert())))

    def chan(self, name, payload, c2s=False, flags=3, length=None):
        """One channel PDU (CHANNEL_PDU_HEADER + payload) on the static channel `name`."""
        cid = self.ids[self.names.index(name)]
        pdu = chan_pdu(len(payload) if length is None else length, flags, payload)
        if c2s:
            return self.t.send(True, cotp_dt(send_data_req(cid, pdu)))
        return self.t.send(False, cotp_dt(send_data_ind(cid, pdu)))

    def chunks(self, name, payload, c2s=False, size=1000):
        """The payload in CHANNEL_FLAG_FIRST ... CHANNEL_FLAG_LAST chunks."""
        parts = [payload[i:i + size] for i in range(0, len(payload), size)]
        for i, p in enumerate(parts):
            fl = (1 if i == 0 else 0) | (2 if i == len(parts) - 1 else 0)
            self.chan(name, p, c2s, fl, len(payload))

    def msg(self, body, c2s=False):
        if c2s:
            return self.t.send(True, cotp_dt(send_data_req(MSGCHAN, body)))
        return self.t.send(False, cotp_dt(send_data_ind(MSGCHAN, body)))
