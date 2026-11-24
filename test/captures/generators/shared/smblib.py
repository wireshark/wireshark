#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared SMB1 frame helpers (from the smb-coverage generator).


# addresses are documentation addresses, nothing comes from a network.
# No keys, passwords or ciphertext are produced: password fields are empty.
import struct
import sys
import os

MAC_C = bytes.fromhex('020000000011')
MAC_S = bytes.fromhex('020000000012')
IP_C = bytes([198, 51, 100, 1])
IP_S = bytes([198, 51, 100, 2])
U16 = lambda *a: struct.pack('<%dH' % len(a), *a)
U32 = lambda *a: struct.pack('<%dI' % len(a), *a)
U64 = lambda *a: struct.pack('<%dQ' % len(a), *a)
U8 = lambda *a: bytes(a)
NT = 0x01d0000000000000      # an NT time, fixed





def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    def __init__(self, name):
        self.name = name
        self.f = open(name, 'wb')
        self.f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        self.t = 1700000000
        self.n = 0
        self.record = None

    def raw(self, frame):
        self.n += 1
        self.t += 1
        self.f.write(struct.pack('<IIII', self.t, 0, len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.close()


class Conn:
    """A TCP connection client:cport <-> server:sport with NBSS framing."""

    def __init__(self, cap, cport, sport=445, uni=False, ipc=False):
        self.cap, self.cport, self.sport = cap, cport, sport
        self.seq = {True: 1000, False: 70000}
        self.mid = 0
        self.uni = uni
        self.uid = 0x0800
        self.pid = 0x1234
        self.tid = 1
        self.flags2 = 0xc001 if uni else 0x4001
        self.ipid = 1
        self.tcp(True, b'', 0x02)
        self.tcp(False, b'', 0x12)
        self.tcp(True, b'', 0x10)

    def tcp(self, to_server, payload, flags=0x18):
        if to_server:
            src, dst, sp, dp, ms, md = IP_C, IP_S, self.cport, self.sport, MAC_C, MAC_S
        else:
            src, dst, sp, dp, ms, md = IP_S, IP_C, self.sport, self.cport, MAC_S, MAC_C
        seq = self.seq[to_server]
        ack = self.seq[not to_server]
        self.seq[to_server] += len(payload) + (1 if flags & 3 else 0)
        # an ACK bit-only packet must not carry data; flags 0x18 = PSH|ACK
        opts = b'\x02\x04\x05\xb4' if flags & 2 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        self.ipid += 1
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.ipid, 0x4000, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.cap.raw(md + ms + b'\x08\x00' + ip + tcp + payload)

    # --- SMB construction -------------------------------------------------
    def hdr(self, cmd, reply, mid=None, tid=None, pid=None, uid=None,
            flags2=None, status=0, flags=None, ecls=None):
        if flags is None:
            flags = 0x18 | (0x80 if reply else 0)
        f2 = self.flags2 if flags2 is None else flags2
        if f2 & 0x4000:
            st = struct.pack('<I', status)
        else:
            st = struct.pack('<BBH', ecls or 0, 0, status & 0xffff)
        return (b'\xffSMB' + bytes([cmd]) + st + bytes([flags]) + struct.pack('<H', f2) +
                struct.pack('<H', 0) + b'\0' * 8 + struct.pack('<H', 0) +
                struct.pack('<HHHH', self.tid if tid is None else tid,
                            self.pid if pid is None else pid,
                            self.uid if uid is None else uid,
                            self.mid if mid is None else mid))

    def smb(self, cmd, reply, words=b'', data=b'', wc=None, bc=None, **kw):
        """data may be bytes, or a list of bytes/str: str items are encoded
        as ASCII or UTF-16LE (aligned to the SMB start) with a terminator."""
        h = self.hdr(cmd, reply, **kw)
        if wc is None:
            assert len(words) % 2 == 0, (cmd, len(words))
            wc = len(words) // 2
        uni = (kw.get('flags2') or self.flags2) & 0x8000
        base = 32 + 1 + len(words) + 2
        if isinstance(data, (list, tuple)):
            out = b''
            for it in data:
                if isinstance(it, str):
                    if uni:
                        if (base + len(out)) % 2:
                            out += b'\0'
                        out += it.encode('utf-16le') + b'\0\0'
                    else:
                        out += it.encode('latin-1') + b'\0'
                else:
                    out += it
            data = out
        return h + bytes([wc]) + words + struct.pack('<H', len(data) if bc is None else bc) + data

    def send(self, to_server, *pdus):
        """One TCP segment with all PDUs NBSS framed."""
        out = b''
        for p in pdus:
            if self.cap.record is not None:
                self.cap.record.append((to_server, p))
            out += struct.pack('!BBH', 0, (len(p) >> 16) & 1, len(p) & 0xffff) + p
        self.tcp(to_server, out)

    def nextmid(self):
        self.mid += 1
        return self.mid

    def rr(self, cmd, rwords=b'', rdata=b'', qwords=b'', qdata=b'', status=0,
           qkw=None, rkw=None, **kw):
        """Request + response pair with a fresh MID, two TCP segments."""
        self.nextmid()
        a = dict(kw); a.update(qkw or {})
        b = dict(kw); b.update(rkw or {})
        self.send(True, self.smb(cmd, False, qwords, qdata, **a))
        self.send(False, self.smb(cmd, True, rwords, rdata, status=status, **b))


B4 = b'\x04'
def _layout(c, uni, base0, name, params, data, align):
    """Offsets of name, params and data relative to the SMB start."""
    nm = b''
    if name is False:
        pass
    elif name is not None:
        if uni:
            if base0 % 2:
                nm += b'\0'
            nm += name.encode('utf-16le') + b'\0\0'
        else:
            nm += name.encode('latin-1') + b'\0'
    else:
        nm = b'\0' if not uni else b'\0\0'
    po = base0 + len(nm)
    pad1 = (-po) % align
    po += pad1
    od = po + len(params)
    pad2 = (-od) % align
    od += pad2
    body = nm + b'\0' * pad1 + params + b'\0' * pad2 + data
    return po, od, body


def trans_req(c, cmd, setup=b'', params=b'', data=b'', name=None, tpc=None, tdc=None,
              flags=0, timeout=1000, mpc=64, mdc=4096, **kw):
    """Primary Transaction / Transaction2 request."""
    uni = (kw.get('flags2') or c.flags2) & 0x8000
    sc = len(setup) // 2
    wc = 14 + sc
    base = 32 + 1 + 2 * wc + 2
    po, od, body = _layout(c, uni, base, name, params, data, 4)
    words = U16(len(params) if tpc is None else tpc, len(data) if tdc is None else tdc, mpc, mdc) + U8(0, 0) + \
        U16(flags) + U32(timeout) + U16(0) + U16(len(params), po, len(data), od if data else 0) + U8(sc, 0) + setup
    return c.hdr(cmd, False, **kw) + bytes([wc]) + words + U16(len(body)) + body


def trans_resp(c, cmd, setup=b'', params=b'', data=b'', tpc=None, tdc=None, pd=0, dd=0, **kw):
    uni = (kw.get('flags2') or c.flags2) & 0x8000
    sc = len(setup) // 2
    wc = 10 + sc
    base = 32 + 1 + 2 * wc + 2
    po, od, body = _layout(c, uni, base, False, params, data, 4)
    words = U16(len(params) if tpc is None else tpc, len(data) if tdc is None else tdc, 0) + \
        U16(len(params), po, pd, len(data), od, dd) + U8(sc, 0) + setup
    return c.hdr(cmd, True, **kw) + bytes([wc]) + words + U16(len(body)) + body


def trans_sec(c, cmd, tpc, tdc, params=b'', pd=0, data=b'', dd=0, fid=0, **kw):
    """Transaction (0x26) / Transaction2 (0x33) secondary request."""
    uni = (kw.get('flags2') or c.flags2) & 0x8000
    wc = 9 if cmd == 0x33 else 8
    base = 32 + 1 + 2 * wc + 2
    po, od, body = _layout(c, 0, base, False, params, data, 4)
    words = U16(tpc, tdc, len(params), po, pd, len(data), od if data else 0, dd)
    if cmd == 0x33:
        words += U16(fid)
    return c.hdr(cmd, False, **kw) + bytes([wc]) + words + U16(len(body)) + body


def interim(c, cmd, **kw):
    return c.hdr(cmd, True, **kw) + b'\0' + U16(0)


def eth_frame(cap, dst, src, etype, payload):
    cap.raw(dst + src + struct.pack('!H', etype) + payload)

def nb_name(name, typ=0x20):
    n = name.ljust(15)[:15].encode() + bytes([typ])
    return b'\x20' + bytes(0 for b in b'')[:0] + bytes(sum(([65 + (b >> 4), 65 + (b & 15)] for b in n), [])) + b'\0'



def udp_frame(cap, src, dst, sport, dport, payload, msrc=None, mdst=None, ipid=1):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ipid, 0x4000, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    cap.raw((mdst or MAC_S) + (msrc or MAC_C) + b'\x08\x00' + ip + udp)


def nbds(cap, c, smbpdu, src='HOST1', dst='WORKGROUP', dtype=0x1d, ip=None, msgtype=0x11, ipid=1):
    """NetBIOS datagram (UDP 138) carrying an SMB PDU."""
    ip = ip or IP_C
    h = struct.pack('!BBH', msgtype, 0x02, 0x1234) + ip + struct.pack('!HHH', 138, 68 + len(smbpdu), 0) + \
        nb_name(src, 0) + nb_name(dst, dtype) + smbpdu
    udp_frame(cap, ip, IP_S, 138, 138, h, ipid=ipid)


def hdr_conn(cap, uni=False):
    """A Conn used only to build SMB headers (no TCP handshake)."""
    c = Conn.__new__(Conn)
    c.cap, c.cport, c.sport = cap, 0, 0
    c.seq = {True: 0, False: 0}
    c.mid, c.uni, c.uid, c.pid, c.tid = 0, uni, 0x0800, 0x1234, 1
    c.flags2 = 0xc001 if uni else 0x4001
    c.ipid = 1
    return c
