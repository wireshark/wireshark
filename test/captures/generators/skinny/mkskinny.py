#!/usr/bin/env python3
# Generates test/captures/skinny_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the SKINNY dissector
(packet-skinny.c, generated from tools/dissector_generators/
SkinnyProtocolOptimized.xml).

The SKINNY PDUs are built from the same XML file the dissector is
generated from (a copy is next to this script): for every message and
for a set of header versions the fields of the groups that apply to the
version are serialised with the layout the generated handler expects
(fixed arrays always take their maximum number of entries, dynamic
messages hold NUL-terminated strings, unions take the branch selected
by their guard field). Values are chosen from the enum tables of the
XML; request and response messages share the pass-through party id so
that the request/response tracking of the dissector links them.

Capture layout, all on TCP port 2000 (registered by default), phone
192.0.2.1, call manager 192.0.2.2:

  - one TCP stream per header version; the PDUs of a stream are packed
    several to a TCP segment, and some PDUs are split over two segments
    (desegmentation);
  - a call scenario with registration, call state, call info and
    media set-up;
  - the reproducers of the fixed bug (soft key template with display
    labels, SoftKeyTemplateRes, many embedded labels).

Usage: mkskinny.py <output directory>
Writes skinny-coverage.pcap and skinny-coverage-malformed.pcap.
"""

import os
import struct
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = ET.parse(os.path.join(HERE, '..', '..', '..', '..', 'tools', 'dissector_generators',
                        'SkinnyProtocolOptimized.xml')).getroot()

VERSIONS = (0, 10, 11, 15, 16, 17, 18, 19, 20, 21, 22)   # the header versions of the dissector
MAIN_VERSIONS = (0, 11, 17, 22)   # below and above the version thresholds of the XML
PPID = 0x00012345     # pass-through party id shared by requests and responses
CALLREF = 0x00005000

INT_SIZES = {'uint32': 4, 'uint16': 2, 'uint8': 1, 'int32': 4, 'int16': 2, 'int8': 1, 'ipport': 4}


# ------------------------------------------------------------- the XML model

ENUMS = {}      # subtype -> [values]
ENTRY_VALUES = {}  # entry name (upper) -> value
for e in ROOT.findall('enum'):
    vals = []
    for entries in e.findall('entries'):
        for en in entries.findall('entry'):
            v = int(en.get('value'), 0)
            vals.append(v)
            ENTRY_VALUES[en.get('name').upper()] = v
    name = e.get('name')
    ENUMS[name[0].upper() + name[1:]] = sorted(set(vals))


def children_groups(node):
    return [c for c in node if c.tag == 'fields']


def group_applies(g, version):
    b, e = g.get('beginversion'), g.get('endversion')
    if b is not None and version < int(b):
        return False
    if e is not None and version > int(e):
        return False
    if g.get('size_lt'):
        return False
    return True


def isz(n):
    """The size the generator computes for a node (used for fillers)."""
    t = n.tag
    if t == 'integer':
        return INT_SIZES[n.get('type')]
    if t == 'enum':
        return INT_SIZES[n.get('type')]
    if t == 'string':
        if n.get('size'):
            return 24 if n.get('size') == 'VariableDirnumSize' else int(n.get('size'))
        return 0
    if t == 'ether':
        return int(n.get('size', 6))
    if t == 'bitfield':
        return INT_SIZES[n.get('size')]
    if t == 'ip':
        return 16 if n.get('type') == 'ipv6' else 4
    if t == 'ipv4or6':
        return 4 + (16 if n.get('endianness') is None else 0)
    if t == 'xml':
        return int(n.get('size') or n.get('maxsize') or 0)
    if t == 'struct':
        gs = children_groups(n)
        return fields_size(gs[-1]) if gs else 0
    if t == 'union':
        m = 0
        for g in children_groups(n):
            for f in g:
                m = max(m, isz(f))
        return m
    return 0


def fields_size(g):
    return sum(isz(c) for c in g if c.tag != 'code')


def size_names(msg):
    names = {}
    for n in msg.iter():
        s = n.get('size_fieldname')
        if s:
            names.setdefault(s, []).append(n)
    return names


# --------------------------------------------------------------- serialiser

class Ser:
    def __init__(self, msg, version, variant):
        self.msg = msg
        self.v = version
        self.k = variant
        self.dynamic = msg.get('dynamic') == 'yes'
        self.sizes = size_names(msg)
        self.over = {}
        self.out = bytearray()
        self.idx = 0          # entry number of the innermost array being built
        self.last = {}        # last value written for each field name
        # union guards: the values that select the branches
        self.guards = {}
        for u in msg.iter('union'):
            g = u.get('lookup_guide')
            vals = []
            for grp in children_groups(u):
                for f in grp:
                    for key in ('lookup_eq', 'lookup_ge', 'lookup_le'):
                        e = f.get(key)
                        if e and e not in ('skip',):
                            vals.append(0x7f7f7f if e == '*' else ENTRY_VALUES[e.upper()])
            self.guards.setdefault(g, [])
            self.guards[g] += [v for v in sorted(set(vals)) if v not in self.guards[g]]

    # --- value choices
    def count(self, name):
        users = self.sizes.get(name, [])
        c = 2
        if not self.dynamic:
            c = min([int(u.get('maxsize') or 2) for u in users] or [2])
            if self.k % 2:
                # fewer entries than the array holds: the rest is skipped
                c = max(1, c // 2)
        return c

    def intval(self, n, size):
        name = n.get('name')
        if name in self.over:
            return self.over[name]
        if name in self.guards:
            g = self.guards[name]
            return g[(self.k + self.idx) % len(g)]
        if name in self.sizes:
            users = self.sizes[name]
            if users[0].tag in ('string', 'xml'):
                return 12 if users[0].tag == 'string' else len(self.xmltext())
            return self.count(name)
        if name in ('callReference', 'callReference1', 'callReference2'):
            return CALLREF
        if name == 'passThroughPartyId' or name == 'conferenceId' or name == 'conferenceID':
            return PPID
        if name == 'lineInstance':
            return 1
        if name == 'callState' or name == 'callType':
            return 1 + self.k % 6
        v = (self.k * 7 + len(name)) % 5 + 1
        return v

    def xmltext(self):
        return b'<x><y a="1">z</y></x>'

    def put_int(self, v, size, big=False):
        v &= (1 << (8 * size)) - 1
        self.out += v.to_bytes(size, 'big' if big else 'little')

    # --- nodes
    def fields(self, g):
        for c in g:
            self.node(c)

    def groups(self, node):
        for g in children_groups(node):
            if group_applies(g, self.v):
                self.fields(g)

    def array_n(self, n):
        """(real entries, total entries) of an array node."""
        sf = n.get('size_fieldname')
        if sf:
            c = self.count(sf) if sf not in self.over else self.over[sf]
            mx = int(n.get('maxsize') or c)
            if self.dynamic:
                # a struct array of a dynamic message always takes maxsize entries
                return (mx, mx) if n.tag == 'struct' else (c, c)
            return min(c, mx), mx
        if n.get('size') and n.tag in ('integer', 'enum', 'struct'):
            s = int(n.get('size'))
            return s, s
        return None

    def node(self, n):
        t = n.tag
        arr = self.array_n(n) if t in ('integer', 'enum', 'struct') else None
        if arr is None:
            self.one(n, 0)
        else:
            real, total = arr
            for i in range(total):
                if i < real:
                    old, self.idx = self.idx, i
                    self.one(n, i)
                    self.idx = old
                else:
                    self.out += b'\0' * isz(n)

    def one(self, n, i):
        t = n.tag
        if t == 'integer':
            size = INT_SIZES[n.get('type')]
            v = self.intval(n, size)
            self.last[n.get('name')] = v
            self.put_int(v, size)
        elif t == 'enum':
            size = INT_SIZES[n.get('type')]
            name = n.get('name')
            if name in self.over:
                v = self.over[name]
            elif name in self.guards:
                g = self.guards[name]
                v = g[(self.k + self.idx) % len(g)]
            else:
                vals = ENUMS.get(n.get('subtype')[0].upper() + n.get('subtype')[1:]) or [1]
                v = vals[(self.k + i) % len(vals)]
            self.last[name] = v
            self.put_int(v, size)
        elif t == 'string':
            self.string(n)
        elif t == 'ether':
            if self.dynamic:
                self.out += bytes([2, 0, 0, 0, 0, 1]) + b'\0'
            else:
                self.out += bytes([2, 0, 0, 0, 0, 1 + self.k % 200]) + b'\0' * (isz(n) - 6)
        elif t == 'bitfield':
            size = INT_SIZES[n.get('size')]
            self.put_int(0x5 + 0x100 * self.k, size)
        elif t == 'ip':
            if n.get('type') == 'ipv6':
                self.out += bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [self.k + 1])
            else:
                self.out += bytes([192, 0, 2, 20 + self.k % 200])
        elif t == 'ipv4or6':
            name = n.get('name')
            ipver = self.over.get(name + '__ver', self.k % 2 if self.v >= 17 else 0)
            if self.v >= 17:
                self.put_int(ipver, 4)
                if ipver == 0:
                    self.out += bytes([192, 0, 2, 30 + self.k % 200]) + b'\0' * 12
                else:
                    self.out += bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [self.k + 1])
            else:
                self.out += bytes([192, 0, 2, 30 + self.k % 200])
        elif t == 'xml':
            txt = self.xmltext()
            mx = int(n.get('size') or n.get('maxsize'))
            if n.get('size_fieldname'):
                body = txt
            else:
                body = txt + b'\0'
            self.out += body + b'\0' * (mx - len(body))
        elif t == 'struct':
            self.groups(n)
        elif t == 'union':
            self.union(n)
        elif t == 'code':
            pass

    def string(self, n):
        name = n.get('name')
        size = n.get('size')
        label = n.get('subtype') == 'DisplayLabel'
        if self.dynamic:
            if label:
                txt = b'\x1e' + bytes([2 + self.k % 20]) + b' text'
            elif self.k % 4 == 3:
                txt = b''           # an empty string takes one NUL
            elif name in ('callingParty', 'calledParty', 'AlternateCallingParty', 'originalCalledParty',
                          'lastRedirectingParty', 'lineDirNumber', 'speedDialDirNumber'):
                txt = b'100%d' % (self.k % 10)
            else:
                txt = (name.encode()[:12] or b'x')
            self.out += txt + b'\0'
            return
        if n.get('size_fieldname'):
            ln = self.intval_len(n)
            body = b'\x1e\x02abcdefghijklmnop'[:ln] if label else (b'name' + bytes(60))[:ln]
            self.out += body.ljust(ln, b'a')
            return
        sz = 24 if size == 'VariableDirnumSize' else int(size)
        if self.v >= 18 and size == 'VariableDirnumSize':
            sz = 25
        if label:
            body = [b'\x1e\x02', b'\x80\x03', b'text', b'\x1e\x7f\x80x'][self.k % 4]
        elif name in ('callingParty', 'calledParty', 'AlternateCallingParty', 'originalCalledParty',
                      'lastRedirectingParty'):
            body = b'200%d' % (self.k % 10)
        else:
            body = (name.encode() + b'-' + str(self.k).encode())
        body = body[:sz - 1]
        self.out += body + b'\0' * (sz - len(body))

    def intval_len(self, n):
        sf = n.get('size_fieldname')
        return self.over.get(sf, 12)

    def union(self, n):
        guard = n.get('lookup_guide')
        gval = self.over.get(guard, self.last.get(guard))
        branches = [f for g in children_groups(n) for f in g]
        mx = isz(n)
        # the dissector tests the branches in order
        for f in branches:
            eq, ge, le = f.get('lookup_eq'), f.get('lookup_ge'), f.get('lookup_le')
            if eq == 'skip':
                continue
            hit = False
            if eq == '*':
                hit = True
            else:
                v = gval if gval is not None else 0
                c = []
                if ge:
                    c.append(v >= ENTRY_VALUES[ge.upper()])
                if le:
                    c.append(v <= ENTRY_VALUES[le.upper()])
                if eq:
                    c.append(v == ENTRY_VALUES[eq.upper()])
                hit = bool(c) and all(c)
            if hit:
                self.one(f, 0)
                self.out += b'\0' * (mx - isz(f))
                return


# ---------------------------------------------------------------- messages

class Msg:
    def __init__(self, el):
        self.el = el
        self.name = el.get('name')
        self.opcode = int(el.get('opcode'), 0)
        self.dir = el.get('direction')
        self.type = el.get('msgtype')
        self.request = int(el.get('request'), 0) if el.get('request') else None


MESSAGES = [Msg(m) for m in ROOT.findall('message')]


def union_variants(msg):
    """[(guard, value)] that select each branch of every union of the
    message (the guard is an enum or integer field)."""
    out = []
    for u in msg.el.iter('union'):
        guard = u.get('lookup_guide')
        branches = [f for g in children_groups(u) for f in g]
        for f in branches:
            for key in ('lookup_eq', 'lookup_ge', 'lookup_le'):
                eq = f.get(key)
                if eq in (None, 'skip'):
                    continue
                v = 0x7f7f7f if eq == '*' else ENTRY_VALUES[eq.upper()]
                if (guard, v) not in out:
                    out.append((guard, v))
    return out


def build(msg, version, variant, over=None):
    s = Ser(msg.el, version, variant)
    if over:
        s.over.update(over)
    for g in children_groups(msg.el):
        if group_applies(g, version):
            s.fields(g)
    return bytes(s.out)


def pdu(opcode, version, body):
    data = struct.pack('<I', opcode) + body
    return struct.pack('<II', len(data), version) + data


# ---------------------------------------------------------------- TCP/pcap

PHONE = (bytes([192, 0, 2, 1]), b'\x02\x00\x00\x00\x00\x01')
CM = (bytes([192, 0, 2, 2]), b'\x02\x00\x00\x00\x00\x02')


class Stream:
    def __init__(self, frames, cport, sport=2000):
        self.f = frames
        self.c = (PHONE, cport)
        self.s = (CM, sport)
        self.seq = {True: 1000, False: 9000}
        self.t = 0

    def _pkt(self, to_cm, flags, payload):
        a, b = (self.c, self.s) if to_cm else (self.s, self.c)
        seq = self.seq[to_cm]
        ack = self.seq[not to_cm]
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', a[1], b[1], seq, ack if flags & 0x10 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, a[0][0], b[0][0])
        self.seq[to_cm] = (seq + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
        self.f.append(b[0][1] + a[0][1] + b'\x08\x00' + ip + tcp)

    def handshake(self):
        self._pkt(True, 0x02, b'')
        self._pkt(False, 0x12, b'')
        self._pkt(True, 0x10, b'')

    def send(self, to_cm, payload, seg=1400):
        for i in range(0, max(len(payload), 1), seg):
            self._pkt(to_cm, 0x18, payload[i:i + seg])

    def close(self):
        self._pkt(True, 0x11, b'')
        self._pkt(False, 0x11, b'')
        self._pkt(True, 0x10, b'')


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1793491200 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def ordered_messages():
    """Requests and events in opcode order, each followed by its responses."""
    by_req = {}
    for m in MESSAGES:
        if m.type == 'response' and m.request is not None and m.request != m.opcode:
            by_req.setdefault(m.request, []).append(m)
    out = []
    seen = set()
    for m in sorted(MESSAGES, key=lambda m: m.opcode):
        if m.type == 'response' and m.request is not None and m.request != m.opcode and any(
                r.opcode == m.request for r in MESSAGES):
            continue
        out.append(m)
        seen.add(m.opcode)
        for r in by_req.get(m.opcode, []):
            out.append(r)
    return out


def message_pdus(version, variant, over=None):
    """[(to_cm, pdu bytes)] for every message at one header version."""
    res = []
    for m in ordered_messages():
        to_cm = m.dir == 'dev2pbx'
        body = build(m, version, variant)
        res.append((to_cm, pdu(m.opcode, version, body), m.type in ('request', 'response')))
        for j, (guard, gv) in enumerate(union_variants(m)):
            b2 = build(m, version, variant + j + 1, {guard: gv})
            res.append((to_cm, pdu(m.opcode, version, b2), m.type in ('request', 'response')))
    return res


def pack_stream(st, pdus, per_segment=3, split_every=7):
    """Send the PDUs: several per segment in one direction, and every
    split_every-th segment split over two TCP segments. A request or a
    response PDU is alone in its segment: the dissector keys its request
    and response links by frame number, so two of them in one frame show
    the link of the last one in the second pass (see README)."""
    i = 0
    n = 0
    while i < len(pdus):
        to_cm = pdus[i][0]
        grp = [pdus[i][1]]
        tracked = pdus[i][2]
        i += 1
        while (not tracked and i < len(pdus) and pdus[i][0] == to_cm and not pdus[i][2]
               and len(grp) < per_segment):
            grp.append(pdus[i][1])
            i += 1
        data = b''.join(grp)
        n += 1
        if n % split_every == 0 and len(data) > 30:
            cut = len(data) // 2
            st.send(to_cm, data[:cut])
            st.send(to_cm, data[cut:])
        else:
            st.send(to_cm, data)


def label_leak_pdus():
    """The reproducer of "SKINNY: Fix leak of additionalInfo for display
    labels": SoftKeyTemplateRes with 32 soft keys whose labels hold an
    embedded label code, 4 times in one segment (every label after the
    first overwrote si->additionalInfo without freeing it)."""
    body = struct.pack('<III', 0, 32, 32)
    for i in range(32):
        body += b'\x1e\x02' + b'X' * 13 + b'\x00' + struct.pack('<I', 1)
    return pdu(0x0108, 0, body) * 4


def call_flow(F, port):
    """A phone registering and setting up a call: the requests and
    responses carry the same pass-through party id, so the dissector links
    them ("Response In" / "Request In")."""
    st = Stream(F, port)
    st.handshake()
    byname = {m.name: m for m in MESSAGES}
    seq = ['RegisterReqMessage', 'RegisterAckMessage', 'CapabilitiesReqMessage', 'CapabilitiesResMessage',
           'SoftKeyTemplateReqMessage', 'SoftKeyTemplateResMessage', 'CallStateMessage',
           'CallInfoMessage', 'OpenReceiveChannelMessage', 'OpenReceiveChannelAckMessage',
           'StartMediaTransmissionMessage', 'StopMediaTransmissionMessage',
           'CloseReceiveChannelMessage', 'KeepAliveReqMessage', 'KeepAliveAckMessage']
    for k, name in enumerate(seq):
        m = byname.get(name)
        if m is None:
            continue
        to_cm = m.dir == 'dev2pbx'
        st.send(to_cm, pdu(m.opcode, 22, build(m, 22, k)))
    st.send(False, label_leak_pdus())
    st.close()


def main_frames():
    F = []
    port = 40000
    call_flow(F, port)
    for vi, v in enumerate(MAIN_VERSIONS):
        st = Stream(F, port + 1 + vi)
        st.handshake()
        pack_stream(st, message_pdus(v, vi))
        st.close()
    return F


def malformed_frames():
    """Short and over-long PDUs, unknown opcodes and random payloads for
    every opcode (the sweep of the review, deterministic here)."""
    import random
    rnd = random.Random(34)
    F = []
    st = Stream(F, 45000)
    st.handshake()
    # PDUs whose declared length is shorter or longer than the data
    for m in MESSAGES[:40]:
        body = build(m, 22, 1)
        d = struct.pack('<I', m.opcode) + body
        st.send(m.dir == 'dev2pbx', struct.pack('<II', len(d), 22) + d[:max(4, len(d) // 2)])
        st.send(m.dir == 'dev2pbx', struct.pack('<II', len(d) + 40, 22) + d)
    # array counts above the maximum of the XML (the guards of the
    # generated code skip the array) and counts of zero
    for v in (0, 22):
        for mode in ('big', 'zero'):
            for m in MESSAGES:
                names = size_names(m.el)
                if not names:
                    continue
                over = {}
                for name, users in names.items():
                    mx = min(int(u.get('maxsize') or 2) for u in users)
                    over[name] = mx + 3 if mode == 'big' else 0
                st.send(m.dir == 'dev2pbx', pdu(m.opcode, v, build(m, v, 2, over)))
    # two responses in one segment: the dissector keys the response links
    # by frame number, so the first PDU shows the link of the second one in
    # the second pass (a request sent twice, then both answered at once)
    byname = {x.name: x for x in MESSAGES}
    req, resp = byname['OpenReceiveChannelMessage'], byname['OpenReceiveChannelAckMessage']
    for ppid in (0x100, 0x200):
        st.send(False, pdu(req.opcode, 22, build(req, 22, 0, {'passThroughPartyId': ppid})))
    st.send(True, pdu(resp.opcode, 22, build(resp, 22, 0, {'passThroughPartyId': 0x100})) +
            pdu(resp.opcode, 22, build(resp, 22, 0, {'passThroughPartyId': 0x200})))
    # unknown opcodes
    for op in (0x7777, 0x0fff, 0x9000):
        st.send(True, pdu(op, 22, b'\0' * 12))
    # length field that says 3 (below the 4 of the opcode): not SKINNY
    st.send(True, struct.pack('<II', 3, 0) + b'\0' * 8)
    # a header version that no table knows: not SKINNY
    st.send(True, struct.pack('<III', 8, 99, 1) + b'\0' * 4)
    st.close()
    # random payloads for every opcode at three header versions
    ops = sorted(m.opcode for m in MESSAGES)
    port = 45100
    for v in (0, 17, 22):
        st = Stream(F, port)
        port += 1
        st.handshake()
        for op in ops:
            n = rnd.choice([0, 4, 16, 64, 200, 600])
            mode = rnd.random()
            if mode < 0.4:
                body = bytes(rnd.getrandbits(8) for _ in range(n))
            elif mode < 0.7:
                body = b''.join(struct.pack('<I', rnd.choice([0, 1, 2, 3, 5, 31, 33, 255, 257, 0xffffffff]))
                                for _ in range(n // 4))
            else:
                body = bytes(rnd.choice([0, 0x1e, 0x80, 0x41, 0xff, 1, 2]) for _ in range(n))
            st.send(rnd.random() < 0.5, pdu(op, v, body))
        st.close()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'skinny-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'skinny-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
