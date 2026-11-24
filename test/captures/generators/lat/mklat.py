#!/usr/bin/env python3
# Generates test/captures/lat_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the LAT (Local Area Transport)
dissector (packet-lat.c). LAT runs directly over Ethernet with ethertype
0x6004: virtual circuit messages (run, start, stop) with slots, and the
service announcement, command, status, solicit information and response
information messages. Every packet is built with struct; nothing comes
from a real network.

Usage: mklat.py <output directory>

Writes:
  lat-coverage.pcap            every message type and slot type, service
                               lists (the two fixes), parameter lists
  lat-coverage-malformed.pcap  attention slots (always flagged), slot and
                               entry lengths that are too short, truncated
                               messages
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(data):
    if len(data) & 1:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(proto, payload, src=IP_A, dst=IP_B, ident=1):
    hdr = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0) + src + dst
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def l4_sum(proto, src, dst, seg):
    ph = src + dst + struct.pack('>BBH', 0, proto, len(seg))
    return csum(ph + seg)


def udp_frame(sport, dport, payload, to_b=True, ident=1):
    src, dst = (IP_A, IP_B) if to_b else (IP_B, IP_A)
    seg = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = l4_sum(17, src, dst, seg) or 0xffff
    seg = seg[:6] + struct.pack('>H', c) + seg[8:]
    macs = (MAC_B, MAC_A) if to_b else (MAC_A, MAC_B)
    return macs[0] + macs[1] + b'\x08\x00' + ipv4(17, seg, src, dst, ident)


def tcp_frame(sport, dport, seq, ack, flags, payload=b'', to_b=True, ident=1):
    src, dst = (IP_A, IP_B) if to_b else (IP_B, IP_A)
    seg = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      0x50, flags, 8192, 0, 0) + payload
    seg = seg[:16] + struct.pack('>H', l4_sum(6, src, dst, seg)) + seg[18:]
    macs = (MAC_B, MAC_A) if to_b else (MAC_A, MAC_B)
    return macs[0] + macs[1] + b'\x08\x00' + ipv4(6, seg, src, dst, ident)


class TcpFlow:
    """One TCP connection; data() returns frames with correct seq/ack."""

    def __init__(self, cport, sport, isn_c=1000, isn_s=5000):
        self.c, self.s = cport, sport
        self.seq_c, self.seq_s = isn_c, isn_s
        self.n = 0

    def _id(self):
        self.n += 1
        return self.n

    def open(self):
        f = [tcp_frame(self.c, self.s, self.seq_c, 0, 0x02, b'', True, self._id())]
        self.seq_c += 1
        f.append(tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x12, b'', False, self._id()))
        self.seq_s += 1
        f.append(tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x10, b'', True, self._id()))
        return f

    def data(self, payload, from_client=True):
        if from_client:
            fr = tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x18, payload, True, self._id())
            self.seq_c += len(payload)
        else:
            fr = tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x18, payload, False, self._id())
            self.seq_s += len(payload)
        return fr

    def close(self):
        f = [tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x11, b'', True, self._id())]
        self.seq_c += 1
        f.append(tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x11, b'', False, self._id()))
        self.seq_s += 1
        f.append(tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x10, b'', True, self._id()))
        return f


ETHERTYPE_LAT = 0x6004
MC_LAT = bytes.fromhex('09002b00000f')
NODE_A = bytes.fromhex('08002b111111')
NODE_B = bytes.fromhex('08002b222222')

RUN, START, STOP, SERVICE_ANNOUNCEMENT, COMMAND, STATUS, SOLICIT, RESPONSE = 0, 1, 2, 10, 12, 13, 14, 15

# slot types
S_DATA_A, S_START, S_DATA_B, S_ATTENTION, S_REJECT, S_STOP = 0, 9, 10, 11, 12, 13


def eth(payload, dst=NODE_B, src=NODE_A, pad=True):
    fr = dst + src + struct.pack('>H', ETHERTYPE_LAT) + payload
    if pad and len(fr) < 60:
        fr += b'\0' * (60 - len(fr))
    return fr


def s(text):
    """Counted string."""
    b = text.encode() if isinstance(text, str) else text
    return bytes([len(b)]) + b


def first(msg_type, master=False, rrf=False):
    return bytes([(msg_type << 2) | (int(master) << 1) | int(rrf)])


def vchdr(nslots, dst, src, seq, ack):
    return struct.pack('<BHHBB', nslots, dst, src, seq, ack)


def params(items):
    """Parameter list: (code, data) items and the 0 terminator."""
    return b''.join(bytes([c, len(d)]) + d for c, d in items) + b'\0'


def slot(dst, src, typ, credits, payload=b'', count=None, pad=True):
    cnt = len(payload) if count is None else count
    b = bytes([dst, src, cnt, (typ << 4) | credits]) + payload
    if pad and cnt & 1:
        b += b'\0'
    return b


def start_slot_payload(cls=1, att=4, data=16, obj=b'SERVICE', subj=b'descr',
                       tail=b''):
    return bytes([cls, att, data]) + s(obj) + s(subj) + tail


def run(slots, dst=0x0100, src=0x0200, seq=1, ack=0, master=True):
    return first(RUN, master) + vchdr(len(slots), dst, src, seq, ack) + b''.join(slots)


def start(master=False, dst=0, src=0x0200, seq=0, ack=0, nslots=0, mtu=1500, ver=5,
          eco=2, max_slots=4, bufs=3, ctimer=8, ka=60, fac=0, prod=3, pver=0x42,
          slave=b'SLAVE', mast=b'MASTER', loc=b'Rack 7', par=()):
    return (first(START, master) + vchdr(nslots, dst, src, seq, ack)
            + struct.pack('<HBBBBBBHBB', mtu, ver, eco, max_slots, bufs, ctimer, ka,
                          fac, prod, pver)
            + s(slave) + s(mast) + s(loc) + params(par))


def stop(master=True, reason=2, text=b'closing', **kw):
    return (first(STOP, master) + vchdr(0, 0x0100, 0x0200, 9, 8) + bytes([reason])
            + s(text))


def announce(timer=100, status=2, groups=b'\x01\x00\x00\x80', name=b'NODE1',
             desc=b'Test node', services=((200, b'SVC1', b'first service'),
                                          (3, b'SVC2', b'')),
             classes=(1, 0, 2), inc=3, flags=0x81, mc=30, frame=1518):
    m = first(SERVICE_ANNOUNCEMENT) + struct.pack('<BBBBBBBBHBB', timer, 5, 3, 5, 2, inc,
                                                   flags, 0, frame, mc, status)[:7 + 0]
    # the fields: timer, high, low, cur ver, cur eco, msg inc, change flags
    m = first(SERVICE_ANNOUNCEMENT) + bytes([timer, 5, 3, 5, 2, inc, flags])
    m += struct.pack('<H', frame) + bytes([mc, status])
    m += bytes([len(groups)]) + groups + s(name) + s(desc)
    m += bytes([len(services)])
    for rating, n, d in services:
        m += bytes([rating]) + s(n) + s(d)
    m += bytes([len(classes)]) + bytes(classes)
    return m


def command(cmd=2, modifier=0x03, req=0x1234, entry=0x5678, obj_node=b'OBJNODE',
            groups=b'\xff\x01', subj_node=b'SUBJNODE', subj_port=b'PORT_1',
            subj_desc=b'a user', obj_srvc=b'OBJSVC', obj_port=b'PORT_2',
            par=((1, b'\x00\x01'), (2, b'ab'))):
    return (first(COMMAND, True) + bytes([1, 5, 3, 5, 2]) + struct.pack('<HHH', 1518, req, entry)
            + bytes([cmd, modifier]) + s(obj_node) + bytes([len(groups)]) + groups
            + s(subj_node) + s(subj_port) + s(subj_desc) + s(obj_srvc) + s(obj_port)
            + params(par))


def entry(status=0x02, err=0, req=0x11, ent=0x22, elapsed=5, minq=1, maxq=3,
          obj_srvc=b'OSVC', obj_port=b'OPORT', desc=b'who', length=None):
    body = bytes([status, err, 0]) + struct.pack('<HHHHH', req, ent, elapsed, minq, maxq)
    body += s(obj_srvc) + s(obj_port) + s(desc)
    ln = len(body) if length is None else length
    out = bytes([ln]) + body
    if (ln + 1) & 1:
        out += b'\0'
    return out


def status_msg(entries, subj_node=b'SUBJ', par=(), count=None, retrans=1000):
    m = first(STATUS) + bytes([1, 5, 3, 5, 2]) + struct.pack('<HH', 1518, retrans)
    m += bytes([len(entries) if count is None else count]) + s(subj_node)
    if not (len(subj_node) + 1) & 1:
        m += b'\0'
    return m + b''.join(entries) + params(par)


def solicit(ident=0xbeef, timer=50, dst=b'DSTNODE', groups=b'\x80', src=b'SRCNODE',
            srvc=b'WANTED', par=((9, b'xyz'),)):
    return (first(SOLICIT) + bytes([1, 5, 3, 5, 2]) + struct.pack('<HHH', 1518, ident, timer)
            + s(dst) + bytes([len(groups)]) + groups + s(src) + s(srvc) + params(par))


def svc_entry(classes=(1,), status=0x03, rating=77, groups=b'\x01\x02', name=b'SVC',
              desc=b'service desc'):
    body = bytes([len(classes)]) + bytes(classes) + bytes([status, rating, len(groups)])
    body += groups + s(name) + s(desc)
    return bytes([len(body)]) + body


def response(entries, ident=0xbeef, rstatus=0x0001, nstatus=0x0007, addr=NODE_A, mc=60,
             dst=b'DSTNODE', groups=b'\x80\x01', src=b'SRCNODE', desc=b'source node',
             par=((5, b'1'),), count=None):
    m = first(RESPONSE) + bytes([1, 5, 3, 5, 2]) + struct.pack('<HHHH', 1518, ident, rstatus, nstatus)
    m += addr + struct.pack('<H', mc) + s(dst) + bytes([len(groups)]) + groups + s(src) + s(desc)
    m += bytes([len(entries) if count is None else count]) + b''.join(entries) + params(par)
    return m


def main_frames():
    F = []
    # 1: start (from the slave), no parameters; 2: its answer (master bit set)
    F.append(eth(start(par=())))
    F.append(eth(start(master=True, dst=0x0200, src=0x0100, seq=0, ack=0, slave=b'', mast=b'',
                       loc=b'', par=((1, b'\x01'), (7, b'')), nslots=0), NODE_A, NODE_B))
    # 3: run message with a start slot: terminal parameters and status
    F.append(eth(run([slot(0, 1, S_START, 3, start_slot_payload(
        tail=params([(1, b'\x00\x00'), (4, b'LTA1'), (5, b'port'), (6, b'\x01\x02\x03'), (7, b'pw'),
                     (99, b'?')])))])))
    # 4: start slot whose strings use up the slot (no parameters), and a
    #    start slot of an unknown service class with trailing data
    F.append(eth(run([slot(0, 2, S_START, 1, start_slot_payload()),
                      slot(0, 3, S_START, 2, start_slot_payload(cls=2, tail=b'\x01\x02\x03'))])))
    # 5: start slot with parameters and bytes after the terminator
    F.append(eth(run([slot(0, 4, S_START, 0, start_slot_payload(
        tail=params([(2, b'\x00\x05')]) + b'xyz'))])))
    # 6: data_a slots with and without data, with odd and even counts
    F.append(eth(run([slot(1, 1, S_DATA_A, 15, b'hello'), slot(2, 2, S_DATA_A, 0, b'ab'),
                      slot(3, 3, S_DATA_A, 1)])))
    # 7: data_b slots: flags, channel chars (printable, control, other),
    #    parameters, remaining data
    flags_all = 0x7f
    F.append(eth(run([slot(1, 1, S_DATA_B, 1, bytes([flags_all]) + b'a\x13\x11\xfe' + params(
        [(1, b'\x0b\x01'), (2, b'\x09\x00'), (3, b'\x09\x00'), (4, b'\x01'), (5, b'\x00'),
         (6, b'\x00\x00'), (77, b'')]) + b'tail')])))
    F.append(eth(run([slot(1, 1, S_DATA_B, 2, b'\x00' + b'\x7f\x1f ~' + params([]))])))
    F.append(eth(run([slot(1, 1, S_DATA_B, 3), slot(2, 2, S_DATA_B, 0, b'\x01\x11\x13\x11\x13\x00')])))
    # 10: reject and stop slots, an unknown slot type, a data slot of type 1
    F.append(eth(run([slot(1, 1, S_REJECT, 5, b''), slot(1, 2, S_STOP, 2, b'rs'),
                      slot(1, 3, 1, 4, b'abc'), slot(1, 4, 14, 0), slot(5, 5, 15, 1, b'z')])))
    # 11: run with no slots; 12: run with the master bit clear
    F.append(eth(run([], master=False)))
    F.append(eth(run([slot(7, 8, S_DATA_A, 2, b'\x00\x01')], master=False, seq=255, ack=254)))
    # 13: stop circuit
    F.append(eth(stop(), NODE_A, NODE_B))
    # 14: service announcement (to the multicast address) with 3 classes
    F.append(eth(announce(), MC_LAT))
    F.append(eth(announce(status=3, groups=b'', services=(), classes=()), MC_LAT))
    # 16: command, 17: command with every type, no parameters
    F.append(eth(command()))
    for n in range(1, 7):
        F.append(eth(command(cmd=n, modifier=n & 3, par=())))
    # 24-: status with entries: accepted, rejected with error, long names
    e1 = entry(status=0x02, req=1, ent=2)
    e2 = entry(status=0x80, err=7, desc=b'')
    e3 = entry(status=0x01, obj_srvc=b'A' * 20, obj_port=b'B', desc=b'CC')
    F.append(eth(status_msg([e1, e2, e3], subj_node=b'SUBJ', par=((3, b'p'),))))
    F.append(eth(status_msg([e1], subj_node=b'SUBJ2')))
    F.append(eth(status_msg([], subj_node=b'', par=())))
    # solicit information
    F.append(eth(solicit()))
    F.append(eth(solicit(par=(), groups=b'')))
    # response information with two services
    F.append(eth(response([svc_entry((1,), 0x03, 100, b'\x01\x02', b'FIRST', b'one'),
                           svc_entry((1, 2, 0), 0x01, 5, b'', b'SECOND', b'two')])))
    F.append(eth(response([], par=(), groups=b'')))
    # unknown message types (default case): 3 and 63
    F.append(eth(first(3) + bytes(range(30))))
    F.append(eth(first(63, True, True) + b'\x01\x02\x03'))
    return F


def malformed_frames():
    F = []
    # attention slots: the dissector always reports a nonzero MBZ field,
    # because it takes the whole slot type octet as the MBZ field
    F.append(eth(run([slot(1, 1, S_ATTENTION, 0, b'\x20' + b'xy'),
                      slot(2, 2, S_ATTENTION, 0, b'\x00'),
                      slot(3, 3, S_ATTENTION, 0)])))
    # slot data lengths that run past the slot byte count
    F.append(eth(run([slot(1, 1, S_START, 0, bytes([1]), count=1)]), pad=False))
    F.append(eth(run([slot(1, 1, S_START, 0, bytes([1, 4]), count=2)]), pad=False))
    F.append(eth(run([slot(1, 1, S_START, 0, bytes([1, 4, 5]), count=3)]), pad=False))
    F.append(eth(run([slot(1, 1, S_START, 0, bytes([1, 4, 5, 200]), count=4)]), pad=False))
    F.append(eth(run([slot(1, 1, S_START, 0, bytes([1, 4, 5, 2]) + b'ab' + bytes([9]), count=7)]), pad=False))
    F.append(eth(run([slot(1, 1, S_START, 0, start_slot_payload(tail=b'\x04\x09ab'))]), pad=False))
    F.append(eth(run([slot(1, 1, S_START, 0, start_slot_payload(tail=b'\x04'))]), pad=False))
    F.append(eth(run([slot(1, 1, S_START, 0, start_slot_payload(tail=b'\x03'))]), pad=False))
    F.append(eth(run([slot(1, 1, S_START, 0, start_slot_payload(tail=b'\x03\x01'), count=17)]), pad=False))
    F.append(eth(run([slot(1, 1, S_START, 0, start_slot_payload(tail=b'\x01'), pad=False)])[:-1], pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_B, 0, b'\x00' + b'abcd', count=5)]), pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_B, 0, b'\x00' + b'abc', count=4)]), pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_B, 0, b'\x00abcd\x05\xff', count=7)]), pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_B, 0, b'\x00abcd\x05', count=6)]), pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_B, 0, b'\x00abc', count=2)]), pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_B, 0, b'\x00ab', count=3)]), pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_B, 0, b'\x00a', count=2)]), pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_B, 0, b'\x00', count=1)]), pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_B, 0, b'\x00abcd', count=5)]), pad=False))
    # slots cut off by the end of the frame
    F.append(eth(run([slot(1, 1, S_DATA_A, 0, b'abcdef')])[:-3], pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_A, 0, b'abcdef')])[:12], pad=False))
    F.append(eth(first(RUN), pad=False))
    F.append(eth(run([slot(1, 1, S_DATA_A, 0, b'a')], ) [:15], pad=False))
    # every other message cut short
    for name, m in (('start', start(par=((1, b'ab'),))), ('stop', stop()), ('ann', announce()),
                    ('cmd', command()), ('solicit', solicit())):
        for cut in (8, 20, 33, 50):
            if cut < len(m):
                F.append(eth(m[:cut], pad=False))
    # status: entry lengths that are too short, a name too long, entry
    # count larger than the data
    for ln in (0, 1, 2, 3, 4, 5, 7, 9, 11, 13, 15, 16, 17, 18, 20, 22, 25):
        F.append(eth(status_msg([entry(length=ln)], subj_node=b'S'), pad=False))
    # entries that end exactly after the object port name / the service groups
    body = (bytes([2, 0, 0]) + struct.pack('<HHHHH', 1, 2, 3, 4, 5) + s(b'OSVC') + s(b'OPORT'))
    F.append(eth(status_msg([bytes([len(body)]) + body + b'\0'], subj_node=b'S'), pad=False))
    body = bytes([1, 1, 3, 77, 2, 1, 2])
    F.append(eth(response([bytes([len(body)]) + body], par=()), pad=False))
    F.append(eth(status_msg([entry(length=12)], subj_node=b'S'), pad=False))
    F.append(eth(status_msg([entry(status=0x00, err=9), entry(length=0)], subj_node=b'SS'), pad=False))
    F.append(eth(status_msg([entry()], subj_node=b'S', count=9), pad=False))
    # response information: entry lengths that are too short
    for ln in (0, 1, 2, 3, 4, 5, 6, 8, 12, 14, 15, 17, 19, 22):
        se = svc_entry()
        F.append(eth(response([bytes([ln]) + se[1:]], par=()), pad=False))
    se = svc_entry((1, 2, 3, 4), 1, 2, b'', b'N', b'D')
    for ln in (2, 3, 4, 5, 6, 7, 9, 10, 11, 13):
        F.append(eth(response([bytes([ln]) + se[1:]], par=()), pad=False))
    F.append(eth(response([svc_entry()], count=4, par=()), pad=False))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'lat-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'lat-coverage-malformed.pcap'), malformed_frames())


main()
