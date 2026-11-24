#!/usr/bin/env python3
# Generates test/captures/mbim_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MBIM coverage captures.
Usage: mkmbim.py <outdir>.  Writes mbim-coverage.pcap and
mbim-coverage-malformed.pcap (Exported PDU, link type 252, with the
dissector names mbim.control, mbim.bulk and mbim.descriptor).

The information buffers of the control messages are chosen by
mbim_search.py (random structured candidates, kept when they dissect
without malformed packets or expert infos and give the most tree lines);
the choice is stored in mbim_chosen.json next to this script."""
import struct
import sys
import os
import json
here = os.path.dirname(os.path.abspath(__file__))
from mbimlib import CIDS, command, command_done, ctl, exp_pdu, indicate, pcap, service_uuids

uuids = service_uuids()
def load(tag=''):
    fn = os.path.join(here, 'mbim_chosen%s.json' % ('_' + tag if tag else ''))
    return {tuple(json.loads(k)): bytes.fromhex(v[1]) for k, v in json.load(open(fn)).items()}

chosen = load()

BASIC = uuids[0]
good = []
tid = [0]
def nt():
    tid[0] += 1
    return tid[0]

# ---- session: open, a few commands, close; transaction ids match requests and answers
t = nt()
good.append(ctl(struct.pack('<I', 4096), 1, t))                    # OPEN
good.append(ctl(struct.pack('<I', 0), 0x80000001, t))              # OPEN_DONE
t = nt()
good.append(ctl(struct.pack('<I', 64), 1, t))                      # OPEN, smallest allowed
good.append(ctl(struct.pack('<I', 0), 0x80000001, t))
t = nt()
good.append(ctl(struct.pack('<I', 8), 1, t))                       # OPEN with MBIM_ERROR_MAX_TRANSFER
good.append(ctl(struct.pack('<I', 2), 0x80000001, t))              # OPEN_DONE, failure status

BCE = struct.pack('>IHH', 0x3d01dcc5, 0xfef5, 0x4d05) + bytes([0x0d, 0x3a, 0xbe, 0xf7, 0x05, 0x8e, 0x9a, 0xaf])

def neutral(ui, cid, kind, buf, version=0x0100):
    """The dissector keeps the extended version and the cellular class of the
    last such message for the whole conversation, and with -2 every frame sees
    the last one. Let the frames that set them set the values that are also
    the default: version 1.0 (the preference default) or the version the
    preference says, and a GSM device."""
    if kind.startswith('done') and ((ui == 0 and cid == 1) or (uuids[ui] == BCE and cid in (5, 6))) and len(buf) >= 8:
        buf = buf[:4] + struct.pack('<I', 1) + buf[8:]
    if uuids[ui] == BCE and cid == 15 and len(buf) >= 4:
        buf = struct.pack('<HH', 0x0100, version) + buf[4:]
    return buf

def groups(chosen, out, version=0x0100):
    chosen = {k: neutral(k[0], k[1], k[2], v, version) for k, v in chosen.items()}
    # one group per (service, CID): query, set, answers, indication
    for ui, u in enumerate(uuids):
        for cid in CIDS:
            buf = lambda kind: chosen.get((ui, cid, kind))
            if buf('query') is not None:
                t = nt(); out.append(command(t, u, cid, 0, buf('query')))
                if buf('done_q') is not None:
                    out.append(command_done(t, u, cid, buf('done_q')))
            if buf('set') is not None:
                t = nt(); out.append(command(t, u, cid, 1, buf('set')))
                if buf('done_s') is not None:
                    out.append(command_done(t, u, cid, buf('done_s')))
            if buf('ind') is not None:
                out.append(indicate(nt(), u, cid, buf('ind')))


groups(chosen, good)

# ---- errors and close
t = nt()
good.append(command(t, BASIC, 1, 0, b''))
good.append(ctl(struct.pack('<I', 3), 0x80000004, t))              # FUNCTION_ERROR to a request
good.append(ctl(struct.pack('<I', 2), 0x80000004, 0x7777))         # FUNCTION_ERROR without request
good.append(ctl(struct.pack('<I', 1), 4, nt()))                    # HOST_ERROR
good.append(command_done(0x6666, BASIC, 1, b''))                   # COMMAND_DONE without request
good.append(ctl(b'', 2, nt()))                                     # CLOSE
good.append(ctl(struct.pack('<I', 0), 0x80000002, tid[0]))         # CLOSE_DONE
good.append(ctl(b'\x00' * 4, 0x55, nt()))                          # unknown message type

# ---- fragmented messages: a command (3 fragments), an answer (2) and an indication (2)
def fragged(kind, info, nfrag):
    ln = len(info)
    cut = [ln // nfrag] * (nfrag - 1) + [ln - (ln // nfrag) * (nfrag - 1)]
    return cut

SETKEY = next(k for k in sorted(chosen) if k[2] == 'set' and len(chosen[k]) >= 24)
IND = next(k for k in sorted(chosen) if k[2] == 'ind' and len(chosen[k]) >= 16)
DQ = next(k for k in sorted(chosen) if k[2] == 'done_q' and len(chosen[k]) >= 16)

def fragmented_command(key, nfrag):
    ui, cid, _ = key
    info = chosen[key]
    # the information buffer length of every fragment is the length of that piece in
    # the message; the first fragment carries the header with the total length
    full = uuids[ui] + struct.pack('<III', cid, 1, len(info)) + info
    cuts = fragged('', full, nfrag)
    t = nt(); res, pos = [], 0
    for i, ln in enumerate(cuts):
        res.append(ctl(struct.pack('<II', nfrag, i) + full[pos:pos + ln], 3, t))
        pos += ln
    return res

def fragmented_done(key, nfrag, mt):
    ui, cid, _ = key
    info = chosen[key]
    if mt == 0x80000003:
        full = uuids[ui] + struct.pack('<III', cid, 0, len(info)) + info
    else:
        full = uuids[ui] + struct.pack('<II', cid, len(info)) + info
    cuts = fragged('', full, nfrag)
    t = nt(); res, pos = [], 0
    if mt == 0x80000003:
        good.append(command(t, uuids[ui], cid, 0, b''))
    for i, ln in enumerate(cuts):
        res.append(ctl(struct.pack('<II', nfrag, i) + full[pos:pos + ln], mt, t))
        pos += ln
    return res

good += fragmented_command(SETKEY, 3)
good += fragmented_done(DQ, 2, 0x80000003)
good += fragmented_done(IND, 2, 0x80000007)

# ---- NCM transfer blocks (mbim.bulk)
def ipv4(payload=b'abcdefgh'):
    ln = 20 + len(payload)
    payload = struct.pack('>HHHH', 5000, 5001, 8 + len(payload), 0) + payload
    ln = 20 + len(payload)
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, ln, 1, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return h + payload

def eth_frame():
    return bytes.fromhex('020000000001020000000002') + b'\x08\x00' + ipv4()

def nth16(seq, total, ndp):
    return struct.pack('<4sHHHH', b'NCMH', 12, seq, total, ndp)

def nth32(seq, total, ndp):
    return struct.pack('<4sHHII', b'ncmh', 16, seq, total, ndp)

def ndp16(sig, entries, next_ndp=0, length=None):
    n = len(entries) + 1
    ln = 8 + 4 * n if length is None else length
    return struct.pack('<4sHH', sig, ln, next_ndp) + b''.join(struct.pack('<HH', i, l) for i, l in entries) + struct.pack('<HH', 0, 0)

def ndp32(sig, entries, next_ndp=0, length=None):
    n = len(entries) + 1
    ln = 16 + 8 * n if length is None else length
    return struct.pack('<4sHHII', sig, ln, 0, next_ndp, 0) + b''.join(struct.pack('<II', i, l) for i, l in entries) + struct.pack('<II', 0, 0)

def build16(sig, dgrams, seq=1, second=None, **kw):
    d = [x + b'\x00' * ((4 - len(x) % 4) % 4) for x in dgrams]
    nd = 8 + 4 * (len(dgrams) + 1)
    nd2 = len(ndp16(second[0], [(0, 0)] * len(second[1]))) if second else 0
    off = 12 + nd + nd2
    ent = []
    body = b''
    for x, y in zip(d, dgrams):
        ent.append((off + len(body), len(y)))
        body += x
    first = ndp16(sig, ent, next_ndp=(12 + nd if second else 0))
    pkt = first
    if second:
        e2 = []
        for x in second[1]:
            e2.append((off + len(body), len(x)))
            body += x + b'\x00' * ((4 - len(x) % 4) % 4)
        pkt += ndp16(second[0], e2)
    total = 12 + len(pkt) + len(body)
    return nth16(seq, total, 12) + pkt + body

def build32(sig, dgrams, seq=1):
    nd = 16 + 8 * (len(dgrams) + 1)
    off = 16 + nd
    ent, body = [], b''
    for y in dgrams:
        ent.append((off + len(body), len(y)))
        body += y + b'\x00' * ((4 - len(y) % 4) % 4)
    pkt = ndp32(sig, ent)
    return nth32(seq, 16 + len(pkt) + len(body), 16) + pkt + body

ipc_status = struct.pack('<HHHI', 0, 12, 0x0001, 0xffffffff)    # multiflow status message
ipc_other = struct.pack('<HH', 7, 8) + b'\x00' * 4                  # another NDP control message type
good += [exp_pdu('mbim.bulk', x) for x in [
    build16(b'IPS0', [ipv4(), ipv4(b'x' * 30)]),
    build16(b'IPS\x05', [ipv4()], seq=2),
    build16(b'NCM0', [eth_frame()], seq=3),
    build16(b'NCM1', [eth_frame() + bytes(4)], seq=4),
    build16(b'DSS\x02', [b'dss session data', b'more'], seq=5),
    build16(b'DSC\x01', [ipc_other], seq=6),
    build16(b'IPC\x00', [ipc_status], seq=7),
    build16(b'IPC\x00', [ipc_other], seq=8),
    build16(b'XYZ0', [b'unknown signature data'], seq=9),
    build16(b'IPS0', [ipv4()], seq=10, second=(b'IPS\x01', [ipv4(b'second ndp')])),
    build32(b'ips\x00', [ipv4(), ipv4(b'y' * 12)], seq=11),
    build32(b'ncm0', [eth_frame()], seq=12),
    build32(b'ncm1', [eth_frame() + bytes(4)], seq=13),
    build32(b'ipc\x00', [ipc_status], seq=14),
    build32(b'dss\x03', [b'dss32 data'], seq=15),
    build32(b'dsc\x00', [ipc_other], seq=16),
    build32(b'abcd', [b'unknown'], seq=17),
]]

# ---- USB descriptors (mbim.descriptor)
good += [exp_pdu('mbim.descriptor', x) for x in [
    bytes([12, 0x24, 0x1b]) + struct.pack('<HHBBHB', 0x0100, 4096, 16, 128, 1500, 0x20),   # MBIM functional descriptor
    bytes([8, 0x24, 0x1c]) + struct.pack('<HBH', 0x0300, 64, 1500),                       # MBIM extended functional descriptor
]]

bad = []
# the cross-pass state bug: frame 1 differs in one pass and with -2
bad += [command(1, BASIC, 2, 0, struct.pack('<I', 1)),
        command(2, struct.pack('>IHH', 0x3d01dcc5, 0xfef5, 0x4d05) + bytes([0x0d, 0x3a, 0xbe, 0xf7, 0x05, 0x8e, 0x9a, 0xaf]), 15, 0, struct.pack('<HH', 0x0100, 0x0400))]
# every known (service, CID) with an empty, a zero and a counting buffer, as
# query, set, answer and indication: the "unexpected message" and exception paths
known = sorted({(k[0], k[1]) for tag in ('', '_ex2', '_ex3', '_ex4', '_cdma')
                for k in load(tag.lstrip('_')).keys()})
for ui, cid in known:
    u = uuids[ui]
    for buf in (b'', bytes(48), b''.join(struct.pack('<I', i % 5) for i in range(40))):
        t = nt()
        bad.append(command(t, u, cid, 0, buf))
        bad.append(command_done(t, u, cid, buf))
        bad.append(command(nt(), u, cid, 1, buf))
        bad.append(indicate(nt(), u, cid, buf))
# truncated and inconsistent control messages
bad += [ctl(b'\x00' * 20, 3, nt()),                                   # command shorter than its header
        ctl(b'', 1, nt()),                                             # OPEN without the maximum transfer size
        ctl(struct.pack('<I', 16), 1, nt()),                           # OPEN, maximum transfer size too small
        ctl(b'', 0x80000001, nt()), ctl(b'', 4, nt()), ctl(b'', 0x80000004, nt()),
        exp_pdu('mbim.control', struct.pack('<II', 3, 100)),           # truncated message header
        exp_pdu('mbim.bulk', b'NCMH' + b'\x00' * 4),                    # truncated NTH16
        exp_pdu('mbim.bulk', struct.pack('<4sHHHH', b'NCMH', 12, 1, 12, 6)),        # NDP index not a multiple of 4
        exp_pdu('mbim.bulk', struct.pack('<4sHHHH', b'NCMH', 12, 1, 12, 400)),      # NDP index out of bounds
        exp_pdu('mbim.bulk', struct.pack('<4sHHHH', b'NCMH', 12, 1, 99, 12) + struct.pack('<4sHHHHHH', b'IPS0', 10, 0, 0, 0, 0, 0)),  # block and NDP length wrong
        exp_pdu('mbim.bulk', struct.pack('<4sHHII', b'ncmh', 16, 1, 40, 18) + bytes(24)),         # 32-bit NTH, misaligned index
        exp_pdu('mbim.bulk', struct.pack('<4sHHII', b'ncmh', 16, 1, 40, 4000) + bytes(24)),       # 32-bit NTH, index out of bounds
        exp_pdu('mbim.bulk', struct.pack('<4sHHII', b'ncmh', 16, 1, 60, 16) + struct.pack('<4sHHIIII', b'ips\x00', 20, 0, 36, 0, 0, 0) + bytes(20)),
        exp_pdu('mbim.bulk', struct.pack('<4sHHHH', b'NCMH', 12, 1, 28, 12) + struct.pack('<4sHH', b'IPS0', 16, 12) + struct.pack('<HHHH', 28, 4, 0, 0)),   # NDP chain pointing at itself
        exp_pdu('mbim.descriptor', bytes([12, 0x24, 0x1b, 0, 1])),     # truncated descriptor
        exp_pdu('mbim.descriptor', bytes([9, 0x24, 0x1b, 0, 1, 0, 0, 0, 0])),  # wrong length: not decoded
        ]
out = sys.argv[1]
for tag in ('ex2', 'ex3', 'ex4', 'cdma'):
    if os.path.exists(os.path.join(here, 'mbim_chosen_%s.json' % tag)):
        extra = []
        groups(load(tag), extra, {'ex2': 0x0200, 'ex3': 0x0300, 'ex4': 0x0400, 'cdma': 0x0100}[tag])
        pcap(os.path.join(out, 'mbim-coverage-%s.pcap' % tag), extra)
pcap(os.path.join(out, 'mbim-coverage.pcap'), good)
pcap(os.path.join(out, 'mbim-coverage-malformed.pcap'), bad)
