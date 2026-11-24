#!/usr/bin/env python3
# Generates test/captures/bpv7_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic BPv7 (RFC 9171) coverage captures for
epan/dissectors/packet-bpv7.c.  Every packet is built here with struct;
nothing comes from a real network.

Usage: mkbpv7.py <outdir>
Writes bpv7-coverage.pcap (main), bpv7-coverage-malformed.pcap and
bpv7-coverage-exppdu.pcap (Exported PDU frames that call "bpv7" and
"bpv7.admin_rec" directly).
"""
import os
import struct
import sys

# ---------------------------------------------------------------- CBOR


def head(major, val):
    if val < 24:
        return bytes([(major << 5) | val])
    if val < 0x100:
        return bytes([(major << 5) | 24, val])
    if val < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack('>H', val)
    if val < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack('>I', val)
    return bytes([(major << 5) | 27]) + struct.pack('>Q', val)


def u(v):
    return head(0, v)


def bstr(b):
    return head(2, len(b)) + b


def tstr(s):
    b = s.encode()
    return head(3, len(b)) + b


def arr(*items):
    return head(4, len(items)) + b''.join(items)


TRUE = b'\xf5'
FALSE = b'\xf4'
BREAK = b'\xff'

# ---------------------------------------------------------------- CRCs


def crc16_x25(data):
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xffff


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return crc ^ 0xffffffff


def with_crc(nitems, body, crc_type, bad=False):
    """Encode a block array of nitems (counting the CRC field) whose
    fields before the CRC are body, appending a valid CRC value."""
    if crc_type == 1:
        blk = head(4, nitems) + body + b'\x42\x00\x00'
        v = crc16_x25(blk) ^ (1 if bad else 0)
        return blk[:-2] + struct.pack('>H', v)
    if crc_type == 2:
        blk = head(4, nitems) + body + b'\x44\x00\x00\x00\x00'
        v = crc32c(blk) ^ (1 if bad else 0)
        return blk[:-4] + struct.pack('>I', v)
    return head(4, nitems) + body

# ---------------------------------------------------------------- BPv7


def eid_ipn(node, svc):
    return arr(u(2), arr(u(node), u(svc)))


def eid_ipn3(alloc, node, svc):
    return arr(u(2), arr(u(alloc), u(node), u(svc)))


def eid_dtn(ssp):
    return arr(u(1), tstr(ssp))


DTN_NONE = arr(u(1), u(0))


def primary(flags=0, dst=None, src=None, rep=None, ts=(0, 0), lifetime=3600000,
            crc=1, frag=None, bad_crc=False):
    dst = dst or eid_ipn(2, 1)
    src = src or eid_ipn(1, 1)
    rep = rep or eid_ipn(1, 0)
    body = (u(7) + u(flags) + u(crc) + dst + src + rep
            + arr(u(ts[0]), u(ts[1])) + u(lifetime))
    n = 8
    if frag is not None:
        body += u(frag[0]) + u(frag[1])
        n += 2
    if crc:
        n += 1
    return with_crc(n, body, crc, bad_crc)


def canonical(btype, num, data, flags=0, crc=0, data_raw=None, bad_crc=False):
    d = data_raw if data_raw is not None else bstr(data)
    body = u(btype) + u(num) + u(flags) + u(crc) + d
    return with_crc(6 if crc else 5, body, crc, bad_crc)


def bundle(*blocks):
    return b'\x9f' + b''.join(blocks) + BREAK


def status_info(rcv=(False,), fwd=(False,), dlv=(False,), dele=(False,)):
    def a(t):
        items = [TRUE if t[0] else FALSE]
        if len(t) > 1:
            items.append(u(t[1]))
        return arr(*items)
    return arr(a(rcv), a(fwd), a(dlv), a(dele))


def status_report(info, reason, subj_src, subj_ts, frag=()):
    items = [info, u(reason), subj_src, arr(u(subj_ts[0]), u(subj_ts[1]))]
    items += [u(x) for x in frag]
    return arr(u(1), arr(*items))


def asb(targets, ctx, src, params, results):
    """BPSec abstract security block (RFC 9172)."""
    flags = 1 if params is not None else 0
    out = arr(*[u(t) for t in targets]) + u(ctx) + u(flags) + src
    if params is not None:
        out += arr(*[arr(u(i), v) for i, v in params])
    out += arr(*[arr(*[arr(u(i), v) for i, v in r]) for r in results])
    return out

# ---------------------------------------------------------------- framing


def ip_csum(b):
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4_udp(payload, sport=4556, dport=4556, src='192.0.2.1', dst='192.0.2.2'):
    def ip(a):
        return bytes(int(x) for x in a.split('.'))
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                      ip(src), ip(dst))
    iph = iph[:10] + struct.pack('>H', ip_csum(iph)) + iph[12:]
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    return eth + iph + udp


def ipv4_tcp(payload, src, dst, sport, dport, seq, ack):
    def ip(a):
        return bytes(int(x) for x in a.split('.'))
    tcph = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
    pseudo = ip(src) + ip(dst) + struct.pack('>BBH', 0, 6, len(tcph) + len(payload))
    seg = tcph + payload
    csum = ip_csum(pseudo + seg + (b'\x00' if len(seg) % 2 else b''))
    seg = seg[:16] + struct.pack('>H', csum) + seg[18:]
    iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), 1, 0x4000, 64, 6, 0,
                      ip(src), ip(dst))
    iph = iph[:10] + struct.pack('>H', ip_csum(iph)) + iph[12:]
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    return eth + iph + seg


def sdnv(v):
    out = [v & 0x7f]
    v >>= 7
    while v:
        out.append(0x80 | (v & 0x7f))
        v >>= 7
    return bytes(reversed(out))


def tcpclv3_contact(eid):
    e = eid.encode()
    return b'dtn!' + bytes([3, 0]) + struct.pack('>H', 0) + sdnv(len(e)) + e


def tcpclv3_data(data):
    return b'\x13' + sdnv(len(data)) + data


def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def exported_pdu(proto_name, payload):
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tlv = struct.pack('>HH', 12, len(name) + pad) + name + b'\x00' * pad
    tlv += struct.pack('>HH', 0, 0)
    return tlv + payload

# ---------------------------------------------------------------- main


ADMIN = 0x02
FRAG = 0x01
# every flag but "is fragment" and "payload admin"
ALL_REQ = 0x040000 | 0x020000 | 0x010000 | 0x004000 | 0x40 | 0x20 | 0x04

A_SRC = eid_ipn(1, 1)
A_TS = (1000, 1)
B_SRC = eid_dtn('//node1/')
B_TS = (2000, 2)
E_SRC = eid_ipn(1, 1)
E_TS = (3000, 7)
E_DATA = b'0123456789abcdefghijKLMNOPQRST'   # 30 octets, 3 fragments


def admin_bundle(rec, ts, crc=2):
    return ipv4_udp(bundle(
        primary(flags=ADMIN, src=eid_ipn(2, 0), dst=eid_ipn(1, 0),
                rep=eid_ipn(2, 0), ts=ts, crc=crc),
        canonical(1, 1, rec, crc=1)))


def tcpcl_session(nseg):
    c, sv = '192.0.2.10', '192.0.2.20'
    chc = tcpclv3_contact('dtn://client/')
    chs = tcpclv3_contact('dtn://server/')
    tb = bundle(primary(dst=eid_dtn('//server/inbox'), src=eid_dtn('//client/app'),
                        rep=eid_dtn('//client/app'), ts=(10000, nseg), crc=2),
                canonical(1, 1, b'over tcpcl', crc=2))
    return [ipv4_tcp(chc, c, sv, 40000, 4556, 1000, 5000),
            ipv4_tcp(chs, sv, c, 4556, 40000, 5000, 1000 + len(chc)),
            ipv4_tcp(tcpclv3_data(tb) * nseg, c, sv, 40000, 4556,
                     1000 + len(chc), 5000 + len(chs))]


def main_frames():
    f = []
    # 1: bundle A, ipn 2-element EIDs, every request flag, CRC-16 primary,
    #    CRC-32C payload.
    bundle_a = ipv4_udp(bundle(
        primary(flags=ALL_REQ, ts=A_TS, crc=1),
        canonical(1, 1, b'hello, bundle', crc=2)))
    f.append(bundle_a)
    # 2: bundle B, dtn EIDs (service "svc", empty service, dtn:none),
    #    extension blocks with every block flag, experimental block 192.
    f.append(ipv4_udp(bundle(
        primary(dst=eid_dtn('//node2/svc'), src=B_SRC, rep=DTN_NONE, ts=B_TS, crc=2),
        canonical(6, 2, eid_ipn3(977000, 5, 0), flags=0x17, crc=1),
        canonical(7, 3, u(123456), crc=2),
        canonical(10, 4, arr(u(30), u(3))),
        canonical(192, 5, arr(u(1), tstr('exp'))),
        canonical(1, 1, b'payload to svc', crc=1))))
    # 3: well-known dtn destination, 3-element IPN source, FQNN with a
    #    non-zero allocator, creation time 0 (undefined), service in the
    #    Example range.
    f.append(ipv4_udp(bundle(
        primary(dst=eid_dtn('mailbox'), src=eid_ipn3(977000, 9, 0xEEE1),
                rep=eid_ipn((977000 << 32) | 9, 0), ts=(0, 3), crc=2),
        canonical(1, 1, b'well known'))))
    # 4: dtn:none destination, IPN service above 2^32 for the report-to,
    #    and an IPN destination service above 2^32.
    f.append(ipv4_udp(bundle(
        primary(dst=DTN_NONE, src=eid_ipn(7, 0x100), rep=eid_ipn(7, 0x100000001),
                ts=(4000, 4), crc=1),
        canonical(1, 1, b'to none'))))
    f.append(ipv4_udp(bundle(
        primary(dst=eid_ipn(8, 0x100000001), src=eid_ipn(7, 0x100),
                ts=(4000, 5), crc=1),
        canonical(1, 1, b'big service'))))
    # 6: BIB over the primary block and the payload (primary without CRC).
    bib = asb([0, 1], 1, eid_ipn(1, 1), [(1, u(5))],
              [[(1, bstr(b'\x11' * 32))], [(1, bstr(b'\x22' * 32))]])
    f.append(ipv4_udp(bundle(
        primary(ts=(5000, 6), crc=0),
        canonical(11, 2, bib),
        canonical(1, 1, b'integrity protected'))))
    # 7: hop count, BIB over the hop count block, BCB over the payload: the
    #    dissection order is BCB, BIB, hop count, payload; the encrypted
    #    payload is not dissected.
    bib = asb([3], 1, eid_ipn(1, 1), None, [[(1, bstr(b'\x33' * 32))]])
    bcb = asb([1], 2, eid_ipn(1, 1), [(1, bstr(b'\x44' * 12))],
              [[(1, bstr(b'\x55' * 16))]])
    f.append(ipv4_udp(bundle(
        primary(ts=(5000, 7), crc=2),
        canonical(10, 3, arr(u(10), u(1)), crc=1),
        canonical(11, 4, bib, crc=1),
        canonical(12, 5, bcb, flags=0x01, crc=2),
        canonical(1, 1, b'\xc0' * 24, crc=2))))
    # 8-10: bundle E in three fragments (offsets 0, 10, 20; total 30).
    for i, off in enumerate((0, 10, 20)):
        f.append(ipv4_udp(bundle(
            primary(flags=FRAG, src=E_SRC, ts=E_TS, frag=(off, 30), crc=(1, 2, 1)[i]),
            canonical(1, 1, E_DATA[off:off + 10], crc=(0, 1, 2)[i]))))
    # 11: status report on bundle A: received at a time, forwarded with
    #     time 0, delivered without a time.
    f.append(admin_bundle(status_report(
        status_info((True, 5000), (True, 0), (True,), (False,)), 0, A_SRC, A_TS),
        (6000, 1)))
    # 12: second status report on bundle A: every status, reason 1.
    f.append(admin_bundle(status_report(
        status_info((True,), (True,), (True,), (True, 6500)), 1, A_SRC, A_TS),
        (6000, 2), crc=1))
    # 13: status report on fragment 2 of bundle E (fragment offset 10,
    #     payload length 30 as in the fragment's identity).
    f.append(admin_bundle(status_report(
        status_info((True, 7000)), 3, E_SRC, E_TS, frag=(10, 30)),
        (6000, 3)))
    # 14: the reproducer bpv7_status_fragfields.py.
    status = (head(4, 6) + arr(arr(TRUE), arr(FALSE), arr(FALSE), arr(FALSE))
              + u(0) + eid_ipn(1, 1) + arr(u(1000), u(1)) + u(100) + u(200))
    rec = arr(u(1), status)
    f.append(ipv4_udp(bundle(
        primary(flags=0x2, ts=(1001, 2), src=eid_ipn(2, 0), dst=eid_ipn(1, 0),
                rep=eid_ipn(1, 0), lifetime=1000, crc=0),
        canonical(1, 1, rec))))
    # 15: status report on a dtn-scheme subject (bundle B), reason 16, with
    #     only the fragment offset present.
    f.append(admin_bundle(status_report(
        status_info((False,), (False,), (False,), (True,)), 16, B_SRC, B_TS, frag=(0,)),
        (6000, 4)))
    # 16: status report on an unknown bundle with an unlisted reason code.
    f.append(admin_bundle(status_report(
        status_info(), 99, eid_ipn(99, 1), (12345, 0)), (6000, 5)))
    # 17: experimental administrative record type 65536.
    f.append(admin_bundle(arr(u(65536), bstr(b'private')), (6000, 6)))
    # 18: retransmission of bundle A.
    f.append(bundle_a)
    # 19: payload that is CBOR (decoded with bp_payload_try_heur), to
    #     ipn service 1.
    f.append(ipv4_udp(bundle(
        primary(ts=(8000, 1), crc=1),
        canonical(1, 1, arr(u(1), tstr('cbor'), bstr(b'\x01\x02'))))))
    # 20-22: TCPCL version 3 session carrying one bundle.
    f += tcpcl_session(1)
    # 23: LTP green data block, client service 4 (BPv7 aggregation, each
    #     bundle in a CBOR byte string), holding the same bundle twice: two
    #     BPv7 layers with one identity in one frame.
    lb = bundle(primary(dst=eid_ipn(20, 1), src=eid_ipn(21, 1), rep=eid_ipn(21, 0),
                        ts=(11000, 1), crc=1),
                canonical(1, 1, b'over ltp', crc=1))
    data = bstr(lb) + bstr(lb)
    ltp = b'\x07' + sdnv(1) + sdnv(1) + b'\x00' + sdnv(4) + sdnv(0) + sdnv(len(data)) + data
    f.append(ipv4_udp(ltp, sport=1113, dport=1113))
    return f


def malformed_frames():
    f = []
    p = lambda **kw: primary(ts=(9000, len(f)), **kw)
    pay = canonical(1, 1, b'x')
    # 1: definite-length bundle array
    f.append(head(4, 2) + p() + pay)
    # 2: primary array with 7 items
    f.append(bundle(head(4, 7) + u(7) + u(0) + u(0) + eid_ipn(1, 1) + eid_ipn(1, 1)
                    + eid_ipn(1, 1) + arr(u(1), u(1)), pay))
    # 3: unknown EID scheme 3, dtn SSP code 5, dtn SSP of a wrong type
    f.append(bundle(p(dst=arr(u(3), tstr('x')), src=arr(u(1), u(5)),
                      rep=arr(u(1), arr(u(1)))), pay))
    # 4: EID not an array, scheme not a uint
    f.append(bundle(p(dst=u(5), src=arr(tstr('a'), u(1))), pay))
    # 5: IPN with 4 elements, 3-element allocator and node above 2^32
    f.append(bundle(p(dst=arr(u(2), arr(u(1), u(2), u(3), u(4))),
                      src=eid_ipn3(1 << 33, 1 << 33, 1)), pay))
    # 6: IPN 2-element with non-uint node and service
    f.append(bundle(p(dst=arr(u(2), arr(tstr('n'), tstr('s')))), pay))
    # 7: fragment flag without fragment fields
    f.append(bundle(p(flags=FRAG, crc=0), pay))
    # 8: CRC-16 primary without the CRC value
    f.append(bundle(head(4, 8) + u(7) + u(0) + u(1) + eid_ipn(1, 1) + eid_ipn(1, 1)
                    + eid_ipn(1, 1) + arr(u(1), u(1)) + u(1), pay))
    # 9: unknown CRC type 3 in the primary and a canonical block, canonical
    #    CRC-32C block without CRC value
    f.append(bundle(head(4, 8) + u(7) + u(0) + u(3) + eid_ipn(1, 1) + eid_ipn(1, 1)
                    + eid_ipn(1, 1) + arr(u(1), u(1)) + u(1),
                    head(4, 5) + u(7) + u(2) + u(0) + u(3) + bstr(u(1)),
                    head(4, 5) + u(1) + u(1) + u(0) + u(2) + bstr(b'x')))
    # 10: bad CRC-16 and CRC-32C values
    f.append(bundle(p(crc=1, bad_crc=True), canonical(1, 1, b'x', crc=2, bad_crc=True)))
    # 11: duplicate payload, duplicate block number, payload not last,
    #     payload block number 2
    f.append(bundle(p(), canonical(1, 2, b'a'), canonical(7, 2, u(1)),
                    canonical(1, 1, b'b')))
    # 12: unknown block type 20, bundle age with trailing octets, hop count
    #     not an array
    f.append(bundle(p(), canonical(20, 2, b'zz'), canonical(7, 3, u(1) + u(2)),
                    canonical(10, 4, u(5)), pay))
    # 13: fragment offset above 2^32
    f.append(bundle(p(flags=FRAG, frag=(1 << 33, 1 << 34)), pay))
    # 14-15: inconsistent total length between fragments
    f.append(bundle(primary(flags=FRAG, ts=(9100, 1), frag=(0, 10)), canonical(1, 1, b'ab')))
    f.append(bundle(primary(flags=FRAG, ts=(9100, 1), frag=(2, 12)), canonical(1, 1, b'cd')))
    # 16: fragment with a non-uint fragment offset
    f.append(bundle(head(4, 10) + u(7) + u(1) + u(0) + eid_ipn(1, 1) + eid_ipn(1, 1)
                    + eid_ipn(1, 1) + arr(u(9100), u(2)) + u(1) + tstr('o') + u(4), pay))
    # 17-18: unknown administrative record type 2, record not an array
    f.append(bundle(p(flags=ADMIN), canonical(1, 1, arr(u(2), u(0)))))
    f.append(bundle(p(flags=ADMIN), canonical(1, 1, u(1))))
    # 19-21: status report array of 3, status info of 3, assertion of 3
    f.append(bundle(p(flags=ADMIN), canonical(1, 1, arr(u(1), arr(u(1), u(2), u(3))))))
    f.append(bundle(p(flags=ADMIN), canonical(1, 1, arr(u(1), arr(
        arr(arr(TRUE), arr(TRUE), arr(TRUE)), u(0), eid_ipn(1, 1), arr(u(1), u(1)))))))
    f.append(bundle(p(flags=ADMIN), canonical(1, 1, arr(u(1), arr(
        arr(arr(TRUE, u(1), u(2)), arr(u(1)), arr(TRUE), arr(TRUE)), u(0),
        eid_ipn(1, 1), arr(u(1), u(1)))))))
    # 22-23: creation timestamp not an array, DTN time not a uint
    f.append(bundle(head(4, 8) + u(7) + u(0) + u(0) + eid_ipn(1, 1) + eid_ipn(1, 1)
                    + eid_ipn(1, 1) + u(5) + u(1), pay))
    f.append(bundle(head(4, 8) + u(7) + u(0) + u(0) + eid_ipn(1, 1) + eid_ipn(1, 1)
                    + eid_ipn(1, 1) + arr(tstr('t'), u(1)) + u(1), pay))
    # 24: canonical block type not a uint
    f.append(bundle(p(), head(4, 5) + tstr('t') + u(2) + u(0) + u(0) + bstr(b'q'), pay))
    # 25: canonical CRC value not a byte string, payload data not a byte
    #     string, SSP with a reserved minor value
    f.append(bundle(p(dst=arr(u(2), b'\x1c')),
                    head(4, 6) + u(7) + u(2) + u(0) + u(1) + bstr(u(1)) + u(5),
                    head(4, 5) + u(1) + u(1) + u(0) + u(0) + u(5)))
    # 26: missing break (truncated bundle)
    f.append(b'\x9f' + p() + pay)
    # 27: truncated SSP
    f.append(b'\x9f' + head(4, 8) + u(7) + u(0) + u(0) + arr(u(2)) + b'\x82\x01')
    # 28: reproducer bpv7_bigtimes (times above INT64_MAX, unfixed)
    big = (1 << 64) - 1
    f.append(bundle(primary(ts=(big, 1), lifetime=big, crc=0),
                    canonical(7, 2, u(big)), canonical(1, 1, b'big')))
    # 29: reproducer bpv7_indef_payload_len (indefinite-length payload
    #     bstr, unfixed item length)
    f.append(bundle(primary(ts=(9200, 1), crc=0),
                    head(4, 5) + u(1) + u(1) + u(0) + u(0) + b'\x5f' + bstr(b'ab')
                    + bstr(b'cd') + BREAK))
    # 30-32 (TCP): TCPCL version 3 with two DATA_SEGMENTs in one TCP
    #     segment; the second is not dissected because BPv7 replaced
    #     pinfo->src/dst and conv_elements (see README).
    return [ipv4_udp(x) for x in f] + tcpcl_session(2)


def exppdu_frames():
    rec = arr(u(1), arr(arr(arr(TRUE), arr(FALSE), arr(FALSE), arr(FALSE)), u(0),
                        eid_ipn(1, 1), arr(u(1), u(1))))
    good = bundle(primary(ts=(1, 1), crc=1), canonical(1, 1, b'exp'))
    return [
        # 1: reproducer bpv7_admin_exppdu_null.py
        exported_pdu('bpv7.admin_rec', rec),
        # 2: a whole bundle straight to "bpv7"
        exported_pdu('bpv7', good),
        # 3: version 8
        exported_pdu('bpv7', bundle(head(4, 8) + u(8) + primary(ts=(1, 2), crc=0)[2:])),
        # 4: not an array
        exported_pdu('bpv7', u(1)),
        # 5: indefinite array with nothing after it (break missing)
        exported_pdu('bpv7', b'\x9f'),
    ]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bpv7-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'bpv7-coverage-malformed.pcap'), malformed_frames())
    write_pcap(os.path.join(out, 'bpv7-coverage-exppdu.pcap'), exppdu_frames(), linktype=252)


if __name__ == '__main__':
    main()
