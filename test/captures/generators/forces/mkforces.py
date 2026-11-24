#!/usr/bin/env python3
# Generates test/captures/forces_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the ForCES coverage captures (synthetic data only).

usage: mkforces.py <outdir> [-v]

ForCES (RFC 5810) has no default port: forces.tcp / forces / SCTP ports are
Decode As or preference only. The main capture is a pcapng with

  interface 0  Exported PDU (linktype 252) naming the dissectors "forces"
               (message starts at offset 0, as for UDP and SCTP) and
               "forces.tcp" (two TML octets, then the message)
  interface 1  Ethernet with the same kind of messages in UDP/6700, TCP/6700
               and SCTP/6700-6702, which only become ForCES with
               -d udp.port==6700,forces -d tcp.port==6700,forces
               -o forces.sctp_high_prio_port:6700 (and 6701, 6702)

forces-coverage.pcapng            valid messages
forces-coverage-malformed.pcapng  bad lengths, unknown TLVs, truncation
"""
import os
import struct
import sys

# ----------------------------------------------------------- pcapng writer


def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)


def write_pcapng(path, idbs, frames):
    """idbs: list of linktypes; frames: list of (idb index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                   len(fr), len(fr)) + fr)
    with open(path, 'wb') as f:
        f.write(out)


def exp_pdu(name, payload):
    """Exported PDU: dissector name tag (12), padded to 4 octets, end tag."""
    n = name.encode()
    pad = (-len(n)) % 4
    return (struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad +
            struct.pack('>HH', 0, 0) + payload)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64,
                    proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def eth(payload):
    return bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00' + payload


CP = [192, 0, 2, 1]
FE = [192, 0, 2, 2]


def udp_frame(sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(CP, FE, 17, u))


def tcp_frame(sport, dport, seq, payload):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, 1, 5 << 4, 0x18, 65535, 0, 0)
    return eth(ipv4(CP, FE, 6, t + payload))


def sctp_frame(sport, dport, tsn, payload):
    pad = (-len(payload)) % 4
    chunk = struct.pack('>BBHIHHI', 0, 3, 16 + len(payload), tsn, 0, tsn, 0)
    chunk += payload + b'\0' * pad
    s = struct.pack('>HHII', sport, dport, 0x1234, 0) + chunk
    return eth(ipv4(CP, FE, 132, s))


# ------------------------------------------------------ ForCES structures
AS_SETUP, AS_TEARDOWN, CONFIG, QUERY, EVENT, REDIRECT = 1, 2, 3, 4, 5, 6
HEARTBEAT, AS_SETUP_RESP, CONFIG_RESP, QUERY_RESP = 0x0F, 0x11, 0x13, 0x14

T_REDIRECT, T_ASRESULT, T_ASTREASON, T_LFBSELECT = 0x0001, 0x0010, 0x0011, 0x1000
P_PATH, P_KEYINFO, P_FULL, P_SPARSE, P_RESULT, P_META, P_REDIRDATA = (
    0x0110, 0x0111, 0x0112, 0x0113, 0x0114, 0x0115, 0x0116)
SET, SET_PROP, SET_RESP, SET_PROP_RESP, DEL, DEL_RESP, GET, GET_PROP = range(1, 9)
GET_RESP, GET_PROP_RESP, REPORT, COMMIT, COMMIT_RESP, TRCOMP = range(9, 15)


def flags(ack=0, pri=0, rsrvd=0, em=0, at=0, tp=0, reserved=0):
    return (ack << 30) | (pri << 27) | (rsrvd << 24) | (em << 22) | (at << 21) | \
        (tp << 19) | reserved


def header(mtype, total, sid=0x0a000001, did=0x0a000002, corr=1, fl=0, ver=1,
           words=None):
    """Common header; total is the length in octets (it need not be real)."""
    if words is None:
        words = total // 4
    return struct.pack('>BBHIIQI', ver << 4, mtype, words, sid, did, corr, fl)


def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)


def tlv(t, value, words=None):
    """Main TLV: the length is in 4 octet units and includes the header."""
    value = pad4(value)
    if words is None:
        words = (4 + len(value)) // 4
    return struct.pack('>HH', t, words) + value


def path(ids, flg=0, n=None):
    """PATH-DATA TLV (octet length)."""
    d = struct.pack('>HH', flg, len(ids) if n is None else n)
    d += b''.join(struct.pack('>I', i) for i in ids)
    return struct.pack('>HH', P_PATH, 4 + len(d)) + d


def pdata(t, data, length=None):
    return struct.pack('>HH', t, 4 + len(data) if length is None else length) + data


def op(t, *paths, length=None):
    body = b''.join(paths)
    return struct.pack('>HH', t, 4 + len(body) if length is None else length) + body


def lfb(cls, inst, *ops):
    return tlv(T_LFBSELECT, struct.pack('>II', cls, inst) + b''.join(ops))


def message(mtype, tlvs=b'', tcp=False, **kw):
    body = tlvs
    total = 24 + len(body)
    m = header(mtype, total, **kw) + body
    return (b'\x10\x00' + m) if tcp else m


def icmp_echo():
    icmp = struct.pack('>BBHHH', 8, 0, 0, 0x1234, 1) + b'ping'
    icmp = icmp[:2] + struct.pack('>H', csum(icmp)) + icmp[4:]
    return ipv4([10, 1, 1, 1], [10, 2, 2, 2], 1, icmp)


def redirect(meta_words=2, ip=None, meta_len=None, redir_len=None):
    """Redirect TLV body: Meta Data TLV (16 or 32 octets, laid out as
    dissect_redirecttlv() reads it) then the Redirect Data TLV with an IP packet."""
    if ip is None:
        ip = icmp_echo()
    if meta_words == 1:
        meta = struct.pack('>HH', P_META, 16 if meta_len is None else meta_len)
        meta += b'\0\0\0\x01' + struct.pack('>II', 0x11, 8)
    else:
        meta = struct.pack('>HH', P_META, 32 if meta_len is None else meta_len)
        meta += b'\0\0\0\x01' + struct.pack('>II', 0x11, 8) + b'\xaa' * 8
        meta += struct.pack('>II', 0x12, 8)
    rd = struct.pack('>HH', P_REDIRDATA, 4 + len(ip) if redir_len is None else redir_len) + ip
    return tlv(T_REDIRECT, meta + rd)


# ------------------------------------------------------------- the capture
def valid_messages():
    """(label, message bytes without the TML octets)"""
    m = []
    A = m.append
    A(('AssociationSetup', message(AS_SETUP, fl=flags(ack=3, pri=1, em=1, tp=0))))
    for i, res in enumerate((0, 1, 2, 7)):
        A(('AssociationSetupResponse result %d' % res,
           message(AS_SETUP_RESP, tlv(T_ASRESULT, struct.pack('>I', res)),
                   corr=2 + i, fl=flags(ack=0, pri=7, em=3, at=1, tp=2))))
    for i, rsn in enumerate((0, 1, 2, 3, 4, 0x255, 99)):
        A(('AssociationTeardown reason %d' % rsn,
           message(AS_TEARDOWN, tlv(T_ASTREASON, struct.pack('>I', rsn)),
                   corr=10 + i, fl=flags(ack=2, pri=3, tp=3))))
    # LFB select TLVs: every operation type, one path with several IDs,
    # a selector chain, path data TLVs of every type
    ops = []
    for t in range(0, 15):
        ops.append(op(t, path([1, 2, 3])))
    A(('Config with every operation type',
       message(CONFIG, lfb(0x00000010, 1, *ops), fl=flags(ack=1, em=2, at=1, tp=1), corr=30)))
    A(('Config: selector chain and path data',
       message(CONFIG, tlv(T_ASRESULT, struct.pack('>I', 0)) +
               lfb(0x2a, 2,
                   op(SET, path([5, 6], flg=0x8000), path([7], flg=0x8000), path([8])),
                   op(SET_PROP, path([1], flg=0)),
                   op(DEL, path([], flg=0)),
                   op(GET, path([1], flg=0x8000), pdata(P_FULL, b'\x01\x02\x03\x04')),
                   op(GET_RESP, path([9], flg=0x8000), pdata(P_SPARSE, b'sparse\0\0')),
                   op(COMMIT, pdata(P_KEYINFO, b'\xde\xad\xbe\xef')),
                   op(COMMIT_RESP, pdata(P_RESULT, b'\0\0\0\0')),
                   op(TRCOMP, pdata(P_META, b'')),
                   op(REPORT, pdata(0x0999, b'zzzz'))),
               corr=31, fl=flags(ack=3, pri=5, rsrvd=2, em=3, at=1, tp=1, reserved=0x5a5a))))
    A(('ConfigResponse',
       message(CONFIG_RESP, lfb(0x2a, 2, op(SET_RESP, path([5, 6]),),
                               op(DEL_RESP, path([1]))), corr=32)))
    A(('Query',
       message(QUERY, lfb(0x2a, 2, op(GET, path([1, 2], flg=0x8000), path([3]))), corr=33)))
    A(('QueryResponse',
       message(QUERY_RESP, lfb(0x2a, 3, op(GET_RESP, path([1], flg=0x8000),
                                          pdata(P_FULL, b'ABCDEFGH')),
                              op(GET_PROP_RESP, path([2]))), corr=34)))
    A(('EventNotification',
       message(EVENT, lfb(0x2b, 1, op(REPORT, path([4, 5, 6, 7]))), corr=35,
               fl=flags(ack=0, pri=2))))
    # an LFB select TLV with no operation (the loop needs more than 12 octets)
    A(('Query with LFB select without operations',
       message(QUERY, lfb(0x2a, 2), corr=36)))
    # redirects
    A(('PacketRedirect (one meta data entry)', message(REDIRECT, redirect(1), corr=40)))
    A(('PacketRedirect (two meta data entries)',
       message(REDIRECT, redirect(2), corr=41, fl=flags(ack=3))))
    A(('Heartbeat', message(HEARTBEAT, corr=50, fl=flags(pri=7))))
    A(('Heartbeat with version 2', message(HEARTBEAT, corr=51, ver=2)))
    A(('unknown message type 0x07', message(7, corr=52)))
    return m


def cubic(size):
    """The reproducer of "ForCES: Fix cubic time in nested LFB select TLV
    loops": operation TLVs (type 0x8000, length 8) and path data TLVs
    (type 0x0110, length 8) overlap, so each level walks to the end."""
    U1 = struct.pack('>HH', 0x8000, 8)
    U0 = struct.pack('>HH', 0x0110, 8)
    k = max(4, (size - 24 - 4 - 8 - 56) // 8)
    body = struct.pack('>II', 1, 1)
    body += (U1 + U0) * k
    body += U1 + U0 + b'\0' * 4
    body += b'\0' * 52
    body += b'\0' * ((-len(body)) % 4)
    t = struct.pack('>HH', T_LFBSELECT, (4 + len(body)) // 4) + body
    return header(QUERY, 24 + len(t), sid=1, did=2, corr=0, fl=0) + t


def build_main(verbose):
    frames = []
    marks = []

    def add(label, ifc, fr):
        marks.append((len(frames) + 1, label))
        frames.append((ifc, fr))

    for label, m in valid_messages():
        add('forces: ' + label, 0, exp_pdu('forces', m))
    # the same messages with the TML octets of TCP
    tcp_labels = ('AssociationSetup', 'AssociationSetupResponse result 0',
                  'AssociationTeardown reason 0', 'Config: selector chain and path data',
                  'ConfigResponse', 'Query', 'QueryResponse', 'EventNotification',
                  'PacketRedirect (two meta data entries)', 'Heartbeat',
                  'unknown message type 0x07')
    for label, m in valid_messages():
        if label in tcp_labels:
            add('forces.tcp: ' + label, 0, exp_pdu('forces.tcp', b'\x10\x00' + m))
    # real network frames (only ForCES with Decode As / preferences)
    msgs = dict(valid_messages())
    add('UDP/6700 Config response (-d udp.port==6700,forces)', 1,
        udp_frame(40000, 6700, msgs['ConfigResponse']))
    add('UDP/6700 Query response', 1, udp_frame(40000, 6700, msgs['QueryResponse']))
    add('TCP/6700 Heartbeat (-d tcp.port==6700,forces)', 1,
        tcp_frame(40001, 6700, 1, b'\x10\x00' + msgs['Heartbeat']))
    add('TCP/6700 Query', 1, tcp_frame(40001, 6700, 27, b'\x10\x00' + msgs['Query']))
    add('SCTP/6700 high priority channel (-o forces.sctp_high_prio_port:6700)', 1,
        sctp_frame(40002, 6700, 1, msgs['Heartbeat']))
    add('SCTP/6701 medium priority channel', 1,
        sctp_frame(40002, 6701, 2, msgs['Query']))
    add('SCTP/6702 low priority channel', 1,
        sctp_frame(40002, 6702, 3, msgs['AssociationSetup']))
    return frames, marks


def build_malformed():
    frames = []
    ok = dict(valid_messages())
    A = lambda name, m: frames.append((0, exp_pdu(name, m)))
    # header length field
    m = header(HEARTBEAT, 24, words=40)          # claims 160 octets
    A('forces', m)
    A('forces', header(HEARTBEAT, 24, words=3))  # less than 24 octets, wrong
    A('forces', header(HEARTBEAT, 24, words=0) + tlv(T_ASRESULT, b'\0\0\0\0'))
    # main TLV lengths
    A('forces', header(CONFIG, 24 + 8) + struct.pack('>HH', T_ASRESULT, 0) + b'\0' * 4)
    A('forces', header(CONFIG, 24 + 8) + struct.pack('>HH', T_ASRESULT, 100) + b'\0' * 4)
    A('forces', header(CONFIG, 24 + 8) + struct.pack('>HH', T_ASTREASON, 1) + b'\0' * 4)
    # unknown main TLV, with and without data
    A('forces', header(CONFIG, 24 + 12) + tlv(0x7777, b'\1\2\3\4\5\6\7\x08'))
    A('forces', header(CONFIG, 24 + 4) + tlv(0, b''))
    # the TLV header cut short
    A('forces', header(CONFIG, 24 + 6) + b'\x10\x00\x00\x02\0\0')
    # operation TLVs: unsupported type, length below 4, path TLV length below 4
    A('forces', message(CONFIG, lfb(5, 5, op(0x8001, path([1])), op(0x00ff, path([1])))))
    A('forces', message(CONFIG, lfb(5, 5, op(SET, length=2), path([1]))))
    A('forces', message(CONFIG, lfb(5, 5, op(SET, pdata(P_PATH, b'', length=2)))))
    A('forces', message(CONFIG, lfb(5, 5, op(SET, path([1], flg=0x8000), pdata(P_PATH, b'', length=3)))))
    A('forces', message(CONFIG, lfb(5, 5, op(0, length=0), op(SET, path([1])))))
    # operation TLV longer than the packet / shorter than its paths
    A('forces', message(CONFIG, lfb(5, 5, op(SET, path([1]), length=200))))
    A('forces', message(CONFIG, lfb(5, 5, op(SET, path([1, 2, 3, 4]), length=8))))
    # path IDs past the end, path data TLV longer than the operation
    A('forces', message(CONFIG, lfb(5, 5, op(SET, path([1], n=500)))))
    A('forces', message(CONFIG, lfb(5, 5, op(SET, pdata(P_FULL, b'\1\2', length=900)))))
    A('forces', message(CONFIG, lfb(5, 5, op(SET, path([1], flg=0x8000), path([2], flg=0x8000)))))
    # redirect TLVs
    A('forces', message(REDIRECT, redirect(1, ip=icmp_echo(), redir_len=60)))      # longer than data
    A('forces', message(REDIRECT, redirect(1, ip=icmp_echo()[:12], redir_len=16)))  # too short for IP
    A('forces', message(REDIRECT, redirect(1, ip=b'')))                             # no IP at all
    A('forces', message(REDIRECT, redirect(1, ip=b'\0' * 8)))
    A('forces', message(REDIRECT, tlv(T_REDIRECT, struct.pack('>HH', P_META, 0) +
                                      struct.pack('>HH', P_REDIRDATA, 0) + b'\0' * 12)))
    A('forces', message(REDIRECT, tlv(T_REDIRECT, struct.pack('>HH', P_META, 4) + b'\0' * 12)))
    A('forces', message(REDIRECT, tlv(T_REDIRECT, struct.pack('>HH', P_META, 24) +
                                      b'\0' * 4 + struct.pack('>II', 1, 0) +
                                      struct.pack('>II', 2, 0) + b'\0' * 8)))
    A('forces', message(REDIRECT, tlv(T_REDIRECT, b'\x01\x15\0\x08\0\0\0\0')))
    # Redirect with an ILV whose length is past the end
    A('forces', message(REDIRECT, tlv(T_REDIRECT, struct.pack('>HH', P_META, 16) +
                                      b'\0\0\0\1' + struct.pack('>II', 1, 4000) + b'\0' * 8)))
    # truncated packets (exceptions)
    A('forces', header(HEARTBEAT, 24)[:20])
    A('forces', header(HEARTBEAT, 24)[:3])
    A('forces', b'')
    A('forces.tcp', b'\x10\x00' + header(HEARTBEAT, 24)[:10])
    A('forces.tcp', b'\x10')
    # a TCP message whose header length is for the whole frame (TML counted)
    A('forces.tcp', b'\x10\x00' + header(HEARTBEAT, 24, words=7))
    # an LFB select TLV cut after the class ID
    A('forces', header(CONFIG, 24 + 8) + struct.pack('>HH', T_LFBSELECT, 3) + b'\0\0\0\1')
    # an LFB select TLV followed by another main TLV: the operation loop
    # walks on past the end of the LFB select TLV
    A('forces', message(QUERY, lfb(0x2a, 2, op(GET, path([1]))) +
                        tlv(T_ASRESULT, struct.pack('>I', 0)), corr=37))
    # the reproducer of "ForCES: Fix cubic time in nested LFB select TLV
    # loops", smaller (the Operation TLV is 8 octets, its path TLV overlaps
    # the next Operation TLV: Malformed Packet after the fix)
    A('forces', cubic(1200))
    A('forces.tcp', b'\x10\x00' + cubic(800))
    return frames


def main(out):
    verbose = '-v' in sys.argv
    frames, marks = build_main(verbose)
    write_pcapng(os.path.join(out, 'forces-coverage.pcapng'), [252, 1], frames)
    if verbose:
        for n, label in marks:
            print('%4d  %s' % (n, label))
    print('forces-coverage.pcapng', len(frames), 'frames')
    mal = build_malformed()
    write_pcapng(os.path.join(out, 'forces-coverage-malformed.pcapng'), [252], mal)
    print('forces-coverage-malformed.pcapng', len(mal), 'frames')


if __name__ == '__main__':
    main(sys.argv[1])
