#!/usr/bin/env python3
# Generates test/captures/bicc_mst_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BICC MST dissector
(packet-bicc_mst.c).

packet-bicc_mst.c only decodes the LCLS Global Call Reference (3GPP TS
29.205 B.2.1.9), and only the GSM A-interface BSSMAP dissector calls it,
for the Global Call Reference element (IEI 0x89) of ASSIGNMENT REQUEST and
HANDOVER REQUEST. The captures carry BSSMAP over SCCP (SSN 254, found by
the BSSAP heuristic dissector), M3UA and SCTP (port 2905), all registered
by default. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkbicc_mst.py <output directory>

Writes:
  bicc_mst-coverage.pcap            ASSIGNMENT REQUEST and HANDOVER REQUEST
                                    with GCRs of 1, 3 and 5 octet network
                                    IDs and empty fields
  bicc_mst-coverage-malformed.pcap  GCRs whose lengths run past the frame
"""

import os
import struct
import sys

MAC_MSC = bytes.fromhex('020000000001')
MAC_BSC = bytes.fromhex('020000000002')
IP_MSC = (10, 1, 0, 1)
IP_BSC = (10, 1, 0, 2)
MSC_PC, BSC_PC = 100, 200
SSN_BSSAP = 254
M3UA_PORT = 2905


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def _crc32c_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t


_CRC32C = _crc32c_table()


def crc32c(b):
    c = 0xffffffff
    for x in b:
        c = _CRC32C[(c ^ x) & 0xff] ^ (c >> 8)
    return c ^ 0xffffffff


def ipv4(proto, payload, src, dst, ident):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000,
                      64, proto, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def sctp(sport, dport, vtag, chunks):
    body = b''.join(chunks)
    h = struct.pack('>HHII', sport, dport, vtag, 0)
    c = crc32c(h + body)
    return struct.pack('>HHI', sport, dport, vtag) + struct.pack('<I', c) + body


def sctp_data(tsn, sid, ssn, ppid, data):
    ln = 16 + len(data)
    ch = struct.pack('>BBHIHHI', 0, 3, ln, tsn, sid, ssn, ppid) + data
    return ch + b'\0' * ((-ln) % 4)


def m3ua_data(opc, dpc, si, ni, mp, sls, data):
    pd = struct.pack('>IIBBBB', opc, dpc, si, ni, mp, sls) + data
    plen = 4 + len(pd)
    param = struct.pack('>HH', 0x0210, plen) + pd + b'\0' * ((-plen) % 4)
    rc = struct.pack('>HHI', 0x0006, 8, 1)
    body = rc + param
    return struct.pack('>BBBBI', 1, 0, 1, 1, 8 + len(body)) + body


# SCCP (ITU) -------------------------------------------------------------

def sccp_addr(ssn, pc):
    a = bytes([0x43]) + struct.pack('<H', pc) + bytes([ssn])
    return bytes([len(a)]) + a


def ref(r):
    return struct.pack('>I', r)[1:]


def sccp_cr(slr, called, calling, data=None):
    opts = bytes([0x04, len(calling) - 1]) + calling[1:]
    if data is not None:
        opts += bytes([0x0f, len(data)]) + data
    opts += b'\0'
    return bytes([0x01]) + ref(slr) + bytes([0x02, 2, 1 + len(called)]) + called + opts


def sccp_cc(dlr, slr):
    return bytes([0x02]) + ref(dlr) + ref(slr) + bytes([0x02, 0])


def sccp_dt1(dlr, data):
    return bytes([0x06]) + ref(dlr) + bytes([0x00, 0x01, len(data)]) + data


def sccp_rlsd(dlr, slr, cause=0):
    return bytes([0x04]) + ref(dlr) + ref(slr) + bytes([cause, 0])


def sccp_rlc(dlr, slr):
    return bytes([0x05]) + ref(dlr) + ref(slr)


# BSSMAP -----------------------------------------------------------------

def bssmap(msg):
    """BSSAP header: discriminator 0x00 (BSSMAP) and length."""
    return bytes([0x00, len(msg)]) + msg


def tlv(iei, v):
    return bytes([iei, len(v)]) + v


def gcr(net_id, node_id, call_ref):
    """3GPP TS 29.205 B.2.1.9 Global Call Reference: length-prefixed
    Network ID, Node ID and Call Reference ID."""
    return (bytes([len(net_id)]) + net_id + bytes([len(node_id)]) + node_id
            + bytes([len(call_ref)]) + call_ref)


CHAN_TYPE = tlv(0x0b, b'\x01\x08\x01')       # speech, full rate, GSM FR
CIC = b'\x01\x00\x21'
LCLS_CONF = b'\x8a\x00'                     # connect both-way
LCLS_CSC = b'\x8b\x00'                      # connect
LCLS_CORR_NOT_NEEDED = b'\x8c'


def ass_req(gcr_value, extra=LCLS_CONF + LCLS_CSC):
    return bssmap(b'\x01' + CHAN_TYPE + CIC + tlv(0x89, gcr_value) + extra)


def ho_req(gcr_value):
    return bssmap(b'\x10' + CHAN_TYPE
                  + tlv(0x0a, b'\x01')                     # no encryption
                  + tlv(0x12, b'\x33\x19\xa2')             # classmark 2
                  + tlv(0x05, b'\x01\x00\x01\x00\x0a')     # serving: LAC 1 CI 10
                  + tlv(0x05, b'\x01\x00\x02\x00\x14')     # target: LAC 2 CI 20
                  + tlv(0x89, gcr_value) + LCLS_CONF + LCLS_CSC)


# pcap writer ------------------------------------------------------------

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


class Cap:
    def __init__(self):
        self.frames = []
        self.tsn = {True: 1000, False: 5000}
        self.ssn = {True: 0, False: 0}
        self.next_ref = 0x10

    def m3ua(self, from_msc, sccp_msg):
        opc, dpc = (MSC_PC, BSC_PC) if from_msc else (BSC_PC, MSC_PC)
        src, dst = (IP_MSC, IP_BSC) if from_msc else (IP_BSC, IP_MSC)
        m = m3ua_data(opc, dpc, 3, 2, 0, 1, sccp_msg)
        ch = sctp_data(self.tsn[from_msc], 1, self.ssn[from_msc], 3, m)
        self.tsn[from_msc] += 1
        self.ssn[from_msc] = (self.ssn[from_msc] + 1) & 0xffff
        pkt = sctp(M3UA_PORT, M3UA_PORT, 0x11223344 if from_msc else 0x55667788, [ch])
        self.frames.append(MAC_BSC + MAC_MSC + b'\x08\x00' if from_msc else
                           MAC_MSC + MAC_BSC + b'\x08\x00')
        self.frames[-1] += ipv4(132, pkt, src, dst, len(self.frames))

    def connect(self, data=None):
        """MSC opens an SCCP connection to the BSC (optionally with data,
        as for HANDOVER REQUEST); the BSC confirms. Returns (msc_ref,
        bsc_ref)."""
        msc_ref = self.next_ref
        bsc_ref = self.next_ref + 0x100
        self.next_ref += 1
        self.m3ua(True, sccp_cr(msc_ref, sccp_addr(SSN_BSSAP, BSC_PC),
                                sccp_addr(SSN_BSSAP, MSC_PC), data))
        self.m3ua(False, sccp_cc(msc_ref, bsc_ref))
        return msc_ref, bsc_ref

    def send(self, conn, data):
        self.m3ua(True, sccp_dt1(conn[1], data))

    def release(self, conn):
        self.m3ua(True, sccp_rlsd(conn[1], conn[0]))
        self.m3ua(False, sccp_rlc(conn[0], conn[1]))


GCR_A = gcr(b'\x62\xf2\x10', b'\x12\x34', b'\xde\xad\xbe\xef\x01')
GCR_B = gcr(b'\x11\x22\x33\x44\x55', b'\xab\xcd', b'\x00\x00\x00\x00\x02')
GCR_C = gcr(b'\x99', b'\x56\x78', b'\x01\x02\x03\x04\x05')
GCR_EMPTY = gcr(b'', b'', b'')


def main_frames():
    c = Cap()
    # 1-2: CR / CC
    conn = c.connect()
    # 3: ASSIGNMENT REQUEST, GCR with a 3 octet network ID (the node ID
    # 0x1234 checks the fixed node ID field), LCLS-Configuration and
    # LCLS-Connection-Status-Control after it
    c.send(conn, ass_req(GCR_A))
    # 4: ASSIGNMENT REQUEST, 5 octet network ID, LCLS-Correlation-Not-Needed
    c.send(conn, ass_req(GCR_B, LCLS_CONF + LCLS_CSC + LCLS_CORR_NOT_NEEDED))
    # 5: ASSIGNMENT REQUEST, 1 octet network ID, GCR the last element
    c.send(conn, ass_req(GCR_C, b''))
    # 6: ASSIGNMENT REQUEST, all three fields empty
    c.send(conn, ass_req(GCR_EMPTY))
    # 7-8: RLSD / RLC
    c.release(conn)
    # 9-10: HANDOVER REQUEST in the CR, GCR with a 3 octet network ID, CC
    conn = c.connect(ho_req(gcr(b'\x00\xf1\x10', b'\x0f\xa0', b'\x10\x20\x30\x40\x50')))
    # 11-12: RLSD / RLC
    c.release(conn)
    return c.frames


def malformed_frames():
    c = Cap()
    conn = c.connect()
    # 3: network ID length past the end of the frame
    c.send(conn, ass_req(b'\x20\x01\x02', b''))
    # 4: GCR element of length 2 whose node ID and call reference ID
    # lengths are read from the two octets after the element (no
    # exception; the element's own length is not checked, see README)
    c.send(conn, ass_req(b'\x01\xaa', b'\x00\x00'))
    # 5: GCR element of length 0 at the end of the message (BSSMAP does
    # not call the element dissector for an empty element)
    c.send(conn, ass_req(b'', b''))
    # 6: call reference ID cut short at the end of the frame
    c.send(conn, ass_req(b'\x01\x01\x02\x12\x34\x05\xaa\xbb', b''))
    return c.frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bicc_mst-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'bicc_mst-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
