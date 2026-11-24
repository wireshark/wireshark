#!/usr/bin/env python3
# Generates test/captures/bctp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BCTP dissector (packet-bctp.c).

BCTP (Q.1990 Bearer Control Tunnelling Protocol) has no port of its own:
it is called by the H.248 Q.1950 Bearer Control Tunnelling package (0x0022)
for the "bit" parameter (0x0001) of the Tunnel Indication event and of
the Bearer Information Tunnel signal. The captures carry binary (BER)
H.248 on UDP port 2945 (registered by default) between an MGC and an MGW.
Every packet is built from scratch with struct; no captured traffic is used.

Usage: mkbctp.py <output directory>

Writes:
  bctp-coverage.pcap            BCTP in Notify (event) and Modify (signal)
                                requests: IPBCP (TPI 0x20, to SDP), binary
                                TPIs (data), text TPIs (data-text-lines),
                                the version and tunnelled protocol error
                                indicators, empty tunnelled protocol
  bctp-coverage-malformed.pcap  BCTP of 0 and 1 octets
"""

import os
import struct
import sys

MAC_MGC = bytes.fromhex('020000000001')
MAC_MGW = bytes.fromhex('020000000002')
IP_MGC = (192, 0, 2, 1)
IP_MGW = (198, 51, 100, 1)
H248_PORT = 2945


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src, dst, ident):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, data, src, dst):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def eth(dst, src, etype, payload):
    return dst + src + struct.pack('>H', etype) + payload


# BER --------------------------------------------------------------------

def blen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + blen(len(content)) + content


def ber_int(tag, v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big')
    return tlv(tag, b)


def ctx(n, content, constructed=True):
    return tlv((0xa0 if constructed else 0x80) | n, content)


# H.248 ------------------------------------------------------------------

def megaco(mid_ip, mid_port, transactions):
    mid = ctx(1, ctx(0, ctx(0, bytes(mid_ip), False) + ber_int(0x81, mid_port)))
    body = ctx(2, ctx(1, b''.join(transactions)))
    mess = ctx(1, ber_int(0x80, 2) + mid + body)
    return tlv(0x30, mess)


def trans_req(tid, context_id, commands):
    cmds = b''.join(tlv(0x30, ctx(0, c)) for c in commands)
    action = tlv(0x30, ber_int(0x80, context_id) + ctx(3, cmds))
    return ctx(0, ber_int(0x80, tid) + ctx(1, action))


def term_ids(name):
    return ctx(0, tlv(0x30, ctx(0, b'') + ctx(1, name, False)))


def bit_value(bctp):
    """The 'bit' parameter value: an OCTET STRING holding BCTP. The
    Q.1950 package expects the value itself to be a BER OCTET STRING."""
    return tlv(0x04, bctp)


def notify(term, req_id, bctp_list):
    """Notify with one observed Tunnel Indication (bt/tind, 0x0022/0x0001)
    event per BCTP PDU, each with the bit parameter (0x0001)."""
    events = b''
    for bctp in bctp_list:
        par = tlv(0x30, ctx(0, b'\x00\x01', False) +
                  ctx(1, tlv(0x04, bit_value(bctp))))
        events += tlv(0x30, ctx(0, b'\x00\x22\x00\x01', False) + ctx(2, par))
    oed = ctx(1, ber_int(0x80, req_id) + ctx(1, events))
    return ctx(6, term_ids(term) + oed)


def modify_signal(term, bctp):
    """Modify with a signals descriptor holding the Bearer Information
    Tunnel signal (bt/bit, 0x0022/0x0001) with the bit parameter."""
    sigpar = tlv(0x30, ctx(0, b'\x00\x01', False) + ctx(1, tlv(0x04, bit_value(bctp))))
    signal = ctx(0, b'\x00\x22\x00\x01', False) + ctx(6, sigpar)
    # SignalsDescriptor ::= SEQUENCE OF SignalRequest; SignalRequest ::=
    # CHOICE { signal [0] Signal, ... }
    sigdesc = ctx(0, signal)
    # AmmDescriptor CHOICE: signalsDescriptor [5]
    amm = ctx(5, sigdesc)
    # AmmRequest ::= SEQUENCE { terminationID [0], descriptors [1] SEQUENCE OF AmmDescriptor }
    return ctx(2, term_ids(term) + ctx(1, amm))


# BCTP -------------------------------------------------------------------

def bctp(tpi, payload, bvi=1, bvei=0, tpei=0):
    """Q.1990: octet 1 = spare | BVEI | spare | BVI(5); octet 2 = spare |
    TPEI | TPI(6)."""
    return struct.pack('>BB', (bvei << 6) | (bvi & 0x1f),
                       (tpei << 6) | (tpi & 0x3f)) + payload


IPBCP_REQ = (b'v=0\r\n'
             b'o=- 7 7 IN IP4 198.51.100.1\r\n'
             b's=-\r\n'
             b'c=IN IP4 198.51.100.1\r\n'
             b't=0 0\r\n'
             b'a=ipbcp:1 Request\r\n'
             b'm=audio 5004 RTP/AVP 0\r\n')

IPBCP_ACC = (b'v=0\r\n'
             b'o=- 8 8 IN IP4 192.0.2.1\r\n'
             b's=-\r\n'
             b'c=IN IP4 192.0.2.1\r\n'
             b't=0 0\r\n'
             b'a=ipbcp:1 Accepted\r\n'
             b'm=audio 6004 RTP/AVP 0\r\n')


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
        self.tid = 100

    def h248(self, from_mgw, commands, context_id=1):
        self.tid += 1
        src, dst = (IP_MGW, IP_MGC) if from_mgw else (IP_MGC, IP_MGW)
        msg = megaco(src, H248_PORT, [trans_req(self.tid, context_id, commands)])
        pkt = ipv4(17, udp(H248_PORT, H248_PORT, msg, src, dst), src, dst,
                   len(self.frames) + 1)
        self.frames.append(eth(MAC_MGC if from_mgw else MAC_MGW,
                               MAC_MGW if from_mgw else MAC_MGC, 0x0800, pkt))


def main_frames():
    c = Cap()
    # 1: MGW notifies an IPBCP Request (TPI 0x20, to SDP), BVI 1
    c.h248(True, [notify(b'ip/1', 1, [bctp(0x20, IPBCP_REQ)])])
    # 2: MGC tunnels the IPBCP Accepted back in a Modify signal
    c.h248(False, [modify_signal(b'ip/1', bctp(0x20, IPBCP_ACC))])
    # 3: binary encoded spare TPI 0x00 (no dissector: data)
    c.h248(True, [notify(b'ip/2', 2, [bctp(0x00, b'\x01\x02\x03\x04')])])
    # 4: TPI 0x17 and 0x18 (spare / national binary) and 0x22 ("not
    # used", the last value that goes to data) in one Notify
    c.h248(True, [notify(b'ip/3', 3, [bctp(0x17, b'\xaa\xbb'),
                                      bctp(0x18, b'\xcc\xdd\xee'),
                                      bctp(0x22, b'\x00')])])
    # 5: text encoded spare TPI 0x23 (data-text-lines), two lines
    c.h248(True, [notify(b'ip/4', 4, [bctp(0x23, b'line one\r\nline two\r\n')])])
    # 6: TPI 0x21 (spare text, but <= 0x22 so data) and 0x3f (national
    # text, data-text-lines)
    c.h248(True, [notify(b'ip/5', 5, [bctp(0x21, b'spare text'),
                                      bctp(0x3f, b'national use\n')])])
    # 7: Version Error Indication set, BVI 0x1f, tunnelled protocol error
    # indicator set, IPBCP
    c.h248(True, [notify(b'ip/6', 6, [bctp(0x20, IPBCP_REQ, bvi=0x1f, bvei=1, tpei=1)])])
    # 8: only the BCTP header, nothing tunnelled (empty data)
    c.h248(True, [notify(b'ip/7', 7, [bctp(0x00, b'')])])
    # 9: reserved bits set in both octets (masked out of TPI): octet 2
    # 0xa3 is TPI 0x23, TPEI 0
    c.h248(False, [modify_signal(b'ip/8', b'\xa1\xa3' + b'masked bits\n')])
    return c.frames


def malformed_frames():
    c = Cap()
    # 1: an empty BCTP (the octet string has length 0)
    c.h248(True, [notify(b'ip/9', 9, [b''])])
    # 2: one octet of BCTP: reading TPI throws
    c.h248(True, [notify(b'ip/10', 10, [b'\x01'])])
    return c.frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bctp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'bctp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
