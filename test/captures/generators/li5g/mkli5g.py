#!/usr/bin/env python3
# Generates test/captures/li5g_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic ETSI TS 103 221-2 (X2/X3, "LI5G") captures.
# Every packet is built here; nothing is captured traffic. The LI5G PDUs
# are carried in Exported PDUs (linktype 252), named either with the
# dissector name tag ("li5g") or the heuristic dissector name tag
# ("li5g_tls", the 5G LI over TLS heuristic).
#
# Usage: mkli5g.py <outdir>
import os
import struct
import sys

# ---------------------------------------------------------------- helpers


def tlv(t, v):
    return struct.pack('>HH', t, len(v)) + v


def exp_pdu(payload, name='li5g', heur=False, addrs=None):
    tags = tlv(13 if heur else 12, name.encode())
    if addrs:
        src, dst, sport, dport = addrs
        tags += (tlv(20, bytes(src)) + tlv(21, bytes(dst)) + tlv(24, struct.pack('>I', 2)) +
                 tlv(25, struct.pack('>I', sport)) + tlv(26, struct.pack('>I', dport)))
    return tags + struct.pack('>HH', 0, 0) + payload


def write_pcap(fn, pkts, linktype=252):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


XID = bytes.fromhex('0123456789abcdef0123456789abcdef')


def attr(atype, value):
    return struct.pack('>HH', atype, len(value)) + value


def li5g(pdu_type, pformat, pdir, attrs=b'', payload=b'', cid=0x1122334455667788,
         version=1, header_len=None, payload_len=None):
    hl = 40 + len(attrs) if header_len is None else header_len
    pl = len(payload) if payload_len is None else payload_len
    return (struct.pack('>HHIIHH', version, pdu_type, hl, pl, pformat, pdir) + XID +
            struct.pack('>Q', cid) + attrs + payload)


# ------------------------------------------------------- payload builders


def ipv4(proto, payload, src=(10, 0, 0, 1), dst=(10, 0, 0, 2), ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                      bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp4(sport, dport, payload, **kw):
    return ipv4(17, struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload, **kw)


def syslog(text):
    # syslog has no request/response tracking, so one and two passes match
    return b'<34>Nov 14 22:13:20 poi li5g: ' + text


def ipv6_udp_syslog():
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    data = syslog(b'over IPv6')
    msg = struct.pack('>HHHH', 40514, 514, 8 + len(data), 0) + data
    pseudo = src + dst + struct.pack('>IxxxB', len(msg), 17)
    msg = msg[:6] + struct.pack('>H', csum(pseudo + msg)) + msg[8:]
    return struct.pack('>IHBB', 0x60000000, len(msg), 17, 64) + src + dst + msg


def ethernet():
    return (bytes.fromhex('020000000002') + bytes.fromhex('020000000001') + b'\x08\x00' +
            udp4(40514, 514, syslog(b'over Ethernet'), ident=7))


def rtp():
    return struct.pack('>BBHII', 0x80, 0, 1000, 160000, 0xdeadbeef) + b'\xff' * 160


def sip():
    return (b'OPTIONS sip:target@example.net SIP/2.0\r\n'
            b'Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776asdhds\r\n'
            b'Max-Forwards: 70\r\n'
            b'To: <sip:target@example.net>\r\n'
            b'From: <sip:poi@example.org>;tag=1928301774\r\n'
            b'Call-ID: a84b4c76e66710@192.0.2.10\r\n'
            b'CSeq: 63104 OPTIONS\r\n'
            b'Content-Length: 0\r\n\r\n')


def dhcp():
    return (struct.pack('>BBBBIHH4s4s4s4s', 1, 1, 6, 0, 0x3903f326, 0, 0x8000,
                        b'\0' * 4, b'\0' * 4, b'\0' * 4, b'\0' * 4) +
            bytes.fromhex('020000000001') + b'\0' * 10 + b'\0' * 64 + b'\0' * 128 +
            b'\x63\x82\x53\x63' + b'\x35\x01\x01' + b'\x0c\x04host' + b'\xff')


def radius():
    attrs = b'\x01\x06user' + b'\x04\x06' + bytes([192, 0, 2, 20])
    return struct.pack('>BBH', 1, 42, 20 + len(attrs)) + bytes(range(16)) + attrs


def gtpu():
    inner = udp4(5000, 514, syslog(b'over GTP-U'), src=(10, 45, 0, 1), dst=(10, 45, 0, 2))
    return struct.pack('>BBHI', 0x30, 0xff, len(inner), 0x01020304) + inner


def msrp():
    return (b'MSRP a786hjs2 SEND\r\n'
            b'To-Path: msrp://biloxi.example.com:12763/kjhd37s2s20w2a;tcp\r\n'
            b'From-Path: msrp://atlanta.example.com:7654/jshA7weztas;tcp\r\n'
            b'Message-ID: 87652491\r\n'
            b'Byte-Range: 1-5/5\r\n'
            b'Content-Type: text/plain\r\n\r\n'
            b'Hello\r\n'
            b'-------a786hjs2$\r\n')


def ber(tag, content):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82, n >> 8, n & 0xff])
    return bytes([tag]) + ln + content


def xiri():
    # XIRIPayload { xIRIPayloadOID [1], event [2] deregistration [2]
    #   { deregistrationDirection [1] uEInitiated, accessType [2] 3GPP } }
    dereg = ber(0x81, b'\x02') + ber(0x82, b'\x01')
    return ber(0x30, ber(0x81, bytes([4, 0, 2, 2, 5, 1, 17])) + ber(0xa2, ber(0xa2, dereg)))


def hi2_eps():
    # EpsIRIContent iRI-Begin-record [1] IRI-Parameters
    params = (ber(0x80, bytes([0x04, 0x00, 0x02, 0x02, 0x04, 0x08, 0x12, 0x00])) +  # hi2epsDomainId
              ber(0x81, b'LIID-0001') +                                           # LIID
              ber(0xa3, ber(0x81, b'231114221320Z')) +                             # utcTime
              ber(0x84, b'\x01'))                                                 # originating-Target
    return ber(0xa1, params)


# ------------------------------------------------------------ attributes

SUPI_A = b'<supiimsi>001010123456789</supiimsi>'
SUPI_B = b'<targetIdentifier><SUPIIMSI>310410987654321</SUPIIMSI></targetIdentifier>'


def all_attrs():
    return (attr(1, b'\x30\x03\x02\x01\x01') +           # ETSI TS 102 232-1
            attr(2, b'\x30\x03\x80\x01\x05') +           # 3GPP TS 33.128
            attr(3, b'\x30\x03\x81\x01\x07') +           # 3GPP TS 33.108
            attr(4, b'\x00\x00\x00\x2a' + b'vendor') +   # proprietary
            attr(5, b'operator.example') +               # Domain ID
            attr(6, b'smf-01.example') +                 # NF ID
            attr(7, b'ipid-7') +                         # Interception Point ID
            attr(8, struct.pack('>H', 4242)) +           # Sequence Number
            attr(9, struct.pack('>II', 1700000000, 500000000)) +  # Timestamp
            attr(10, bytes([10, 1, 2, 3])) +
            attr(11, bytes([10, 4, 5, 6])) +
            attr(12, bytes.fromhex('20010db8000000000000000000000010')) +
            attr(13, bytes.fromhex('20010db8000000000000000000000020')) +
            attr(14, struct.pack('>H', 5060)) +
            attr(15, struct.pack('>H', 443)) +
            attr(16, b'\x11') +                          # UDP
            attr(17, SUPI_A) +                           # Matched Target Identifier
            attr(18, SUPI_B) +                           # Other Target Identifier (case)
            attr(19, b'application/sdp') +
            attr(20, b'8bit') +
            attr(21, b'\x00\x01\x02\x03') +
            attr(22, b'v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\n'))


OUTER = ((198, 51, 100, 1), (198, 51, 100, 2), 40001, 40002)


def main_frames():
    F = []          # (description, exported pdu)
    # 1-4: the four PDU types, by name
    F.append(('X2 xIRI with every defined attribute, xIRI payload',
              exp_pdu(li5g(1, 2, 2, all_attrs(), xiri()), addrs=OUTER)))
    F.append(('X3 xCC, IPv4 payload',
              exp_pdu(li5g(2, 5, 3, attr(8, b'\x00\x01'), udp4(40514, 514, syslog(b'X3 xCC'))),
                      addrs=OUTER)))
    F.append(('Keepalive', exp_pdu(li5g(3, 0, 0))))
    F.append(('Keepalive Acknowledgement', exp_pdu(li5g(4, 0, 0))))
    # 5: unknown PDU type: no Info text
    F.append(('unknown PDU type 9', exp_pdu(li5g(9, 4, 1, payload=b'opaque'))))
    # 6: reserved attribute type 0 between two attributes (the assertion fix)
    F.append(('attribute type 0',
              exp_pdu(li5g(1, 2, 2, attr(5, b'did') + attr(0, b'\xde\xad\xbe\xef') +
                           attr(8, b'\x00\x02'), xiri()))))
    # 7: unknown attribute types 23, 0x8000, 0xffff (skipped), and an empty attribute
    F.append(('unknown attribute types',
              exp_pdu(li5g(2, 6, 4, attr(23, b'x') + attr(0x8000, b'abcd') +
                           attr(0xffff, b'') + attr(7, b''), ipv6_udp_syslog()))))
    # 8-10: SUPI matching
    F.append(('SUPI: two IMSIs in one header (regex reused)',
              exp_pdu(li5g(1, 2, 3, attr(17, SUPI_A) + attr(18, SUPI_B), xiri()))))
    F.append(('SUPI: NAI and too-short IMSI, no match',
              exp_pdu(li5g(1, 2, 3, attr(17, b'<supinai>user@example.net</supinai>') +
                           attr(18, b'<supiimsi>1234</supiimsi>'), xiri()))))
    F.append(('SUPI: IMSI after a newline (first line only), no match',
              exp_pdu(li5g(1, 2, 3, attr(17, b'target\n<supiimsi>001010000000001</supiimsi>'),
                           xiri()))))
    # 11-: every payload format
    payloads = [
        (0, b''), (1, b'\x30\x00'), (3, b'\x30\x00'), (4, b'proprietary'),
        (6, ipv6_udp_syslog()), (7, ethernet()), (8, rtp()), (9, sip()),
        (10, dhcp()), (11, radius()), (12, gtpu()), (13, msrp()), (14, hi2_eps()),
        (15, b'Content-Type: text/plain\r\n\r\nmime body'), (16, b'\x45unstructured'),
        (17, b'future format'), (0xffff, b'\x01\x02'),
    ]
    for d, (fmt, pl) in enumerate(payloads):
        ptype = 3 if fmt == 0 else (1 if fmt in (1, 2, 3, 14) else 2)
        F.append(('payload format %d' % fmt,
                  exp_pdu(li5g(ptype, fmt, d % 7, attr(8, struct.pack('>H', fmt)), pl),
                          addrs=OUTER if fmt == 7 else None)))
    # several LI5G PDUs in one frame
    multi = (li5g(2, 5, 2, payload=udp4(40514, 514, syslog(b'first of three'))) +
             li5g(2, 9, 3, payload=sip()) +
             li5g(3, 0, 0))
    F.append(('three PDUs in one frame', exp_pdu(multi, addrs=OUTER)))
    # the 5G LI over TLS heuristic
    F.append(('li5g_tls: X2 xIRI', exp_pdu(li5g(1, 2, 2, attr(17, SUPI_A) + attr(0, b''), xiri()),
                                           name='li5g_tls', heur=True)))
    F.append(('li5g_tls: Keepalive', exp_pdu(li5g(3, 0, 0), name='li5g_tls', heur=True)))
    F.append(('li5g_tls: X3 xCC, two PDUs', exp_pdu(
        li5g(2, 5, 2, payload=udp4(40514, 514, syslog(b'over TLS'))) + li5g(4, 0, 0),
        name='li5g_tls', heur=True)))
    # heuristic rejects: too short, version 2, PDU type 0 and 5 -> data
    F.append(('li5g_tls reject: 39 bytes', exp_pdu(li5g(3, 0, 0)[:39], name='li5g_tls', heur=True)))
    F.append(('li5g_tls reject: version 2', exp_pdu(li5g(3, 0, 0, version=2), name='li5g_tls', heur=True)))
    F.append(('li5g_tls reject: PDU type 0', exp_pdu(li5g(0, 0, 0), name='li5g_tls', heur=True)))
    F.append(('li5g_tls reject: PDU type 5', exp_pdu(li5g(5, 0, 0), name='li5g_tls', heur=True)))
    return F


def malformed_frames():
    F = []
    # header length below 40: the attribute loop runs past the header
    F.append(('header length 0', exp_pdu(li5g(3, 0, 0, header_len=0))))
    # the batch reproducer (header length 0 through the heuristic)
    F.append(('li5g_tls header length 0', exp_pdu(b'\0\x01\0\x01' + b'\0' * 40,
                                                  name='li5g_tls', heur=True)))
    # attribute running past the header length
    F.append(('attribute past header', exp_pdu(li5g(1, 4, 1, attr(5, b'abcdef'), b'pl',
                                                    header_len=44))))
    # payload length past the end
    F.append(('payload length too long', exp_pdu(li5g(2, 4, 1, payload=b'abc', payload_len=100))))
    # truncated fixed header
    F.append(('truncated header', exp_pdu(li5g(3, 0, 0)[:20])))
    # attribute lengths that do not fit the field types
    F.append(('sequence number of 4 octets (TS 103 221-2)', exp_pdu(li5g(1, 4, 1, attr(8, b'\0\0\0\1'), b'x'))))
    F.append(('IPv4 address of 3 octets', exp_pdu(li5g(1, 4, 1, attr(10, b'\1\2\3'), b'x'))))
    F.append(('timestamp of 4 octets', exp_pdu(li5g(1, 4, 1, attr(9, b'\0\0\0\1'), b'x'))))
    # a broken inner IPv4 packet
    F.append(('bad inner IPv4', exp_pdu(li5g(2, 5, 1, payload=b'\x45\x00\x00'))))
    # more PDUs in one frame than the dissection depth limit (500)
    F.append(('many PDUs in one frame', exp_pdu(li5g(3, 0, 0) * 600)))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = main_frames()
    write_pcap(os.path.join(out, 'li5g-coverage.pcap'), [p for _, p in m])
    write_pcap(os.path.join(out, 'li5g-coverage-malformed.pcap'), [p for _, p in malformed_frames()])
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for i, (d, _) in enumerate(m, 1):
            f.write('%3d %s\n' % (i, d))


if __name__ == '__main__':
    main()
