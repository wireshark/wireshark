#!/usr/bin/env python3
# Generates test/captures/exported_pdu_tls_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate a synthetic Exported PDU capture with one PDU for every
# heuristic dissector of the "tls" list, named with the heuristic
# dissector name tag (13), as "tshark -U" writes for TLS application
# data found by heuristics. Nothing here is captured traffic.
#
# Usage: mkexported_pdu_tls.py <outdir>
import os
import struct
import sys


def tlv(t, v):
    return struct.pack('>HH', t, len(v)) + v


def exp_pdu(heur_name, payload, extra=b''):
    # tag 13 = heuristic dissector name, then optional tags, then end
    return tlv(13, heur_name.encode()) + extra + struct.pack('>HH', 0, 0) + payload


def ipv4_ports(src, dst, sport, dport):
    return (tlv(20, bytes(src)) + tlv(21, bytes(dst)) +
            tlv(24, struct.pack('>I', 2)) +          # port type TCP
            tlv(25, struct.pack('>I', sport)) + tlv(26, struct.pack('>I', dport)))


def pcapng_block(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    n = len(body) + 12
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)


def write_pcapng(fn, pkts, linktype=252):
    with open(fn, 'wb') as f:
        f.write(pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        f.write(pcapng_block(1, struct.pack('<HHI', linktype, 0, 0)))
        for i, p in enumerate(pkts):
            ts = (1700000000 + i) * 1000000
            f.write(pcapng_block(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff,
                                                len(p), len(p)) + p))


def fix_msg(fields):
    body = b''.join(b'%d=%s\x01' % (t, v) for t, v in fields)
    head = b'8=FIX.4.2\x019=%d\x01' % len(body)
    msg = head + body
    return msg + b'10=%03d\x01' % (sum(msg) % 256)


def li5g(pdu_type, pformat, pdir, attrs=b'', payload=b''):
    hl = 40 + len(attrs)
    return (struct.pack('>HHIIHH', 1, pdu_type, hl, len(payload), pformat, pdir) +
            bytes(range(0x10, 0x20)) + struct.pack('>Q', 7) + attrs + payload)


def rpc_call(xid, prog, vers, proc):
    body = struct.pack('>IIIIIIIIII', xid, 0, 2, prog, vers, proc, 0, 0, 0, 0)
    return struct.pack('>I', 0x80000000 | len(body)) + body


def mq_tsh(segtype, body=b''):
    n = 28 + len(body)
    return (b'TSH ' + struct.pack('>IBBBB', n, 1, segtype, 0x30, 0) + b'\0' * 8 +
            struct.pack('>IHH', 0x0111, 819, 0) + body)


def cases():
    frames = []
    # 1: the reproducer of issue 21702: HTTP response found by http_tls
    frames.append(('http_tls', b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', b''))
    # 2: HTTP request, with addresses and ports
    frames.append(('http_tls', b'GET /index.html HTTP/1.1\r\nHost: example.net\r\n\r\n',
                   ipv4_ports((192, 0, 2, 1), (192, 0, 2, 2), 40000, 443)))
    # 3: HTTP/2 connection preface and an empty SETTINGS frame
    frames.append(('http2_tls', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' +
                   struct.pack('>I', 0)[1:] + b'\x04\x00' + struct.pack('>I', 0), b''))
    # 4: WebSphere MQ heartbeat
    frames.append(('mq_tls', mq_tsh(0x09), b''))
    # 5: FIX heartbeat
    frames.append(('fix_tls', fix_msg([(35, b'0'), (49, b'SENDER'), (56, b'TARGET'),
                                       (34, b'1'), (52, b'20231114-22:13:20')]), b''))
    # 6: 5G LI keepalive
    frames.append(('li5g_tls', li5g(3, 0, 0), b''))
    # 7: AIM FLAP sign-on (aim_tls is disabled by default but is called
    # directly by name)
    frames.append(('aim_tls', b'\x2a\x01' + struct.pack('>HH', 1, 4) + struct.pack('>I', 1), b''))
    # 8: ONC RPC NFSv3 NULL call with a record marker
    frames.append(('rpc_tls', rpc_call(0x12345678, 100003, 3, 0), b''))
    # 9: TPKT with a COTP connection request
    cotp = b'\x06\xe0\x00\x00\x00\x00\x00'
    frames.append(('tpkt_tls', struct.pack('>BBH', 3, 0, 4 + len(cotp)) + cotp, b''))
    # 10: SMPP enquire_link
    frames.append(('smpp_tls', struct.pack('>IIII', 16, 0x15, 0, 1), b''))
    # 11: RTI TCP Identity Bind Request (control message, no attributes)
    frames.append(('rtitcp_tls', struct.pack('>HHIHHI', 0, 20, 0xdd54dd55, 0x0c01, 0, 0x2112A442) +
                   bytes(range(1, 13)), b''))
    # 12: RDP multitransport TunnelCreateRequest
    frames.append(('rdpmt_tls_', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 1, 0) +
                   bytes(range(0xa0, 0xb0)), b''))
    # 13: RDP Fast-Path client input PDU with one scancode event (no
    # addresses, so it is taken as client to server)
    frames.append(('rdp_tls', b'\x04\x04\x00\x1e', b''))
    # 14: CredSSP TSRequest version 6 with pubKeyAuth
    frames.append(('credssp_tls', bytes.fromhex('300fa003020106a308040601020304050f'), b''))
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pkts = [exp_pdu(name, payload, extra) for name, payload, extra in cases()]
    write_pcapng(os.path.join(out, 'exported_pdu_tls-coverage.pcapng'), pkts)


if __name__ == '__main__':
    main()
