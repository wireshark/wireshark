#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Generate json_3gpp_session.pcap: a synthetic Nsmf_PDUSession Create of a
# home routed PDU session (HTTP2 without TLS) and the GTP-U of its N9 and
# S8-U tunnels, for the IMSI of the HTTP2 stream and GTP session tracking
# (gtp.track_gtp_session). The IMSI and addresses are made up.
#
#   1  V-SMF -> H-SMF  HTTP2 connection preface and SETTINGS
#   2  H-SMF -> V-SMF  SETTINGS and SETTINGS ACK
#   3  V-SMF -> H-SMF  SETTINGS ACK, POST /nsmf-pdusession/v1/pdu-sessions
#                      with the SUPI and the vcnTunnelInfo of the V-UPF
#   4  H-SMF -> V-SMF  201 Created with the hcnTunnelInfo of the H-UPF and
#                      an epsBearerInfo with the base64 PGW S8-U F-TEID
#   5  V-UPF -> H-UPF  GTP-U T-PDU to the hcnTunnelInfo TEID (frame 4)
#   6  H-UPF -> V-UPF  GTP-U T-PDU to the vcnTunnelInfo TEID (frame 3)
#   7  SGW -> PGW      GTP-U T-PDU to the PGW S8-U TEID (frame 4)

import base64
import json
import struct
import sys

SBI_PORT = 80
GTPU_PORT = 2152

V_SMF = (10, 0, 7, 1)
H_SMF = (10, 0, 7, 2)
V_UPF = (10, 0, 8, 1)
H_UPF = (10, 0, 8, 2)
SGW = (10, 0, 9, 1)
PGW = (10, 0, 9, 2)

SUPI = 'imsi-001010000000007'

VCN_TEID = 0x7101
HCN_TEID = 0x8101
PGW_S8U_TEID = 0x9101


def ipv4_str(addr):
    return '.'.join(map(str, addr))


def f_teid_ie(if_type, teid, ipv4):
    # GTPv2 F-TEID IE (3GPP TS 29.274 8.22) with its header, IPv4
    value = struct.pack('!BI4s', 0x80 | if_type, teid, bytes(ipv4))
    return struct.pack('!BHB', 87, len(value), 0) + value


def hpack_literal(name, value):
    # Literal Header Field without Indexing, New Name, no Huffman coding
    name, value = name.encode(), value.encode()
    return bytes((0x00, len(name))) + name + bytes((len(value),)) + value


def h2_frame(frame_type, flags, stream_id, payload=b''):
    return struct.pack('!I', len(payload))[1:] + bytes((frame_type, flags)) + \
        struct.pack('!I', stream_id) + payload


DATA, HEADERS, SETTINGS = 0, 1, 4
END_STREAM, ACK, END_HEADERS = 0x1, 0x1, 0x4

PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


def headers(stream_id, *fields):
    return h2_frame(HEADERS, END_HEADERS, stream_id,
                    b''.join(hpack_literal(n, v) for n, v in fields))


def body(stream_id, obj):
    return h2_frame(DATA, END_STREAM, stream_id, json.dumps(obj).encode())


def tcp(sport, dport, seq, ack, payload):
    # PSH, ACK; the checksum is not checked
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, 0x18, 65535, 0, 0) + payload


def udp(port, payload):
    return struct.pack('!HHHH', port, port, 8 + len(payload), 0) + payload


def gtpu_tpdu(teid):
    # An IPv4 packet with protocol 253 (for experimentation) as the T-PDU
    tpdu = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 24, 0, 0x4000, 64, 253, 0,
                       bytes((192, 168, 0, 1)), bytes((192, 168, 0, 2))) + bytes(4)
    return struct.pack('!BBHI', 0x30, 0xff, len(tpdu), teid) + tpdu


def frame(src, dst, proto, payload):
    eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb' + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0,
                     bytes(src), bytes(dst))
    return eth + ip + payload


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'json_3gpp_session.pcap'
    create_data = {
        'supi': SUPI,
        'pduSessionId': 5,
        'dnn': 'internet',
        'vcnTunnelInfo': {'ipv4Addr': ipv4_str(V_UPF), 'gtpTeid': '%08X' % VCN_TEID},
    }
    created_data = {
        'pduSessionType': 'IPV4',
        'hcnTunnelInfo': {'ipv4Addr': ipv4_str(H_UPF), 'gtpTeid': '%08X' % HCN_TEID},
        'epsBearerInfo': [{
            'ebi': 5,
            # F-TEID interface type 5: S5/S8 PGW GTP-U
            'pgwS8uFteid': base64.b64encode(f_teid_ie(5, PGW_S8U_TEID, PGW)).decode(),
        }],
    }
    client = [
        PREFACE + h2_frame(SETTINGS, 0, 0),
        h2_frame(SETTINGS, ACK, 0) +
        headers(1, (':method', 'POST'), (':scheme', 'http'), (':authority', 'h-smf.example'),
                (':path', '/nsmf-pdusession/v1/pdu-sessions'),
                ('content-type', 'application/json')) +
        body(1, create_data),
    ]
    server = [
        h2_frame(SETTINGS, 0, 0) + h2_frame(SETTINGS, ACK, 0),
        headers(1, (':status', '201'), ('content-type', 'application/json')) +
        body(1, created_data),
    ]
    cseq, sseq = 1000, 5000
    segments = []
    for c, s in zip(client, server):
        segments.append(frame(V_SMF, H_SMF, 6, tcp(40000, SBI_PORT, cseq, sseq, c)))
        cseq += len(c)
        segments.append(frame(H_SMF, V_SMF, 6, tcp(SBI_PORT, 40000, sseq, cseq, s)))
        sseq += len(s)
    frames = segments + [
        frame(V_UPF, H_UPF, 17, udp(GTPU_PORT, gtpu_tpdu(HCN_TEID))),
        frame(H_UPF, V_UPF, 17, udp(GTPU_PORT, gtpu_tpdu(VCN_TEID))),
        frame(SGW, PGW, 17, udp(GTPU_PORT, gtpu_tpdu(PGW_S8U_TEID))),
    ]
    with open(path, 'wb') as f:
        # pcap global header, LINKTYPE_ETHERNET (1)
        f.write(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, rec in enumerate(frames):
            f.write(struct.pack('!IIII', i, 0, len(rec), len(rec)))
            f.write(rec)


if __name__ == '__main__':
    main()
