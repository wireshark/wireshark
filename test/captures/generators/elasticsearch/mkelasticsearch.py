#!/usr/bin/env python3
# Generates test/captures/elasticsearch_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Elasticsearch dissector
(packet-elasticsearch.c).

Two protocols: the Zen discovery ping over UDP port 54328 (internal
header, VInt version, ping ID, cluster name and the discovery node with
its transport address) and the binary transport protocol over TCP port
9300: "ES", a 4 octet message length, request ID, status flags
(response, error, compressed), version, then depending on the version
a variable header size (7.6+), request and response thread context
headers (5.0+) and, for requests, the feature list (6.3+) and the
action name. Strings are VInt length prefixed. Every packet is built
from scratch with struct; no captured traffic is used.

Usage: mkelasticsearch.py <output directory>

Writes:
  elasticsearch-coverage.pcap            Zen pings with every address
                                         form; binary requests and
                                         responses of every version
                                         range, compressed and error
                                         messages, VInts of every length,
                                         two messages in a segment and
                                         one over two segments
  elasticsearch-coverage-malformed.pcap  strings and addresses past the
                                         end of the data
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from pkt import (LINKTYPE_ETHERNET, TcpFlow, eth, ip6, ipv4, udp,
                 write_pcap)

ZEN_PORT = 54328
BIN_PORT = 9300
NODE1, NODE2 = "192.0.2.31", "192.0.2.32"

V1 = 1070099      # 1.7.0: no thread context
V5 = 5060099      # 5.6.0: thread context headers
V6 = 6080099      # 6.8.0: features
V7 = 7100299      # 7.10.2: variable header size


def vint(v, width=None):
    """Elasticsearch VInt: 7 bits per octet, low bits first. width forces
    a longer (non-minimal) encoding."""
    v &= 0xFFFFFFFF
    out = []
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b)
        if not v:
            break
    if width:
        out += [0] * (width - len(out))
    return bytes([b | 0x80 for b in out[:-1]] + [out[-1]])


def vstr(s, width=None):
    if isinstance(s, str):
        s = s.encode()
    return vint(len(s), width) + s


# ---------------------------------------------------------------- Zen ping

def address(kind):
    if kind == "ipv4":
        return struct.pack(">HBB", 1, 0, 4) + bytes([192, 0, 2, 31]) + struct.pack(">I", 9300)
    if kind == "ipv6":
        return (struct.pack(">HBB", 1, 0, 16) + ip6("2001:db8::31") +
                struct.pack(">I", 3) + struct.pack(">I", 9301))
    if kind == "string":
        return struct.pack(">HB", 1, 1) + vstr("node1.example") + struct.pack(">I", 9302)
    if kind == "badtype":
        return struct.pack(">H", 2)
    if kind == "badformat":
        return struct.pack(">HB", 1, 2) + struct.pack(">I", 9303)
    raise ValueError(kind)


def zen(version, ping_id, cluster, node, addr, attrs=0):
    p = struct.pack(">I", 0x01090309) + vint(version) + struct.pack(">I", ping_id)
    p += vstr(cluster) + vstr(node) + vstr("nodeid-" + node) + vstr(node + ".example")
    p += vstr("192.0.2.31") + address(addr) + vint(attrs) + vint(version)
    return p


def zen_frame(payload, n):
    src, dst = NODE1, "192.0.2.255"
    return eth(ipv4(udp(payload, ZEN_PORT, ZEN_PORT, src, dst), 17, src, dst,
                    ident=n), 0x0800, 1, 0xff)


# ---------------------------------------------------------- binary protocol

def es_msg(request_id, status, version, rest, header_size=None):
    """'ES', message length, request ID, status, version, rest."""
    body = struct.pack(">QBI", request_id, status, version)
    if version >= 7060099:
        body += struct.pack(">I", len(rest) if header_size is None else header_size)
    body += rest
    return b"ES" + struct.pack(">I", len(body)) + body


def headers(req=(), resp=(), req_count=None, resp_count=None, width=None):
    """Thread context: request headers (key, value) and response headers
    (key, [values])."""
    h = vint(len(req), width) if req_count is None else req_count
    for k, v in req:
        h += vstr(k) + vstr(v)
    h += vint(len(resp), width) if resp_count is None else resp_count
    for k, vals in resp:
        h += vstr(k) + vint(len(vals))
        for v in vals:
            h += vstr(v)
    return h


def request(features=None, action="", data=b"", feature_count=None):
    r = b""
    if features is not None:
        r += vint(len(features)) if feature_count is None else feature_count
        for f in features:
            r += vstr(f)
    return r + vstr(action) + data


def main_frames():
    F = []
    # 1: Zen ping, IPv4 numeric transport address
    F.append(zen_frame(zen(V1, 1, "cluster-a", "node1", "ipv4"), 1))
    # 2: Zen ping, IPv6 address with a scope ID
    F.append(zen_frame(zen(V5, 2, "cluster-a", "node2", "ipv6"), 2))
    # 3: Zen ping, address as a host name string
    F.append(zen_frame(zen(V6, 3, "cluster-b", "node3", "string"), 3))
    # 4: Zen ping from a 7.10 node with an IPv4 address
    F.append(zen_frame(zen(V7, 4, "c", "n4", "ipv4"), 4))
    # 5: Zen ping with an address string and attributes length 130 (a
    #    2 octet VInt)
    F.append(zen_frame(zen(V1, 5, "c", "n5", "string", attrs=130), 5))

    f = TcpFlow(NODE1, NODE2, 50000, BIN_PORT, 1, 2)
    F += f.handshake()                                          # 6-8
    # 9: 1.7 request: no thread context, action and data
    F.append(f.data(True, es_msg(1, 0x00, V1,
                                 request(None, "internal:discovery/zen/unicast",
                                         b"\x01\x02\x03"))))
    # 10: 1.7 response OK
    F.append(f.data(False, es_msg(1, 0x01, V1, b"\x00\x00")))
    # 11: 5.6 request with two request headers and a response header with
    #     two values, then the action
    F.append(f.data(True, es_msg(2, 0x00, V5,
                                 headers([("X-Opaque-Id", "abc"), ("k", "")],
                                         [("Warning", ["w1", "w2"])]) +
                                 request(None, "cluster:monitor/health", b"\x00"))))
    # 12: 5.6 error response with an empty response header list item
    F.append(f.data(False, es_msg(2, 0x03, V5,
                                  headers([], [("Empty", [])]) + b"error-data")))
    # 13: 6.8 request with two features
    F.append(f.data(True, es_msg(3, 0x00, V6,
                                 headers() + request(["x-pack", "security"],
                                                     "indices:data/read/search",
                                                     b"query"))))
    # 14: 6.8 compressed request (the rest is compressed data)
    F.append(f.data(True, es_msg(4, 0x04, V6, headers() + b"DFL\x00\x01\x02")))
    # 15: 7.10 response, compressed and error
    F.append(f.data(False, es_msg(4, 0x07, V7, headers() + b"DFL\x00\x09")))
    # 16: 7.10 request: header size, VInts in 2-5 octets (a 200 octet
    #     action name, a header count of 1 in 4 octets, feature count 0 in
    #     5 octets)
    F.append(f.data(True, es_msg(5, 0x00, V7,
                                 headers([("h", "v")], [], width=4) +
                                 request([], "a" * 200, b"\x00",
                                         feature_count=vint(0, 5)))))
    # 17: the fix "Elasticsearch: Avoid a signed shift overflow in
    #     read_vint()": request header count ff ff ff ff 0f, whose fifth
    #     octet shifted left by 28 overflowed an int; the count is -1,
    #     so there are no headers.
    F.append(f.data(True, es_msg(6, 0x00, V5,
                                 b"\xff\xff\xff\xff\x0f" + vint(0) +
                                 request(None, "after/negative", b"\x00"))))
    # 18: two responses in one segment
    F.append(f.data(False, es_msg(5, 0x01, V7, headers() + b"r5") +
                    es_msg(6, 0x01, V5, headers() + b"r6")))
    # 19-20: a request over two segments (TCP reassembly)
    m = es_msg(7, 0x00, V6, headers([("trace", "t" * 30)]) +
               request(["f1"], "indices:admin/create", b"D" * 40))
    F.append(f.data(True, m[:30]))
    F.append(f.data(True, m[30:]))
    # 21: not an Elasticsearch header (warning)
    F.append(f.data(False, b"HTTP/1.0 400\r\n"))
    return F


def malformed_frames():
    F = []
    # 1: Zen ping cut in the cluster name
    F.append(zen_frame(zen(V1, 1, "cluster-a", "node1", "ipv4")[:14], 1))
    # 2: Zen ping cut in the IPv6 address
    F.append(zen_frame(zen(V1, 2, "c", "n", "ipv6")[:-30], 2))
    # 3: Zen ping, unsupported address type (malformed group warning)
    F.append(zen_frame(zen(V7, 3, "c", "n3", "badtype"), 3))
    # 4: Zen ping, unsupported address format (malformed group warning)
    F.append(zen_frame(zen(V1, 4, "c", "n4", "badformat"), 4))
    f = TcpFlow(NODE1, NODE2, 50001, BIN_PORT, 1, 2)
    F += f.handshake()
    # 8: request with an action name length past the end
    F.append(f.data(True, es_msg(1, 0x00, V1, vint(100) + b"short")))
    # 9: request with a negative (5 octet) action length
    F.append(f.data(True, es_msg(2, 0x00, V1, b"\x80\x80\x80\x80\x08x")))
    # 10: a request with nothing after the action name: the empty data
    #    item at the end of the message throws
    F.append(f.data(True, es_msg(4, 0x00, V1, vstr("empty/body"))))
    # 11: response header list cut short
    F.append(f.data(False, es_msg(3, 0x01, V5, vint(0) + vint(2) + vstr("k"))))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "elasticsearch-coverage.pcap"),
               main_frames(), LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "elasticsearch-coverage-malformed.pcap"),
               malformed_frames(), LINKTYPE_ETHERNET)


if __name__ == "__main__":
    main()
