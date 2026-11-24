#!/usr/bin/env python3
# Generates test/captures/socks_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SOCKS coverage captures. Usage: mksocks.py <outdir> [-v]
Writes socks-coverage.pcapng (main, with two interfaces: Ethernet and Exported PDU) and socks-coverage-malformed.pcap.
SOCKS is registered on TCP 1080 by default (and on TLS with a keyed
session, not used here). The tunnelled traffic after a CONNECT is plain
HTTP on port 80 and DNS in the UDP ASSOCIATE datagrams. The user names
and passwords are made up. Everything is synthetic (192.0.2.0/24,
198.51.100.0/24, 2001:db8::/32)."""
import os
import socket
import struct
import sys
from pcaplib import CLI, exp_pdu, SRV, TcpFlow, udp, write_pcap, write_pcapng

PROXY, CLIENT = SRV, CLI
V6 = socket.inet_pton(socket.AF_INET6, '2001:db8::25')

def a4(ip=(198, 51, 100, 7)):
    return b'\x01' + bytes(ip)

def a6():
    return b'\x04' + V6

def adom(name):
    n = name.encode()
    return b'\x03' + bytes([len(n)]) + n

def port(p):
    return struct.pack('!H', p)

def req5(cmd, addr, p):
    return bytes([5, cmd, 0]) + addr + port(p)

def rep5(rc, addr, p):
    return bytes([5, rc, 0]) + addr + port(p)

def dns_query(name=b'example.invalid', txid=0x1234):
    q = b''.join(bytes([len(x)]) + x for x in name.split(b'.')) + b'\x00'
    return struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0) + q + struct.pack('!HH', 1, 1)

def dns_reply(name=b'example.invalid', txid=0x1234):
    q = b''.join(bytes([len(x)]) + x for x in name.split(b'.')) + b'\x00'
    return (struct.pack('!HHHHHH', txid, 0x8180, 1, 1, 0, 0) + q + struct.pack('!HH', 1, 1)
            + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + bytes((198, 51, 100, 9)))

HTTP_REQ = b'GET /index.html HTTP/1.1\r\nHost: www.example.invalid\r\n\r\n'
HTTP_RSP = b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello'

def main_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    def addl(name, frs):
        R[name] = len(F) + 1; F.extend(frs)
    # ---- SOCKS5, no authentication, CONNECT to IPv4; HTTP through the tunnel ----
    f = TcpFlow(40000, 1080)
    addl('s1-handshake', f.handshake())
    add('s1-greeting', f.c2s(b'\x05\x01\x00'))
    add('s1-method', f.s2c(b'\x05\x00'))
    add('s1-connect', f.c2s(req5(1, a4(), 80)))
    add('s1-reply', f.s2c(rep5(0, a4((192, 0, 2, 2)), 40001)))
    add('s1-http-req', f.c2s(HTTP_REQ))
    add('s1-http-rsp', f.s2c(HTTP_RSP))
    addl('s1-fin', f.fin())
    # ---- SOCKS5, greeting and command in one segment, two methods offered, CONNECT to a name ----
    f = TcpFlow(40002, 1080)
    addl('s2-handshake', f.handshake())
    add('s2-greeting-cmd', f.c2s(b'\x05\x01\x00' + req5(1, adom('www.example.invalid'), 80)))
    add('s2-reply', f.s2c(b'\x05\x00' + rep5(0, a4((192, 0, 2, 2)), 40003)))
    add('s2-http', f.c2s(HTTP_REQ))
    addl('s2-fin', f.fin())
    # ---- SOCKS5, username/password authentication, CONNECT to IPv6 ----
    f = TcpFlow(40004, 1080)
    addl('s3-handshake', f.handshake())
    add('s3-greeting', f.c2s(b'\x05\x03\x00\x02\x80'))
    add('s3-method', f.s2c(b'\x05\x02'))
    add('s3-auth', f.c2s(b'\x01\x05alice\x08password'))
    add('s3-auth-ok', f.s2c(b'\x01\x00'))
    add('s3-connect', f.c2s(req5(1, a6(), 8080)))
    add('s3-reply', f.s2c(rep5(0, a6(), 40005)))
    add('s3-data', f.c2s(b'opaque tunnelled data'))
    addl('s3-fin', f.fin())
    # authentication failure
    f = TcpFlow(40006, 1080)
    addl('s3b-handshake', f.handshake())
    add('s3b-greeting', f.c2s(b'\x05\x01\x02'))
    add('s3b-method', f.s2c(b'\x05\x02'))
    add('s3b-auth', f.c2s(b'\x01\x03bob\x05wrong'))
    add('s3b-auth-fail', f.s2c(b'\x01\x01'))
    add('s3b-connect', f.c2s(req5(1, a4(), 80)))
    addl('s3b-fin', f.fin())
    # ---- SOCKS5, GSSAPI authentication ----
    f = TcpFlow(40008, 1080)
    addl('s4-handshake', f.handshake())
    add('s4-greeting', f.c2s(b'\x05\x01\x01'))
    add('s4-method', f.s2c(b'\x05\x01'))
    add('s4-gss', f.c2s(b'\x01\x01' + struct.pack('!H', 12) + b'GSS-API-DATA'))
    add('s4-gss-reply', f.s2c(b'\x01\x01' + struct.pack('!H', 0)))
    add('s4-connect', f.c2s(req5(1, a4(), 80)))
    add('s4-reply', f.s2c(rep5(0, a4((192, 0, 2, 2)), 40009)))
    addl('s4-fin', f.fin())
    f = TcpFlow(40010, 1080)
    addl('s4b-handshake', f.handshake())
    add('s4b-greeting', f.c2s(b'\x05\x01\x01'))
    add('s4b-method', f.s2c(b'\x05\x01'))
    add('s4b-gss', f.c2s(b'\x01\x01' + struct.pack('!H', 4) + b'ABCD'))
    add('s4b-gss-fail', f.s2c(b'\x01\xff'))
    addl('s4b-fin', f.fin())
    # ---- SOCKS5, no acceptable method; unsupported auth ----
    f = TcpFlow(40012, 1080)
    addl('s5-handshake', f.handshake())
    add('s5-greeting', f.c2s(b'\x05\x02\x03\xc0'))
    add('s5-method', f.s2c(b'\x05\xff'))
    add('s5-more', f.c2s(b'closing'))
    addl('s5-fin', f.fin())
    f = TcpFlow(40014, 1080)
    addl('s5b-handshake', f.handshake())
    add('s5b-greeting', f.c2s(b'\x05\x01\x03'))
    add('s5b-method', f.s2c(b'\x05\x03'))
    add('s5b-chap', f.c2s(b'\x01\x01\x00'))
    add('s5b-more', f.s2c(b'\x01\x00'))
    addl('s5b-fin', f.fin())
    # ---- SOCKS5, no methods offered (greeting with a count of 0) followed by the command ----
    f = TcpFlow(40016, 1080)
    addl('s6-handshake', f.handshake())
    add('s6-greeting', f.c2s(b'\x05\x00'))
    add('s6-method', f.s2c(b'\x05\x00'))
    add('s6-connect', f.c2s(req5(1, adom('host.example.invalid'), 443)))
    add('s6-reply', f.s2c(rep5(5, a4((0, 0, 0, 0)), 0)))
    addl('s6-fin', f.fin())
    # ---- SOCKS5 BIND with a second reply ----
    f = TcpFlow(40018, 1080)
    addl('s7-handshake', f.handshake())
    add('s7-greeting', f.c2s(b'\x05\x01\x00'))
    add('s7-method', f.s2c(b'\x05\x00'))
    add('s7-bind', f.c2s(req5(2, a4((198, 51, 100, 20)), 2021)))
    add('s7-bind-reply1', f.s2c(rep5(0, a4((192, 0, 2, 2)), 50000)))
    add('s7-bind-reply2', f.s2c(rep5(0, a4((198, 51, 100, 20)), 2021)))
    add('s7-data', f.c2s(b'ftp data'))
    addl('s7-fin', f.fin())
    # ---- SOCKS5 UDP ASSOCIATE with datagrams (DNS in the tunnel) ----
    f = TcpFlow(40020, 1080)
    addl('s8-handshake', f.handshake())
    add('s8-greeting', f.c2s(b'\x05\x01\x00'))
    add('s8-method', f.s2c(b'\x05\x00'))
    add('s8-associate', f.c2s(req5(3, a4(CLIENT), 5000)))
    add('s8-associate-reply', f.s2c(rep5(0, a4(PROXY), 6000)))
    hdr4 = b'\x00\x00\x00' + a4((198, 51, 100, 53)) + port(53)
    add('s8-udp-query', udp(5000, 6000, hdr4 + dns_query(), src=CLIENT, dst=PROXY))
    add('s8-udp-reply', udp(6000, 5000, hdr4 + dns_reply(), src=PROXY, dst=CLIENT))
    hdrn = b'\x00\x00\x00' + adom('ns.example.invalid') + port(53)
    add('s8-udp-name', udp(5000, 6000, hdrn + dns_query(b'name.example.invalid', 0x2222), src=CLIENT, dst=PROXY))
    hdr6 = b'\x00\x00\x00' + a6() + port(53)
    add('s8-udp-v6', udp(5000, 6000, hdr6 + dns_query(b'v6.example.invalid', 0x3333), src=CLIENT, dst=PROXY))
    add('s8-udp-frag', udp(5000, 6000, b'\x00\x00\x01' + a4((198, 51, 100, 53)) + port(53) + dns_query(b'f.example.invalid', 0x4444), src=CLIENT, dst=PROXY))
    # the reproducer of the fix: the destination port of the SOCKS header is the relay's own port
    # (3 nested headers shown; 6000 of them made tshark abort with a tree)
    nested = (b'\x00\x00\x00' + a4(PROXY) + port(6000)) * 3 + b'inner payload'
    add('s8-udp-recursion', udp(5000, 6000, nested, src=CLIENT, dst=PROXY))
    long_nested = (b'\x00\x00\x00' + a4(PROXY) + port(6000)) * 600
    add('s8-udp-recursion-600', udp(5000, 6000, long_nested, src=CLIENT, dst=PROXY))
    addl('s8-fin', f.fin())
    # ---- SOCKS5 PING and TRACEROUTE extensions ----
    f = TcpFlow(40022, 1080)
    addl('s9-handshake', f.handshake())
    add('s9-greeting', f.c2s(b'\x05\x01\x00'))
    add('s9-method', f.s2c(b'\x05\x00'))
    add('s9-ping', f.c2s(req5(0x80, a4(), 0)))
    add('s9-ping-reply', f.s2c(rep5(0, a4(PROXY), 0)))
    add('s9-ping-results', f.s2c(b'Reply from 198.51.100.7: time=1ms\r\nReply from 198.51.100.7: time=2ms\r\n'))
    add('s9-ping-end', f.c2s(b'\x00'))
    addl('s9-fin', f.fin())
    f = TcpFlow(40024, 1080)
    addl('s10-handshake', f.handshake())
    add('s10-greeting', f.c2s(b'\x05\x01\x00'))
    add('s10-method', f.s2c(b'\x05\x00'))
    add('s10-trace', f.c2s(req5(0x81, a4(), 0)))
    add('s10-trace-reply', f.s2c(rep5(0, a4(PROXY), 0)))
    add('s10-trace-results', f.s2c(b' 1  192.0.2.2  1ms\r\n 2  198.51.100.7  3ms\r\n'))
    add('s10-trace-end', f.c2s(b'\x00'))
    addl('s10-fin', f.fin())
    # ---- SOCKS4 CONNECT, SOCKS4a CONNECT (host name), rejected, BIND ----
    f = TcpFlow(40026, 1080)
    addl('s11-handshake', f.handshake())
    add('s11-connect4', f.c2s(b'\x04\x01' + port(80) + bytes((198, 51, 100, 7)) + b'alice\x00'))
    add('s11-reply4', f.s2c(b'\x00\x5a' + port(80) + bytes((198, 51, 100, 7))))
    add('s11-http', f.c2s(HTTP_REQ))
    add('s11-http-rsp', f.s2c(HTTP_RSP))
    addl('s11-fin', f.fin())
    f = TcpFlow(40028, 1080)
    addl('s12-handshake', f.handshake())
    add('s12-connect4a', f.c2s(b'\x04\x01' + port(80) + bytes((0, 0, 0, 5)) + b'bob\x00' + b'www.example.invalid\x00'))
    add('s12-reply4', f.s2c(b'\x00\x5b' + port(80) + bytes((0, 0, 0, 0))))
    add('s12-more', f.c2s(b'x'))
    addl('s12-fin', f.fin())
    f = TcpFlow(40030, 1080)
    addl('s13-handshake', f.handshake())
    add('s13-bind4', f.c2s(b'\x04\x02' + port(2021) + bytes((198, 51, 100, 20)) + b'carol\x00'))
    add('s13-reply4', f.s2c(b'\x00\x5a' + port(50001) + bytes((192, 0, 2, 2))))
    add('s13-reply4b', f.s2c(b'\x00\x5a' + port(2021) + bytes((198, 51, 100, 20))))
    addl('s13-fin', f.fin())
    # ---- not SOCKS: the first byte is not a version ----
    f = TcpFlow(40032, 1080)
    addl('s14-handshake', f.handshake())
    add('s14-text', f.c2s(b'GET / HTTP/1.0\r\n\r\n'))
    addl('s14-fin', f.fin())
    # ---- SOCKS4 with more client data before the reply (the state of the second packet) ----
    f = TcpFlow(40034, 1080)
    addl('s15-handshake', f.handshake())
    add('s15-connect4', f.c2s(b'\x04\x01' + port(80) + bytes((198, 51, 100, 7)) + b'dave\x00'))
    add('s15-early-data', f.c2s(HTTP_REQ))
    add('s15-reply4', f.s2c(b'\x00\x5a' + port(80) + bytes((198, 51, 100, 7))))
    add('s15-reply4-again', f.s2c(b'\x00\x5a' + port(80) + bytes((198, 51, 100, 7))))
    addl('s15-fin', f.fin())
    # ---- SOCKS5 where the client sends the command and data before the server answers ----
    f = TcpFlow(40036, 1080)
    addl('s16-handshake', f.handshake())
    add('s16-greeting', f.c2s(b'\x05\x01\x00'))
    add('s16-connect', f.c2s(req5(1, a4(), 80)))
    add('s16-early-data', f.c2s(HTTP_REQ))
    add('s16-method', f.s2c(b'\x05\x00'))
    add('s16-reply', f.s2c(rep5(0, a4((192, 0, 2, 2)), 40037)))
    add('s16-reply-again', f.s2c(rep5(0, a4((192, 0, 2, 2)), 40037)))
    addl('s16-fin', f.fin())
    # ---- SOCKS5 GSSAPI where the server's first reply carries a token ----
    f = TcpFlow(40038, 1080)
    addl('s17-handshake', f.handshake())
    add('s17-greeting', f.c2s(b'\x05\x01\x01'))
    add('s17-method', f.s2c(b'\x05\x01'))
    add('s17-gss', f.c2s(b'\x01\x01' + struct.pack('!H', 4) + b'ABCD'))
    add('s17-gss-reply-token', f.s2c(b'\x01\x01' + struct.pack('!H', 6) + b'TOKEN!'))
    add('s17-gss-reply-done', f.s2c(b'\x01\x01' + struct.pack('!H', 0)))
    add('s17-connect', f.c2s(req5(1, a4(), 80)))
    addl('s17-fin', f.fin())
    # ---- SOCKS5 CONNECT to a SOCKS server (port 1080): the tunnelled bytes reach the dissector again ----
    f = TcpFlow(40040, 1080)
    addl('s18-handshake', f.handshake())
    add('s18-greeting', f.c2s(b'\x05\x01\x00'))
    add('s18-method', f.s2c(b'\x05\x00'))
    add('s18-connect', f.c2s(req5(1, a4(), 1080)))
    add('s18-reply', f.s2c(rep5(0, a4((192, 0, 2, 2)), 40041)))
    add('s18-nested', f.c2s(b'\x05\x01\x00'))
    add('s18-nested-reply', f.s2c(b'\x05\x00'))
    addl('s18-fin', f.fin())
    # ---- Exported PDUs naming socks and socks_tls: no TCP conversation exists ----
    # no ports: all four frames share one conversation; the first has to be rejected by the version check
    add('exp-socks-bad', ('X', exp_pdu('socks_tcp', b'\x07\x01\x00'), 1))
    add('exp-socks-v5', ('X', exp_pdu('socks_tcp', b'\x05\x01\x00'), 1))
    add('exp-socks-tls-command', ('X', exp_pdu('socks_tls', req5(1, a4(), 80)), 1))
    add('exp-socks-tls-data', ('X', exp_pdu('socks_tls', b'tunnelled bytes'), 1))
    return F, R

def malformed_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    f = TcpFlow(41000, 1080)
    F += f.handshake()
    add('greeting-cut', f.c2s(b'\x05\x05\x00'))
    add('method', f.s2c(b'\x05\x00'))
    add('connect-cut', f.c2s(b'\x05\x01\x00\x01\xc6\x33'))
    f = TcpFlow(41001, 1080)
    F += f.handshake()
    add('s2-greeting', f.c2s(b'\x05\x01\x00'))
    add('s2-method', f.s2c(b'\x05\x00'))
    add('s2-domain-cut', f.c2s(b'\x05\x01\x00\x03\x40www.short'))
    add('s2-reply-cut', f.s2c(b'\x05\x00\x00\x03\x10ab'))
    f = TcpFlow(41002, 1080)
    F += f.handshake()
    add('s3-greeting', f.c2s(b'\x05\x01\x02'))
    add('s3-method', f.s2c(b'\x05\x02'))
    add('s3-auth-cut', f.c2s(b'\x01\x20alice'))
    add('s3-reply-cut', f.s2c(b'\x01'))
    f = TcpFlow(41003, 1080)
    F += f.handshake()
    add('s4-greeting', f.c2s(b'\x05\x01\x01'))
    add('s4-method', f.s2c(b'\x05\x01'))
    add('s4-gss-cut', f.c2s(b'\x01\x01' + struct.pack('!H', 200) + b'short'))
    add('s4-reply-cut', f.s2c(b'\x01\x01\x00'))
    f = TcpFlow(41004, 1080)
    F += f.handshake()
    add('s5-v4-cut', f.c2s(b'\x04\x01\x00'))
    add('s5-v4-reply-cut', f.s2c(b'\x00\x5a'))
    f = TcpFlow(41005, 1080)
    F += f.handshake()
    add('s6-v4-nonul', f.c2s(b'\x04\x01\x00\x50\xc6\x33\x64\x07' + b'nonul'))
    f = TcpFlow(41006, 1080)
    F += f.handshake()
    add('s7-greeting', f.c2s(b'\x05\x01\x00'))
    add('s7-method', f.s2c(b'\x05\x00'))
    add('s7-assoc', f.c2s(req5(3, a4(CLIENT), 5100)))
    add('s7-assoc-reply', f.s2c(rep5(0, a4(PROXY), 6100)))
    add('s7-udp-cut', udp(5100, 6100, b'\x00\x00\x00\x03\x20abc', src=CLIENT, dst=PROXY))
    add('s7-udp-short', udp(5100, 6100, b'\x00\x00', src=CLIENT, dst=PROXY))
    add('s7-udp-badtype', udp(5100, 6100, b'\x00\x00\x00\x09' + b'\x00' * 10, src=CLIENT, dst=PROXY))
    return F, R

if __name__ == '__main__':
    out = sys.argv[1]
    F, R = main_frames()
    write_pcapng(os.path.join(out, 'socks-coverage.pcapng'), [(f[1], None, 1) if isinstance(f, tuple) else (f, None, 0) for f in F], dlts=(1, 252))
    G, RM = malformed_frames()
    write_pcap(os.path.join(out, 'socks-coverage-malformed.pcap'), G)
    if '-v' in sys.argv:
        print(len(F), R); print(len(G), RM)
