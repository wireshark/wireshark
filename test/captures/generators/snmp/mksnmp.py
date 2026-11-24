#!/usr/bin/env python3
# Generates test/captures/snmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SNMP coverage captures.  Usage: mksnmp.py <outdir>
All packets are synthetic.  SNMPv3 messages carry filler instead of
authentication parameters and encrypted PDUs (no keys, no hashes, no
ciphertext); only the USM header is parsed."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from berlib import eth, gz, integer, null, octets, oid, seq, TcpStream, tlv, udp, write_pcap

# ---- BER values ----
def ip(a): return tlv(0x40, bytes(map(int, a.split('.'))))
def cnt32(v): return tlv(0x41, v.to_bytes(4 if v >= 0x800000 else max(1, (v.bit_length() + 8) // 8), 'big') if v else b'\0')
def gauge(v): return tlv(0x42, (v.to_bytes((v.bit_length() + 8) // 8, 'big')) if v else b'\0')
def ticks(v): return tlv(0x43, (v.to_bytes((v.bit_length() + 8) // 8, 'big')) if v else b'\0')
def opaque(b): return tlv(0x44, b)
def cnt64(v): return tlv(0x46, v.to_bytes((v.bit_length() + 8) // 8, 'big') if v else b'\0')
NOSUCHOBJ = tlv(0x80); NOSUCHINST = tlv(0x81); ENDOFMIB = tlv(0x82)

def varbind(name, value=None):
    return seq(oid(name), value if value is not None else null())
def varbinds(*vbs): return seq(*vbs)

def pdu(tag, reqid, err, idx, vbs):
    return tlv(tag, integer(reqid) + integer(err) + integer(idx) + vbs)
GET, GETNEXT, RESPONSE, SET, TRAP1, GETBULK, INFORM, TRAP2, REPORT = 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8

def msg(version, community, p): return seq(integer(version), octets(community), p)

def trap1(enterprise, agent, generic, specific, stamp, vbs):
    return tlv(TRAP1, oid(enterprise) + ip(agent) + integer(generic) + integer(specific) + ticks(stamp) + vbs)

# ---- SNMPv3 ----
def usm(engine=b'', boots=0, etime=0, user=b'', auth=b'', priv=b''):
    return seq(octets(engine), integer(boots), integer(etime), octets(user), octets(auth), octets(priv))
def scoped(engine, ctxname, p): return seq(octets(engine), octets(ctxname), p)
def v3(msgid, flags, model, secparams, data, maxsize=65507):
    hdr = seq(integer(msgid), integer(maxsize), octets(bytes([flags])), integer(model))
    return seq(integer(3), hdr, octets(secparams), data)

def eid(enterprise, fmt, data, rfc3411=True):
    return struct.pack('>I', enterprise | (0x80000000 if rfc3411 else 0)) + (bytes([fmt]) if rfc3411 else b'') + data

SYSDESCR = '1.3.6.1.2.1.1.1.0'
SYSOID = '1.3.6.1.2.1.1.2.0'
SYSUP = '1.3.6.1.2.1.1.3.0'
SYSNAME = '1.3.6.1.2.1.1.5.0'
IFNUM = '1.3.6.1.2.1.2.1.0'
IFDESCR = '1.3.6.1.2.1.2.2.1.2'
IFINOCT = '1.3.6.1.2.1.2.2.1.10'
HRDATE = '1.3.6.1.2.1.25.1.2.0'
SNMPTRAPOID = '1.3.6.1.6.3.1.1.4.1.0'
COLDSTART = '1.3.6.1.6.3.1.1.5.1'

def main(out):
    f = []
    t = [1750000000.0]
    def add(fr, dt=0.01): t[0] += dt; f.append((t[0], fr))
    C = 'public'
    def req(p, sport=41000, dport=161, src='192.0.2.1', dst='192.0.2.2'):
        add(udp(sport, dport, p, src=src, dst=dst))
    def rsp(p, sport=161, dport=41000, src='192.0.2.2', dst='192.0.2.1'):
        add(udp(sport, dport, p, rev=True, src=src, dst=dst))

    # --- SNMPv1 requests and responses
    vb0 = varbinds(varbind(SYSDESCR), varbind(SYSNAME), varbind(SYSUP))
    req(msg(0, C, pdu(GET, 1, 0, 0, vb0)))
    rsp(msg(0, C, pdu(RESPONSE, 1, 0, 0, varbinds(
        varbind(SYSDESCR, octets('Synthetic test agent, version 1.0')), varbind(SYSNAME, octets('router1')),
        varbind(SYSUP, ticks(123456789))))))
    req(msg(0, C, pdu(GETNEXT, 2, 0, 0, varbinds(varbind(IFDESCR + '.1'), varbind(IFNUM)))))
    rsp(msg(0, C, pdu(RESPONSE, 2, 0, 0, varbinds(varbind(IFDESCR + '.2', octets('eth0')), varbind(IFNUM, integer(2))))))
    req(msg(0, C, pdu(SET, 3, 0, 0, varbinds(varbind(SYSNAME, octets('newname'))))))
    for e in range(6):
        rsp(msg(0, C, pdu(RESPONSE, 3 if e == 0 else 10 + e, e, 1 if e else 0, varbinds(varbind(SYSNAME, octets('x'))))))
    req(msg(0, C, pdu(GET, 4, 0, 0, varbinds(varbind('1.3.6.1.4.1.99999.1.2.3')))))
    rsp(msg(0, C, pdu(RESPONSE, 4, 2, 1, varbinds(varbind('1.3.6.1.4.1.99999.1.2.3')))))
    # values of every type in a response
    vals = [
        varbind('1.3.6.1.4.1.99999.2.1', integer(-5)),
        varbind('1.3.6.1.4.1.99999.2.2', octets(b'\x00\xff binary \x01')),
        varbind('1.3.6.1.4.1.99999.2.3', null()),
        varbind('1.3.6.1.4.1.99999.2.4', oid('1.3.6.1.4.1.99999.9.8.7')),
        varbind('1.3.6.1.4.1.99999.2.5', ip('198.51.100.7')),
        varbind('1.3.6.1.4.1.99999.2.6', cnt32(4000000000)),
        varbind('1.3.6.1.4.1.99999.2.7', gauge(4294967295)),
        varbind('1.3.6.1.4.1.99999.2.8', ticks(1)),
        varbind('1.3.6.1.4.1.99999.2.9', opaque(b'\x9f\x78\x04\x3f\x80\x00\x00')),
        varbind('1.3.6.1.4.1.99999.2.10', cnt64(0xffffffffffffffff)),
        varbind('1.3.6.1.4.1.99999.2.11', cnt64(1)),
        varbind('1.3.6.1.4.1.99999.2.12', integer(2147483647)),
        varbind('1.3.6.1.4.1.99999.2.13', integer(-2147483648)),
        varbind('1.3.6.1.4.1.99999.2.14', octets(b'')),
        varbind('1.3.6.1.4.1.99999.2.15', cnt32(0)),
    ]
    rsp(msg(0, C, pdu(RESPONSE, 5, 0, 0, varbinds(*vals))))
    # DateAndTime in the system date (8 and 11 octets)
    rsp(msg(0, C, pdu(RESPONSE, 6, 0, 0, varbinds(varbind(HRDATE, octets(struct.pack('>HBBBBBB', 2025, 6, 15, 12, 30, 45, 5)))))))
    rsp(msg(0, C, pdu(RESPONSE, 7, 0, 0, varbinds(varbind(HRDATE, octets(struct.pack('>HBBBBBB', 2025, 6, 15, 12, 30, 45, 5) + b'-\x04\x1e'))))))
    # request without a response, long community string, and a response without request
    req(msg(0, 'x' * 40, pdu(GET, 8, 0, 0, vb0)))
    req(msg(0, 'x' * 40, pdu(GET, 8, 0, 0, vb0)))              # retransmission
    rsp(msg(0, C, pdu(RESPONSE, 9, 0, 0, vb0)))                 # no request
    # --- SNMPv1 traps: every generic trap, enterprise specific, with and without varbinds
    for g in range(7):
        if g == 3: tv = varbinds()
        elif g % 2: tv = varbinds(varbind(IFNUM, integer(g)))
        else: tv = varbinds(varbind(SYSNAME, octets('t%d' % g)))
        req(msg(0, C, trap1('1.3.6.1.4.1.99999.1', '192.0.2.1', g, 5 if g == 6 else 0, 1000 + g, tv)),
            sport=40162, dport=162)
    req(msg(0, C, trap1('1.3.6.1.6.3.1.1.5', '10.1.2.3', 6, 70000, 0xffffffff, varbinds())), sport=40162, dport=162)
    # --- SNMPv2c: every PDU type
    C2 = 'private'
    req(msg(1, C2, pdu(GET, 100, 0, 0, vb0)))
    rsp(msg(1, C2, pdu(RESPONSE, 100, 0, 0, varbinds(varbind(SYSDESCR, octets('v2c agent')), varbind(SYSNAME, octets('sw1')),
                                                    varbind(SYSUP, ticks(0))))))
    req(msg(1, C2, pdu(GETNEXT, 101, 0, 0, varbinds(varbind(IFINOCT), varbind(IFDESCR)))))
    rsp(msg(1, C2, pdu(RESPONSE, 101, 0, 0, varbinds(varbind(IFINOCT + '.1', cnt32(99)), varbind(IFDESCR + '.1', octets('lo'))))))
    req(msg(1, C2, pdu(GETBULK, 102, 0, 10, varbinds(varbind(IFDESCR), varbind(IFINOCT)))))      # non-repeaters 0, max-repetitions 10
    rsp(msg(1, C2, pdu(RESPONSE, 102, 0, 0, varbinds(*[varbind(IFDESCR + '.%d' % i, octets('if%d' % i)) for i in range(1, 6)]))))
    req(msg(1, C2, pdu(SET, 103, 0, 0, varbinds(varbind(SYSNAME, octets('set-by-v2c'))))))
    for e in (0, 6, 7, 10, 12, 17, 18):
        rsp(msg(1, C2, pdu(RESPONSE, 103, e, 1 if e else 0, varbinds(varbind(SYSNAME, octets('set-by-v2c'))))))
    req(msg(1, C2, pdu(GET, 104, 0, 0, varbinds(varbind('1.3.6.1.4.1.99999.3.1'), varbind('1.3.6.1.4.1.99999.3.2'),
                                                varbind('1.3.6.1.4.1.99999.3.3')))))
    rsp(msg(1, C2, pdu(RESPONSE, 104, 0, 0, varbinds(varbind('1.3.6.1.4.1.99999.3.1', NOSUCHOBJ),
                                                    varbind('1.3.6.1.4.1.99999.3.2', NOSUCHINST),
                                                    varbind('1.3.6.1.4.1.99999.3.3', ENDOFMIB)))))
    # notifications: SNMPv2-Trap, Inform (answered by a response), Report
    tr = varbinds(varbind(SYSUP, ticks(5000)), varbind(SNMPTRAPOID, oid(COLDSTART)), varbind(SYSNAME, octets('sw1')))
    req(msg(1, C2, pdu(TRAP2, 105, 0, 0, tr)), sport=40162, dport=162)
    req(msg(1, C2, pdu(INFORM, 106, 0, 0, tr)), sport=40162, dport=162)
    rsp(msg(1, C2, pdu(RESPONSE, 106, 0, 0, tr)), sport=162, dport=40162)
    req(msg(1, C2, pdu(REPORT, 107, 0, 0, varbinds(varbind('1.3.6.1.6.3.15.1.1.1.0', cnt32(1))))), sport=40162, dport=162)
    # response from an ephemeral port (IBM i style: conversation with the request)
    req(msg(1, C2, pdu(GET, 110, 0, 0, varbinds(varbind(SYSNAME)))), sport=41001)
    rsp(msg(1, C2, pdu(RESPONSE, 110, 0, 0, varbinds(varbind(SYSNAME, octets('ibm-i'))))), sport=5555, dport=41001)
    # other ports: the Patrol port 8161, and SNMP over Ethernet (ethertype 0x814c)
    req(msg(1, C2, pdu(GET, 111, 0, 0, varbinds(varbind(SYSNAME)))), sport=41002, dport=8161)
    add(eth(msg(1, C2, pdu(GET, 112, 0, 0, varbinds(varbind(SYSNAME)))), etype=0x814c))
    # --- SNMPv3
    E1 = eid(8072, 128, b'\x01\x02\x03\x04' + struct.pack('<I', 1750000000))
    flagsNone, flagsAuth, flagsPriv, flagsRep = 0x04, 0x05, 0x07, 0x04
    # discovery: empty engine id, noAuthNoPriv, reportable
    sc = scoped(E1, b'', pdu(GET, 200, 0, 0, varbinds()))
    req(v3(1, 0x04, 3, usm(b'', 0, 0, b'discover'), sc))
    rep = scoped(E1, b'', pdu(REPORT, 200, 0, 0, varbinds(varbind('1.3.6.1.6.3.15.1.1.4.0', cnt32(3)))))
    rsp(v3(1, 0x00, 3, usm(E1, 5, 1234, b'discover'), rep))
    # noAuthNoPriv with a user name and context
    req(v3(2, 0x04, 3, usm(E1, 5, 1240, b'noauthuser'),
           scoped(E1, b'ctx', pdu(GET, 201, 0, 0, varbinds(varbind(SYSDESCR), varbind(SYSNAME))))))
    rsp(v3(2, 0x00, 3, usm(E1, 5, 1241, b'noauthuser'),
           scoped(E1, b'ctx', pdu(RESPONSE, 201, 0, 0, varbinds(varbind(SYSDESCR, octets('v3 agent')), varbind(SYSNAME, octets('r3')))))))
    # authNoPriv: the authentication parameters are filler (12 octets), the message is not verified
    req(v3(3, 0x05, 3, usm(E1, 5, 1250, b'authuser', b'\x00' * 12),
           scoped(E1, b'', pdu(GETNEXT, 202, 0, 0, varbinds(varbind(SYSUP))))))
    rsp(v3(3, 0x01, 3, usm(E1, 5, 1251, b'authuser', b'\x00' * 12),
           scoped(E1, b'', pdu(RESPONSE, 202, 0, 0, varbinds(varbind(SYSUP + '.0', ticks(77)))))))
    # authPriv: encryptedPDU (opaque filler) with 8 octets of privacy parameters
    for i, ua in enumerate((b'privuser', b'a')):
        req(v3(4 + i, 0x07, 3, usm(E1, 5, 1260, ua, b'\x00' * 12, bytes(range(8))), octets(bytes((j * 5) & 0xff for j in range(64)))))
    rsp(v3(6, 0x03, 3, usm(E1, 5, 1261, b'privuser', b'\x00' * 12, bytes(range(8, 16))), octets(b'\x30' * 48)))
    # engine id formats
    good_ids = (eid(9, 1, bytes([192, 0, 2, 1])), eid(9, 2, bytes(range(16))),
                eid(9, 3, bytes.fromhex('020000000001')), eid(9, 3, b'\x01' + bytes.fromhex('020000000001')),
                eid(25506, 4, b'engine-text'), eid(32473, 5, b'\x01\x02\x03'), eid(32473, 128 + 1, b'ent'),
                eid(2021, 128, b'\xaa\xbb\xcc\xdd' + struct.pack('<I', 1700000000)),
                eid(8072, 128, b'\xaa\xbb\xcc\xdd' + struct.pack('<q', 1700000000)),
                eid(4, 0, b'x'),
                eid(1234, 0, b'\x01\x02\x03\x04\x05\x06\x07\x08', False))
    for n, e in enumerate(good_ids):
        req(v3(10 + n, 0x04, 3, usm(e, 1, 100 + n, b'eng%d' % n), scoped(E1, b'', pdu(GET, 210 + n, 0, 0, varbinds()))))
    # other security models and a message whose security parameters are not USM
    req(v3(40, 0x04, 1, b'v1-community', scoped(E1, b'', pdu(GET, 220, 0, 0, varbinds(varbind(SYSNAME))))))
    req(v3(41, 0x00, 2, b'\x30\x00', scoped(E1, b'', pdu(GET, 221, 0, 0, varbinds(varbind(SYSNAME))))))
    req(v3(43, 0x04, 99, b'private model', scoped(E1, b'', pdu(GET, 223, 0, 0, varbinds(varbind(SYSNAME))))))
    # --- SNMP over TCP (ports 161 and 162), one message per segment, several in one segment and split
    def tcp_msgs(sp, items):
        s = TcpStream(42000 + len(f), sp)
        for fr in s.handshake(): add(fr)
        for who, b in items: add(s.c2s(b) if who == 'c' else s.s2c(b))
    def g(i, c=C): return msg(0, c, pdu(GET, i, 0, 0, varbinds(varbind(SYSNAME))))
    r = lambda i: msg(0, C, pdu(RESPONSE, i, 0, 0, varbinds(varbind(SYSNAME, octets('tcp')))))
    tcp_msgs(161, [('c', g(300)), ('s', r(300)), ('c', g(301) + g(302) + g(303)), ('s', r(301) + r(302)),
                   ('s', r(303))])
    big = msg(1, C, pdu(RESPONSE, 304, 0, 0, varbinds(*[varbind(IFDESCR + '.%d' % i, octets('x' * 50)) for i in range(1, 8)])))
    tcp_msgs(161, [('c', g(304)), ('s', big[:100]), ('s', big[100:200]), ('s', big[200:])])
    tcp_msgs(162, [('c', msg(0, C, trap1('1.3.6.1.4.1.99999.1', '192.0.2.1', 6, 1, 7, varbinds(varbind(SYSNAME, octets('tcp-trap'))))))])
    tcp_msgs(161, [('c', v3(50, 0x04, 3, usm(E1, 1, 1, b'tcpuser'), scoped(E1, b'', pdu(GET, 305, 0, 0, varbinds(varbind(SYSNAME))))))])
    # --- SMUX (TCP 199)
    def smux(p): return p
    sm = [
        ('c', tlv(0x60, integer(0) + oid('1.3.6.1.4.1.99999.77') + octets('smux peer') + octets('secret'))),     # OpenPDU
        ('s', pdu(GET, 400, 0, 0, varbinds(varbind('1.3.6.1.4.1.99999.77.1')))),
        ('c', pdu(RESPONSE, 400, 0, 0, varbinds(varbind('1.3.6.1.4.1.99999.77.1', integer(5))))),
        ('c', tlv(0x63, oid('1.3.6.1.4.1.99999.77') + integer(0) + integer(1))),                                 # RReqPDU (priority 0, operation)
        ('s', tlv(0x43, b'\x00') ),                                                                              # RRspPDU
        ('c', tlv(0x64, oid('1.3.6.1.4.1.99999.77.2') + ip('192.0.2.9') + integer(6) + integer(1) + ticks(9) + varbinds())),   # SOutPDU
        ('c', tlv(0x41, b'\x00')),                                                                               # ClosePDU
    ]
    sx = TcpStream(43000, 199)
    for fr in sx.handshake(): add(fr)
    for who, b in sm: add(sx.c2s(b) if who == 'c' else sx.s2c(b))
    write_pcap(os.path.join(out, 'snmp-coverage.pcap'), f)
    gz(os.path.join(out, 'snmp-coverage.pcap'), os.path.join(out, 'snmp_coverage.pcap.gz'))

def malformed(out):
    f = []
    t = [1750000000.0]
    def add(fr, dt=0.01): t[0] += dt; f.append((t[0], fr))
    def req(p, sport=41000, dport=161): add(udp(sport, dport, p))
    E1 = eid(8072, 128, b'\x01\x02\x03\x04' + struct.pack('<I', 1750000000))
    g = lambda i: pdu(GET, i, 0, 0, varbinds(varbind(SYSNAME)))
    # engine ids that do not conform to RFC 3411 / RFC 1910, and empty ones
    for n, e in enumerate((eid(8072, 128, b'\xaa\xbb\xcc\xdd\xee'), eid(100, 1, b'\x01\x02'), eid(100, 2, b'\x01'), eid(9, 4, b'x' * 30), eid(100, 5, b'x' * 30),
                           eid(7, 0, b'', True), eid(1234, 0, b'\x01\x02\x03', False), b'\x80', b'\x80\x00', b'',
                           eid(9, 3, b'\x01\x02\x03\x04\x05'), eid(9, 1, b'\x01\x02\x03\x04\x05'))):
        req(v3(10 + n, 0x04, 3, usm(e, 1, 100 + n, b'eng%d' % n), scoped(E1, b'', g(300 + n))))
    # discovery as sent by real managers (empty context engine id), message id and model 0
    req(v3(1, 0x04, 3, usm(), scoped(b'', b'', pdu(GET, 200, 0, 0, varbinds()))))
    req(v3(42, 0x04, 0, b'', scoped(E1, b'', g(222))))
    req(v3(0, 0x04, 3, usm(), scoped(E1, b'', g(223)), maxsize=0))
    # v1 trap whose enterprise is not an OID (reproducer of the NULL enterprise lookup, needs the
    # "SNMP Enterprise Specific Trap Types" UAT) and a v1 trap with an enterprise-specific code
    bad = tlv(TRAP1, integer(5) + ip('192.0.2.1') + integer(6) + integer(1) + ticks(1) + varbinds())
    req(msg(0, 'public', bad), 40162, 162)
    # truncated messages and messages with wrong types
    good = msg(1, 'public', pdu(GET, 5, 0, 0, varbinds(varbind(SYSDESCR), varbind(IFNUM, integer(1)))))
    for n in (1, 2, 3, 5, 8, 12, 16, 20, 30, len(good) - 1):
        req(good[:n])
    req(msg(3, 'public', g(1)))            # version 3 header with a v1 body
    req(seq(integer(1), octets('public'), tlv(0xa9, integer(1))))                 # unknown PDU type
    req(seq(integer(1), octets('public'), pdu(GET, 1, 0, 0, seq(seq(octets(b'x'))))))   # name is not an OID
    req(seq(integer(1), octets('public'), pdu(GET, 1, 0, 0, seq(seq(oid('1.3.6.1'), tlv(0x47, b'\x01'))))))  # unknown value tag
    req(seq(integer(1), octets('public'), pdu(GET, 1, 0, 0, seq(seq(oid('1.3.6.1'), tlv(0x40, b'\x01\x02'))))))  # short IpAddress
    req(seq(integer(1), octets('public'), pdu(GET, 1, 0, 0, seq(seq(oid('1.3.6.1.2.1.25.1.2.0'), octets(b'\x07\xe9'))))))   # short date
    req(seq(integer(1), octets('public'), pdu(GET, 1, 0, 0, seq(seq(oid('1.3.6.1.2.1.25.1.2.0'), octets(b'\x07\xe9\x06\x0f\x0c\x1e\x2d\x05\x2b\x04\x1e')))))) # date with UTC offset
    req(seq(integer(1), octets('public'), pdu(GET, 1 << 40, 1 << 40, 5, seq(seq(oid('1.3.6.1'), integer(1 << 40))))))
    req(b'\x30\x80\x02\x01\x01\x04\x00\x00\x00')          # indefinite length
    req(b'\x31\x03\x02\x01\x01')                              # not a SEQUENCE: not SNMP
    req(b'\x30\x03\x04\x01\x01')                              # no version
    req(seq(integer(1), octets('public'), pdu(GET, 1, 0, 0, seq(*[seq(oid('1.3.6.1.2.1.1.%d.0' % i), null()) for i in range(1, 80)]))))
    req(seq(integer(1), octets('public'), pdu(GET, 1, 0, 0, seq(seq(tlv(0x06, b'\x2b\x86\x86\x86\x86\x86\x86\x86\x86\x86\x86\x01'), null())))))
    # TCP: partial and malformed messages
    s = TcpStream(44000, 161)
    for fr in s.handshake(): add(fr)
    add(s.c2s(good[:10]))
    add(s.c2s(good[10:]))
    add(s.c2s(b'\x30\x84\xff\xff\xff\xff'))
    add(s.c2s(b'\x30\x05\x02'))
    s = TcpStream(44001, 199)
    for fr in s.handshake(): add(fr)
    add(s.c2s(b'\x60\x05\x02\x01\x00'))
    add(s.c2s(b'\x41\x05\x02'))
    add(s.c2s(b'\x62\x03\x02\x01'))
    add(s.c2s(b'\xa0\x00'))
    add(s.c2s(b'\x7f'))
    write_pcap(os.path.join(out, 'snmp-coverage-malformed.pcap'), f)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
    malformed(sys.argv[1] if len(sys.argv) > 1 else '.')
