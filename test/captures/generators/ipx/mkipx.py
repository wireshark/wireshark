#!/usr/bin/env python3
# Generates test/captures/ipx_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-ipx.c (IPX, SPX, IPX RIP, IPX SAP,
IPX Message, Serialization).

Usage: mkipx.py <outdir> [-v]

Writes ipx-coverage.pcapng (clean) and ipx-coverage-malformed.pcapng.
Everything is made up (documentation-style network numbers and locally
administered node addresses).  pcapng with one interface per link type:
Ethernet, PPP, Linux cooked, Null/Loopback, Cisco HDLC, ARCnet (BSD and
Linux).
"""
import struct
import sys
import os

VERBOSE = '-v' in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith('-')]
OUT = args[0] if args else '.'

def blk(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)

def shb():
    return blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

def idb(linktype):
    return blk(1, struct.pack('<HHI', linktype, 0, 65535))

LT = {'eth': 1, 'ppp': 9, 'null': 0, 'chdlc': 104, 'sll': 113, 'arc_bsd': 7, 'arc_linux': 129}
IF = {k: i for i, k in enumerate(['eth', 'ppp', 'null', 'chdlc', 'sll', 'arc_bsd', 'arc_linux'])}

class Cap:
    def __init__(self):
        self.blocks = [shb()] + [idb(LT[k]) for k in IF]
        self.n = 0
        self.ts = 1700000000 * 1000000
        self.marks = []
    def mark(self, t):
        self.marks.append((self.n + 1, t))
    def pkt(self, p, link='eth', caplen=None):
        self.n += 1
        self.ts += 1000
        cl = len(p) if caplen is None else caplen
        self.blocks.append(blk(6, struct.pack('<IIIII', IF[link], self.ts >> 32,
                               self.ts & 0xffffffff, cl, len(p)) + p[:cl]))
    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(b''.join(self.blocks))
        if VERBOSE:
            print(name, self.n, 'frames')
            for i, (n, t) in enumerate(self.marks):
                end = self.marks[i + 1][0] - 1 if i + 1 < len(self.marks) else self.n
                print('  %d-%d  %s' % (n, end, t))

# ------------------------------------------------------------ IPX building
NA = b'\x02\x00\x00\x00\x00\x0a'     # node addresses
NB = b'\x02\x00\x00\x00\x00\x0b'
NC = b'\xff\xff\xff\xff\xff\xff'
NETA = 0x0000a001
NETB = 0x0000b002

def ipx(dsock, ssock, ptype, payload, dnet=NETB, dnode=NB, snet=NETA, snode=NA, hops=0,
        csum=0xffff, length=None):
    n = 30 + len(payload) if length is None else length
    return (struct.pack('!HHBB', csum, n, hops, ptype) + struct.pack('!I', dnet) + dnode +
            struct.pack('!H', dsock) + struct.pack('!I', snet) + snode + struct.pack('!H', ssock) + payload)

def eth2(p, et=0x8137):
    pad = b'\0' * max(0, 46 - len(p))        # Ethernet minimum frame, trimmed by the IPX length
    return NB + NA + struct.pack('!H', et) + p + pad

def eth_raw(p):
    return NB + NA + struct.pack('!H', len(p)) + p + b'\0' * max(0, 46 - len(p))

def eth_llc(p, sap=0xe0):
    llc = bytes([sap, sap, 3]) + p
    return NB + NA + struct.pack('!H', len(llc)) + llc + b'\0' * max(0, 46 - len(llc))

def eth_snap(p):
    llc = b'\xaa\xaa\x03\x00\x00\x00\x81\x37' + p
    return NB + NA + struct.pack('!H', len(llc)) + llc + b'\0' * max(0, 46 - len(llc))

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(proto, payload, src=b'\xc0\x00\x02\x01', dst=b'\xc0\x00\x02\x02'):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def eth_ip(p):
    return NB + NA + b'\x08\x00' + p

def sap_query(qtype, stype):
    return struct.pack('!HH', qtype, stype)

def sap_server(stype, name, net, node, sock, hops):
    return struct.pack('!H', stype) + name.ljust(48, b'\0') + struct.pack('!I', net) + node + struct.pack('!HH', sock, hops)

def sap_resp(rtype, servers):
    return struct.pack('!H', rtype) + b''.join(servers)

def rip(op, routes):
    return struct.pack('!H', op) + b''.join(struct.pack('!IHH', n, h, t) for n, h, t in routes)

def spx(cc, dstream, srcid, dstid, seq, ack, alloc, data=b'', neg=None):
    h = struct.pack('!BBHHHHH', cc, dstream, srcid, dstid, seq, ack, alloc)
    if neg is not None:
        h += struct.pack('!H', neg)
    return h + data

S_PEP = 4
T_SPX = 5

def build():
    c = Cap()
    # ---- link layers, one IPX packet each (SAP general query)
    q = sap_query(1, 4)
    pk = ipx(0x452, 0x4003, 0, q)
    c.mark('IPX over every link layer: Ethernet II (0x8137), raw 802.3, 802.2 LLC (DSAP 0xE0 and 0x10), SNAP, UDP port 213, GRE, PPP, Linux cooked, Null/Loopback, Cisco HDLC, ARCnet BSD (IPX and Novell EC) and Linux')
    c.pkt(eth2(pk))
    c.pkt(eth_raw(pk))
    c.pkt(eth_llc(pk, 0xe0))
    c.pkt(eth_llc(pk, 0x10))
    c.pkt(eth_snap(pk))
    c.pkt(eth_ip(ip4(17, struct.pack('!HHHH', 213, 213, 8 + len(pk), 0x1234) + pk)))
    c.pkt(eth_ip(ip4(47, struct.pack('!HH', 0, 0x8137) + pk)))
    c.pkt(b'\xff\x03\x00\x2b' + pk, link='ppp')
    c.pkt(struct.pack('!HHH', 0, 1, 6) + NA + b'\0\0' + struct.pack('!H', 1) + pk, link='sll')
    c.pkt(struct.pack('<I', 23) + pk, link='null')
    c.pkt(b'\x0f\x00\x81\x37' + pk, link='chdlc')
    c.pkt(bytes([0x0a, 0x0b, 250, 0, 0, 0]) + pk, link='arc_bsd')
    c.pkt(bytes([0x0a, 0x0b, 0, 0, 236, 0, 0, 0]) + pk, link='arc_linux')

    # ---- IPX header variants
    c.mark('IPX header: checksum other than 0xffff, hops, broadcast and same-network addresses, length shorter than the frame (Ethernet padding), packet types 0, 1, 2, 3, 4, 16, 20 and unknown sockets (data)')
    c.pkt(eth2(ipx(0x4010, 0x4011, 0, b'hello ipx', csum=0x1234, hops=3)))
    c.pkt(eth2(ipx(0x4010, 0x4011, 1, b'rip type, unknown socket', dnode=NC, dnet=0)))
    c.pkt(eth2(ipx(0x4010, 0x4011, 2, b'echo')))
    c.pkt(eth2(ipx(0x4010, 0x4011, S_PEP, b'pep payload')))
    c.pkt(eth2(ipx(0x4010, 0x4011, 16, b'experimental')))
    c.pkt(eth2(ipx(0x0455, 0x0455, 20, b'\x00' * 40, dnode=NC)))
    c.pkt(eth2(ipx(0x4011, 0x4010, 3, b'error packet payload')))
    c.pkt(eth2(ipx(0x4012, 0x4013, 0, b'', csum=0xffff)))
    c.pkt(eth2(ipx(0x4012, 0x4013, 0, b'x' * 300)))

    # ---- SAP
    c.mark('SAP: general and nearest queries and responses (servers of several types), unknown query type, a server entry with a long name and 16 hops')
    c.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_query(1, 0xffff), dnode=NC)))
    c.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_query(3, 4), dnode=NC)))
    srv = [sap_server(4, b'FS1', NETA, NA, 0x451, 1),
           sap_server(0x107, b'RCONSOLE', NETA, NA, 0x8104, 2),
           sap_server(0x278, b'NDS-TREE', NETB, NB, 0x4006, 3),
           sap_server(0x0640, b'GW-NT', NETB, NB, 0x1234, 1)]
    c.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_resp(2, srv))))
    c.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_resp(4, srv[:1]))))
    c.pkt(eth2(ipx(0x452, 0x4004, S_PEP, sap_query(9, 4))))
    c.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_resp(2, [sap_server(0xfffe, b'name' * 12, 0xffffffff, NC, 0xffff, 16)]))))

    # ---- RIP
    c.mark('RIP: request and response with routes, request for all routes, zero routes, an unknown operation, a single route')
    c.pkt(eth2(ipx(0x453, 0x453, 1, rip(1, [(0xffffffff, 0xffff, 0xffff)]), dnode=NC)))
    c.pkt(eth2(ipx(0x453, 0x453, 1, rip(1, [(0xa001, 0, 0), (0xb002, 0, 0)]))))
    c.pkt(eth2(ipx(0x453, 0x453, 1, rip(2, [(0xa001, 1, 2), (0xb002, 2, 20), (0xc003, 15, 270)]))))
    c.pkt(eth2(ipx(0x453, 0x453, 1, rip(2, []))))
    c.pkt(eth2(ipx(0x453, 0x453, 1, rip(0, [(0xd004, 3, 4)]))))
    c.pkt(eth2(ipx(0x453, 0x453, 1, rip(3, [(0xe005, 4, 5)]))))

    # ---- Serialization and IPX message
    c.mark('Serialization, IPX message (sockets 0x4001 and 0x4003, signature characters ?, Y, ! and another)')
    c.pkt(eth2(ipx(0x457, 0x457, 0, b'\x02\x00\x00\x00\x00\x99')))
    c.pkt(eth2(ipx(0x4001, 0x4002, 0, bytes([5, ord('?')]))))
    c.pkt(eth2(ipx(0x4002, 0x4001, 0, bytes([5, ord('Y')]))))
    c.pkt(eth2(ipx(0x4003, 0x4002, 0, bytes([6, ord('!')]))))
    c.pkt(eth2(ipx(0x4003, 0x4002, 0, bytes([7, 0x41]))))

    # ---- SPX
    c.mark('SPX: connection request (SPX II, destination ID 0xffff), SPX II data with negotiated size, SPX I data, system ack, attention, end of message, end of connection (0xfe, 0xff), a retransmission, all flag bits')
    sa, sb = 0x4020, 0x4021
    def sp(cc, ds, sid, did, seq, ack, alloc, data=b'', neg=None, a=sa, b=sb):
        return eth2(ipx(b, a, T_SPX, spx(cc, ds, sid, did, seq, ack, alloc, data, neg)))
    c.pkt(sp(0x48 | 0x80, 0, 0x1111, 0xffff, 0, 0, 0))                      # SPX II connection request
    c.pkt(sp(0x48 | 0x80, 0, 0x2222, 0x1111, 0, 1, 10, neg=0x0200, a=sb, b=sa))   # reply (system, SPX II)
    c.pkt(sp(0x48, 0, 0x1111, 0x2222, 1, 0, 10, b'spx2 data block', neg=0x0200))
    c.pkt(sp(0x40 | 0x10, 0, 0x1111, 0x2222, 2, 0, 10, b'spx I style data'))        # send ack + EOM
    c.pkt(sp(0x80, 0, 0x2222, 0x1111, 0, 3, 12, a=sb, b=sa))                          # system packet (ack)
    c.pkt(sp(0x80 | 0x40, 0, 0x2222, 0x1111, 0, 3, 12, a=sb, b=sa))                   # system, send ack
    c.pkt(sp(0x20, 0, 0x1111, 0x2222, 3, 3, 12, b'attention'))
    c.pkt(sp(0x10, 0, 0x1111, 0x2222, 4, 3, 12, b'eom data'))
    c.pkt(sp(0x00, 0, 0x1111, 0x2222, 5, 3, 12, b'plain data'))
    c.pkt(sp(0x00, 0, 0x1111, 0x2222, 5, 3, 12, b'plain data'))                       # retransmission of the previous
    c.pkt(sp(0x01 | 0x02 | 0x04 | 0x08, 0, 0x1111, 0x2222, 6, 3, 12, b'ext hdr', neg=0x0100))
    c.pkt(sp(0x40, 0xfe, 0x1111, 0x2222, 7, 3, 12))                                  # end of connection
    c.pkt(sp(0x40, 0xff, 0x2222, 0x1111, 0, 8, 12, a=sb, b=sa))                      # acknowledgment
    c.pkt(sp(0x00, 0x05, 0x1111, 0x2222, 8, 3, 12))                                   # header only, no data
    c.pkt(eth2(ipx(0x4040, 0x4041, T_SPX, spx(0x00, 0, 1, 2, 1, 1, 1, b'unknown sockets: data dissector'))))
    c.pkt(eth2(ipx(0x4040, 0x4041, T_SPX, spx(0x00, 0, 1, 2, 1, 1, 1, b'unknown sockets: data dissector'))))
    c.pkt(eth2(ipx(0x4040, 0x4041, 5, spx(0x08, 0, 1, 0xffff, 1, 1, 1, b'x'))))
    c.pkt(eth2(ipx(0x5e86, 0x4042, T_SPX, spx(0x00, 0, 1, 2, 1, 1, 1, b'data for a registered spx socket (MQ)'))))
    c.pkt(eth2(ipx(0x4043, 0x5e86, T_SPX, spx(0x00, 0, 1, 2, 2, 1, 1, b'data for a registered spx socket (MQ)'))))

    # ---- other sockets (dissector table, socket ordering)
    c.mark('Socket ordering: lower socket tried first (source higher, source lower), SMB and NCP by socket and packet type')
    c.pkt(eth2(ipx(0x452, 0x4003, S_PEP, sap_query(1, 4))))
    c.pkt(eth2(ipx(0x4003, 0x452, S_PEP, sap_query(1, 4))))
    c.pkt(eth2(ipx(0x453, 0x452, S_PEP, sap_query(1, 4))))
    c.pkt(eth2(ipx(0x550, 0x4044, 0, b'\xffSMB' + b'\x00' * 32)))
    c.pkt(eth2(ipx(0x4044, 0x451, 17, b'\x22\x22\x01\x02\x03\x04\x00\x00' * 2)))   # NCP packet type and socket

    # ---- fix reproducers (SAP request / response flags; IPXWAN NLSP throughput fields are in the ipxwan capture)
    c.mark('Reproducer of "IPX: Fix the SAP request and response flags": general query (ipxsap.request) and general response (ipxsap.response)')
    c.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_query(1, 4))))
    c.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_resp(2, [sap_server(4, b'SERVER', 1, b'\x02\x00\x00\x00\x00\x09', 0x451, 1)]))))
    c.mark('SPX: two packets of one connection whose header sums are equal but whose sequence numbers differ (hash collision, not a retransmission); MQ on the lower socket')
    c.pkt(sp(0x00, 0, 0x1111, 0x2222, 10, 3, 12, b'collision one', a=0x4050, b=0x4051))
    c.pkt(sp(0x00, 0, 0x1111, 0x2222, 3, 10, 12, b'collision two', a=0x4050, b=0x4051))
    c.pkt(eth2(ipx(0x5e86, 0x6001, T_SPX, spx(0x00, 0, 1, 2, 1, 1, 1, b'data for MQ on the lower socket'))))
    c.write('ipx-coverage.pcapng')

    # ---------------------------------------------------------------- malformed
    m = Cap()
    m.mark('Packets shorter than the IPX header, SAP response and RIP entries cut short, SPX shorter than its header, IPX message of 1 octet, serialization shorter than 6 octets')
    full = ipx(0x452, 0x452, S_PEP, sap_resp(2, [sap_server(4, b'FS1', NETA, NA, 0x451, 1)]))
    m.pkt(eth2(full[:20]))
    m.pkt(eth2(full[:29]))
    m.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_resp(2, [sap_server(4, b'FS1', NETA, NA, 0x451, 1)])[:40])))
    m.pkt(eth2(ipx(0x452, 0x452, S_PEP, b'\x00')))
    m.pkt(eth2(ipx(0x453, 0x453, 1, rip(2, [(1, 1, 1)])[:8])))
    m.pkt(eth2(ipx(0x453, 0x453, 1, b'\x00')))
    m.pkt(eth2(ipx(0x4020, 0x4021, T_SPX, spx(0, 0, 1, 2, 3, 4, 5)[:10])))
    m.pkt(eth2(ipx(0x4020, 0x4021, T_SPX, spx(0x08, 0, 1, 2, 3, 4, 5))))      # SPX II header cut at 12 octets
    m.pkt(eth2(ipx(0x4001, 0x4002, 0, bytes([5]))))
    m.pkt(eth2(ipx(0x457, 0x457, 0, b'\x01\x02\x03')))
    m.mark('SAP response without a server (2 octets: the server type is read anyway), NWLink name query as the higher socket (NMPI header missing)')
    m.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_resp(2, []))))
    m.pkt(eth2(ipx(0x551, 0x552, 0, b'\x00' * 32)))
    m.pkt(eth2(ipx(0x552, 0x551, 0, b'\x00' * 32)))
    m.mark('IPX length field smaller than the header, larger than the frame, snaplen cut-offs, ethernet 802.3 with a bad length, truncated GRE and ARCnet')
    m.pkt(eth2(ipx(0x4010, 0x4011, 0, b'hello', length=10)))
    m.pkt(eth2(ipx(0x4010, 0x4011, 0, b'hello', length=1000)))
    m.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_query(1, 4))), caplen=14 + 30)
    m.pkt(eth2(ipx(0x452, 0x452, S_PEP, sap_query(1, 4))), caplen=14 + 20)
    m.pkt(eth2(ipx(0x4020, 0x4021, T_SPX, spx(0, 0, 1, 2, 3, 4, 5, b'data'))), caplen=14 + 30 + 8)
    m.pkt(eth_ip(ip4(47, struct.pack('!HH', 0, 0x8137) + b'\xff\xff\x00')))
    m.pkt(bytes([0x0a, 0x0b, 250, 0]), link='arc_bsd')
    m.write('ipx-coverage-malformed.pcapng')

build()
