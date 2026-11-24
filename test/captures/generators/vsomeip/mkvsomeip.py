# Generates test/captures/vsomeip_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (copied into each generator) ----
import struct
import os
import sys
import gzip

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def pcap_write(fname, pkts, linktype=1, t0=1700000000):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            olen = None
            if isinstance(p, tuple):
                if len(p) == 3:
                    p, ts, olen = p
                else:
                    p, ts = p
            else:
                ts = t0 + i
            f.write(struct.pack('<IIII', ts, 0, len(p), olen or len(p)))
            f.write(p)

def eth(payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01', et=0x0800):
    f = dst + src + struct.pack('!H', et) + payload
    return f + b'\0' * max(0, 60 - len(f))

def ip4(proto, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ttl=64, ident=1, flags_frag=0, tos=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(payload), ident, flags_frag, ttl, proto, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def ip6(nh, payload, src=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\1', dst=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\2', hlim=64):
    return struct.pack('!IHBB', 0x60000000, len(payload), nh, hlim) + src + dst + payload

def udp(sport, dport, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

def tcp(sport, dport, seq, ack, flags, payload=b'', src=(192, 0, 2, 1), dst=(192, 0, 2, 2), win=65535, opts=b''):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0) + opts + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(t))
    return t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    tags += struct.pack('>HH', 0, 0)
    return tags + payload

def rtp(pt, seq, ts, ssrc, payload, marker=0):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload

def gz(path, gzpath):
    with open(path, 'rb') as f:
        d = f.read()
    with open(gzpath, 'wb') as g:
        g.write(gzip.compress(d, 9, mtime=0))

def pcapng_write(fname, frames, t0=1700000000):
    """frames: list of (linktype, bytes) or (linktype, bytes, ts); one interface per link type."""
    def blk(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ifaces = {}
    for fr in frames:
        lt = fr[0]
        if lt not in ifaces:
            ifaces[lt] = len(ifaces)
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, fr in enumerate(frames):
        lt, data = fr[0], fr[1]
        ts = fr[2] if len(fr) > 2 else t0 + i
        us = ts * 1000000
        out += blk(6, struct.pack('<IIIII', ifaces[lt], us >> 32, us & 0xffffffff, len(data), len(data)) + data)
    with open(fname, 'wb') as f:
        f.write(out)

# ---- vSomeIP internal routing protocol ----
# Reached by default through Exported PDU "vsomeip" and, once a ROUTING_INFO command with an IPv4
# address and port has been seen, through the TCP port it names (the preference "auto_register_port").
MAGIC = b'\x67\x37\x6d\x07'
EMAGIC = b'\x07\x6d\x37\x67'

def vs(cmd, body=b'', client=0x1234, version=0, size=None, magic=MAGIC, emagic=EMAGIC, no_client=False):
    sz = len(body) if size is None else size
    h = magic + struct.pack('<BH', cmd, version)
    if not no_client:
        h += struct.pack('<H', client)
    return h + struct.pack('<I', sz) + body + emagic

def svc(sid, iid, major=1, minor=0):
    return struct.pack('<HHBI', sid, iid, major, minor)

def sub(sid, iid, evg, major, event, pending):
    return struct.pack('<HHHBHH', sid, iid, evg, major, event, pending)

def someip_msg(sid, mid, client, session, mtype, payload=b'', rc=0):
    return struct.pack('!HHIHHBBBB', sid, mid, 8 + len(payload), client, session, 1, 1, mtype, rc) + payload

def ri_client(subcmd, client, ip=None, port=None, pad=0):
    if ip is not None:
        body = struct.pack('<H', client) + bytes(ip) + struct.pack('<H', port)
    else:
        body = struct.pack('<H', client) + b'\xee' * pad
    return struct.pack('<BI', subcmd, len(body)) + body

def ri_service(subcmd, client, services, client_pad=0, ip=None, port=None):
    cl = struct.pack('<H', client)
    if ip is not None:
        cl += bytes(ip) + struct.pack('<H', port)
    cl += b'\xdd' * client_pad
    sv = b''.join(services)
    body = struct.pack('<I', len(cl)) + cl + struct.pack('<I', len(sv)) + sv
    return struct.pack('<BI', subcmd, len(body)) + body

def tcp_seg(sport, dport, seq, ack, flags, payload=b'', src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    opts = b'\x02\x04\x05\xb4' if flags & 2 else b''
    return eth(ip4(6, tcp(sport, dport, seq, ack, flags, payload, src=src, dst=dst, opts=opts), src=src, dst=dst, ident=seq & 0xffff))

def build(outdir):
    pk = []
    add = lambda frame: pk.append(exp_pdu('vsomeip', frame))
    # --- session management ---
    add(vs(0x00, b'client-app-one', client=0xffff))                        # ASSIGN_CLIENT (name)
    add(vs(0x00, b'', client=0xffff))
    add(vs(0x01, struct.pack('<H', 0x0101), client=0xffff))                 # ASSIGN_CLIENT_ACK
    add(vs(0x02))                                                           # REGISTER_APPLICATION
    add(vs(0x03))
    add(vs(0x04))                                                           # APPLICATION_LOST
    add(vs(0x06))                                                           # REGISTERED_ACK
    add(vs(0x07))
    add(vs(0x08))
    # --- ROUTING_INFO: all sub commands in one message and alone ---
    srv = [svc(0x1234, 0x0001, 1, 0), svc(0x5678, 0x0002, 0xff, 0xffffffff), svc(0x0042, 0x0003, 3, 17)]
    add(vs(0x05, ri_client(0, 0x0101, (192, 0, 2, 2), 30509)))              # ADD_CLIENT with an address; port 30509
    add(vs(0x05, ri_client(0, 0x0102, (192, 0, 2, 2), 30510)))              # ADD_CLIENT; port 30510
    add(vs(0x05, ri_client(0, 0x0103)))                                     # client only
    add(vs(0x05, ri_client(0, 0x0104, pad=18)))                             # larger client info (skipped)
    add(vs(0x05, ri_client(1, 0x0101, (192, 0, 2, 2), 30509)))              # DEL_CLIENT
    add(vs(0x05, ri_client(1, 0x0105)))
    add(vs(0x05, ri_service(2, 0x0101, srv)))                               # ADD_SERVICE_INSTANCE
    add(vs(0x05, ri_service(2, 0x0102, srv[:1], ip=(192, 0, 2, 3), port=30511)))
    add(vs(0x05, ri_service(2, 0x0103, [], client_pad=5)))
    add(vs(0x05, ri_service(4, 0x0101, srv[:2])))                           # DEL_SERVICE_INSTANCE
    add(vs(0x05, ri_service(4, 0x0104, srv[:2], ip=(192, 0, 2, 4), port=30512)))
    add(vs(0x05, ri_client(0, 0x0201, (192, 0, 2, 5), 30513) + ri_service(2, 0x0202, srv) +
           ri_client(1, 0x0201) + ri_service(4, 0x0202, srv[:1]) + ri_client(1, 0x0203, (192, 0, 2, 6), 30514)))
    add(vs(0x05, struct.pack('<BI', 9, 6) + b'\x09\x00\x00\x00\x00\xaa'))   # unknown sub command, rest unparsed
    add(vs(0x05, b''))
    add(vs(0x05, b'\x00\x02\x00\x00'))                                      # too short for a sub command
    # --- service offers, requests and subscriptions ---
    add(vs(0x10, svc(0x1234, 0x0001, 1, 0)))                                # OFFER_SERVICE
    add(vs(0x10, svc(0x5678, 0x0002, 0xff, 0xffffffff)))                    # any major and minor
    add(vs(0x11, svc(0x1234, 0x0001, 1, 5)))                                # STOP_OFFER_SERVICE
    add(vs(0x12, sub(0x1234, 0x0001, 0x0010, 1, 0x8001, 0x0001)))           # SUBSCRIBE
    add(vs(0x12, sub(0x1234, 0x0001, 0x0010, 0xff, 0xffff, 0xffff)))        # any major
    add(vs(0x13, sub(0x1234, 0x0001, 0x0010, 1, 0x8001, 0x0001)))           # UNSUBSCRIBE
    add(vs(0x2a, sub(0x1234, 0x0001, 0x0010, 1, 0x8001, 0x0001)))           # EXPIRE
    add(vs(0x14, b''.join(srv)))                                            # REQUEST_SERVICE
    add(vs(0x14, b''))
    add(vs(0x15, struct.pack('<HH', 0x1234, 0x0001)))                       # RELEASE_SERVICE
    add(vs(0x16, struct.pack('<HHHHHH', 0x1234, 1, 0x10, 0x101, 0x8001, 7)))   # SUBSCRIBE_NACK
    add(vs(0x17, struct.pack('<HHHHHH', 0x1234, 1, 0x10, 0x101, 0x8001, 7)))   # SUBSCRIBE_ACK
    add(vs(0x21, struct.pack('<HHHH', 0x1234, 1, 0x10, 9)))                 # UNSUBSCRIBE_ACK
    # --- SOME/IP messages and events ---
    msg = someip_msg(0x1234, 0x0421, 0x0101, 0x0001, 0x00, b'\x01\x02\x03\x04\x05\x06\x07\x08')
    for cmd in (0x18, 0x19, 0x1a):                                          # SEND, NOTIFY, NOTIFY_ONE
        add(vs(cmd, struct.pack('<HBB', 0x0001, 0, 1) + struct.pack('!H', 0x0102) + msg, size=6 + len(msg)))
    add(vs(0x18, struct.pack('<HBB', 0x0002, 1, 0) + struct.pack('!H', 0xffff) +
           someip_msg(0x8001, 0x8001, 0x0000, 0x0002, 0x02, b'\xaa' * 5), size=6 + 16 + 5))
    add(vs(0x18, struct.pack('<HBB', 0x0002, 7, 0) + struct.pack('!H', 0x0000) + someip_msg(0x1234, 0x0001, 1, 1, 0x80, b'', 0x00),
           size=6 + 16))
    # REGISTER_EVENT with two entries; UNREGISTER_EVENT
    ev = struct.pack('<HHHBBBBH', 0x1234, 1, 0x8001, 0, 1, 0, 1, 2) + struct.pack('<HH', 0x10, 0x11)
    ev += struct.pack('<HHHBBBBH', 0x1234, 1, 0x8002, 1, 0, 1, 0, 0)
    add(vs(0x1b, ev))
    add(vs(0x1c, struct.pack('<HHHBB', 0x1234, 1, 0x8001, 1, 0)))
    add(vs(0x1d))                                                           # ID_RESPONSE / ID_REQUEST
    add(vs(0x1e))
    add(vs(0x1f, b'\x02'))                                                  # OFFERED_SERVICES_REQUEST
    osr = struct.pack('<BI', 0, 4) + b'\x01\x00\x02\x00' + struct.pack('<BI', 1, 8) + b'\x34\x12\x01\x00\x01\x00\x00\x00'
    add(vs(0x20, osr))                                                      # OFFERED_SERVICES_RESPONSE
    add(vs(0x22, struct.pack('<I', 0x77)))                                  # RESEND_PROVIDED_EVENTS
    for cmd in (0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29):                  # security commands: not implemented
        add(vs(cmd, b'\x01\x02\x03\x04\x05\x06'))
    add(vs(0x30))                                                           # SUSPEND
    cfg = b''
    for k, v in ((b'logging.level', b'debug'), (b'routing', b'app'), (b'k', b'')):
        cfg += struct.pack('<I', len(k)) + k + struct.pack('<I', len(v)) + v
    add(vs(0x31, cfg))                                                      # CONFIG
    add(vs(0x7f, b'\x01\x02\x03'))                                          # unknown command
    add(vs(0x06, b'\x09\x08', version=1))                                   # version other than 0, extra bytes
    # --- TCP: port 30509 was registered by the ROUTING_INFO message above ---
    frames = [(252, p) for p in pk]
    pk = []
    c, s = (192, 0, 2, 1), (192, 0, 2, 2)
    P = 30509
    pk.append(tcp_seg(40000, P, 1000, 0, 0x02))
    pk.append(tcp_seg(P, 40000, 5000, 1001, 0x12, src=s, dst=c))
    pk.append(tcp_seg(40000, P, 1001, 5001, 0x10))
    nxt = [1001]
    def send(data):
        pk.append(tcp_seg(40000, P, nxt[0], 5001, 0x18, data))
        nxt[0] += len(data)
    ping = vs(0x07)
    pong = vs(0x08, client=0x4321)
    big = vs(0x18, struct.pack('<HBB', 1, 0, 1) + struct.pack('!H', 0x0102) + msg, size=6 + len(msg))
    send(ping)                                  # one PDU
    send(ping + pong)                           # two PDUs in one segment
    send(big[:14])                              # a PDU split over two segments
    send(big[14:])
    send(pong + big[:20])                       # a PDU and the start of the next
    send(big[20:] + ping)
    send(vs(0x31, cfg))
    # the other direction, from the router to the client
    pk.append(tcp_seg(P, 40000, 5001, nxt[0], 0x18, vs(0x05, ri_client(1, 0x0101)), src=s, dst=c))
    frames += [(1, p) for p in pk]
    pcapng_write(os.path.join(outdir, 'vsomeip-coverage.pcapng'), frames)
    gz(os.path.join(outdir, 'vsomeip-coverage.pcapng'), os.path.join(outdir, 'vsomeip_coverage.pcapng.gz'))

    # malformed and special cases (Exported PDU only; TCP data on the registered port)
    mal = []
    madd = lambda frame: mal.append((252, exp_pdu('vsomeip', frame)))
    madd(vs(0x05, ri_client(0, 0x0101, (192, 0, 2, 2), 30509)))     # registers TCP port 30509
    # the reproducer of "vSomeIP: Bound ROUTING_INFO sizes and fix PDU length offset": ci_size = -5
    madd(vs(0x05, struct.pack('<BI', 0, 0xFFFFFFFB) + struct.pack('<H', 0xabcd), client=0x1234, version=0))
    # sub command sizes larger than the data, client info larger than the data
    madd(vs(0x05, struct.pack('<BI', 0, 0x7fffffff) + b'\x01\x02\x03\x04\x05\x06\x07\x08'))
    madd(vs(0x05, struct.pack('<BI', 2, 20) + struct.pack('<I', 0x7ffffff0) + b'\0' * 12))
    madd(vs(0x05, struct.pack('<BI', 2, 12) + struct.pack('<I', 1) + b'\x01' + struct.pack('<I', 0x10) + b'\0'))
    madd(vs(0x05, struct.pack('<BI', 2, 20) + struct.pack('<I', 2) + b'\x01\x01' + struct.pack('<I', 0xFFFFFFFF) + b'\0' * 6))
    # ci_size 0 and 1 for the service instance sub commands
    madd(vs(0x05, struct.pack('<BI', 2, 12) + struct.pack('<I', 0) + struct.pack('<I', 0) + b'\0' * 4))
    madd(vs(0x05, struct.pack('<BI', 2, 13) + struct.pack('<I', 1) + b'\x07' + struct.pack('<I', 0) + b'\0' * 4))
    # OFFERED_SERVICES_RESPONSE and CONFIG sizes that wrap, size larger than the data
    madd(vs(0x20, struct.pack('<BI', 0, 0xFFFFFFFB) + b'\0' * 4))
    madd(vs(0x31, struct.pack('<I', 0xFFFFFFF8) + b'abcd' + struct.pack('<I', 5) + b'v'))
    madd(vs(0x31, struct.pack('<I', 1) + b'k' + struct.pack('<I', 0xFFFFFFFF) + b'v'))
    madd(vs(0x31, struct.pack('<I', 2) + b'kk'))
    madd(vs(0x18, struct.pack('<HBB', 1, 0, 1) + struct.pack('!H', 0x0102) + b'\x00\x01', size=4))
    madd(vs(0x18, b'\x00', size=0xfffffff0))
    madd(vs(0x1b, struct.pack('<HHHBBBBH', 1, 1, 1, 0, 0, 0, 0, 5000)))
    madd(vs(0x00, b'name', size=100))
    # truncated PDUs
    full = vs(0x12, sub(0x1234, 1, 0x10, 1, 0x8001, 1))
    for cut in (3, 5, 8, 12, 20, 28):
        mal.append((252, exp_pdu('vsomeip', full[:cut])))
    mal.append((252, exp_pdu('vsomeip', vs(0x10, svc(1, 1))[:20])))
    mal.append((252, exp_pdu('vsomeip', vs(0x17, b'\x01\x02\x03'))))
    # TCP: an incomplete PDU at the end of the stream and a PDU announcing a large size
    t2 = []
    t2.append(tcp_seg(40002, P, 100, 0, 0x02))
    t2.append(tcp_seg(P, 40002, 900, 101, 0x12, src=s, dst=c))
    t2.append(tcp_seg(40002, P, 101, 901, 0x10))
    t2.append(tcp_seg(40002, P, 101, 901, 0x18, vs(0x07)[:11]))
    t2.append(tcp_seg(40003, P, 200, 0, 0x18, vs(0x31, b'\0' * 3, size=0x10000000)[:30]))
    # a PDU with a SUSPEND command (the client field is only present with vsomeip.suspend_without_client off)
    t2.append(tcp_seg(40004, P, 300, 0, 0x18, vs(0x30) + vs(0x30, no_client=True)))
    mal += [(1, p) for p in t2]
    pcapng_write(os.path.join(outdir, 'vsomeip-coverage-malformed.pcapng'), mal)

    # UDP datagrams on port 30490 (coverage only: reached with Decode As udp.port==30490,vsomeip_udp,
    # the dissector has no default UDP port) and TCP streams for vsomeip.suspend_without_client
    u = []
    def dg(payload, sport=41000):
        u.append(eth(ip4(17, udp(sport, 30490, payload))))
    dg(vs(0x07))
    dg(vs(0x07) + vs(0x08, client=0x4321))
    dg(vs(0x18, struct.pack('<HBB', 1, 0, 1) + struct.pack('!H', 0x0102) + msg, size=6 + len(msg)) + vs(0x07))
    dg(vs(0x30, no_client=True) + vs(0x07))                  # decoded as such with suspend_without_client
    dg(vs(0x30) + vs(0x07))
    dg(vs(0x31, cfg))
    dg(vs(0x07)[:10])                                        # incomplete datagram
    pcap_write(os.path.join(outdir, 'vsomeip-coverage-udp.pcap'), u)
    # TCP with SUSPEND PDUs on the port 30510 registered by ROUTING_INFO in the main capture
    t3 = [(252, exp_pdu('vsomeip', vs(0x05, ri_client(0, 0x0102, (192, 0, 2, 2), 30510))))]
    sq = 1
    for data in (vs(0x30, no_client=True) + vs(0x07), vs(0x07) + vs(0x30, no_client=True), vs(0x30, no_client=True)):
        t3.append((1, tcp_seg(40010, 30510, sq, 1, 0x18, data)))
        sq += len(data)
    pcapng_write(os.path.join(outdir, 'vsomeip-coverage-suspend.pcapng'), t3)
    return pk

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
