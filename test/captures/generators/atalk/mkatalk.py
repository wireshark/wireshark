#!/usr/bin/env python3
# Generates test/captures/atalk_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the AppleTalk dissectors in
packet-atalk.c (LLAP, DDP, NBP, RTMP, ZIP, ATP, ASP, PAP, ADSP, MacIP).

Every packet is built from scratch with struct; no captured traffic is
used. The captures are pcapng because they mix link types:

  interface 0  LocalTalk (linktype 114)
  interface 1  Ethernet (linktype 1): EtherTalk phase 2 (802.3 + LLC/SNAP
               OUI 08:00:07 PID 0x809B, long DDP), and gatewayed LLAP
               (Ethertype 0x809B and SNAP OUI 00:00:00 PID 0x809B)
  interface 2  Exported PDU (linktype 252): PDUs naming the AppleTalk
               dissectors, among them the "ddp_short" reproducer
  interface 3  BSD loopback / DLT_NULL (linktype 0), AF_APPLETALK
  interface 4  PPP (linktype 9), protocol 0x0029
  interface 5  Cisco HDLC (linktype 104), protocol 0x809B

Usage: mkatalk.py <output directory>

Writes:
  atalk-coverage.pcapng            the main capture: decodes without
                                   malformed packets or error expert infos
                                   in one pass and with -2
  atalk-coverage-malformed.pcapng  truncated and inconsistent packets,
                                   invalid DDP lengths, a reply before its
                                   request
"""

import os
import struct
import sys

LT_LOCALTALK, LT_ETH, LT_EXPPDU, LT_NULL, LT_PPP, LT_CHDLC = range(6)
LINKTYPES = [114, 1, 252, 0, 9, 104]


# --------------------------------------------------------------------------
# pcapng writer

def block(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    blen = 12 + len(body)
    return struct.pack('<II', btype, blen) + body + struct.pack('<I', blen)


class Pcapng:
    def __init__(self):
        self.frames = []

    def add(self, iface, data):
        self.frames.append((iface, data))

    def write(self, path):
        out = [block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))]
        for lt in LINKTYPES:
            out.append(block(1, struct.pack('<HHI', lt, 0, 262144)))
        t = 1700000000 * 1000000
        for i, (iface, data) in enumerate(self.frames):
            ts = t + i * 10000
            out.append(block(6, struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff,
                                            len(data), len(data)) + data))
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


# --------------------------------------------------------------------------
# AppleTalk building blocks

def pstr(s):
    if isinstance(s, str):
        s = s.encode('mac_roman')
    return bytes([len(s)]) + s


def ddp(dnet, dnode, dsock, snet, snode, ssock, typ, payload, hops=0, cksum=0, length=None):
    """Long (extended) DDP header."""
    if length is None:
        length = 13 + len(payload)
    return struct.pack('>HHHHBBBBB', (hops << 10) | length, cksum, dnet, snet,
                       dnode, snode, dsock, ssock, typ) + payload


def ddp_short(dsock, ssock, typ, payload, length=None, reserved=0):
    if length is None:
        length = 5 + len(payload)
    return struct.pack('>HBBB', reserved | length, dsock, ssock, typ) + payload


def llap(dnode, snode, ltype, payload=b''):
    return bytes([dnode, snode, ltype]) + payload


def atp(ctrl, bitmap, tid, user=b'\0\0\0\0', data=b''):
    assert len(user) == 4
    return struct.pack('>BBH', ctrl, bitmap, tid) + user + data


# ATP control bytes
TREQ, TRESP, TREL = 0x40, 0x80, 0xC0
XO, EOM, STS = 0x20, 0x10, 0x08

# DDP types
T_RTMPDATA, T_NBP, T_ATP, T_AEP, T_RTMPREQ, T_ZIP, T_ADSP = 1, 2, 3, 4, 5, 6, 7
T_MACIP, T_ARP, T_EIGRP = 0x16, 0x17, 0x58


def ether(dst, src, payload, ethertype=None):
    if ethertype is None:      # 802.3 length + LLC/SNAP done by caller
        hdr = dst + src + struct.pack('>H', len(payload))
    else:
        hdr = dst + src + struct.pack('>H', ethertype)
    f = hdr + payload
    return f + b'\0' * max(0, 60 - len(f))


def snap(oui, pid, payload):
    return b'\xaa\xaa\x03' + oui.to_bytes(3, 'big') + struct.pack('>H', pid) + payload


MAC_WS = b'\x08\x00\x07\x11\x22\x33'      # workstation
MAC_SRV = b'\x08\x00\x07\x44\x55\x66'     # file server
MAC_RTR = b'\x08\x00\x07\x77\x88\x99'     # router
MAC_BCAST = b'\x09\x00\x07\xff\xff\xff'   # AppleTalk broadcast
MAC_ZONE = b'\x09\x00\x07\x00\x00\x2a'    # zone multicast


def ethertalk(dst, src, ddp_pkt):
    return ether(dst, src, snap(0x080007, 0x809B, ddp_pkt))


def ipv4(src, dst, proto, payload, ident=1):
    def cks(b):
        if len(b) % 2:
            b += b'\0'
        s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                      bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', cks(hdr)) + hdr[12:]
    if proto == 1:
        payload = payload[:2] + struct.pack('>H', cks(payload)) + payload[4:]
    return hdr + payload


def tlv(t, v):
    v = v + b'\0' * ((-len(v)) % 4)
    return struct.pack('>HH', t, len(v)) + v


def exported_pdu(name, payload, extra=b''):
    return tlv(12, name.encode()) + extra + struct.pack('>HH', 0, 0) + payload


# --------------------------------------------------------------------------
# Hosts on EtherTalk (phase 2): workstation 100.10, file server 100.20,
# router 100.1 (also a MacIP gateway), print server 200.30

WS = (100, 10)
SRV = (100, 20)
RTR = (100, 1)
PRT = (200, 30)


def et(src, ssock, dst, dsock, typ, payload, macs=None, **kw):
    """EtherTalk DDP packet between two hosts."""
    if macs is None:
        m = {WS: MAC_WS, SRV: MAC_SRV, RTR: MAC_RTR, PRT: MAC_RTR}
        macs = (m.get(dst, MAC_BCAST), m.get(src, MAC_RTR))
    return ethertalk(macs[0], macs[1],
                     ddp(dst[0], dst[1], dsock, src[0], src[1], ssock, typ, payload, **kw))


# AFP server status block (reply to ASP GetStatus)
def afp_status():
    name = pstr('Synthetic Server')
    fixed_len = 10 + len(name)
    fixed_len += fixed_len & 1
    mach = pstr('Macintosh')
    vers = bytes([2]) + pstr('AFPVersion 2.0') + pstr('AFPVersion 2.1')
    uams = bytes([2]) + pstr('No User Authent') + pstr('Cleartxt passwrd')
    mach_off = fixed_len
    vers_off = mach_off + len(mach)
    uams_off = vers_off + len(vers)
    hdr = struct.pack('>HHHHH', mach_off, vers_off, uams_off, 0, 0x0001) + name
    hdr += b'\0' * (fixed_len - len(hdr))
    return hdr + mach + vers + uams


def afp_getsrvrparms_reply():
    vols = [(0x80, 'Macintosh HD'), (0x00, 'Public'), (0x01, 'Projects')]
    body = struct.pack('>I', 0x2a000000) + bytes([len(vols)])
    for flags, name in vols:
        body += bytes([flags]) + pstr(name)
    return body


def build_main():
    cap = Pcapng()
    L = lambda pkt: cap.add(LT_LOCALTALK, pkt)
    E = lambda pkt: cap.add(LT_ETH, pkt)
    X = lambda pkt: cap.add(LT_EXPPDU, pkt)

    # ---------------- LocalTalk: LLAP control frames
    L(llap(0x2a, 0x2a, 0x81))          # ENQ (node address acquisition)
    L(llap(0x2a, 0x2a, 0x82))          # ACK
    L(llap(0x05, 0x2a, 0x84))          # RTS
    L(llap(0x2a, 0x05, 0x85))          # CTS
    L(llap(0x05, 0x2a, 0x10, b'\x01\x02\x03'))   # unknown LLAP type

    # ---------------- LocalTalk: short DDP
    # NBP lookup broadcast on the local network
    nbp_tuple = struct.pack('>HBBB', 0, 0x2a, 253, 0) + pstr('=') + pstr('LaserWriter') + pstr('*')
    L(llap(0xff, 0x2a, 0x01, ddp_short(2, 253, T_NBP, bytes([0x21, 7]) + nbp_tuple)))
    # NBP reply from the printer
    rep = struct.pack('>HBBB', 0, 0x05, 128, 1) + pstr('Office LaserWriter') + pstr('LaserWriter') + pstr('*')
    L(llap(0x2a, 0x05, 0x01, ddp_short(253, 2, T_NBP, bytes([0x31, 7]) + rep)))
    # RTMP request and non-extended RTMP data on LocalTalk
    L(llap(0xff, 0x2a, 0x01, ddp_short(1, 253, T_RTMPREQ, b'\x01')))
    L(llap(0xff, 0x01, 0x01, ddp_short(1, 1, T_RTMPDATA,
          struct.pack('>HBB', 5, 8, 1) + b'\x00\x00\x82' +
          struct.pack('>HB', 5, 0) + struct.pack('>HB', 7, 1) + struct.pack('>HB', 9, 2))))
    # AEP echo request/reply over short DDP (no AEP dissector: data)
    L(llap(0x05, 0x2a, 0x01, ddp_short(4, 253, T_AEP, b'\x01echo')))
    L(llap(0x2a, 0x05, 0x01, ddp_short(253, 4, T_AEP, b'\x02echo')))
    # Reproducer (atalk_misc.py): short DDP whose length word
    # has the reserved bits set; the length is 7, the 2 trailing octets
    # are not part of the datagram.
    # The original frame (NBP count 1 with no tuple) throws in the NBP
    # dissector when a tree is built and is in the malformed capture; this
    # one carries a complete NBP lookup.
    L(llap(2, 1, 0x01, ddp_short(2, 2, T_NBP, bytes([0x21, 1]) + nbp_tuple, reserved=0xFC00) + b'\xee\xee'))

    # ---------------- LocalTalk: long DDP to a LaserWriter, PAP over ATP
    def lt_long(dnode, dsock, snode, ssock, typ, payload):
        return llap(dnode, snode, 0x02, ddp(0, dnode, dsock, 0, snode, ssock, typ, payload, cksum=0x1234))
    PW, PP = 0x2a, 0x05            # workstation and printer nodes
    # Conversation 1 (ws 0x90 <-> printer SLS 0x80): SendStatus with
    # connection ID 0 (picked as PAP because the first octet is 0)
    L(lt_long(PP, 0x80, PW, 0x90, T_ATP, atp(TREQ, 0x01, 1, bytes([0, 8, 0, 0]))))
    L(lt_long(PW, 0x90, PP, 0x80, T_ATP, atp(TRESP | EOM, 0, 1, bytes([0, 9, 0, 0]),
          b'\0\0\0\0' + pstr('status: idle'))))
    # OpenConn / OpenConnReply on the same conversation (ID 0x2a)
    L(lt_long(PP, 0x80, PW, 0x90, T_ATP, atp(TREQ | XO, 0x01, 2, bytes([0x2a, 1, 0, 0]),
          bytes([0x91, 8]) + struct.pack('>H', 0))))
    L(lt_long(PW, 0x90, PP, 0x80, T_ATP, atp(TRESP | EOM, 0, 2, bytes([0x2a, 2, 0, 0]),
          bytes([0x81, 8]) + struct.pack('>H', 0) + pstr('status: busy; source: AppleTalk'))))
    L(lt_long(PP, 0x80, PW, 0x90, T_ATP, atp(TREL, 0, 2, bytes([0x2a, 2, 0, 0]))))
    # Conversation 2 (ws 0x91 <-> printer 0x81): SendData, Data reply in
    # three ATP packets (reassembled), Tickle, CloseConn, unknown function
    L(lt_long(PW, 0x91, PP, 0x81, T_ATP, atp(TREQ | XO | 1, 0x07, 3, bytes([0x2a, 3]) + struct.pack('>H', 1))))
    ps = b'%!PS-Adobe-3.0\n/Times-Roman findfont 12 scalefont setfont\n'
    L(lt_long(PP, 0x81, PW, 0x91, T_ATP, atp(TRESP, 0, 3, bytes([0x2a, 4, 0, 0]), ps[:20])))
    L(lt_long(PP, 0x81, PW, 0x91, T_ATP, atp(TRESP, 1, 3, bytes([0x2a, 4, 0, 0]), ps[20:40])))
    L(lt_long(PP, 0x81, PW, 0x91, T_ATP, atp(TRESP | EOM, 2, 3, bytes([0x2a, 4, 1, 0]), ps[40:])))
    L(lt_long(PW, 0x91, PP, 0x81, T_ATP, atp(TREL, 0, 3, bytes([0x2a, 4, 0, 0]))))
    L(lt_long(PP, 0x81, PW, 0x91, T_ATP, atp(TREQ, 0x01, 4, bytes([0x2a, 5, 0, 0]))))
    L(lt_long(PW, 0x91, PP, 0x81, T_ATP, atp(TREQ, 0x01, 5, bytes([0x2a, 0x0b, 0, 0]))))  # unknown fn
    L(lt_long(PP, 0x81, PW, 0x91, T_ATP, atp(TREQ | XO | 4, 0x01, 6, bytes([0x2a, 6, 0, 0]))))
    L(lt_long(PW, 0x91, PP, 0x81, T_ATP, atp(TRESP | EOM, 0, 6, bytes([0x2a, 7, 0, 0]))))

    # ---------------- EtherTalk: RTMP
    E(et(RTR, 1, (0, 0xff), 1, T_RTMPDATA,     # extended RTMP data, 2-octet node length
         struct.pack('>HBH', 100, 16, 1) +
         struct.pack('>HBHB', 100, 0x80, 109, 0x82) +      # first tuple: version
         struct.pack('>HBHB', 200, 0x81, 209, 0x82) +      # extended tuple
         struct.pack('>HB', 300, 2), macs=(MAC_BCAST, MAC_RTR)))  # non-extended tuple
    E(et(RTR, 1, (0, 0xff), 1, T_RTMPDATA,     # extended, 1-octet node, one tuple
         struct.pack('>HBB', 100, 8, 1) + struct.pack('>HBHB', 100, 0x80, 109, 0x82),
         macs=(MAC_BCAST, MAC_RTR)))
    for fn in (1, 2, 3, 4):
        E(et(WS, 253, RTR, 1, T_RTMPREQ, bytes([fn])))

    # ---------------- EtherTalk: NBP
    ent = lambda node, sock, enum, o, t, z: struct.pack('>HBBB', 100, node, sock, enum) + pstr(o) + pstr(t) + pstr(z)
    E(et(WS, 2, RTR, 2, T_NBP, bytes([0x11, 9]) + ent(10, 253, 0, '=', 'AFPServer', 'Engineering')))
    E(et(RTR, 2, (0, 0xff), 2, T_NBP, bytes([0x21, 9]) + ent(10, 253, 0, '=', 'AFPServer', 'Engineering'),
         macs=(MAC_ZONE, MAC_RTR)))
    E(et(RTR, 2, (200, 1), 2, T_NBP, bytes([0x41, 9]) + ent(10, 253, 0, '=', 'AFPServer', 'Engineering')))
    E(et(SRV, 2, WS, 253, T_NBP, bytes([0x33, 9]) +
         ent(20, 0xfd, 0, 'Synthetic Server', 'AFPServer', '*') +
         ent(20, 0xfd, 1, 'Synthetic Server', 'AFPServer', '*') +
         ent(20, 0x04, 0, 'Synthetic Server', 'Workstation', '*')))
    E(et(WS, 2, RTR, 2, T_NBP, bytes([0x50, 1])))    # unknown operation, no tuples

    # ---------------- EtherTalk: ZIP over DDP (socket 6)
    zinfo = lambda: None
    E(et(WS, 6, RTR, 6, T_ZIP, bytes([1, 3]) + struct.pack('>HHH', 100, 200, 300)))  # Query
    E(et(RTR, 6, WS, 6, T_ZIP, bytes([2, 2]) + struct.pack('>H', 200) + pstr('Engineering') +
         struct.pack('>H', 300) + pstr('Sales')))                                  # Reply
    E(et(RTR, 6, WS, 6, T_ZIP, bytes([8, 2]) + struct.pack('>H', 100) + pstr('Engineering') +
         struct.pack('>H', 100) + pstr('Marketing')))                              # Extended reply
    E(et(WS, 6, (0, 0xff), 6, T_ZIP, bytes([5, 0]) + b'\0\0\0\0' + pstr('Engineering'),
         macs=(MAC_BCAST, MAC_WS)))                                               # GetNetInfo request
    E(et(RTR, 6, WS, 6, T_ZIP, bytes([6, 0x80]) + struct.pack('>HH', 100, 109) + pstr('Nowhere') +
         bytes([6]) + MAC_ZONE + pstr('Engineering')))                            # GetNetInfo reply, zone invalid
    E(et(RTR, 6, WS, 6, T_ZIP, bytes([6, 0x20]) + struct.pack('>HH', 100, 109) + pstr('Engineering') +
         bytes([6]) + MAC_ZONE))                                                  # GetNetInfo reply, only one zone
    E(et(RTR, 6, (0, 0xff), 6, T_ZIP, bytes([7, 0x40]) + b'\0\0\0\0' + pstr('Old Zone') +
         bytes([6]) + MAC_ZONE + pstr('New Zone'), macs=(MAC_BCAST, MAC_RTR)))    # Notify
    E(et(WS, 6, RTR, 6, T_ZIP, bytes([0x0a, 0])))                                 # unknown function

    # Reproducer frames from atalk_misc.py (Notify, GetNetInfo reply)
    L(llap(2, 1, 0x02, ddp(1, 2, 6, 1, 1, 6, T_ZIP, bytes([7, 0x80]) + b'\0' * 4 + b'\x03abc' + b'\x06' +
                           b'\x09\0\x07\xff\xff\xff' + b'\x03xyz')))
    L(llap(2, 1, 0x02, ddp(1, 2, 6, 1, 1, 6, T_ZIP, bytes([6, 0x80, 0, 1, 0, 9]) + b'\x03abc' + b'\x06' +
                           b'\x09\0\x07\xff\xff\xff' + b'\x03dfz')))

    # ---------------- EtherTalk: ZIP over ATP (to socket 6)
    E(et(WS, 0x84, RTR, 6, T_ATP, atp(TREQ, 0x01, 400, bytes([7, 0, 0, 0]))))     # GetMyZone
    E(et(RTR, 6, WS, 0x84, T_ATP, atp(TRESP | EOM, 0, 400, bytes([0, 0, 0, 1]), pstr('Engineering'))))
    E(et(WS, 0x84, RTR, 6, T_ATP, atp(TREQ, 0xff, 401, bytes([8, 0, 0, 1]))))     # GetZoneList, 8 packets
    E(et(RTR, 6, WS, 0x84, T_ATP, atp(TRESP | EOM, 0, 401, bytes([1, 0, 0, 3]),
         pstr('Engineering') + pstr('Marketing') + pstr('Sales'))))
    E(et(WS, 0x84, RTR, 6, T_ATP, atp(TREQ, 0x01, 402, bytes([9, 0, 0, 1]))))     # GetLocalZones
    E(et(RTR, 6, WS, 0x84, T_ATP, atp(TRESP | EOM, 0, 402, bytes([1, 0, 0, 2]),
         pstr('Engineering') + pstr('Marketing'))))
    E(et(WS, 0x84, RTR, 6, T_ATP, atp(TREQ, 0x01, 403, bytes([10, 0, 0, 1]))))    # unknown
    E(et(RTR, 6, WS, 0x84, T_ATP, atp(TRESP | EOM, 0, 403, bytes([0, 0, 0, 0]))))

    # A reply to a transaction never requested: rejected after the ZIP
    # columns are set
    E(et(RTR, 6, WS, 0x84, T_ATP, atp(TRESP | EOM, 0, 404, bytes([1, 0, 0, 1]), pstr('Lost'))))
    # GetMyZone from another socket with a transaction ID that ASP uses
    # below (same hash bucket, different conversation)
    E(et(WS, 0x8b, RTR, 6, T_ATP, atp(TREQ, 0x01, 1000, bytes([7, 0, 0, 0]))))
    E(et(RTR, 6, WS, 0x8b, T_ATP, atp(TRESP | EOM, 0, 1000, bytes([0, 0, 0, 1]), pstr('Engineering'))))

    # ---------------- EtherTalk: MacIP gateway protocol over ATP (socket 72)
    E(et(WS, 0x85, RTR, 72, T_ATP, atp(TREQ, 0x01, 500, b'\0\0\0\0', struct.pack('>i', 1) + b'\0' * 20)))
    E(et(RTR, 72, WS, 0x85, T_ATP, atp(TRESP | EOM, 0, 500, struct.pack('>HH', 1, 0),
         struct.pack('>i', 1) + bytes([192, 0, 2, 10, 192, 0, 2, 53, 192, 0, 2, 255, 192, 0, 2, 20,
                                       192, 0, 2, 21, 192, 0, 2, 22, 192, 0, 2, 23, 192, 0, 2, 24]))))
    E(et(WS, 0x85, RTR, 72, T_ATP, atp(TREQ, 0x01, 501, b'\0\0\0\0', struct.pack('>i', 3) + b'\0' * 20)))
    E(et(RTR, 72, WS, 0x85, T_ATP, atp(TRESP | EOM, 0, 501, struct.pack('>HH', 1, 0),
         struct.pack('>i', 3) + bytes([192, 0, 2, 1, 192, 0, 2, 53, 192, 0, 2, 255, 0, 0, 0, 0, 0, 0, 0, 0]))))
    E(et(WS, 0x85, RTR, 72, T_ATP, atp(TREQ, 0x01, 502, b'\0\0\0\0', struct.pack('>i', 2) + b'\0' * 20)))
    # Reproducer frames from atalk_misc.py: MacIP ASSIGN, ERROR reply
    L(llap(2, 1, 0x02, ddp(1, 2, 72, 1, 1, 0x80, T_ATP, atp(0x40, 1, 7, b'\0\0\0\0', struct.pack('>i', 1) + b'\0' * 20))))
    # The ERROR reply of atalk_misc.py has five addresses before the
    # message; the dissector takes the message for three more addresses
    # and throws, so it is in the malformed capture. This one has eight.
    L(llap(1, 2, 0x02, ddp(1, 1, 0x80, 1, 2, 72, T_ATP, atp(0x90, 0, 7, b'\0\x01\0\0',
                                                          struct.pack('>i', -1) + b'\0' * 32 + b'no address\0'))))

    # ---------------- EtherTalk: MacIP datagrams (DDP type 22, IPv4)
    icmp = struct.pack('>BBHHH', 8, 0, 0, 0x1234, 1) + b'macip ping'
    E(et(WS, 72, RTR, 72, T_MACIP, ipv4((192, 0, 2, 10), (198, 51, 100, 1), 1, icmp)))
    icmp = struct.pack('>BBHHH', 0, 0, 0, 0x1234, 1) + b'macip ping'
    E(et(RTR, 72, WS, 72, T_MACIP, ipv4((198, 51, 100, 1), (192, 0, 2, 10), 1, icmp, ident=2)))

    # ---------------- EtherTalk: ASP with AFP above it
    # Conversation A1: workstation 0x80 <-> server SLS 0xfd
    E(et(WS, 0x80, SRV, 0xfd, T_ATP, atp(TREQ, 0x03, 1000, bytes([3, 0, 0, 0]))))   # GetStatus, 2 packets
    st = afp_status()
    E(et(SRV, 0xfd, WS, 0x80, T_ATP, atp(TRESP, 0, 1000, b'\0\0\0\0', st[:40])))
    E(et(SRV, 0xfd, WS, 0x80, T_ATP, atp(TRESP | EOM, 1, 1000, b'\0\0\0\0', st[40:])))
    E(et(WS, 0x80, SRV, 0xfd, T_ATP, atp(TREQ | XO | 2, 0x01, 1001, bytes([4, 0x81]) + struct.pack('>H', 0x0100))))  # OpenSession
    E(et(SRV, 0xfd, WS, 0x80, T_ATP, atp(TRESP | EOM, 0, 1001, bytes([0x82, 7]) + struct.pack('>H', 0))))
    E(et(WS, 0x80, SRV, 0xfd, T_ATP, atp(TREL, 0, 1001, bytes([4, 0x81, 1, 0]))))
    # Conversation A2: workstation 0x80 <-> server session socket 0x82
    # Command: AFP GetSrvrParms, reply in three ATP packets (reassembled)
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TREQ | XO | 3, 0x07, 1002, bytes([2, 7, 0, 1]), bytes([16, 0]))))
    r = afp_getsrvrparms_reply()
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TRESP, 0, 1002, b'\0\0\0\0', r[:10])))
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TRESP, 1, 1002, b'\0\0\0\0', r[10:22])))
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TRESP | EOM, 2, 1002, b'\0\0\0\0', r[22:])))
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TREL, 0, 1002, bytes([2, 7, 0, 1]))))
    # Command: AFP CloseVol, error reply (AFPERR_PARAM -5019) without data
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TREQ | STS, 0x01, 1003, bytes([2, 7, 0, 2]), bytes([2, 0]) + struct.pack('>H', 1))))
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TRESP | EOM, 0, 1003, struct.pack('>i', -5019))))
    # Write: AFP Write, server asks for the data with WriteContinue
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TREQ, 0x01, 1004, bytes([6, 7, 0, 3]),
         bytes([33, 0]) + struct.pack('>HII', 5, 0, 16))))
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TREQ, 0x01, 1, bytes([7, 7, 0, 3]), struct.pack('>H', 578))))
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TRESP | EOM, 0, 1, b'\0\0\0\0', b'sixteen octets!!')))
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TRESP | EOM, 0, 1004, b'\0\0\0\0', struct.pack('>I', 16))))
    # Tickle, Attention (server to workstation), an undefined function
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TREQ, 0x01, 1005, bytes([5, 7, 0, 0]))))
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TRESP | EOM, 0, 1005, b'\0\0\0\0')))
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TREQ, 0x01, 2, bytes([8, 7]) + struct.pack('>H', 0x8005))))
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TRESP | EOM, 0, 2, b'\0\0\0\0')))
    # Tickle from the workstation with the transaction ID of the server's
    # Attention: same conversation and ID, other requester
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TREQ, 0x01, 2, bytes([5, 7, 0, 0]))))
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TREQ, 0x01, 1006, bytes([9, 7, 0, 0]), b'\x01\x02')))
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TRESP | EOM, 0, 1006, b'\0\0\0\0', b'\x03\x04')))
    # A reply to a transaction never requested: ASP rejects it, data
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TRESP | EOM, 0, 1999, b'\0\0\0\0', b'stray')))
    # A reply fragment (sequence 1) with no request: shown as a fragment
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TRESP | EOM, 1, 1998, b'\0\0\0\0', b'orphan')))
    # CloseSession
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TREQ | XO, 0x01, 1007, bytes([1, 7, 0, 0]))))
    E(et(SRV, 0x82, WS, 0x80, T_ATP, atp(TRESP | EOM, 0, 1007, b'\0\0\0\0')))
    E(et(WS, 0x80, SRV, 0x82, T_ATP, atp(TREL, 0, 1007, bytes([1, 7, 0, 0]))))

    # ---------------- EtherTalk: ADSP (DDP type 7)
    adsp = lambda cid, first, nxt, win, desc, data=b'': struct.pack('>HIIHB', cid, first, nxt, win, desc) + data
    A, B = (WS, 0x86), (SRV, 0x87)
    def ad(src, dst, pkt):
        E(et(src[0], src[1], dst[0], dst[1], T_ADSP, pkt))
    ad(A, B, adsp(0x1111, 0, 0, 4096, 0x81, struct.pack('>HHI', 0x0100, 0, 0)))    # Open Request
    ad(B, A, adsp(0x2222, 0, 0, 4096, 0x83, struct.pack('>HHI', 0x0100, 0x1111, 0)))  # Open Req+Ack
    ad(A, B, adsp(0x1111, 0, 0, 4096, 0x82, struct.pack('>HHI', 0x0100, 0x2222, 0)))  # Open Ack
    ad(A, B, adsp(0x1111, 0, 0, 4096, 0x00, b'hello adsp'))                         # Data
    ad(A, B, adsp(0x1111, 10, 0, 4096, 0x20, b'end of message'))                     # Data + EOM
    ad(B, A, adsp(0x2222, 0, 24, 4096, 0x40))                                        # Data + Ack, no data
    ad(B, A, adsp(0x2222, 0, 24, 4096, 0xc0))                                        # Probe/Ack
    ad(A, B, adsp(0x1111, 0, 0, 4096, 0x10, struct.pack('>H', 0x1000) + b'attn'))    # Attention
    ad(B, A, adsp(0x2222, 0, 1, 4096, 0x90))                                         # Attention Ack
    ad(A, B, adsp(0x1111, 24, 0, 4096, 0x86))                                        # Forward Reset
    ad(B, A, adsp(0x2222, 0, 24, 4096, 0x87))                                        # Forward Reset Ack
    ad(B, A, adsp(0x2222, 0, 20, 4096, 0x88))                                        # Retransmit Advice
    ad(A, B, adsp(0x1111, 24, 0, 4096, 0x8f))                                        # undefined control code
    ad(A, B, adsp(0x1111, 24, 0, 4096, 0x85))                                        # Close Advice
    ad((WS, 0x88), B, adsp(0x3333, 0, 0, 4096, 0x81, struct.pack('>HHI', 0x0100, 0, 0)))
    ad(B, (WS, 0x88), adsp(0x0000, 0, 0, 0, 0x84, struct.pack('>HHI', 0x0100, 0x3333, 0)))  # Open Deny

    # ---------------- EtherTalk: AEP, DDP ARP type, EIGRP, unknown type
    E(et(WS, 4, SRV, 4, T_AEP, b'\x01ping', hops=0))
    E(et(SRV, 4, WS, 4, T_AEP, b'\x02ping', hops=2, cksum=0xbeef))
    E(et(WS, 0x89, SRV, 0x89, T_ARP, b'\x00\x01\x02\x03'))
    eigrp = struct.pack('>BBHIIIHH', 2, 5, 0xfdf9, 0, 0, 0, 0, 1)
    E(et(RTR, 0x58, (0, 0xff), 0x58, T_EIGRP, eigrp, macs=(MAC_BCAST, MAC_RTR)))
    E(et(WS, 0x8a, SRV, 0x8a, 0x40, b'unknown ddp type'))

    # ---------------- gatewayed LLAP over Ethernet
    E(ether(MAC_BCAST, MAC_RTR, llap(0xff, 0x01, 0x01, ddp_short(2, 2, T_NBP, bytes([0x21, 3]) + nbp_tuple)),
            ethertype=0x809B))
    E(ether(MAC_BCAST, MAC_RTR, snap(0x000000, 0x809B,
            llap(0xff, 0x01, 0x02, ddp(0, 0xff, 1, 5, 1, 1, T_RTMPREQ, b'\x01')))))

    # ---------------- other link layers carrying long DDP
    nbp_l = bytes([0x21, 4]) + nbp_tuple
    cap.add(LT_NULL, struct.pack('<I', 16) + ddp(0, 0xff, 2, 100, 10, 2, T_NBP, nbp_l))
    cap.add(LT_PPP, b'\xff\x03\x00\x29' + ddp(100, 20, 4, 100, 10, 4, T_AEP, b'\x01ppp'))
    cap.add(LT_CHDLC, b'\x0f\x00\x80\x9b' + ddp(100, 20, 4, 100, 10, 4, T_AEP, b'\x01chdlc'))

    # ---------------- Exported PDUs naming AppleTalk dissectors
    # Reproducer (atalk_ddpshort_null.py): "ddp_short" without
    # its LLAP node data is rejected and shown as data.
    X(exported_pdu('ddp_short', struct.pack('>HBBB', 7, 2, 2, 2) + b'\x21\x01'))
    # Without DDP addresses ATP rejects the packet; ASP, ZIP and MacIP
    # over ATP reject a call without their ATP data.
    X(exported_pdu('atp', atp(TREQ, 0x01, 9, bytes([2, 1, 0, 1]), b'\x10\x00')))
    X(exported_pdu('asp', bytes([2, 1, 0, 1, 16, 0])))
    X(exported_pdu('zip.atp', bytes([7, 0, 0, 0])))
    X(exported_pdu('macip.atp', b'\0\0\0\0' + struct.pack('>i', 1)))
    # These work without lower layer data
    X(exported_pdu('llap', llap(0xff, 0x2a, 0x01, ddp_short(2, 253, T_NBP, bytes([0x21, 8]) + nbp_tuple))))
    X(exported_pdu('ddp', ddp(0, 0xff, 2, 100, 10, 2, T_NBP, bytes([0x21, 5]) + nbp_tuple)))
    X(exported_pdu('nbp', bytes([0x21, 6]) + nbp_tuple))
    X(exported_pdu('prap', bytes([0x2a, 5, 0, 0])))
    X(exported_pdu('adsp', adsp(0x4444, 0, 0, 4096, 0x00, b'exported')))
    X(exported_pdu('rtmp.request', b'\x02'))
    X(exported_pdu('rtmp.data', struct.pack('>HBB', 5, 8, 1) + b'\x00\x00\x82' + struct.pack('>HB', 5, 0)))
    X(exported_pdu('zip.ddp', bytes([1, 1]) + struct.pack('>H', 100)))
    return cap


def build_malformed():
    cap = Pcapng()
    L = lambda pkt: cap.add(LT_LOCALTALK, pkt)
    E = lambda pkt: cap.add(LT_ETH, pkt)
    # Reproducer frames from atalk_misc.py that throw with a
    # tree: short DDP with the reserved length bits set carrying an NBP
    # packet with count 1 and no tuple; MacIP ERROR reply whose message
    # is read as three more addresses.
    L(bytes([2, 1, 1]) + struct.pack('>HBBB', 0xFC00 | 7, 2, 2, 2) + b'\x21\x01' + b'\xee\xee')
    L(llap(1, 2, 0x02, ddp(1, 1, 0x80, 1, 2, 72, T_ATP, atp(0x90, 0, 7, b'\0\x01\0\0',
                                                          struct.pack('>i', -1) + b'\0' * 20 + b'no address\0'))))
    # RTMP response (net, node length, node only): the dissector peeks at
    # a tuple past the end and throws when a tree is built
    E(et(RTR, 1, WS, 253, T_RTMPDATA, struct.pack('>HBB', 100, 8, 1)))
    # Invalid DDP lengths (expert info), long and short
    L(llap(2, 1, 0x02, ddp(0, 2, 4, 0, 1, 4, T_AEP, b'\x01abc', length=5)))
    L(llap(2, 1, 0x02, ddp(0, 2, 4, 0, 1, 4, T_AEP, b'\x01abc', length=300)))
    L(llap(2, 1, 0x01, ddp_short(4, 4, T_AEP, b'\x01abc', length=3)))
    L(llap(2, 1, 0x01, ddp_short(4, 4, T_AEP, b'\x01abc', length=300)))
    # Truncated headers
    L(bytes([2, 1]))
    L(llap(2, 1, 0x01, b'\x00'))
    L(llap(2, 1, 0x02, b'\x00\x0d\x00'))
    L(llap(2, 1, 0x01, ddp_short(2, 2, T_ATP, b'\x40\x01')))                 # ATP
    L(llap(2, 1, 0x01, ddp_short(1, 1, T_RTMPREQ, b'')))                     # RTMP request
    L(llap(2, 1, 0x01, ddp_short(1, 1, T_RTMPDATA, b'\x00\x05\x08')))        # RTMP data
    L(llap(2, 1, 0x01, ddp_short(1, 1, T_RTMPDATA, struct.pack('>HBB', 5, 8, 1) + b'\x00\x05\x81\x00')))
    L(llap(2, 1, 0x01, ddp_short(2, 2, T_NBP, b'\x23\x01' + b'\x00\x05\x01\x02\x00\x05ab')))   # NBP
    L(llap(2, 1, 0x01, ddp_short(2, 2, T_NBP, b'')))
    L(llap(2, 1, 0x01, ddp_short(6, 6, T_ZIP, b'')))
    for z in (b'\x01\x05\x00\x01', b'\x02\x02\x00\x01\x05ab', b'\x05\x00\x00', b'\x06\x80\x00\x01\x00\x02\x09ab',
              b'\x07\x00\x00\x00\x00\x00\x02ab', b'\x08\x01\x00\x01\x20ab'):
        L(llap(2, 1, 0x01, ddp_short(6, 6, T_ZIP, z)))
    # Reproducer from atalk_misc.py: ZIP GetNetInfo reply cut short
    L(llap(2, 1, 0x02, ddp(1, 2, 6, 1, 1, 6, T_ZIP, bytes([8, 2, 0, 1, 3]) + b'abc' + b'\0\x02\xff')))
    L(llap(2, 1, 0x01, ddp_short(7, 7, T_ADSP, b'\x00\x01\x00\x00')))      # ADSP
    L(llap(2, 1, 0x01, ddp_short(7, 7, T_ADSP, struct.pack('>HIIHB', 1, 0, 0, 0, 0x10) + b'\x00')))
    L(llap(2, 1, 0x01, ddp_short(T_MACIP, T_MACIP, T_MACIP, b'\x45\x00')))  # MacIP truncated IP
    # ATP / ASP / PAP / ZIP-ATP / MacIP-ATP truncations
    L(llap(2, 1, 0x02, ddp(1, 2, 0x81, 1, 1, 0x80, T_ATP, atp(TREQ, 1, 50, bytes([2, 1, 0, 1]), b''))))
    L(llap(2, 1, 0x02, ddp(1, 2, 0x81, 1, 1, 0x80, T_ATP, atp(TREQ, 1, 51, bytes([4, 1, 0, 1]))[:6])))
    L(llap(1, 2, 0x02, ddp(1, 1, 0x80, 1, 2, 0x81, T_ATP, atp(TRESP | EOM, 0, 50, b'\0\0'[:2] + b'\0\0')[:6])))
    L(llap(2, 1, 0x02, ddp(1, 2, 0x83, 1, 1, 0x82, T_ATP, atp(TREQ, 1, 60, bytes([0x2a, 2, 0, 0]), b'\x00\x08'))))
    L(llap(2, 1, 0x02, ddp(1, 2, 0x83, 1, 1, 0x82, T_ATP, atp(TREQ, 1, 61, bytes([0x2a, 9, 0, 0]), b'\0\0\0\0\x10ab'))))
    L(llap(2, 1, 0x02, ddp(1, 2, 6, 1, 1, 0x84, T_ATP, atp(TREQ, 1, 70, bytes([8, 0, 0, 1]))[:5])))
    L(llap(1, 2, 0x02, ddp(1, 1, 0x84, 1, 2, 6, T_ATP, atp(TRESP | EOM, 0, 70, bytes([1, 0, 0, 5]), b'\x04Zone'))))
    L(llap(1, 2, 0x02, ddp(1, 1, 0x85, 1, 2, 72, T_ATP, atp(TRESP | EOM, 0, 71, b'\0\x01\0\0', struct.pack('>i', 1) + b'\0' * 6))))
    L(llap(2, 1, 0x02, ddp(1, 2, 72, 1, 1, 0x85, T_ATP, atp(TREQ, 1, 72, b'\0\0\0\0', b'\0\0'))))
    # ASP GetStatus reply too short for the AFP status block
    L(llap(2, 1, 0x02, ddp(1, 2, 0xfd, 1, 1, 0x86, T_ATP, atp(TREQ, 1, 80, bytes([3, 0, 0, 0])))))
    L(llap(1, 2, 0x02, ddp(1, 1, 0x86, 1, 2, 0xfd, T_ATP, atp(TRESP | EOM, 0, 80, b'\0\0\0\0', b'\0\x0a'))))
    # From atalk_twopass.py: replies before their requests and
    # a reply in a conversation no request has been seen in. These decode
    # differently with -2 (the request is known in the second pass).
    def tp(snode, ss, dnode, sd, payload):
        return llap(dnode, snode, 0x02, ddp(1, dnode, sd, 1, snode, ss, T_ATP, payload))
    L(tp(1, 0x90, 2, 0x91, atp(0x40, 0x07, 100, bytes([2, 5, 0, 1]), bytes([0x12, 0, 0, 0]))))
    L(tp(2, 0x91, 1, 0x90, atp(0x80, 0, 100, b'\0\0\0\0', b'X' * 20)))
    L(tp(2, 0x91, 1, 0x90, atp(0x80, 1, 100, b'\0\0\0\0', b'Y' * 20)))
    L(tp(2, 0x91, 1, 0x90, atp(0x90, 2, 100, b'\0\0\0\0', b'Z' * 20)))
    L(tp(2, 0x91, 1, 0x90, atp(0x80, 0, 200, b'\0\0\0\0', b'Q' * 10)))
    L(tp(1, 0x90, 2, 0x91, atp(0x40, 0x03, 200, bytes([3, 0, 0, 0]))))
    L(tp(2, 0x91, 1, 0x90, atp(0x90, 1, 200, b'\0\0\0\0', b'R' * 10)))
    L(tp(2, 0x92, 1, 0x93, atp(0x90, 0, 300, b'\0\0\0\0', b'S' * 8)))
    L(tp(1, 0x93, 2, 0x92, atp(0x40, 0x01, 300, bytes([1, 3, 0, 0]))))
    L(tp(1, 0x94, 2, 6, atp(0x40, 0x01, 400, bytes([8, 0, 0, 1]))))
    L(tp(2, 6, 1, 0x94, atp(0x90, 0, 400, bytes([1, 0, 0, 2]), b'\x04Zone\x05Zone2')))
    # ZIP over ATP reply with no request: rejected after setting columns
    L(tp(2, 6, 1, 0x95, atp(0x90, 0, 401, bytes([1, 0, 0, 1]), b'\x04Zone')))
    # Overlapping ATP reply fragments with different data
    L(tp(1, 0x96, 2, 0x97, atp(0x40, 0x07, 500, bytes([2, 5, 0, 1]), bytes([16, 0]))))
    L(tp(2, 0x97, 1, 0x96, atp(0x80, 1, 500, b'\0\0\0\0', b'A' * 8)))
    L(tp(2, 0x97, 1, 0x96, atp(0x80, 1, 500, b'\0\0\0\0', b'B' * 8)))
    L(tp(2, 0x97, 1, 0x96, atp(0x80, 0, 500, b'\0\0\0\0', b'C' * 8)))
    L(tp(2, 0x97, 1, 0x96, atp(0x90, 2, 500, b'\0\0\0\0', b'D' * 8)))
    E(ethertalk(MAC_SRV, MAC_WS, ddp(100, 20, 4, 100, 10, 4, T_AEP, b'\x01x', length=1023)))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main().write(os.path.join(out, 'atalk-coverage.pcapng'))
    build_malformed().write(os.path.join(out, 'atalk-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
