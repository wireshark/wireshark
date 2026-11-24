#!/usr/bin/env python3
# Generates test/captures/bthfp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth HFP dissector
(packet-bthfp.c).

HFP AT commands and responses run over RFCOMM. The captures are Bluetooth
HCI H4 with pseudo-header (link type 201): HCI Connection Complete events,
L2CAP connections to SDP (PSM 1) and RFCOMM (PSM 3), an SDP exchange that
announces an HFP service on an RFCOMM channel, then RFCOMM UIH frames with
the AT data. The SDP record tells both RFCOMM (which dissector) and HFP
(which side is the Audio Gateway) what the channel is, so the default
preferences are enough. The helpers follow
bthfp_rfcomm_lib.py. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkbthfp.py <output directory>

Writes:
  bthfp-coverage.pcap            the main capture (frame ranges in README)
  bthfp-coverage-malformed.pcap  AT data cut short by the snapshot length
  bthfp-coverage-exported.pcap   HFP in Exported PDU frames (no RFCOMM
                                 below), for the coverage run only
"""

import os
import struct
import sys

SENT, RECV = 0, 1


# ---------------------------------------------------------------- HCI/L2CAP

def h4(direction, ptype, body):
    return struct.pack('>I', direction) + bytes([ptype]) + body


def fcs(data):
    crc = 0xff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xe0 if crc & 1 else crc >> 1
    return 0xff - crc


def seq(*items):
    b = b''.join(items)
    return bytes([0x35, len(b)]) + b


def u8(v): return bytes([0x08, v])
def u16(v): return b'\x09' + struct.pack('>H', v)
def u32(v): return b'\x0a' + struct.pack('>I', v)
def uuid16(v): return b'\x19' + struct.pack('>H', v)


class Conn:
    """One ACL connection with an SDP and an RFCOMM L2CAP channel.

    remote_sdp: the remote device's SDP record is read by us (the local side
    connects to SDP and RFCOMM). Otherwise the remote reads our record and
    connects to us."""

    def __init__(self, cap, handle, bdaddr, svc_uuid, channel, remote_sdp,
                 cids):
        self.cap = cap
        self.handle = handle
        self.bdaddr = bdaddr
        self.svc_uuid = svc_uuid
        self.channel = channel
        self.remote_sdp = remote_sdp
        self.sdp_local, self.sdp_remote, self.rf_local, self.rf_remote = cids
        self.dlci = channel << 1
        # The side that opens the L2CAP channels is the RFCOMM initiator
        self.init_dir = SENT if remote_sdp else RECV

    def acl(self, direction, cid, payload, caplen=None):
        l2 = struct.pack('<HH', len(payload), cid) + payload
        body = struct.pack('<HH', (self.handle & 0x0fff) | 0x2000, len(l2)) + l2
        self.cap.add(h4(direction, 2, body), caplen)

    def send(self, direction, local_cid, remote_cid, payload, caplen=None):
        # Data we send goes to the remote CID, data we receive to ours
        self.acl(direction, remote_cid if direction == SENT else local_cid,
                 payload, caplen)

    def connect(self):
        ev = struct.pack('<BH', 0, self.handle) + self.bdaddr[::-1] + b'\x01\x00'
        self.cap.add(h4(RECV, 4, bytes([0x03, len(ev)]) + ev))

    def l2_connect(self, psm, local_cid, remote_cid, ident):
        d = self.init_dir
        other = RECV if d == SENT else SENT
        req_scid = local_cid if d == SENT else remote_cid
        rsp_dcid = remote_cid if d == SENT else local_cid
        req = struct.pack('<BBHHH', 0x02, ident, 4, psm, req_scid)
        rsp = struct.pack('<BBHHHHH', 0x03, ident, 8, rsp_dcid, req_scid, 0, 0)
        self.acl(d, 1, req)
        self.acl(other, 1, rsp)

    def sdp(self):
        self.l2_connect(1, self.sdp_local, self.sdp_remote, 1)
        d = self.init_dir
        other = RECV if d == SENT else SENT
        params = seq(uuid16(self.svc_uuid)) + struct.pack('>H', 0xffff) + \
            seq(u32(0x0000ffff)) + b'\x00'
        req = struct.pack('>BHH', 0x06, 1, len(params)) + params
        self.send(d, self.sdp_local, self.sdp_remote, req)
        generic = 0x111F if self.svc_uuid == 0x111F else 0x111E
        rec = seq(u16(0x0001), seq(uuid16(self.svc_uuid), uuid16(0x1203)),
                  u16(0x0004), seq(seq(uuid16(0x0100)),
                                   seq(uuid16(0x0003), u8(self.channel))),
                  u16(0x0009), seq(seq(uuid16(generic), u16(0x0108))))
        lists = seq(rec)
        params = struct.pack('>H', len(lists)) + lists + b'\x00'
        rsp = struct.pack('>BHH', 0x07, 1, len(params)) + params
        self.send(other, self.sdp_local, self.sdp_remote, rsp)

    def rfcomm(self, direction, dlci, ctrl, payload=b''):
        addr = (dlci << 2) | ((1 if direction == self.init_dir else 0) << 1) | 1
        if len(payload) < 128:
            ln = bytes([(len(payload) << 1) | 1])
        else:
            ln = struct.pack('<H', len(payload) << 1)
        hdr = bytes([addr, ctrl]) + ln
        f = fcs(hdr[:2]) if (ctrl & 0xef) == 0xef else fcs(hdr)
        return hdr + payload + bytes([f])

    def rf_send(self, direction, frame, caplen=None):
        self.send(direction, self.rf_local, self.rf_remote, frame, caplen)

    def rfcomm_setup(self):
        self.l2_connect(3, self.rf_local, self.rf_remote, 2)
        d = self.init_dir
        other = RECV if d == SENT else SENT
        self.rf_send(d, self.rfcomm(d, 0, 0x3f))
        self.rf_send(other, self.rfcomm(d, 0, 0x73))
        self.open_dlci(self.dlci)

    def open_dlci(self, dlci):
        d = self.init_dir
        other = RECV if d == SENT else SENT
        self.rf_send(d, self.rfcomm(d, dlci, 0x3f))
        self.rf_send(other, self.rfcomm(d, dlci, 0x73))

    def setup(self):
        self.connect()
        self.sdp()
        self.rfcomm_setup()

    def at(self, direction, data, dlci=None, caplen=None):
        if dlci is None:
            dlci = self.dlci
        frame = self.rfcomm(direction, dlci, 0xef, data)
        if caplen is not None:
            caplen += 4 + 4 + 5 + (len(frame) - len(data) - 1)
        self.rf_send(direction, frame, caplen)


class Capture:
    def __init__(self):
        self.frames = []
        self.marks = []

    def add(self, data, caplen=None):
        self.frames.append((data, caplen))

    def mark(self, text):
        self.marks.append((len(self.frames) + 1, text))

    def write(self, path, linktype=201):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144,
                                linktype))
            for i, (data, caplen) in enumerate(self.frames):
                usec = i * 10000
                cl = len(data) if caplen is None else caplen
                f.write(struct.pack('<IIII', 1700000000 + usec // 1000000,
                                    usec % 1000000, cl, len(data)) + data[:cl])
        for num, text in self.marks:
            print('%s: %4d %s' % (os.path.basename(path), num, text))


def bdaddr(n):
    return bytes.fromhex('0200000000%02x' % n)


# ---------------------------------------------------------------- main capture

def hs_ag(c, pairs):
    """Commands from the HS side and responses from the AG side; c.hs is the
    direction of the headset."""
    for d, data in pairs:
        c.at(c.hs if d == 'hs' else c.ag, data)


def main_capture():
    cap = Capture()
    # Connection 1: we read the remote's HFP AG record (0x111F): we are the
    # hands-free unit (HS), the remote is the AG.
    c1 = Conn(cap, 1, bdaddr(1), 0x111F, 3, True, (0x40, 0x41, 0x42, 0x43))
    c1.hs, c1.ag = SENT, RECV
    cap.mark('connection 1: remote HFP AG record, RFCOMM channel 3')
    c1.setup()

    cap.mark('service level connection')
    hs_ag(c1, [
        ('hs', b'AT+BRSF=959\r'),
        ('ag', b'\r\n+BRSF: 4095\r\n'),
        ('ag', b'\r\nOK\r\n'),
        ('hs', b'AT+BAC=1,2\r'),
        ('ag', b'\r\nOK\r\n'),
        ('hs', b'AT+CIND=?\r'),
        ('ag', b'\r\n+CIND: ("service",(0,1)),("call",(0,1)),("callsetup",(0-3)),'
               b'("callheld",(0-2)),("signal",(0-5)),("roam",(0,1)),("battchg",(0-5))\r\n'),
        ('ag', b'\r\nOK\r\n'),
        ('hs', b'AT+CIND?\r'),
        ('ag', b'\r\n+CIND: 1,0,0,0,5,0,5\r\n\r\nOK\r\n'),
        ('hs', b'AT+CMER=3,0,0,1\r'),
        ('ag', b'\r\nOK\r\n'),
        ('hs', b'AT+CHLD=?\r'),
        ('ag', b'\r\n+CHLD: (0,1,1x,2,2x,3,4)\r\n'),
        ('ag', b'\r\nOK\r\n'),
        ('hs', b'AT+BIND=1,2\r'),
        ('hs', b'AT+BIND=?\r'),
        ('ag', b'\r\n+BIND: (1,2)\r\n'),
        ('hs', b'AT+BIND?\r'),
        ('ag', b'\r\n+BIND: 1,1\r\n\r\n+BIND: 2,0\r\n\r\nOK\r\n'),
    ])

    cap.mark('HS commands with their parameters, AG responses')
    hs_ag(c1, [
        ('hs', b'AT+CMEE=1\r'),
        ('hs', b'AT+CLIP=1\r'),
        ('hs', b'AT+CLIP=1,1\r'),
        ('hs', b'AT+CLIP?\r'),
        ('hs', b'AT+CLIP=?\r'),
        ('hs', b'AT+CCWA=1\r'),
        ('hs', b'AT+CCWA=1,2,1\r'),
        ('hs', b'AT+CCWA?\r'),
        ('hs', b'AT+CCWA=?\r'),
        ('hs', b'AT+NREC=0\r'),
        ('hs', b'AT+VGS=7\r'),
        ('hs', b'AT+VGM=8\r'),
        ('hs', b'AT+BVRA=1\r'),
        ('ag', b'\r\n+BVRA: 0\r\n'),
        ('hs', b'AT+BCC\r'),
        ('ag', b'\r\n+BCS: 2\r\n'),
        ('hs', b'AT+BCS=2\r'),
        ('hs', b'AT+BIA=1,1,0,0,1,1,0\r'),
        ('hs', b'AT+COPS=3,0\r'),
        ('hs', b'AT+COPS?\r'),
        ('ag', b'\r\n+COPS: 0,0,"Synthetic Net",2\r\n'),
        ('hs', b'AT+CNUM\r'),
        ('ag', b'\r\n+CNUM: ,"5551234",129,,4\r\n'),
        ('ag', b'\r\n+CNUM: ,"+15551234",145,,4,1\r\n'),
        ('hs', b'AT+BTRH?\r'),
        ('hs', b'AT+BTRH=0\r'),
        ('ag', b'\r\n+BTRH: 0\r\n'),
        ('hs', b'AT+BINP=1\r'),
        ('ag', b'\r\n+BINP: "5559876"\r\n'),
        ('hs', b'AT+BLDN\r'),
        ('ag', b'\r\n+BSIR: 1\r\n'),
        ('ag', b'\r\n+BSIR: 0\r\n'),
        ('ag', b'\r\n+VGS: 9\r\n'),
        ('ag', b'\r\n+VGM: 10\r\n'),
        ('hs', b'AT+BIEV=2,90\r'),
        ('hs', b'AT+BIEV=1,0\r'),
        ('hs', b'AT+VTS=5\r'),
        ('hs', b'AT+VTS=#,300\r'),
        ('hs', b'AT+VTS=?\r'),
        ('hs', b'AT+CHUP\r'),
        ('hs', b'AT+CHUP=?\r'),
        ('hs', b'AT+CLCC\r'),
        ('hs', b'AT+CLCC=?\r'),
        ('ag', b'\r\n+CLCC: 1,1,4,0,0,"5551234",129,"Bob",1\r\n'),
        ('ag', b'\r\n+CLCC: 2,0,1,0,1,"5550000",161\r\n'),
        ('hs', b'AT+CHLD=1\r'),
        ('hs', b'AT+CHLD=1x\r'),
        ('hs', b'AT+CHLD=2x\r'),
        ('hs', b'AT+CHLD=3x\r'),
        ('hs', b'AT+CMER?\r'),
        ('hs', b'AT+CMER=?\r'),
        ('ag', b'\r\n+CME ERROR: 30\r\n'),
        ('ag', b'\r\nERROR\r\n'),
    ])

    cap.mark('incoming call: RING, +CLIP, +CCWA, +CIEV, answer, dial')
    hs_ag(c1, [
        ('ag', b'\r\n+CIEV: 3,1\r\n'),
        ('ag', b'\r\nRING\r\n'),
        ('ag', b'\r\n+CLIP: "5551234",129\r\n'),
        ('ag', b'\r\n+CLIP: "555,1234",145,"",128,"Alice",0\r\n'),
        ('hs', b'ATA\r'),
        ('ag', b'\r\n+CIEV: 2,1\r\n\r\n+CIEV: 3,0\r\n'),
        ('ag', b'\r\n+CCWA: "5550000",129,1\r\n'),
        ('ag', b'\r\n+CCWA: "5550000",145,1,"Carol",0,"12",128,1\r\n'),
        ('hs', b'ATD5551234;\r'),
        ('ag', b'\r\nOK\r\n'),
    ])

    cap.mark('Apple extensions')
    hs_ag(c1, [
        ('hs', b'AT+XAPL=05AC-1234-0100,10\r'),
        ('hs', b'AT+XAPL=ABCD-EF01-0200,31\r'),
        ('ag', b'\r\n+XAPL=iPhone,6\r\n'),
        ('ag', b'\r\n+XAPL: iPhone,30\r\n'),
        ('ag', b'\r\n+XAPL: iPhone,63\r\n'),
        ('hs', b'AT+IPHONEACCEV=2,1,5,2,0\r'),
        ('hs', b'AT+APLSIRI?\r'),
        ('ag', b'\r\n+APLSIRI: 1\r\n'),
        ('ag', b'\r\n+APLSIRI: 2\r\n'),
        ('hs', b'AT+APLEFM=1\r'),
        ('ag', b'\r\n+APLEFM: 0\r\n'),
    ])

    cap.mark('out-of-range values (warnings)')
    hs_ag(c1, [
        ('hs', b'AT+BRSF=4095\r'),
        ('ag', b'\r\n+BRSF: 8191\r\n'),
        ('hs', b'AT+VGS=16\r'),
        ('hs', b'AT+VGM=20\r'),
        ('ag', b'\r\n+VGS: 99\r\n'),
        ('hs', b'AT+NREC=1\r'),
        ('hs', b'AT+BVRA=2\r'),
        ('hs', b'AT+BCS=3\r'),
        ('hs', b'AT+BAC=1,2,3\r'),
        ('ag', b'\r\n+BSIR: 2\r\n'),
        ('hs', b'AT+BTRH=1\r'),
        ('hs', b'AT+BINP=2\r'),
        ('hs', b'AT+BIA=1,2\r'),
        ('hs', b'AT+BIEV=3,1\r'),
        ('hs', b'AT+BIEV=70000,1\r'),
        ('hs', b'AT+CMER=2,1,1,2,1\r'),
        ('hs', b'AT+CHLD=5x\r'),
        ('hs', b'AT+CHLD=12\r'),
        ('ag', b'\r\n+CIEV: 25,1\r\n'),
        ('ag', b'\r\n+CIEV: 0,1\r\n'),
        ('hs', b'AT+VTS=12\r'),
        ('ag', b'\r\n+CLIP: "5551234",100\r\n'),
        ('ag', b'\r\n+CCWA: "5551234",200,1\r\n'),
        ('ag', b'\r\n+CLCC: 1,0,0,0,0,"5551234",127\r\n'),
        ('ag', b'\r\n+CNUM: "x","5551234",99,9600,9,2\r\n'),
        ('ag', b'\r\n+APLSIRI: 9\r\n'),
        ('hs', b'AT+APLEFM=2\r'),
        ('hs', b'AT+IPHONEACCEV=1,3,1\r'),
        ('hs', b'AT+XAPL=0001-02,1\r'),
    ])

    cap.mark('extra parameters (unknown parameter), wrong direction (invalid usage)')
    hs_ag(c1, [
        ('hs', b'AT+BRSF=1,2\r'),
        ('hs', b'AT+VGS=1,2\r'),
        ('hs', b'AT+VGM=1,2\r'),
        ('hs', b'AT+NREC=0,0\r'),
        ('hs', b'AT+BVRA=0,0\r'),
        ('hs', b'AT+BCS=1,1\r'),
        ('hs', b'AT+BIND=' + b','.join([b'1'] * 21) + b'\r'),
        ('hs', b'AT+APLEFM=1,1\r'),
        ('ag', b'\r\n+APLSIRI: 1,1\r\n'),
        ('hs', b'AT+XAPL=05AC-1234-0100,10,1\r'),
        ('hs', b'AT+BIEV=1,1,1\r'),
        ('ag', b'\r\n+BSIR: 1,1\r\n'),
        ('hs', b'AT+BTRH=0,0\r'),
        ('hs', b'AT+BINP=1,1\r'),
        ('hs', b'AT+BIA=' + b','.join([b'1'] * 21) + b'\r'),
        ('ag', b'\r\n+CIND: ' + b','.join([b'0'] * 21) + b'\r\n'),
        ('hs', b'AT+CCWA=1,1,1,1\r'),
        ('ag', b'\r\n+CCWA: "1",129,1,"a",0,"s",128,1,9\r\n'),
        ('hs', b'AT+CMER=3,0,0,1,0,9\r'),
        ('ag', b'\r\n+CMER: 3,0,0,1\r\n'),
        ('hs', b'AT+CLIP=1,1,1\r'),
        ('ag', b'\r\n+CLIP: "1",129,"",128,"a",0,7\r\n'),
        ('hs', b'AT+CMEE=1,1\r'),
        ('ag', b'\r\n+COPS: 0,0,"op",2,1\r\n'),
        ('ag', b'\r\n+CLCC: 1,0,0,0,0,"1",129,"a",1,9\r\n'),
        ('ag', b'\r\n+CME ERROR: 3,1\r\n'),
        ('ag', b'\r\n+CNUM: ,"1",129,,4,1,9\r\n'),
        ('hs', b'AT+VTS=1,2,3\r'),
        ('ag', b'\r\n+CIEV: 1,1,1\r\n'),
        ('ag', b'\r\n+CIEV:\r2\r\n'),
        ('hs', b'AT+BSIR=1\r'),
        ('hs', b'AT+CIEV=1,1\r'),
        ('hs', b'AT+CNUM=1\r'),
        ('hs', b'AT+CME ERROR=1\r'),
        ('hs', b'AT+OK\r'),
        ('hs', b'AT+CIND=1\r'),
        ('ag', b'\r\n+VTS: 1\r\n'),
        ('ag', b'\r\n+BCC\r\n'),
        ('ag', b'\r\nA\r\n'),
        ('ag', b'\r\nD123\r\n'),
        ('ag', b'\r\n+BLDN\r\n'),
        ('hs', b'ATD\r'),
    ])

    cap.mark('every command with a type its role does not use (invalid usage)')
    hs_ag(c1, [(d, b'AT' + cmd + b'\r' if d == 'hs' else b'\r\n' + cmd + b'\r\n')
               for d, cmd in [
        ('hs', b'+XAPL?'), ('hs', b'+IPHONEACCEV?'), ('hs', b'+APLSIRI=1'),
        ('hs', b'+APLEFM?'), ('hs', b'+BIEV?'), ('ag', b'+BIND=1'),
        ('hs', b'+BAC?'), ('hs', b'+BCS?'), ('hs', b'+BCC=1'), ('hs', b'+BIA?'),
        ('hs', b'+BINP?'), ('hs', b'+BLDN?'), ('hs', b'+BVRA?'), ('hs', b'+BRSF?'),
        ('hs', b'+NREC?'), ('hs', b'+VGS?'), ('hs', b'+VGM?'), ('hs', b'+BTRH=?'),
        ('hs', b'OK'), ('ag', b'+CCWA=1'), ('hs', b'+CHLD?'), ('hs', b'+CHUP?'),
        ('hs', b'+CLCC?'), ('hs', b'+CMER'), ('hs', b'+COPS=?'), ('hs', b'+CMEE?'),
        ('hs', b'+CLIP'), ('hs', b'+VTS?'), ('ag', b'+CNUM?'), ('ag', b'+CIND=1'),
        # A response from the HS side: the parameter dissectors refuse it
        ('hs', b'+BRSF: 1'), ('hs', b'+VGS: 1'), ('hs', b'+VGM: 1'),
        ('hs', b'+NREC: 1'), ('ag', b'+NREC: 0'), ('hs', b'+BVRA: 1'), ('hs', b'+BCS: 1'),
        ('hs', b'+BAC: 1'), ('hs', b'+BTRH: 1'), ('hs', b'+BINP: 1'),
        ('hs', b'+CLIP: 1'), ('hs', b'+CMEE: 1'), ('hs', b'+COPS: 1'),
        ('hs', b'+CLCC: 1'), ('hs', b'+CMER: 1'),
        # Commands without parameters given one
        ('hs', b'+CHUP=1'), ('hs', b'+BLDN=1'), ('ag', b'OK: 1'),
        ('ag', b'RING: 1'), ('ag', b'ERROR: 1'), ('hs', b'A=1'),
    ]])

    cap.mark('unknown commands, syntax corner cases')
    hs_ag(c1, [
        ('hs', b'AT+CKPD=200\r'),
        ('ag', b'\r\n+FOO: 1,2\r\n'),
        ('hs', b'AT\r'),
        ('hs', b'at+vgs=3\r'),
        ('hs', b'xxAT+VGS=4\r'),
        ('hs', b'no command here\r'),
        ('hs', b'AT+VGS= \t5\r'),
        ('hs', b'AT+BRSF=\r'),
        ('hs', b'AT=?\r'),
        ('hs', b'AT+X=((1,2),3),"a,b",(4)\r'),
        ('ag', b'\r\n\r\n'),
        ('ag', b'\r\n:\r\n'),
        ('ag', b'\r\n=?\r\n'),
        ('ag', b'\r\n+CIND: \r\n'),
    ])

    cap.mark("several ';' separated HS commands on one line")
    hs_ag(c1, [
        ('hs', b'AT+VGS=7;+VGM=3;+NREC=0;+BVRA=1\r'),
        ('hs', b'AT+CKPD=1;+CLIP=1;;\r'),
        ('ag', b'\r\nOK\r\n\r\nRING\r\n'),
    ])

    cap.mark('fragments: commands and responses split over frames')
    hs_ag(c1, [
        ('hs', b'AT+CI'),
        ('hs', b'ND=?\r'),
        ('ag', b'\r\n+CIND: ("call",(0,1)),'),
        ('ag', b'("callsetup",(0-3))\r\n'),
        ('hs', b'AT'),
        ('hs', b'+CKPD'),
        ('hs', b'=200\r'),
        ('ag', b'\r\n+VG'),
        ('ag', b'S: 12\r\n'),
        ('hs', b'AT+VGS=1\rAT+V'),
        ('hs', b'GM=2\r'),
        ('ag', b'\r\n+CIEV: 1,1\r\n\r\n+CI'),
        ('ag', b'EV: 2,0\r\n'),
        ('ag', b'OK'),
        ('ag', b'\r\nRING\r\n'),
    ])
    cap.mark('fragments interleaved with the other direction')
    hs_ag(c1, [
        ('hs', b'AT+CL'),
        ('ag', b'\r\n+CIEV: 5,'),
        ('hs', b'CC\r'),
        ('ag', b'4\r\n'),
    ])

    cap.mark('non-ASCII octets (the highbyte reproducer)')
    hs_ag(c1, [
        ('hs', b'AT+VGS=1\xe9\r'),
        ('hs', b'AT+VGM=2\r'),
        ('ag', b'\r\n+CIEV: 2,\xe9\r\n'),
        ('ag', b'\r\nOK\r\n'),
    ])

    cap.mark('message longer than 64 KiB: restarted')
    c1.at(c1.hs, b'AT+CKPD=' + b'A' * 29992)
    c1.at(c1.hs, b'A' * 30000)
    c1.at(c1.hs, b'AT+CKPD=' + b'B' * 5992)
    c1.at(c1.hs, b'B\r')

    # Connection 2: the remote's hands-free record (0x111E): we are the AG.
    c2 = Conn(cap, 2, bdaddr(2), 0x111E, 5, True, (0x50, 0x51, 0x52, 0x53))
    c2.hs, c2.ag = RECV, SENT
    cap.mark('connection 2: remote HFP HF record, RFCOMM channel 5')
    c2.setup()
    hs_ag(c2, [
        ('hs', b'AT+BRSF=63\r'),
        ('ag', b'\r\n+BRSF: 871\r\n'),
        ('ag', b'\r\nOK\r\n'),
        ('hs', b'AT+VG'),
        ('hs', b'S=5\r'),
        ('ag', b'\r\n+VGM: 3\r\n'),
    ])

    # Connection 3: the remote reads our AG record and connects to us.
    c3 = Conn(cap, 3, bdaddr(3), 0x111F, 7, False, (0x60, 0x61, 0x62, 0x63))
    c3.hs, c3.ag = RECV, SENT
    cap.mark('connection 3: local HFP AG record, RFCOMM channel 7')
    c3.setup()
    hs_ag(c3, [
        ('hs', b'AT+BRSF=63\r'),
        ('ag', b'\r\n+BRSF: 871\r\n'),
        ('ag', b'\r\nOK\r\n'),
    ])

    # Connection 4: the remote reads our hands-free record: we are the HS.
    c4 = Conn(cap, 4, bdaddr(4), 0x111E, 9, False, (0x70, 0x71, 0x72, 0x73))
    c4.hs, c4.ag = SENT, RECV
    cap.mark('connection 4: local HFP HF record, RFCOMM channel 9')
    c4.setup()
    hs_ag(c4, [
        ('hs', b'AT+BRSF=63\r'),
        ('ag', b'\r\n+BRSF: 871\r\n'),
        ('ag', b'\r\nOK\r\n'),
    ])
    return cap


# ---------------------------------------------------------------- malformed

def malformed_capture():
    cap = Capture()
    c1 = Conn(cap, 1, bdaddr(1), 0x111F, 3, True, (0x40, 0x41, 0x42, 0x43))
    c1.setup()
    cap.mark('complete HS command and AG response cut by the snapshot length')
    c1.at(SENT, b'AT+VGS=7;+VGM=3\r', caplen=6)
    c1.at(RECV, b'\r\n+CIEV: 2,1\r\n', caplen=4)
    cap.mark('fragments cut by the snapshot length')
    c1.at(SENT, b'AT+VGS', caplen=3)
    c1.at(SENT, b'=1\r')
    return cap


# ---------------------------------------------------------------- exported PDU

def exported_capture():
    def tag(t, v):
        return struct.pack('>HH', t, len(v)) + v

    def pdu(payload, direction=None):
        b = tag(12, b'bthfp')
        if direction is not None:
            b += tag(35, struct.pack('>i', direction))
        return b + struct.pack('>HH', 0, 0) + payload

    cap = Capture()
    cap.mark('HS command (Received), AG response (Sent), no direction')
    cap.add(pdu(b'AT+VGS=7\r', 1))
    cap.add(pdu(b'\r\n+VGS: 7\r\n', 0))
    cap.add(pdu(b'AT+VGS=7\r'))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'bthfp-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'bthfp-coverage-malformed.pcap'))
    exported_capture().write(os.path.join(out, 'bthfp-coverage-exported.pcap'), 252)


if __name__ == '__main__':
    main()
