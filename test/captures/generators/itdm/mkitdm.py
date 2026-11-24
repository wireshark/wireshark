#!/usr/bin/env python3
# Generates test/captures/itdm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the I-TDM (Internal TDM)
dissector (packet-itdm.c, PICMG SFP.0/SFP.1).

I-TDM is carried over MPLS; the dissector is registered on the MPLS label
0x99887 (the "Flow Bundle ID", the itdm.mpls_label preference), so every
frame is Ethernet (ethertype 0x8847) + one MPLS shim header + the I-TDM
packet.  Flow 0 (the itdm.ctl_flowno preference) is the control protocol,
every other flow is a 125 usec data flow.  Every packet is built with
struct; no captured traffic is used.

Usage: mkitdm.py <output directory>

Writes:
  itdm-coverage.pcap            data flow packets with every channel command,
                                flag and location layout, control packets
                                with every command, data mode and packet rate
  itdm-coverage-malformed.pcap  packets cut short
  itdm-coverage-label.pcap      packets on another MPLS label and control flow
                                (needs -o itdm.mpls_label:3039 -o itdm.ctl_flowno:7; the label 0x3039 = 12345)
"""
import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
LABEL = 0x99887


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1793491200 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def mpls(payload, label=LABEL, ttl=64, exp=0, s=1, a_to_b=True):
    shim = struct.pack('>I', (label << 12) | (exp << 9) | (s << 8) | ttl)
    dst, src = (MAC_B, MAC_A) if a_to_b else (MAC_A, MAC_B)
    return dst + src + b'\x88\x47' + shim + payload


def common(ts, seq, sop, last, pktlen, chk, flow):
    """Timestamp, sequence number, SOP/EOP, last packet bit, packet length,
    checksum and the 24 bit flow ID (offsets 0-9)."""
    return (struct.pack('>HB', ts, seq) + struct.pack('>H', (sop << 14) | (last << 13) | (pktlen & 0x7ff))
            + struct.pack('>H', chk) + struct.pack('>I', flow)[1:])


def data(flow, cmd, chan, loc1=0, loc2=0, cxn=0, ack=0, act=0, rate=0x447a0000, payload=b'',
         ts=1000, seq=1, sop=3, last=0, pktlen=None, chk=0xbeef):
    pkt = common(ts, seq, sop, last, 18 + len(payload) if pktlen is None else pktlen, chk, flow)
    pkt += bytes([(ack << 5) | (act << 4) | (cmd & 0xf)]) + struct.pack('>I', chan)[1:]
    if cmd == 5:
        pkt += struct.pack('>I', rate)
    elif cmd in (1, 2, 4):
        pkt += struct.pack('>HH', loc1, cxn)
    else:
        pkt += struct.pack('>HH', loc1, loc2)
    return pkt + payload


def control(command, trans=0x1234, flowid=7, dm=2, emts=0, rate=0x45fa0000, ptid=0x4321, cksum=0xcafe,
            flow=0, extra=b'', ts=2000, seq=2, sop=3, last=1, chk=0xdead):
    pkt = common(ts, seq, sop, last, 34 + len(extra), chk, flow)
    pkt += struct.pack('>I', trans) + bytes([command]) + struct.pack('>I', flowid)[1:]
    pkt += bytes([dm, 0]) + struct.pack('>HIIH', emts, rate, ptid, 0) + struct.pack('>H', cksum)
    return pkt + extra


def main_frames():
    f = []
    n = 0

    def add(pkt, **kw):
        nonlocal n
        n += 1
        f.append(mpls(pkt, a_to_b=(n % 2 == 1), **kw))

    # --- 125 usec data flows: every channel command and its location layout
    add(data(5, 1, 100, loc1=3, cxn=4, act=1))                     # New Channel ID
    add(data(5, 1, 100, loc1=3, cxn=4, act=0, ack=1))              # acknowledged
    add(data(5, 2, 100, loc1=3, cxn=4))                            # Close Channel ID
    add(data(5, 3, 101, loc1=7, loc2=9))                           # Relocate Channel ID
    add(data(5, 4, 102, loc1=300, cxn=2))                          # Cyclic Reaffirmation
    add(data(5, 5, 103, rate=0x447a0000))                          # Packet Rate Integrity Check
    add(data(5, 5, 103, rate=0x45fa0000, act=1, ack=1))
    for cmd in (0, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15):            # Reserved commands
        add(data(6, cmd, 200 + cmd, loc1=cmd, loc2=cmd + 1))
    # payload after the header, several sequence numbers, every SOP/EOP value
    for sop in range(4):
        add(data(9, 1, 7, loc1=1, cxn=1, payload=bytes(range(sop * 16, sop * 16 + 16)), sop=sop,
                 seq=sop + 1, last=(sop == 3)))
    add(data(0xffffff, 3, 0xffffff, loc1=0x1ff, loc2=0x1ff, ts=0xffff, seq=255, pktlen=0x7ff,
             chk=0xffff, payload=b'\xff' * 6))
    add(data(1, 4, 0, payload=b''))
    # flow 1 is not the control flow; flow 0 with a data layout is a control packet
    # --- the control protocol (flow 0)
    add(control(1, flowid=0, dm=2, emts=0, rate=0x45fa0000))               # AFI_REQ
    add(control(1, flowid=0, dm=1, rate=0x447a0000, ptid=0))
    add(control(1, flowid=0, dm=3, emts=8, rate=0x45fa0000))
    add(control(1, flowid=0, dm=4, rate=0x43a6aaab))                       # T1 CAS
    add(control(1, flowid=0, dm=4, rate=0x43fa0000))                       # E1 CAS
    add(control(1, flowid=0, dm=0, rate=0x12345678))                       # not used, unknown rate
    add(control(1, flowid=0, dm=9, rate=0))
    for cmd in (0, 2, 3, 4, 0x10, 0x11, 0x12, 0x13, 0x14, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x05, 0xff):
        add(control(cmd, flowid=40 + cmd, trans=0x1000 + cmd, ptid=0x2000 + cmd))
    add(control(2, extra=b'trailing control bytes'))
    return f


def malformed_frames():
    f = []
    f.append(mpls(b''))                                   # MPLS only
    f.append(mpls(bytes(10)))                             # shorter than 18: not decoded
    f.append(mpls(bytes(17)))
    f.append(mpls(data(5, 1, 100, loc1=3, cxn=4)[:18 - 1]))
    f.append(mpls(control(2)[:18]))                       # control cut after the header: exception
    f.append(mpls(control(2)[:26]))
    f.append(mpls(control(1)[:30]))
    f.append(mpls(control(1)[:33]))
    f.append(mpls(control(1)[:34 - 1] + b''))
    f.append(mpls(common(1, 2, 3, 0, 18, 0, 7) + bytes([0x31, 0, 0, 1])))     # data flow, 15 octets of header
    f.append(mpls(common(1, 2, 3, 0, 18, 0, 7) + bytes([0x01, 0, 0, 1, 0])))  # one octet short of the locations
    return f


def label_frames():
    """Another MPLS label (needs -o itdm.mpls_label:3039, the preference is in hex) and another
    control flow number (-o itdm.ctl_flowno:7)."""
    f = []
    f.append(mpls(data(5, 1, 100, loc1=3, cxn=4), label=12345))
    f.append(mpls(control(1, flow=7), label=12345))              # flow 7 is the control flow
    f.append(mpls(control(2, flow=0), label=12345))                   # flow 0 is a data flow now
    return f


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'itdm-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'itdm-coverage-malformed.pcap'), malformed_frames())
    write_pcap(os.path.join(out, 'itdm-coverage-label.pcap'), label_frames())


if __name__ == '__main__':
    main()
