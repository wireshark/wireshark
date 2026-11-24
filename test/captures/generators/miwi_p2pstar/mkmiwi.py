#!/usr/bin/env python3
# Generates test/captures/miwi_p2pstar_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic MiWi P2P Star captures.  Usage: mkmiwi.py <outdir>
Writes miwi-p2pstar-coverage.pcap (Exported PDU "miwi_p2pstar", valid frames),
miwi-p2pstar-coverage-malformed.pcap and miwi-p2pstar-coverage-wpan.pcap
(IEEE 802.15.4 frames that carry MiWi frames, for Decode As and the heuristic
dissector; used by runcov.sh only)."""
import struct
import sys
import os

def crc16(data):
    """IEEE 802.15.4 FCS: CRC-16/KERMIT (init 0, reflected 0x1021)."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

def write_pcap(fn, frames, linktype):
    """frames: bytes or (bytes, extra) where extra is added to the original length."""
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            extra = 0
            if isinstance(fr, tuple): fr, extra = fr
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr) + extra))
            f.write(fr)

NONE, RES, SHORT, EXT = 0, 1, 2, 3
BEACON, DATA, ACK, CMD = 0, 1, 2, 3

def pans(ver, ftype, dm, sm, comp):
    """(dst pan present, src pan present) or None when the dissector rejects it."""
    if ver in (0, 1):
        if dm != NONE and sm != NONE:
            return (True, False) if comp else (True, True)
        if comp: return None
        if dm != NONE: return (True, False)
        if sm != NONE: return (False, True)
        return (False, False)
    if ftype not in (BEACON, DATA, ACK, CMD): return (False, False)
    if dm == NONE and sm == NONE: return (comp == 1, False)
    if sm == NONE: return (comp == 0, False)
    if dm == NONE: return (False, comp == 0)
    if dm == EXT and sm == EXT: return (comp == 0, False)
    if comp == 0: return (True, True)
    return (True, False)

def addr(mode, v):
    if mode == SHORT: return struct.pack('<H', v)
    if mode == EXT: return struct.pack('<Q', v)
    return b''

def mac(ftype=DATA, dm=SHORT, sm=SHORT, ver=1, comp=1, seq=1, dpan=0x1234, dst=0x0002,
        span=0x1234, src=0x0001, cmd=None, payload=b'', sec=0, pend=0, ack=0, res=0,
        fcs='ok', raw_fcf=None):
    fcf = (ftype | sec << 3 | pend << 4 | ack << 5 | comp << 6 | res << 7 | dm << 10
           | ver << 12 | sm << 14)
    if raw_fcf is not None: fcf = raw_fcf
    b = struct.pack('<HB', fcf, seq)
    p = pans(ver, ftype, dm, sm, comp)
    assert p is not None
    if p[0]: b += struct.pack('<H', dpan)
    b += addr(dm, dst)
    if p[1]: b += struct.pack('<H', span)
    b += addr(sm, src)
    if cmd is not None and ver in (0, 1) and ftype == CMD: b += bytes([cmd])
    b += payload
    if fcs == 'ok': b += struct.pack('<H', crc16(b))
    elif fcs == 'bad': b += struct.pack('<H', (crc16(b) ^ 0x5a5a) & 0xffff)
    return b

frames = []; bad = []
def F(**kw): frames.append(exp_pdu('miwi_p2pstar', mac(**kw)))
def FR(b): frames.append(exp_pdu('miwi_p2pstar', b))
def B(b): bad.append(exp_pdu('miwi_p2pstar', b))

EXT1 = 0x0200000000000001; EXT2 = 0x0200000000000002; EXT3 = 0x0200000000000003

# --- addressing, frame versions 2003 and 2006 -------------------------------
for ver in (1, 0):
    for dm in (SHORT, EXT):
        for sm in (SHORT, EXT):
            for comp in (1, 0):
                F(ver=ver, dm=dm, sm=sm, comp=comp, dst=EXT2 if dm == EXT else 2,
                  src=EXT1 if sm == EXT else 1, span=0x4321, payload=b'\x10\x20\x30')
    for dm, sm in ((SHORT, NONE), (EXT, NONE), (NONE, SHORT), (NONE, EXT), (NONE, NONE)):
        F(ver=ver, dm=dm, sm=sm, comp=0, dst=EXT2 if dm == EXT else 2, src=EXT1 if sm == EXT else 1,
          payload=b'\x55')
# --- 2015 ---------------------------------------------------------------------
for ftype in (DATA, BEACON, ACK, CMD, 5):
    for dm, sm in ((NONE, NONE), (SHORT, NONE), (EXT, NONE), (NONE, SHORT), (NONE, EXT),
                   (SHORT, SHORT), (SHORT, EXT), (EXT, SHORT), (EXT, EXT)):
        for comp in (0, 1):
            if ftype != DATA and (dm, sm) not in ((NONE, NONE), (SHORT, SHORT), (EXT, EXT)):
                continue
            F(ftype=ftype, ver=2, dm=dm, sm=sm, comp=comp, dst=EXT2 if dm == EXT else 2,
              src=EXT1 if sm == EXT else 1, span=0x4321, payload=b'\x77\x88')
# --- frame types, flags -------------------------------------------------------------
F(ftype=BEACON, payload=b'\x00\x01\x02')
F(ftype=ACK, dm=NONE, sm=NONE, comp=0, seq=9)
for t in (4, 5, 6, 7): F(ftype=t, payload=b'\x01')
F(sec=1, pend=1, ack=1, payload=b'\x42')
F(res=7, payload=b'\x42')
# --- commands ---------------------------------------------------------------------------
def C(cmd, payload=b'', **kw): F(ftype=CMD, cmd=cmd, payload=payload, **kw)
for ver in (1, 0):
    C(0x81, b'\x0b\x8f', ver=ver)                         # connection request
    C(0x82, b'', ver=ver)                                 # removal request
    C(0x83, b'', ver=ver)                                 # data request
    C(0x84, b'\x0b\x0c', ver=ver)                         # channel hopping
    C(0x87, b'\x0b', ver=ver)                             # active scan request
    C(0x92, b'\x00', ver=ver)                             # removal response ok
    C(0x92, b'\x05', ver=ver)                             # removal response failed
    C(0x97, b'\x85\x0c', ver=ver)                         # active scan response
    C(0xcc, b'\x03\x01\x02', ver=ver)                     # forward packet
    C(0xda, b'', ver=ver)                                 # soft ack
    C(0x7a, b'\x01', ver=ver)                             # link status
    C(0x77, b'\x04\xaa', ver=ver)                         # connection table
    C(0x55, b'\x01\x02', ver=ver)                         # unknown command
# connection responses: every status, success from a short address (address map update)
for status in range(0, 8):
    C(0x91, bytes([status, 0x8f, 0]), dm=EXT, sm=SHORT, comp=1, dst=EXT3 + status, src=0x0010 + status,
      dpan=0x1234)
C(0x91, bytes([0, 0x01]), dm=EXT, sm=EXT, comp=0, dst=EXT3, src=EXT1, dpan=0x2222)   # success, ext source
C(0x91, bytes([0, 0x01]), dm=EXT, sm=SHORT, comp=1, dst=EXT3, src=0xfffe)             # no short address
C(0x91, bytes([0, 0x01]), dm=SHORT, sm=SHORT, comp=1, dst=0x0044, src=0xffff)         # broadcast source
C(0x91, bytes([0, 0x01]), dm=SHORT, sm=EXT, comp=1, dst=0x0044, src=EXT1, ver=2)      # 2015, no command id
# frames from the address learned above: the extended source address is shown
F(sm=SHORT, dm=SHORT, comp=1, src=0x0010, dst=0x0001, payload=b'\x01\x02')
F(sm=SHORT, dm=SHORT, comp=1, src=0x0013, dst=0x0001, payload=b'\x01\x02')
F(sm=SHORT, dm=SHORT, comp=0, src=0x0010, dst=0x0001, span=0x1234, payload=b'\x01')
F(sm=SHORT, dm=SHORT, comp=0, src=0x0010, dst=0x0001, span=0x9999, payload=b'\x01')   # other PAN
# --- broadcast addresses ("Broadcast", the reproducer of the overflow) ---------------
F(dpan=0xffff, dst=0xffff, src=0xffff, comp=1, payload=b'\x11\x22')
F(dpan=0xffff, dst=0xffff, src=0x0005, span=0xffff, comp=0, payload=b'\x11')
F(dpan=0x1234, dst=0xffff, src=0x0001, comp=1)
F(ftype=CMD, cmd=0x91, payload=b'\x00\x8f\x00', dm=EXT, sm=SHORT, comp=1, dpan=0xffff, dst=EXT3, src=0x0005)
F(dm=NONE, sm=SHORT, comp=0, span=0xffff, src=0xffff)
# --- FCS --------------------------------------------------------------------------------------
F(fcs='bad', payload=b'\x01\x02\x03')
F(ftype=CMD, cmd=0x84, payload=b'\x0b\x0c', fcs='bad')
F(fcs='none', payload=b'\x01\x02\x03\x04')
# captured length 2 octets short of the reported length (the FCS cut off by the snap length)
frames.append((exp_pdu('miwi_p2pstar', mac(payload=b'\x01\x02', fcs='none')), 2))
frames.append((exp_pdu('miwi_p2pstar', mac(ftype=CMD, cmd=0x84, payload=b'\x0b\x0c', fcs='none')), 2))

# --- malformed ---------------------------------------------------------------------------------
# reserved addressing modes, version, bad PAN compression
B(struct.pack('<HB', DATA | 1 << 10 | 1 << 12, 1) + bytes(8))                 # reserved dst mode
B(struct.pack('<HB', DATA | SHORT << 10 | 1 << 12 | RES << 14, 1) + bytes(8))  # reserved src mode
B(struct.pack('<HB', DATA | SHORT << 10 | 3 << 12 | SHORT << 14, 1) + bytes(12))   # reserved version
B(struct.pack('<HB', DATA | 1 << 6 | SHORT << 10 | 1 << 12, 1) + bytes(8))  # comp, one address
B(struct.pack('<HB', DATA | 1 << 6 | 1 << 12, 1) + bytes(8))                    # comp, no address
# truncated headers and commands: the exception in the command dissector
B(struct.pack('<H', DATA | SHORT << 10 | 1 << 12 | SHORT << 14))               # no sequence number
B(struct.pack('<HB', DATA | SHORT << 10 | 1 << 12 | SHORT << 14, 1) + bytes(3))
B(mac(ftype=CMD, cmd=0x81, fcs='none'))
B(mac(ftype=CMD, cmd=0x91, fcs='none', dm=EXT, sm=SHORT))
B(mac(ftype=CMD, cmd=0x84, fcs='none'))
B(mac(ftype=CMD, cmd=0x87, fcs='none'))
B(mac(ftype=CMD, cmd=0x92, fcs='none'))
B(mac(ftype=CMD, cmd=0x97, fcs='none'))
B(mac(ftype=CMD, cmd=0xcc, fcs='none'))
B(mac(ftype=CMD, cmd=0x77, fcs='none'))
B(mac(ftype=CMD, cmd=0x55, fcs='none'))
B(mac(ftype=CMD, dm=NONE, sm=NONE, comp=0, fcs='none'))                      # command without id byte
B(mac(ftype=CMD, cmd=0x81, fcs='ok'))
B(bytes([0x41, 0x98]))                                                          # two octet frame
B(bytes([0x41]))                                                                # shorter than the FCS
# command frames cut off right after the header (the FCS is missing from the capture): the
# command dissector runs into the end of the data
for c in (0x81, 0x91, 0x84, 0x87, 0x92, 0x97, 0xcc, 0x77, 0x55):
    bad.append((exp_pdu('miwi_p2pstar', mac(ftype=CMD, cmd=c, dm=EXT if c == 0x91 else SHORT, fcs='none')), 2))
# Decode As / heuristic carriers: IEEE 802.15.4 frame (version 2003, no FCS needed) with a MiWi frame
def wpan(inner, ftype=DATA):
    return struct.pack('<HBH', ftype | 1 << 6 | SHORT << 10 | SHORT << 14, 1, 0xface) + struct.pack('<HH', 2, 1) + inner

# --- IEEE 802.15.4 carrier (runcov only) -----------------------------------
wp = []
for inner in (mac(payload=b'\x10\x20'), mac(ftype=CMD, cmd=0x84, payload=b'\x0b\x0c'),
              mac(ftype=CMD, cmd=0x91, dm=EXT, sm=SHORT, dst=EXT3, src=0x0020, payload=b'\x00\x8f\x00'),
              mac(dpan=0xffff, dst=0xffff, src=0xffff, payload=b'\x01'),
              mac(fcs='bad', payload=b'\x01\x02')):
    f = wpan(inner)
    wp.append(f + struct.pack('<H', crc16(f)))

out = sys.argv[1] if len(sys.argv) > 1 else '.'
os.makedirs(out, exist_ok=True)
write_pcap(os.path.join(out, 'miwi-p2pstar-coverage.pcap'), frames, 252)
write_pcap(os.path.join(out, 'miwi-p2pstar-coverage-malformed.pcap'), bad, 252)
write_pcap(os.path.join(out, 'miwi-p2pstar-coverage-wpan.pcap'), wp, 195)
print(len(frames), len(bad), len(wp))
