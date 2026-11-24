#!/usr/bin/env python3
# Generates test/captures/btp_matter_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic Matter BTP coverage captures for packet-btp-matter.c.

Usage: mkbtp_matter.py <outdir>

Writes btp_matter-coverage.pcapng (main capture) and
btp_matter-coverage-malformed.pcapng.  Every packet is built with struct:
Bluetooth HCI H4 with the Linux direction header (DLT 201) carrying an LE
connection with ATT on the LE fixed channel (CID 0x0004).  The local host
is the Matter commissioner and GATT client (Sent), the remote device the
commissionee and GATT server (Rcvd).  The server holds the Matter service
0xFFF6 with C1 (client TX, write), C2 (server RX, indicate) and C3
(additional data, read); the capture discovers it first, so BT ATT knows
the characteristic UUID of each handle.  The main capture ends with the
reproducer of btp-matter_exported_pdu_null_data.py, an
Exported PDU (DLT 252) naming "btp-matter".  Nothing comes from a real
device.
"""
import os
import struct
import sys

SENT, RECV = 0, 1
LT_H4_PHDR = 201
LT_EXP_PDU = 252
CHANDLE = 0x0040
ATT_CID = 0x0004

# Flags (Matter Core 4.18.2.1)
H, M, A, E, C, B = 0x40, 0x20, 0x08, 0x04, 0x02, 0x01
OP_HANDSHAKE = 0x6c

# Attribute handles of the Matter service
SVC_START, SVC_END = 0x0001, 0x0008
C1_DECL, C1 = 0x0002, 0x0003
C2_DECL, C2, C2_CCCD = 0x0004, 0x0005, 0x0006
C3_DECL, C3 = 0x0007, 0x0008
OTHER = 0x0011       # Device Name in a second service (0x000f-0x0011), not Matter


def uuid128(text):
    return bytes.fromhex(text.replace('-', ''))[::-1]


C1_UUID = uuid128('18ee2ef5-263d-4559-959f-4f9c429f9d11')
C2_UUID = uuid128('18ee2ef5-263d-4559-959f-4f9c429f9d12')
C3_UUID = uuid128('64630238-8772-45f2-b87d-748a83218f04')


def u8(v):
    return struct.pack('<B', v)


def u16(v):
    return struct.pack('<H', v)


def u32(v):
    return struct.pack('<I', v)


def u64(v):
    return struct.pack('<Q', v)


class Pcapng:
    def __init__(self):
        self.blocks = []
        self.ifaces = {}
        self.n = 0
        self._block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

    def _block(self, btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = len(body) + 12
        self.blocks.append(struct.pack('<II', btype, total) + body + struct.pack('<I', total))

    def iface(self, linktype):
        if linktype not in self.ifaces:
            self.ifaces[linktype] = len(self.ifaces)
            self._block(0x00000001, struct.pack('<HHI', linktype, 0, 65535))
        return self.ifaces[linktype]

    def add(self, linktype, data):
        i = self.iface(linktype)
        ts = (1700000000 + self.n) * 1000000
        self.n += 1
        self._block(0x00000006, struct.pack('<IIIII', i, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(b''.join(self.blocks))


class Conn:
    def __init__(self, cap, linktype=LT_H4_PHDR, chandle=CHANDLE):
        self.cap = cap
        self.lt = linktype
        self.chandle = chandle

    def h4(self, direction, body):
        hdr = struct.pack('>I', direction) if self.lt == LT_H4_PHDR else b''
        self.cap.add(self.lt, hdr + body)

    def connect(self, peer=bytes.fromhex('c0ffee0a7700')):
        ev = bytes([0x01, 0x00]) + u16(self.chandle) + bytes([0x00, 0x00]) + peer[::-1] + \
            u16(0x0018) + u16(0) + u16(0x00c8) + bytes([0x00])
        self.h4(RECV, bytes([0x04, 0x3e, len(ev)]) + ev)

    def att(self, direction, pdu):
        l2 = struct.pack('<HH', len(pdu), ATT_CID) + pdu
        self.h4(direction, struct.pack('<BHH', 0x02, 0x2000 | self.chandle, len(l2)) + l2)

    def discover(self):
        S, R = SENT, RECV
        self.att(S, u8(0x02) + u16(247))                            # Exchange MTU
        self.att(R, u8(0x03) + u16(247))
        # Primary services: Matter 0xFFF6 and GAP 0x1800 (Device Name)
        self.att(S, u8(0x10) + u16(0x0001) + u16(0xffff) + u16(0x2800))
        self.att(R, u8(0x11) + u8(6) + u16(SVC_START) + u16(SVC_END) + u16(0xfff6) +
                 u16(0x000f) + u16(0x0011) + u16(0x1800))
        # Characteristics of the Matter service (128-bit UUIDs)
        self.att(S, u8(0x08) + u16(SVC_START) + u16(SVC_END) + u16(0x2803))
        self.att(R, u8(0x09) + u8(21) +
                 u16(C1_DECL) + u8(0x08) + u16(C1) + C1_UUID +
                 u16(C2_DECL) + u8(0x20) + u16(C2) + C2_UUID +
                 u16(C3_DECL) + u8(0x02) + u16(C3) + C3_UUID)
        self.att(S, u8(0x08) + u16(0x000f) + u16(0x0011) + u16(0x2803))
        self.att(R, u8(0x09) + u8(7) + u16(0x0010) + u8(0x02) + u16(OTHER) + u16(0x2a00))
        # Client Characteristic Configuration of C2
        self.att(S, u8(0x04) + u16(C2_CCCD) + u16(C2_CCCD))
        self.att(R, u8(0x05) + u8(1) + u16(C2_CCCD) + u16(0x2902))
        self.att(S, u8(0x12) + u16(C2_CCCD) + u16(0x0002))
        self.att(R, u8(0x13))

    def write(self, handle, value):
        self.att(SENT, u8(0x12) + u16(handle) + value)
        self.att(RECV, u8(0x13))

    def indicate(self, handle, value):
        self.att(RECV, u8(0x1d) + u16(handle) + value)
        self.att(SENT, u8(0x1e))

    def read(self, handle, value):
        self.att(SENT, u8(0x0a) + u16(handle))
        self.att(RECV, u8(0x0b) + value)


# --- Matter message layer (Matter Core 4.4) ----------------------------------

def matter_msg(session=0, sec=0x00, counter=1, src=None, dest_node=None, dest_group=None,
               exch=0x05, opcode=0x20, exch_id=0x1234, proto=0x0000, vendor=None,
               ack=None, sext=None, app=b''):
    flags = 0x00
    if src is not None:
        flags |= 0x04
    if dest_node is not None:
        flags |= 0x01
    elif dest_group is not None:
        flags |= 0x02
    hdr = u8(flags) + u16(session) + u8(sec)
    if sec & 0x80:                       # privacy: obfuscated header and payload
        return hdr + bytes(range(0x40, 0x40 + 4 + (8 if src is not None else 0) +
                                 (8 if dest_node is not None else 0) +
                                 (2 if dest_group is not None else 0))) + app
    hdr += u32(counter)
    if src is not None:
        hdr += u64(src)
    if dest_node is not None:
        hdr += u64(dest_node)
    elif dest_group is not None:
        hdr += u16(dest_group)
    if session != 0 or (sec & 0x03) != 0:
        return hdr + app + bytes(range(0xe0, 0xf0))     # encrypted payload + MIC
    if vendor is not None:
        exch |= 0x10
    if ack is not None:
        exch |= 0x02
    if sext is not None:
        exch |= 0x08
    pl = u8(exch) + u8(opcode) + u16(exch_id)
    if vendor is not None:
        pl += u16(vendor)
    pl += u16(proto)
    if ack is not None:
        pl += u32(ack)
    if sext is not None:
        pl += u16(len(sext)) + sext
    return hdr + pl + app


# PASE PBKDFParamRequest-like TLV body (anonymous structure, context tags)
PBKDF_REQ = bytes.fromhex('15' '3001' '20') + bytes(range(32)) + bytes.fromhex('2502' '3412' '2403' '00' '2804' '18')


def handshake_request(versions=(4, 3, 0, 0, 0, 0, 0, 0), mtu=244, window=6):
    nib = [v & 0xf for v in versions]
    # Byte order on the air: versions[1]<<4|versions[0], versions[3]<<4|versions[2], ...
    vb = bytes([(nib[1] << 4) | nib[0], (nib[3] << 4) | nib[2], (nib[5] << 4) | nib[4], (nib[7] << 4) | nib[6]])
    return bytes([H | M | E | B, OP_HANDSHAKE]) + vb + u16(mtu) + u8(window)


def handshake_response(version=4, mtu=244, window=6):
    return bytes([H | M | E | B, OP_HANDSHAKE, version]) + u16(mtu) + u8(window)


def segment(flags, payload=b'', ack=None, seq=None, length=None, opcode=None):
    b = u8(flags)
    if flags & M:
        b += u8(opcode)
    if flags & A:
        b += u8(ack)
    if flags & (B | C | E):
        b += u8(seq)
    if flags & B:
        b += u16(length)
    return b + payload


def additional_data(rotating_id):
    # Anonymous structure { 0: octet string rotating id }
    return bytes([0x15, 0x30, 0x00, len(rotating_id)]) + rotating_id + b'\x18'


def exported_pdu_repro():
    """btp-matter_exported_pdu_null_data.py, byte for byte."""
    def tag(t, v):
        pad = (-len(v)) % 4
        return struct.pack('>HH', t, len(v)) + v + b'\0' * pad
    return tag(12, b'btp-matter') + struct.pack('>HH', 0, 0) + bytes([0x05, 0x00, 0x00, 0x04, 0x00, 0x11, 0x22])


def main_capture():
    cap = Pcapng()
    c = Conn(cap)
    c.connect()                                                    # 1
    c.discover()                                                   # 2-13
    # 14-17: BTP handshake
    c.write(C1, handshake_request())
    c.indicate(C2, handshake_response())
    # 18-19: Additional Data (C3) read: TLV with the Rotating Device Identifier
    c.read(C3, additional_data(bytes(range(0x10, 0x22))))
    # 20-21: single segment SDU from the client: unsecured PBKDFParamRequest
    msg1 = matter_msg(counter=0x01020304, src=0x1122334455667788, exch=0x05, opcode=0x20,
                      proto=0x0000, app=PBKDF_REQ)
    c.write(C1, segment(B | E, msg1, seq=0, length=len(msg1)))
    # 22-23: single segment SDU from the server with an ack: unsecured response
    msg2 = matter_msg(counter=0x0a0b0c0d, dest_node=0x1122334455667788, exch=0x04, opcode=0x21,
                      ack=0x01020304, app=bytes.fromhex('1518'))
    c.indicate(C2, segment(A | B | E, msg2, ack=0, seq=0, length=len(msg2)))
    # 24-25: stand-alone acknowledgement: flags, ack and sequence number
    #        (the dissector reads the sequence number only with B/C/E set,
    #        so it shows it as a one octet fragment)
    c.write(C1, segment(A, ack=0) + u8(1))
    # 26-31: client SDU in three segments (Beginning, Continuing, Ending with ack)
    msg3 = matter_msg(counter=7, vendor=0xfff1, proto=0x0001, exch=0x01, opcode=0x02,
                      sext=b'\x01\x02\x03', app=bytes(range(80)))
    p1, p2, p3 = msg3[:30], msg3[30:60], msg3[60:]
    c.write(C1, segment(B, p1, seq=1, length=len(msg3)))
    c.write(C1, segment(C, p2, seq=2))
    c.write(C1, segment(A | E, p3, ack=1, seq=3))
    # 32-35: server SDU in two segments: a secured unicast message
    msg4 = matter_msg(session=0x5a5a, counter=99, app=bytes(range(0x30, 0x70)))
    q1, q2 = msg4[:40], msg4[40:]
    c.indicate(C2, segment(A | B, q1, ack=3, seq=1, length=len(msg4)))
    c.indicate(C2, segment(E, q2, seq=2))
    # 36-37: group session message, with source and group destination
    msg5 = matter_msg(session=0x0101, sec=0x01, counter=5, src=0x0102030405060708,
                      dest_group=0x0042, app=b'\x00' * 8)
    c.write(C1, segment(B | E, msg5, seq=4, length=len(msg5)))
    # 38-39: message with privacy (obfuscated header)
    msg6 = matter_msg(session=0x0202, sec=0x80, src=1, dest_node=2, app=bytes(range(24)))
    c.indicate(C2, segment(B | E, msg6, seq=3, length=len(msg6)))
    # 40-41: management flag on a data segment (op code without handshake)
    msg7 = matter_msg(counter=8, app=b'\x18')
    c.write(C1, segment(M | B | E, msg7, opcode=0x01, seq=5, length=len(msg7)))
    # 42-43: handshake flag with an op code that shares bits with 0x6C
    #        but is not the handshake: no handshake fields
    c.write(C1, bytes([H | M | E | B, 0x6d]) + bytes([0x04, 0x00, 0x00, 0x00]) + u16(244) + u8(6))
    # 44-45: handshake request read back from C1 (Read Response opcode)
    c.read(C1, handshake_request(versions=(4, 0, 0, 0, 0, 0, 0, 0), mtu=23, window=2))
    # 46-47: handshake response read from C2, every version nibble used
    c.read(C2, handshake_response(version=3, mtu=512, window=255))
    c.write(C1, handshake_request(versions=(1, 2, 3, 4, 5, 6, 7, 8), mtu=128, window=4))
    # 50: Write Command and 51: Notification on Matter handles (not dissected by BTP)
    c.att(SENT, u8(0x52) + u16(C1) + segment(A, ack=2))
    c.att(RECV, u8(0x1b) + u16(C2) + segment(A, ack=6))
    # 52-53: read of a characteristic outside the Matter service
    c.read(OTHER, b'Matter Device')
    # 54-55: empty indication on C2 (no BTP flags byte)
    c.indicate(C2, b'')
    # 56: Exported PDU naming "btp-matter" (reproducer: no BT ATT data)
    cap.add(LT_EXP_PDU, exported_pdu_repro())
    return cap


def malformed_capture():
    cap = Pcapng()
    c = Conn(cap)
    c.connect()
    c.discover()
    c.write(C1, bytes([H | M | E | B, OP_HANDSHAKE, 0x04]))           # short handshake request
    c.indicate(C2, bytes([H | M | E | B, OP_HANDSHAKE, 0x04, 0xf4]))   # short handshake response
    c.write(C1, bytes([B, 0x00]))                                     # Beginning without length
    c.write(C1, bytes([M]))                                           # management without op code
    c.write(C1, bytes([A | E]))                                       # ack without value
    c.read(C3, bytes([0x15, 0x30, 0x00, 0x40, 0x01]))                 # TLV string past the end
    c.read(C3, bytes([0x15, 0xe0]))                                   # unsupported TLV tag form
    # Ending segment without a Beginning, then two Beginnings in a row
    c.write(C1, segment(E, b'\x00' * 10, seq=9))
    c.write(C1, segment(B, b'\x01' * 10, seq=10, length=40))
    c.write(C1, segment(B, b'\x02' * 10, seq=11, length=40))
    c.write(C1, segment(E, b'\x03' * 10, seq=12))
    # Stand-alone ack without a sequence number and an Ending segment
    # without payload: the header ends at the end of the packet, and the
    # payload item (offset at the end, length -1) throws
    c.write(C1, segment(A, ack=0))
    c.indicate(C2, segment(E, seq=5))
    # Short Matter message
    c.write(C1, segment(B | E, b'\x00\x00', seq=13, length=2))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'btp_matter-coverage.pcapng'))
    malformed_capture().write(os.path.join(out, 'btp_matter-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
