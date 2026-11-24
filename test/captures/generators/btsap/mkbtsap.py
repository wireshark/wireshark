#!/usr/bin/env python3
# Generates test/captures/btsap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic Bluetooth SIM Access Profile coverage captures for
packet-btsap.c.

Usage: mkbtsap.py <outdir>

Writes btsap-coverage.pcapng (main capture) and
btsap-coverage-malformed.pcapng.  Every packet is built with struct:
Bluetooth HCI H4 with the Linux direction header (DLT 201): a BR/EDR
Connection Complete event, an SDP Service Search Attribute exchange that
puts the SIM Access service (0x112D) on RFCOMM channel 5, the L2CAP and
RFCOMM channel setup, and SAP messages in RFCOMM UIH frames.  The local
host is the SAP client (Sent), the remote device the SAP server (Rcvd).
Two Exported PDUs naming "btsap" (DLT 252) have no direction.
Nothing comes from a real device.
"""
import os
import struct
import sys

SENT, RECV = 0, 1
LT_H4_PHDR = 201
LT_EXP_PDU = 252
HANDLE = 0x0001
BDADDR = bytes.fromhex('020000000005')
SAP_UUID = 0x112D
CHANNEL = 5


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


# --- HCI / L2CAP / SDP / RFCOMM framing ------------------------------------

class Link:
    """One BR/EDR ACL link with SDP and an RFCOMM channel to the SAP server."""

    def __init__(self, cap, linktype=LT_H4_PHDR, handle=HANDLE, bdaddr=BDADDR):
        self.cap = cap
        self.lt = linktype
        self.handle = handle
        self.bdaddr = bdaddr
        self.dlci = CHANNEL << 1

    def h4(self, direction, ptype, body):
        hdr = struct.pack('>I', direction) if self.lt == LT_H4_PHDR else b''
        self.cap.add(self.lt, hdr + bytes([ptype]) + body)

    def acl(self, direction, cid, payload):
        l2 = struct.pack('<HH', len(payload), cid) + payload
        self.h4(direction, 2, struct.pack('<HH', (self.handle & 0x0fff) | 0x2000, len(l2)) + l2)

    def conn_complete(self):
        ev = struct.pack('<BH', 0, self.handle) + self.bdaddr[::-1] + b'\x01\x00'
        self.h4(RECV, 4, bytes([0x03, len(ev)]) + ev)

    def l2_connect(self, psm, scid, dcid, ident):
        self.acl(SENT, 1, struct.pack('<BBHHH', 0x02, ident, 4, psm, scid))
        self.acl(RECV, 1, struct.pack('<BBHHHHH', 0x03, ident, 8, dcid, scid, 0, 0))

    def sdp(self, scid=0x0040, dcid=0x0041):
        def seq(*items):
            b = b''.join(items)
            return bytes([0x35, len(b)]) + b

        def du8(v):
            return bytes([0x08, v])

        def du16(v):
            return b'\x09' + struct.pack('>H', v)

        def du32(v):
            return b'\x0a' + struct.pack('>I', v)

        def uuid16(v):
            return b'\x19' + struct.pack('>H', v)

        self.l2_connect(1, scid, dcid, 1)
        params = seq(uuid16(SAP_UUID)) + struct.pack('>H', 0xffff) + seq(du32(0x0000ffff)) + b'\x00'
        self.acl(SENT, dcid, struct.pack('>BHH', 0x06, 1, len(params)) + params)
        rec = seq(du16(0x0001), seq(uuid16(SAP_UUID), uuid16(0x1204)),
                  du16(0x0004), seq(seq(uuid16(0x0100)), seq(uuid16(0x0003), du8(CHANNEL))),
                  du16(0x0009), seq(seq(uuid16(SAP_UUID), du16(0x0102))))
        lists = seq(rec)
        params = struct.pack('>H', len(lists)) + lists + b'\x00'
        self.acl(RECV, scid, struct.pack('>BHH', 0x07, 1, len(params)) + params)

    @staticmethod
    def fcs(data):
        crc = 0xff
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ 0xe0 if crc & 1 else crc >> 1
        return 0xff - crc

    def rfcomm(self, dlci, ctrl, payload=b'', cr=1):
        addr = (dlci << 2) | (cr << 1) | 1
        if len(payload) < 128:
            ln = bytes([(len(payload) << 1) | 1])
        else:
            ln = struct.pack('<H', len(payload) << 1)
        hdr = bytes([addr, ctrl]) + ln
        f = self.fcs(hdr[:2]) if (ctrl & 0xef) == 0xef else self.fcs(hdr)
        return hdr + payload + bytes([f])

    def rfcomm_setup(self, scid=0x0042, dcid=0x0043):
        self.scid, self.dcid = scid, dcid
        self.l2_connect(3, scid, dcid, 2)
        self.acl(SENT, dcid, self.rfcomm(0, 0x3f))
        self.acl(RECV, scid, self.rfcomm(0, 0x73))
        self.acl(SENT, dcid, self.rfcomm(self.dlci, 0x3f))
        self.acl(RECV, scid, self.rfcomm(self.dlci, 0x73))

    def setup(self):
        self.conn_complete()
        self.sdp()
        self.rfcomm_setup()

    def sap(self, direction, msg):
        cid = self.dcid if direction == SENT else self.scid
        cr = 1 if direction == SENT else 0
        self.acl(direction, cid, self.rfcomm(self.dlci, 0xef, msg, cr))


def exported_pdu(name, payload):
    """Exported PDU: dissector name tag (12), end of options, payload."""
    v = name.encode()
    v += b'\0' * ((-len(v)) % 4)              # NUL padding counted in the length
    tag = struct.pack('>HH', 12, len(v)) + v
    return tag + struct.pack('>HH', 0, 0) + payload


# --- SAP messages -----------------------------------------------------------

def param(pid, value, length=None, pad=None):
    """Parameter: ID, reserved, 16-bit length, value, padding to 4 octets."""
    ln = len(value) if length is None else length
    if pad is None:
        pad = (-len(value)) % 4
    return bytes([pid, 0]) + struct.pack('>H', ln) + value + b'\x00' * pad


def msg(mid, *params, count=None, reserved=0):
    n = len(params) if count is None else count
    return bytes([mid, n]) + struct.pack('>H', reserved) + b''.join(params)


def p_max(v):
    return param(0x00, struct.pack('>H', v))


def p_status(v):
    return param(0x01, bytes([v]))


def p_result(v):
    return param(0x02, bytes([v]))


def p_disc(v):
    return param(0x03, bytes([v]))


def p_cmd(apdu):
    return param(0x04, apdu)


def p_rsp(apdu):
    return param(0x05, apdu)


def p_atr(atr):
    return param(0x06, atr)


def p_crs(v):
    return param(0x07, bytes([v]))


def p_change(v):
    return param(0x08, bytes([v]))


def p_proto(v):
    return param(0x09, bytes([v]))


def p_cmd7816(apdu):
    return param(0x10, apdu)


SELECT_MF_GSM = bytes.fromhex('a0a40000023f00')       # GSM 11.11 SELECT MF
READ_BINARY_GSM = bytes.fromhex('a0b000000a')         # GSM 11.11 READ BINARY
SELECT_MF_7816 = bytes.fromhex('00a4000c023f00')      # ISO 7816-4 SELECT MF
RSP_9F22 = bytes.fromhex('9f22')
RSP_DATA = bytes.fromhex('98765432100123456789') + bytes.fromhex('9000')
RSP_9000 = bytes.fromhex('9000')
ATR = bytes.fromhex('3b0214' + '50')                  # direct convention, 2 historical bytes


def session(link):
    S, R = SENT, RECV
    # Connection
    link.sap(S, msg(0x00, p_max(300)))                        # CONNECT_REQ
    link.sap(R, msg(0x01, p_status(0x02), p_max(276)))        # CONNECT_RESP error + MaxMsgSize
    link.sap(S, msg(0x00, p_max(276)))
    link.sap(R, msg(0x01, p_status(0x00)))                    # OK
    link.sap(R, msg(0x11, p_change(0x01)))                    # STATUS_IND Card Reset
    # ATR
    link.sap(S, msg(0x07))                                    # TRANSFER_ATR_REQ
    link.sap(R, msg(0x08, p_result(0x00), p_atr(ATR)))        # TRANSFER_ATR_RESP
    # APDUs
    link.sap(S, msg(0x05, p_cmd(SELECT_MF_GSM)))
    link.sap(R, msg(0x06, p_result(0x00), p_rsp(RSP_9F22)))
    link.sap(S, msg(0x05, p_cmd(READ_BINARY_GSM)))
    link.sap(R, msg(0x06, p_result(0x00), p_rsp(RSP_DATA)))
    link.sap(S, msg(0x05, p_cmd7816(SELECT_MF_7816)))
    link.sap(R, msg(0x06, p_result(0x00), p_rsp(RSP_9000)))
    link.sap(S, msg(0x05, p_cmd(SELECT_MF_GSM)))
    link.sap(R, msg(0x06, p_result(0x02)))                    # card not accessible, no APDU
    # Card reader status
    link.sap(S, msg(0x0F))
    link.sap(R, msg(0x10, p_result(0x00), p_crs(0xd9)))       # identity 1, removable, present, card present & powered
    link.sap(S, msg(0x0F))
    link.sap(R, msg(0x10, p_result(0x06)))                    # data not available
    link.sap(S, msg(0x0F))
    link.sap(R, msg(0x10, p_result(0x00), p_crs(0x26)))       # other bits
    # Transport protocol
    link.sap(S, msg(0x13, p_proto(0x01)))
    link.sap(R, msg(0x14, p_result(0x07)))                    # not supported
    link.sap(S, msg(0x13, p_proto(0x00)))
    link.sap(R, msg(0x14, p_result(0x00)))
    # Power and reset
    link.sap(S, msg(0x09))
    link.sap(R, msg(0x0A, p_result(0x00)))
    link.sap(S, msg(0x09))
    link.sap(R, msg(0x0A, p_result(0x03)))                    # already powered off
    link.sap(S, msg(0x0B))
    link.sap(R, msg(0x0C, p_result(0x00)))
    link.sap(S, msg(0x0B))
    link.sap(R, msg(0x0C, p_result(0x05)))                    # already powered on
    link.sap(S, msg(0x0D))
    link.sap(R, msg(0x0E, p_result(0x00)))
    link.sap(S, msg(0x0D))
    link.sap(R, msg(0x0E, p_result(0x04)))                    # card removed
    link.sap(S, msg(0x07))
    link.sap(R, msg(0x08, p_result(0x01)))                    # ATR error, no ATR
    # Every status change, the other result and connection status values
    for v in (0x00, 0x02, 0x03, 0x04, 0x05, 0x06):
        link.sap(R, msg(0x11, p_change(v)))                   # 0x06 unknown
    link.sap(R, msg(0x0A, p_result(0x08)))                    # unknown result code
    link.sap(S, msg(0x00, p_max(276)))
    link.sap(R, msg(0x01, p_status(0x01), p_max(276)))
    link.sap(S, msg(0x00, p_max(100)))
    link.sap(R, msg(0x01, p_status(0x03), p_max(276)))
    link.sap(S, msg(0x00, p_max(276)))
    link.sap(R, msg(0x01, p_status(0x05), p_max(276)))        # unknown status
    link.sap(S, msg(0x00, p_max(276)))
    link.sap(R, msg(0x01, p_status(0x04)))                    # OK, ongoing call
    link.sap(S, msg(0x12))                                    # ERROR_RESP
    link.sap(S, msg(0x15))                                    # unknown message ID
    # Disconnection
    link.sap(R, msg(0x04, p_disc(0x00)))                      # Graceful
    link.sap(R, msg(0x04, p_disc(0x01)))                      # Immediate
    link.sap(R, msg(0x04, p_disc(0x02)))                      # unknown type
    link.sap(S, msg(0x02))                                    # DISCONNECT_REQ
    link.sap(R, msg(0x03))                                    # DISCONNECT_RESP


def main_capture():
    c = Pcapng()
    link = Link(c)
    link.setup()
    session(link)
    # Exported PDUs naming "btsap" (no direction: UnknownDirection)
    c.add(LT_EXP_PDU, exported_pdu('btsap', msg(0x00, p_max(276))))
    c.add(LT_EXP_PDU, exported_pdu('btsap', msg(0x01, p_status(0x00))))
    return c


def malformed_capture():
    c = Pcapng()
    link = Link(c)
    link.setup()
    S, R = SENT, RECV
    link.sap(S, msg(0x00))                                    # missing MaxMsgSize
    link.sap(S, msg(0x00, p_max(276), p_max(300)))            # two MaxMsgSize
    link.sap(S, msg(0x02, p_max(276)))                        # parameter where none is allowed
    link.sap(R, msg(0x01, p_max(276)))                        # wrong parameter
    link.sap(R, msg(0x01, p_status(0x01)))                    # error without MaxMsgSize (fine) ...
    link.sap(R, msg(0x01, p_status(0x00), p_max(276)))        # ... OK with MaxMsgSize: too many
    link.sap(R, msg(0x06, p_result(0x00)))                    # OK without APDU
    link.sap(R, msg(0x06, p_rsp(RSP_9000)))                   # APDU without result
    link.sap(R, msg(0x08, p_atr(ATR)))
    link.sap(R, msg(0x10, p_crs(0x00)))
    link.sap(R, msg(0x04))
    link.sap(S, msg(0x05))
    link.sap(R, msg(0x11))
    link.sap(S, msg(0x13))
    link.sap(R, msg(0x0A))
    link.sap(S, msg(0x00, param(0x00, struct.pack('>HH', 1, 2))))   # MaxMsgSize of 4 octets
    link.sap(R, msg(0x01, param(0x01, b'\x00\x00')))          # ConnectionStatus of 2 octets
    link.sap(R, msg(0x0A, param(0x02, b'\x00', pad=0)))       # ResultCode without padding
    link.sap(R, msg(0x04, param(0x03, b'\x00\x01\x02\x03')))
    link.sap(R, msg(0x10, p_result(0), param(0x07, b'\x00\x00\x00')))
    link.sap(R, msg(0x11, param(0x08, b'')))
    link.sap(S, msg(0x13, param(0x09, b'\x00\x00\x00\x00\x00')))
    link.sap(S, msg(0x12, param(0x0b, b'\x01\x02\x03')))      # unknown parameter ID
    link.sap(S, msg(0x05, p_cmd(SELECT_MF_GSM), p_cmd7816(SELECT_MF_7816)))  # two commands
    link.sap(S, msg(0x07) + b'\xde\xad')                      # trailing data
    link.sap(S, msg(0x00, count=3) + p_max(276))              # more parameters than present
    link.sap(S, msg(0x00, param(0x00, b'\x01', length=40)))   # length past the end
    link.sap(S, bytes([0x00, 0x01]))                          # header cut short
    link.sap(R, msg(0x01, param(0x01, b'', pad=0)))           # ConnectionStatus without value at the end
    link.sap(S, msg(0x05, param(0x04, b'\xa0')))              # one octet GSM command
    link.sap(R, msg(0x08, p_result(0), p_atr(b'\x3b\xff')))   # ATR cut short
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'btsap-coverage.pcapng'))
    malformed_capture().write(os.path.join(out, 'btsap-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
