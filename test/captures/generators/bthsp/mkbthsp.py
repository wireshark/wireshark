#!/usr/bin/env python3
# Generates test/captures/bthsp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the synthetic BT HSP coverage captures. Usage: mkbthsp.py <outdir>
#
# Every packet is built here with struct; nothing comes from a real
# network. A host (localhost) and a remote device 02:00:00:00:00:01 on
# Bluetooth HCI H4 with direction (link type 201): SDP records in both
# directions for HSP AG (0x1112), HSP HS (0x1108, 0x1131), one RFCOMM
# session, and AT commands and responses in RFCOMM UIH frames. Exported
# PDUs (link type 252) to "bthsp" give the role-unknown paths.
import os
import struct
import sys

SENT, RECV = 0, 1
HANDLE = 0x0001
BDADDR = bytes.fromhex('020000000001')


def h4(direction, ptype, body):
    return struct.pack('>I', direction) + bytes([ptype]) + body


def acl(direction, cid, payload, handle=HANDLE):
    l2 = struct.pack('<HH', len(payload), cid) + payload
    return h4(direction, 2, struct.pack('<HH', (handle & 0x0fff) | 0x2000, len(l2)) + l2)


def conn_complete():
    ev = struct.pack('<BH', 0, HANDLE) + BDADDR[::-1] + b'\x01\x00'
    return h4(RECV, 4, bytes([0x03, len(ev)]) + ev)


def l2_connect(direction, psm, scid, dcid, ident):
    # direction: who sends the request
    req = struct.pack('<BBHHH', 0x02, ident, 4, psm, scid)
    rsp = struct.pack('<BBHHHHH', 0x03, ident, 8, dcid, scid, 0, 0)
    return [acl(direction, 1, req), acl(1 - direction, 1, rsp)]


def seq(*items):
    b = b''.join(items)
    return bytes([0x35, len(b)]) + b


def u8(v):
    return bytes([0x08, v])


def u16(v):
    return b'\x09' + struct.pack('>H', v)


def u32(v):
    return b'\x0a' + struct.pack('>I', v)


def uuid16(v):
    return b'\x19' + struct.pack('>H', v)


def sdp_record(svc_uuid, channel):
    return seq(u16(0x0001), seq(uuid16(svc_uuid), uuid16(0x1203)),
               u16(0x0004), seq(seq(uuid16(0x0100)), seq(uuid16(0x0003), u8(channel))))


def sdp_exchange(client, records, scid, dcid, ident, tid):
    """client sends the L2CAP connect and the SDP request; the other side
    answers with a Service Search Attribute Response holding records."""
    server = 1 - client
    pkts = l2_connect(client, 1, scid, dcid, ident)
    # client -> server goes to the server's CID (dcid), back to scid
    params = seq(uuid16(0x1108)) + struct.pack('>H', 0xffff) + seq(u32(0x0000ffff)) + b'\x00'
    pkts.append(acl(client, dcid, struct.pack('>BHH', 0x06, tid, len(params)) + params))
    lists = seq(*[sdp_record(u, c) for u, c in records])
    params = struct.pack('>H', len(lists)) + lists + b'\x00'
    pkts.append(acl(server, scid, struct.pack('>BHH', 0x07, tid, len(params)) + params))
    return pkts


def fcs(data):
    crc = 0xff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xe0 if crc & 1 else crc >> 1
    return 0xff - crc


def rfcomm(dlci, ctrl, payload=b'', cr=1):
    addr = (dlci << 2) | (cr << 1) | 1
    if len(payload) < 128:
        ln = bytes([(len(payload) << 1) | 1])
    else:
        ln = struct.pack('<H', len(payload) << 1)
    hdr = bytes([addr, ctrl]) + ln
    f = fcs(hdr[:2]) if (ctrl & 0xef) == 0xef else fcs(hdr)
    return hdr + payload + bytes([f])


# RFCOMM L2CAP channel: the host connects, host CID 0x0042, remote 0x0043
R_SCID, R_DCID = 0x0042, 0x0043


def rf(direction, dlci, ctrl, payload=b''):
    cid = R_DCID if direction == SENT else R_SCID
    cr = 1 if direction == SENT else 0
    return acl(direction, cid, rfcomm(dlci, ctrl, payload, cr))


def uih(direction, dlci, payload):
    return rf(direction, dlci, 0xef, payload)


# Exported PDU to the "bthsp" dissector
def tag(t, v):
    return struct.pack('>HH', t, len(v)) + v


def exp_pdu(payload, direction=None):
    t = tag(12, b'bthsp')
    if direction is not None:
        t += tag(35, struct.pack('>i', direction))
    return t + struct.pack('>HH', 0, 0) + payload


# Channels: 3 = remote HSP AG, 5 = remote HSP HS (0x1108),
# 7 = local HSP AG, 9 = local HSP HS (0x1131). The host opened the
# RFCOMM session, so DLCI = channel << 1 is a remote server channel and
# channel << 1 | 1 a local one.
CH3, CH5, CH7, CH9 = 3 << 1, 5 << 1, (7 << 1) | 1, (9 << 1) | 1


def setup():
    p = [conn_complete()]
    # Host asks the remote device (records with direction "Rcvd")
    p += sdp_exchange(SENT, [(0x1112, 3), (0x1108, 5)], 0x0040, 0x0041, 1, 1)
    # Remote device asks the host (records with direction "Sent")
    p += sdp_exchange(RECV, [(0x1112, 7), (0x1131, 9)], 0x0060, 0x0061, 2, 2)
    p += l2_connect(SENT, 3, R_SCID, R_DCID, 3)
    p += [rf(SENT, 0, 0x3f), rf(RECV, 0, 0x73)]
    for dlci in (CH3, CH5, CH7, CH9):
        p += [rf(SENT, dlci, 0x3f), rf(RECV, dlci, 0x73)]
    return p


def main_capture():
    """(interface, packet) list. Frame numbers are in the README."""
    p = [(0, x) for x in setup()]                                 # 1-21

    def hs(data):        # channel 3: Sent = HS
        p.append((0, uih(SENT, CH3, data)))

    def ag(data):        # channel 3: Rcvd = AG
        p.append((0, uih(RECV, CH3, data)))

    # HS commands, one per frame
    hs(b'AT+CKPD=200\r')                                          # 22
    ag(b'\r\nOK\r\n')                                             # 23
    hs(b'AT+VGS=7\r')                                             # 24
    ag(b'\r\n+VGS:5\r\n')                                         # 25
    hs(b'AT+VGM=9\r')                                             # 26
    ag(b'\r\n+VGM:6\r\n')                                         # 27
    # lower case, three commands in one line (upper-cased copy made once)
    hs(b'at+vgs=3;+vgm=4;+ckpd=200\r')                            # 28
    hs(b'AT+VGS=16\r')                                            # 29 gain warning
    hs(b'AT+VGM=20\r')                                            # 30 gain warning
    hs(b'AT+CKPD=100\r')                                          # 31 key warning
    hs(b'AT+VGS=1,2\r')                                           # 32 unknown 2nd parameter
    hs(b'AT+VGS=?\r')                                             # 33 test command
    hs(b'AT+VGM?\r')                                              # 34 read command
    hs(b'AT\r')                                                   # 35 bare AT
    hs(b'xyAT+CKPD=200\r')                                        # 36 ignored prefix
    hs(b'AT+XYZ= "a,b",(1,(2)), 3\r')                             # 37 unknown, quotes, brackets
    hs(b'AT+XYZ\r')                                               # 38 unknown without delimiter
    hs(b'HELLO\r')                                                # 39 no AT
    hs(b'AT+VGS:3\r')                                             # 40 response type from HS
    hs(b'ATRING\r')                                               # 41 AG-only command from HS
    # bthsp_highbyte_reassembly.py: non-ASCII octets
    hs(b'AT+VGS=1\xe9\r')                                         # 42
    hs(b'AT+CKPD=200\r')                                          # 43
    ag(b'\r\n+VGS=\xe9\r\n')                                      # 44
    ag(b'\r\nOK\r\n')                                             # 45
    ag(b'\r\nRING\r\n')                                           # 46
    ag(b'\r\nERROR\r\n')                                          # 47
    ag(b'\r\nOK\r\n\r\nRING\r\n')                                 # 48 two responses
    ag(b'\r\n+XYZ: 1,"a"\r\n')                                    # 49 unknown response
    # HS reassembly: two and three fragments
    hs(b'AT+VG')                                                  # 50
    hs(b'S=5\r')                                                  # 51
    hs(b'AT')                                                     # 52
    hs(b'+CKPD')                                                  # 53
    hs(b'=200\r')                                                 # 54
    # A complete command and the start of the next in one frame
    hs(b'AT+VGS=1\rAT+V')                                         # 55
    hs(b'GM=2\r')                                                 # 56
    # AG reassembly: the first fragment starts with CR LF
    ag(b'\r\n+VG')                                                # 57
    ag(b'M:4\r\n')                                                # 58
    # AG: a response without the leading CR LF, completed by the next
    ag(b'+VGS:1\r\n')                                             # 59
    ag(b'\r\nOK\r\n')                                             # 60
    # Channel 5, remote HSP HS (0x1108): Rcvd = HS, Sent = AG
    p.append((0, uih(RECV, CH5, b'AT+CKPD=200\r')))               # 61
    p.append((0, uih(SENT, CH5, b'\r\nOK\r\n')))                  # 62
    # Channel 7, local HSP AG: Rcvd = HS, Sent = AG
    p.append((0, uih(RECV, CH7, b'AT+VGS=2\r')))                  # 63
    p.append((0, uih(SENT, CH7, b'\r\nOK\r\n')))                  # 64
    # Channel 9, local HSP HS (0x1131): Sent = HS, Rcvd = AG
    p.append((0, uih(SENT, CH9, b'AT+VGM=3\r')))                  # 65
    p.append((0, uih(RECV, CH9, b'\r\n+VGM:3\r\n')))              # 66
    # Exported PDUs: no direction, and Sent; role unknown
    p.append((1, exp_pdu(b'AT+CKPD=200\r')))                      # 67
    p.append((1, exp_pdu(b'\r\nOK\r\n', SENT)))                   # 68
    # Channel 11 has no SDP record: data unless decoded as HSP
    p.append((0, rf(SENT, 22, 0x3f)))                             # 69
    p.append((0, rf(RECV, 22, 0x73)))                             # 70
    p.append((0, uih(SENT, 22, b'AT+CKPD=200\r')))                # 71
    hs(b'AT+CKPD?\r')                                             # 72 read type
    ag(b'\r\nRING:1\r\n')                                        # 73 parameter
    return p


def malformed_capture():
    p = [(0, x) for x in setup()]                                 # 1-21
    # A truncated frame (captured length short of the length on the wire)
    pkt = uih(SENT, CH3, b'AT+VGS=7;+VGM=8;+CKPD=200\r')
    p.append((0, pkt, len(pkt) - 10))                             # 22
    # A message that never ends: over 64 KiB of fragments, the
    # reassembly gives up and starts again
    for n in (32000, 32000, 2000):                                # 23-25
        p.append((0, uih(SENT, CH3, b'A' * n)))
    p.append((0, uih(SENT, CH3, b'AT+CKPD=200\r')))               # 26
    return p


def write_pcapng(name, pkts):
    def block(btype, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for linktype in (201, 252):
        out += block(1, struct.pack('<HHI', linktype, 0, 0))
    for i, item in enumerate(pkts):
        iface, data = item[0], item[1]
        caplen = item[2] if len(item) > 2 else len(data)
        ts = (1700000000 + i) * 1000000
        out += block(6, struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff,
                                    caplen, len(data)) + data[:caplen])
    with open(name, 'wb') as f:
        f.write(out)


if __name__ == '__main__':
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(outdir, 'bthsp-coverage.pcapng'), main_capture())
    write_pcapng(os.path.join(outdir, 'bthsp-coverage-malformed.pcapng'), malformed_capture())
