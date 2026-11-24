#!/usr/bin/env python3
# Generates test/captures/btrfcomm_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the synthetic BT RFCOMM coverage captures. Usage: mkbtrfcomm.py <outdir>
#
# Every packet is built here with struct; nothing comes from a real
# network. A host (localhost) and a remote device 02:00:00:00:00:01 on
# Bluetooth HCI H4 with direction (link type 201): an SDP response with
# records for SPP, DUN, GNSS, LAN Access, HSP AG, an unnamed 16-bit and a
# 128-bit service on RFCOMM channels, then one RFCOMM session with every
# frame type and multiplexer control command, credit based flow control
# and data for the DUN, SPP and GNSS dissectors in packet-btrfcomm.c.
# A second interface with HCI H4 without direction (link type 187) gives
# the "UnknownDirection" paths.
import os
import struct
import sys

SENT, RECV = 0, 1
HANDLE = 0x0001
BDADDR = bytes.fromhex('020000000001')


def h4(direction, ptype, body, phdr=True):
    return (struct.pack('>I', direction) if phdr else b'') + bytes([ptype]) + body


def acl(direction, cid, payload, handle=HANDLE, phdr=True):
    l2 = struct.pack('<HH', len(payload), cid) + payload
    return h4(direction, 2, struct.pack('<HH', (handle & 0x0fff) | 0x2000, len(l2)) + l2, phdr)


def conn_complete(phdr=True):
    ev = struct.pack('<BH', 0, HANDLE) + BDADDR[::-1] + b'\x01\x00'
    return h4(RECV, 4, bytes([0x03, len(ev)]) + ev, phdr)


def l2_connect(direction, psm, scid, dcid, ident, phdr=True):
    req = struct.pack('<BBHHH', 0x02, ident, 4, psm, scid)
    rsp = struct.pack('<BBHHHHH', 0x03, ident, 8, dcid, scid, 0, 0)
    return [acl(direction, 1, req, phdr=phdr), acl(1 - direction, 1, rsp, phdr=phdr)]


def seq(*items):
    b = b''.join(items)
    return bytes([0x35, len(b)]) + b


def u8(v):
    return bytes([0x08, v])


def u16(v):
    return b'\x09' + struct.pack('>H', v)


def u32(v):
    return b'\x0a' + struct.pack('>I', v)


def uuid(v):
    if isinstance(v, bytes):
        return b'\x1c' + v
    return b'\x19' + struct.pack('>H', v)


def sdp_record(svc, channel):
    return seq(u16(0x0001), seq(uuid(svc)),
               u16(0x0004), seq(seq(uuid(0x0100)), seq(uuid(0x0003), u8(channel))))


UUID128 = bytes.fromhex('8a0b1c2d3e4f40518293a4b5c6d7e8f9')
RECORDS = [(0x1101, 1), (0x1103, 2), (0x1112, 3), (0x1136, 4),
           (0x1102, 5), (UUID128, 6), (0x7777, 7)]


def sdp_exchange():
    pkts = l2_connect(SENT, 1, 0x0040, 0x0041, 1)
    params = seq(uuid(0x0003)) + struct.pack('>H', 0xffff) + seq(u32(0x0000ffff)) + b'\x00'
    pkts.append(acl(SENT, 0x0041, struct.pack('>BHH', 0x06, 1, len(params)) + params))
    lists = seq(*[sdp_record(u, c) for u, c in RECORDS])
    params = struct.pack('>H', len(lists)) + lists + b'\x00'
    pkts.append(acl(RECV, 0x0040, struct.pack('>BHH', 0x07, 1, len(params)) + params))
    return pkts


def fcs(data):
    crc = 0xff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xe0 if crc & 1 else crc >> 1
    return 0xff - crc


def rfcomm(dlci, ctrl, payload=b'', cr=1, credits=None):
    addr = (dlci << 2) | (cr << 1) | 1
    if len(payload) < 128:
        ln = bytes([(len(payload) << 1) | 1])
    else:
        ln = struct.pack('<H', len(payload) << 1)
    hdr = bytes([addr, ctrl]) + ln
    f = fcs(hdr[:2]) if (ctrl & 0xef) == 0xef else fcs(hdr)
    cr_ = bytes([credits]) if credits is not None else b''
    return hdr + cr_ + payload + bytes([f])


# RFCOMM L2CAP channel: the host connects, host CID 0x0042, remote 0x0043
R_SCID, R_DCID = 0x0042, 0x0043
SABM, UA, DM, DISC, UIH, UI = 0x2f, 0x63, 0x0f, 0x43, 0xef, 0x03
PF = 0x10


def rf(direction, dlci, ctrl, payload=b'', credits=None, phdr=True):
    cid = R_DCID if direction == SENT else R_SCID
    cr = 1 if direction == SENT else 0
    return acl(direction, cid, rfcomm(dlci, ctrl, payload, cr, credits), phdr=phdr)


def ea_len(n):
    """MCC length: 7 bits per octet, E/A bit set in the last."""
    out = []
    while True:
        out.append((n & 0x7f) << 1)
        n >>= 7
        if not n:
            break
    out[-1] |= 1
    return bytes(out)


def mcc(mtype, data, cr=1, length=None):
    t = bytes([(mtype << 2) | (cr << 1) | 1]) if isinstance(mtype, int) else mtype
    return t + (ea_len(len(data)) if length is None else length) + data


PN, TEST, FCON, FCOFF, MSC, NSC, RPN, RLS = 0x20, 0x08, 0x28, 0x18, 0x38, 0x04, 0x24, 0x14


def pn(dlci, cl, prio, t1, n1, n2, k):
    return bytes([dlci, cl << 4, prio, t1]) + struct.pack('<H', n1) + bytes([n2, k])


def msc_addr(dlci):
    return bytes([(dlci << 2) | 0x03])


def ppp_fcs16(data):
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xffff


def hdlc(frame):
    frame += struct.pack('<H', ppp_fcs16(frame))
    out = bytearray(b'\x7e')
    for b in frame:
        if b in (0x7e, 0x7d) or b < 0x20:
            out += bytes([0x7d, b ^ 0x20])
        else:
            out.append(b)
    out.append(0x7e)
    return bytes(out)


def main_capture():
    """(interface, packet) list. Frame numbers are in the README."""
    p = [conn_complete()] + sdp_exchange()                        # 1-5
    p += l2_connect(SENT, 3, R_SCID, R_DCID, 2)                   # 6-7
    tx = lambda *a, **k: p.append(rf(SENT, *a, **k))
    rx = lambda *a, **k: p.append(rf(RECV, *a, **k))

    tx(0, SABM | PF)                                              # 8
    rx(0, UA | PF)                                                # 9
    # PN for channel 1 asking for credit based flow control, and the answer
    tx(0, UIH, mcc(PN, pn(2, 0xf, 7, 0, 127, 0, 7)))              # 10
    rx(0, UIH, mcc(PN, pn(2, 0xe, 7, 0, 127, 0, 3), cr=0))        # 11
    tx(2, SABM | PF)                                              # 12 (Serial Port)
    rx(2, UA | PF)                                                # 13
    # MSC with and without a break signal octet, and the answer
    tx(0, UIH, mcc(MSC, msc_addr(2) + b'\x8d'))                   # 14
    rx(0, UIH, mcc(MSC, msc_addr(2) + b'\x8d', cr=0))             # 15
    tx(0, UIH, mcc(MSC, msc_addr(2) + b'\xcf\x31'))               # 16
    # RPN: request (DLCI only) and with the port settings
    tx(0, UIH, mcc(RPN, msc_addr(2)))                             # 17
    rx(0, UIH, mcc(RPN, msc_addr(2) + bytes([0x03, 0x03, 0x00, 0x11, 0x13, 0x7f, 0x3f]), cr=0))  # 18
    # RLS, Test with 130 octets (2 octet MCC and frame lengths)
    tx(0, UIH, mcc(RLS, msc_addr(2) + b'\x03'))                   # 19
    tx(0, UIH, mcc(TEST, bytes(range(130))))                      # 20
    rx(0, UIH, mcc(TEST, bytes(range(130)), cr=0))                # 21
    # FCon, FCoff, NSC for an unsupported type
    tx(0, UIH, mcc(FCON, b''))                                    # 22
    tx(0, UIH, mcc(FCOFF, b''))                                   # 23
    rx(0, UIH, mcc(NSC, bytes([(0x0f << 2) | 0x03]), cr=0))       # 24
    # An unknown one octet type, and two octet type that comes out as 0
    tx(0, UIH, mcc(0x0f, b''))                                    # 25
    tx(0, UIH, mcc(b'\x02\x01', b''))                             # 26
    # Five octet type (the fifth octet lands in bits 28-31, unsigned now)
    # and a five octet MCC length of 0
    tx(0, UIH, mcc(b'\x3c\x00\x00\x00\xff', b''))                 # 27
    tx(0, UIH, mcc(TEST, b'', length=b'\x00\x00\x00\x00\x01'))    # 28
    # btrfcomm_mcc.py: Test (no "-> 255"), MSC length 1
    tx(0, UIH, mcc(TEST, b'test'))                                # 29
    tx(0, UIH, mcc(MSC, b'\x0b'))                                 # 30
    # SPP data with credits; credits alone; data without credits
    tx(2, UIH | PF, b'hello\r\n', credits=7)                      # 31
    rx(2, UIH | PF, b'', credits=5)                               # 32
    rx(2, UIH, b'\x80\x81\x82binary')                             # 33
    tx(2, UIH, b'0123456789' * 7)                                 # 34 over 60 octets
    # DUN on channel 2: AT command, and PPP in HDLC framing
    tx(4, SABM | PF)                                              # 35 (Dialup Networking)
    rx(4, UA | PF)                                                # 36
    tx(4, UIH, b'ATDT*99#\r')                                     # 37
    lcp = b'\xff\x03\xc0\x21' + bytes([0x09, 0x01, 0x00, 0x08]) + b'\x00\x00\x00\x00'
    tx(4, UIH, hdlc(lcp))                                         # 38 LCP Echo-Request
    # HSP AG on channel 3 (bthsp), GNSS on channel 4
    tx(6, SABM | PF)                                              # 39
    rx(6, UA | PF)                                                # 40
    tx(6, UIH, b'AT+CKPD=200\r')                                  # 41
    tx(8, SABM | PF)                                              # 42 (GNSS Server)
    rx(8, UA | PF)                                                # 43
    rx(8, UIH, b'$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\r\n')  # 44
    # LAN Access (named, no dissector), 128 bit and unnamed 16 bit UUIDs
    tx(10, SABM | PF)                                             # 45 (LAN Access Using PPP)
    tx(10, UIH, b'lan')                                           # 46
    tx(12, SABM | PF)                                             # 47 (UUID: 8a0b1c2d-...)
    tx(12, UIH, b'uuid128')                                       # 48
    tx(14, SABM | PF)                                             # 49 (UUID: 7777)
    tx(14, UIH, b'uuid16')                                        # 50
    # Channel 10: no SDP record (no "(UUID: (null))")
    tx(20, SABM | PF)                                             # 51
    rx(20, DM | PF)                                               # 52
    tx(20, UIH, b'nosdp')                                         # 53
    # Channel 1 opened again (the first service direction ends here),
    # an unknown frame type (UI), then DISC/UA
    tx(2, SABM | PF)                                              # 54
    rx(2, UA | PF)                                                # 55
    tx(2, UI, b'ui')                                              # 56
    tx(2, DISC | PF)                                              # 57
    rx(2, UA | PF)                                                # 58
    # A SABM on DLCI 7 is stored under 7 and looked up for channel 7
    # (DLCI 14/15): the next frame on channel 7 takes its direction
    rx(7, SABM | PF)                                              # 59
    tx(14, UIH, b'uuid16')                                        # 60
    # Multiplexer DISC
    tx(0, DISC | PF)                                              # 61
    rx(0, UA | PF)                                                # 62
    p = [(0, x) for x in p]
    # HCI H4 without direction (link type 187): the L2CAP connection
    # frames carry the pcapng direction flag (outbound 2, inbound 1), the
    # RFCOMM frames none, so they have an unknown direction
    q = [(1, conn_complete(False))]                               # 63
    q += [(1, x, f) for x, f in zip(l2_connect(SENT, 3, R_SCID, R_DCID, 3, phdr=False), (2, 1))]  # 64-65
    q += [(1, acl(SENT, R_DCID, rfcomm(0, SABM | PF), phdr=False)),          # 66
          (1, acl(SENT, R_DCID, rfcomm(2, UIH, b'unknown'), phdr=False))]    # 67
    p += q
    # The remote device asks the host: SPP on the host's channel 13
    # (an SDP record with direction "Sent"), then data on DLCI 27
    r = l2_connect(RECV, 1, 0x0060, 0x0061, 4)                    # 68-69
    params = seq(uuid(0x1101)) + struct.pack('>H', 0xffff) + seq(u32(0x0000ffff)) + b'\x00'
    r.append(acl(RECV, 0x0061, struct.pack('>BHH', 0x06, 2, len(params)) + params))   # 70
    lists = seq(sdp_record(0x1101, 13))
    params = struct.pack('>H', len(lists)) + lists + b'\x00'
    r.append(acl(SENT, 0x0060, struct.pack('>BHH', 0x07, 2, len(params)) + params))   # 71
    r += [rf(RECV, 27, SABM | PF), rf(SENT, 27, UA | PF),         # 72-73
          rf(RECV, 27, UIH, b"local spp")]                        # 74
    p += [(0, x) for x in r]
    return p


def malformed_capture():
    p = [conn_complete()] + sdp_exchange() + l2_connect(SENT, 3, R_SCID, R_DCID, 2)  # 1-7
    tx = lambda *a, **k: p.append(rf(SENT, *a, **k))
    tx(0, SABM | PF)                                              # 8
    # btrfcomm_mcc.py: a five octet type that comes out as
    # PN, with no PN data (exception); a five octet length of 2^32-1
    tx(0, UIH, mcc(b'\x82\x00\x00\x00\x01', b''))                 # 9
    tx(0, UIH, bytes([0x23, 0xfe, 0xfe, 0xfe, 0xfe, 0xff]))       # 10
    # MCC length past the end of the frame
    tx(0, UIH, mcc(TEST, b'ab', length=b'\x41'))                  # 11
    # MSC and RPN with no DLCI octet, PN cut short
    tx(0, UIH, mcc(MSC, b''))                                     # 12
    tx(0, UIH, mcc(RPN, b''))                                     # 13
    tx(0, UIH, mcc(PN, b'\x02\xf0\x07'))                          # 14
    # Frame length past the end of the packet, frame without FCS,
    # two octet length with only one octet
    p.append(acl(SENT, R_DCID, bytes([0x0b, UIH, (40 << 1) | 1]) + b'short'))  # 15
    p.append(acl(SENT, R_DCID, bytes([0x0b, UIH, 0x01])))         # 16
    p.append(acl(SENT, R_DCID, bytes([0x0b, UIH])))               # 17
    p.append(acl(SENT, R_DCID, bytes([0x0b, UIH | PF, 0x01])))    # 18 credits missing
    return [(0, x) for x in p]


def write_pcapng(name, pkts):
    def block(btype, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for linktype in (201, 187):
        out += block(1, struct.pack('<HHI', linktype, 0, 0))
    for i, item in enumerate(pkts):
        iface, data = item[0], item[1]
        opts = b''
        if len(item) > 2:       # epb_flags (direction), then opt_endofopt
            opts = struct.pack('<HHI', 2, 4, item[2]) + b'\0' * 4
        ts = (1700000000 + i) * 1000000
        data_pad = data + b'\0' * (-len(data) % 4)
        out += block(6, struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data_pad + opts)
    with open(name, 'wb') as f:
        f.write(out)


if __name__ == '__main__':
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(outdir, 'btrfcomm-coverage.pcapng'), main_capture())
    write_pcapng(os.path.join(outdir, 'btrfcomm-coverage-malformed.pcapng'), malformed_capture())
