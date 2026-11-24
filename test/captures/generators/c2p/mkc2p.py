#!/usr/bin/env python3
# Generates test/captures/c2p_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Commsignia Capture
Protocol dissector (packet-c2p.c).

C2P runs on UDP port 7943. The first octet holds the version (high
nibble) and the type (low nibble), followed by a 32 bit seconds / 32 bit
milliseconds timestamp and the type specific part. Version 1 carries
DSRC RX/TX, CV2X RX/TX (each followed by an IEEE 802.11 frame) and
navigation records; version 2 carries StationInfo (STI) lists, remote
API messages and injected facility packets. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkc2p.py <output directory>

Writes:
  c2p-coverage.pcap            every message type with typical, boundary
                               and "unavailable" values, every STI type, FAC
                               inject with every facility message range,
                               API messages, unhandled types and versions
  c2p-coverage-malformed.pcap  truncated messages, an STI count larger
                               than the items present, payload lengths
                               past the end
"""

import os
import struct
import sys

SRC = (192, 0, 2, 1)
DST = (198, 51, 100, 2)
PORT = 7943

# STI types: sti_type_t in packet-c2p.c runs from STI_TRANSMISSION_STATE
# (0) to STI_COUNTRY_CODE (98), then STI_PROJECT_00 (128) to STI_PROJECT_31
# (159); STI_TYPE_LAST is 160. Types 99-127 have no name and no entry in
# sti_params (shown as plain integers).
STI_TYPES = 160
INT64_MIN = -2 ** 63
INT64_MAX = 2 ** 63 - 1


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src=SRC, dst=DST, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp(sport, dport, data, src=SRC, dst=DST):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def c2p_frame(data, ident=1):
    return (bytes.fromhex('020000000002020000000001') + b'\x08\x00'
            + ipv4(17, udp(50000, PORT, data), ident=ident))


def hdr(version, mtype, sec=600000000, msec=250):
    return bytes([(version << 4) | mtype]) + struct.pack('>II', sec, msec)


def wlan_data(seq=1, data=b'c2p-test'):
    """An IEEE 802.11 data frame (no FCS) with LLC/SNAP and an IPv4 UDP
    datagram to the discard port, so it decodes cleanly."""
    inner = ipv4(17, udp(40000 + seq, 9, data, (10, 0, 0, 1), (10, 0, 0, 2)),
                 (10, 0, 0, 1), (10, 0, 0, 2), ident=seq)
    return (struct.pack('<HH', 0x0008, 0) + bytes.fromhex('ffffffffffff')
            + bytes.fromhex('020000000011') + bytes.fromhex('020000000011')
            + struct.pack('<H', seq << 4) + bytes.fromhex('aaaa03000000') + b'\x08\x00' + inner)


# version 1 ------------------------------------------------------------------

def dsrc_rx(pch, sch, iface, rate, ant, lat, lon, speed, heading, rssi1, rssi2,
            noise1, noise2, cbr1, cbr2):
    return struct.pack('>BBBBBiiHHbbbbHH', pch, sch, iface, rate, ant, lat, lon, speed,
                       heading, rssi1, rssi2, noise1, noise2, cbr1, cbr2)


def dsrc_tx(pch, sch, iface, rate, ant, lat, lon, speed, heading, txp, tssi1, tssi2):
    return struct.pack('>BBBBBiiHHbbb', pch, sch, iface, rate, ant, lat, lon, speed,
                       heading, txp, tssi1, tssi2)


def cv2x_tx(sps, sps_port, ev_port, txp, v2xid, period, size, prio):
    return struct.pack('>BHHiiiiB', sps, sps_port, ev_port, txp, v2xid, period, size, prio)


def cv2x_rx(sock, etype, rssi, rate):
    return struct.pack('>BHbB', sock, etype, rssi, rate)


def nav(fix, gps, lat, lon, alt, heading, speed, smaj, smin, ori, altacc, hacc, sacc):
    return struct.pack('>BQiiiHHHHHHHH', fix, gps, lat, lon, alt, heading, speed, smaj, smin,
                       ori, altacc, hacc, sacc)


# version 2 ------------------------------------------------------------------

def sti(items, count=None):
    if count is None:
        count = len(items)
    return struct.pack('<I', count) + b''.join(struct.pack('<Iq', t, v) for t, v in items)


def api(direction, ip, port, payload):
    return struct.pack('>B4sHH', direction, bytes(ip), port, len(payload)) + payload


def fac(msg_type, payload, ts=1700000000123, iface=1, src=b'\x02\x00\x00\x00\x00\x21',
        dst=b'\xff' * 6, rate=6000, prio=5, rssi=-70, fingerprint=0x1122334455667788,
        verify=1, psid=0x24, ssp_type=1, ssp=b'\x01\x02\x03', signer=0xa1b2c3d4e5f60718,
        gen=630000000123456, plen=None):
    radio = struct.pack('>QI6s6sHBhQ', ts, iface, src, dst, rate, prio, rssi, fingerprint)
    sec = (struct.pack('>II', verify, psid) + struct.pack('>I', ssp_type)
           + ssp.ljust(31, b'\0') + struct.pack('>I', len(ssp))
           + struct.pack('>QQ', signer, gen))
    assert len(radio) == 37 and len(sec) == 63
    if plen is None:
        plen = len(payload)
    return struct.pack('>I', msg_type) + radio + sec + struct.pack('>H', plen) + payload


def its_mapem(station=1234, revision=42):
    """ITS PDU header (protocol version 2, message ID 5 = MAPEM, station
    ID) and a MapData with every optional field absent (UPER: extension
    bit, 8 presence bits, 7 bit msgIssueRevision)."""
    return struct.pack('>BBI', 2, 5, station) + bytes([0, revision & 0x7f])


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main_frames():
    M = []
    # 1: DSRC RX, typical values (north / east, speed and heading values)
    M.append(hdr(1, 1) + dsrc_rx(172, 184, 1, 12, 1, 474979000, 190402000, 1389, 2715,
                                 -65, -70, -95, -96, 250, 300) + wlan_data(1))
    # 2: DSRC RX, "unavailable" values (channel 0, datarate 0, lat/lon NA,
    # speed NA, heading 3601, RSSI 127, CBR 1001)
    M.append(hdr(1, 1, sec=0, msec=0) + dsrc_rx(0, 0, 0, 0, 0, 900000001, 1800000001, 16383,
                                                3601, 127, 127, 127, 127, 1001, 1001)
             + wlan_data(2))
    # 3: DSRC RX, south / west, standstill, predefined headings
    M.append(hdr(1, 1) + dsrc_rx(178, 0, 2, 6, 2, -338688000, -1512093000, 0, 0,
                                 -1, 0, -128, -100, 0, 1000) + wlan_data(3))
    # 4: DSRC TX, typical values and heading wgs84East
    M.append(hdr(1, 2) + dsrc_tx(172, 0, 1, 12, 1, 474979000, 190402000, 2000, 900,
                                 20, 18, 17) + wlan_data(4))
    # 5: DSRC TX, tx power and TSSI unavailable, heading wgs84South
    M.append(hdr(1, 2) + dsrc_tx(184, 172, 1, 54, 3, 0, 0, 1, 1800, 127, 127, 127)
             + wlan_data(5))
    # 6: CV2X TX, typical values, priority 2
    M.append(hdr(1, 8) + cv2x_tx(1, 2001, 2002, 23, 123456, 100, 300, 2) + wlan_data(6))
    # 7: CV2X TX, tx power unavailable (INT16_MAX), negative values
    M.append(hdr(1, 8) + cv2x_tx(0, 0, 65535, 32767, -1, -100, 0, 7) + wlan_data(7))
    # 8: CV2X RX, typical values
    M.append(hdr(1, 7) + cv2x_rx(3, 0x88dc, -80, 12) + wlan_data(8))
    # 9: CV2X RX, RSSI and datarate unavailable
    M.append(hdr(1, 7) + cv2x_rx(0, 0x86dd, 127, 0) + wlan_data(9))
    # 10: navigation, typical values
    M.append(hdr(1, 3) + nav(1, 1700000000123, 474979000, 190402000, 12345, 1234, 1389,
                             250, 120, 450, 300, 15, 10))
    # 11: navigation, every value unavailable / out of range
    M.append(hdr(1, 3) + nav(0, 0, 900000001, 1800000001, 800001, 3600, 16383, 4095, 4094,
                             3601, 65535, 127, 127))
    # 12: navigation, south / west, negative altitude, wgs84West, standstill
    M.append(hdr(1, 3) + nav(1, 1, -1, -1, -42000, 2700, 0, 0, 4094, 0, 0, 0, 0))

    # 13: STI, every type with a typical value (1000 + type)
    M.append(hdr(2, 5) + sti([(t, 1000 + t) for t in range(STI_TYPES)]))
    # 14: STI, every type "unavailable" (INT64_MIN)
    M.append(hdr(2, 5) + sti([(t, INT64_MIN) for t in range(STI_TYPES)]))
    # 15: STI, every type out of range (minimum), then out of range (maximum)
    M.append(hdr(2, 5) + sti([(t, INT64_MIN + 1) for t in range(STI_TYPES)]))
    M.append(hdr(2, 5) + sti([(t, INT64_MAX) for t in range(STI_TYPES)]))
    # 17: STI, enumerated values (0..3 for each type), negative values,
    # unknown STI types (160, 0xFFFFFFFF), and an empty list
    M.append(hdr(2, 5) + sti([(t, t % 4) for t in range(STI_TYPES)]
                             + [(5, -1500), (52, -125), (160, 7), (0xffffffff, -7)]))
    M.append(hdr(2, 5) + sti([]))

    # 19-20: remote API, received from and sent to the client (the
    # commsigniaapi plugin is not available: data)
    M.append(hdr(2, 11) + api(0, (10, 1, 2, 3), 7942, bytes.fromhex('0001000c') + b'api-request!'))
    M.append(hdr(2, 11) + api(1, (10, 1, 2, 3), 7942, b'api-response'))
    # 21: remote API, unknown direction, empty payload
    M.append(hdr(2, 11) + api(2, (0, 0, 0, 0), 0, b''))

    # 22-: injected facility packets, one per facility message range:
    # EU (ITS MAPEM), US WSA, US J2735, China, and types outside every
    # range (0, 50, 150, 300); the last ones also use the unavailable values
    M.append(hdr(2, 12) + fac(3, its_mapem()))
    M.append(hdr(2, 12) + fac(5, its_mapem(station=0xffffffff, revision=127), psid=0x7f,
                              verify=0, ssp_type=0))
    M.append(hdr(2, 12) + fac(111, b'wsa-payload', psid=0x80, verify=26, ssp_type=2))
    M.append(hdr(2, 12) + fac(100, b'bsm-payload', psid=0x4080, verify=4))
    M.append(hdr(2, 12) + fac(132, b'tlsm-payload', psid=0x204080))
    M.append(hdr(2, 12) + fac(202, b'cn-spat-payload', psid=0x1020407f))
    M.append(hdr(2, 12) + fac(0, b'type-0', ts=0xffffffffffffffff, iface=0xffffffff,
                              rate=65535, prio=255, rssi=32767, fingerprint=0, psid=0xffffffff,
                              signer=0, gen=0, verify=27, ssp_type=3, ssp=b''))
    M.append(hdr(2, 12) + fac(50, b'type-50', psid=0, ts=0))
    M.append(hdr(2, 12) + fac(150, b'type-150', psid=0x10204080))
    M.append(hdr(2, 12) + fac(300, b'', psid=0x20000000))
    M.append(hdr(2, 12) + fac(10, its_mapem(station=0), psid=0x1020407f + 0x10))

    # Unhandled types and versions: header and timestamp only
    # CAN and POTI (version 1), an unknown type, version 2 with a version
    # 1 type, version 0, version 3, version 1 with a version 2 type
    for v, t in ((1, 4), (1, 6), (1, 9), (2, 1), (0, 5), (3, 12), (1, 5), (2, 13)):
        M.append(hdr(v, t, sec=0xffffffff, msec=999) + b'extra')
    return [c2p_frame(m, ident=i + 1) for i, m in enumerate(M)]


def malformed_frames():
    M = []
    # 1: shorter than the header
    M.append(bytes([0x11, 0, 0]))
    # 2-6: DSRC RX, DSRC TX, CV2X RX, CV2X TX, NAV cut short
    M.append(hdr(1, 1) + bytes(10))
    M.append(hdr(1, 2) + bytes(10))
    M.append(hdr(1, 7) + bytes(2))
    M.append(hdr(1, 8) + bytes(10))
    M.append(hdr(1, 3) + bytes(20))
    # 7: STI count larger than the items present (c2p_probe.py frame 4)
    M.append(hdr(2, 5) + sti([(44, 123)] * 50, count=1000))
    # 8: STI count 0xFFFFFFFF, an item cut short (c2p_probe.py frame 1)
    M.append(hdr(2, 5) + struct.pack('<II', 0xffffffff, 0) + struct.pack('<q', 1)[:5])
    # 9: FAC inject cut in the radio parameters (c2p_probe.py frame 2)
    M.append(hdr(2, 12) + struct.pack('>I', 1) + bytes(5))
    # 10: FAC inject payload length past the end
    M.append(hdr(2, 12) + fac(50, b'short', plen=1000))
    # 11: API cut in the metadata (c2p_probe.py frame 3)
    M.append(hdr(2, 11) + bytes(3))
    # 12: API payload length past the end
    M.append(hdr(2, 11) + struct.pack('>B4sHH', 0, b'\0' * 4, 0, 500) + b'abc')
    # 13: FAC inject with a malformed ITS payload
    M.append(hdr(2, 12) + fac(2, struct.pack('>BBI', 2, 2, 1) + b'\xff'))
    # 14: DSRC RX with a truncated 802.11 frame
    M.append(hdr(1, 1) + dsrc_rx(1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) + b'\x08\x00')
    return [c2p_frame(m, ident=i + 1) for i, m in enumerate(M)]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'c2p-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'c2p-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
