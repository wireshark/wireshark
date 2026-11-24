#!/usr/bin/env python3
# Generates test/captures/charging_ase_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Charging ASE dissector
(packet-charging_ase.c, generated from asn1/charging_ase; ETSI ES 201
296 / Q.1218 tariffing data types).

Charging ASE messages are carried in the APM-user information field of
the ISUP/BICC Application Transport parameter (code 120) with
application context identifier 3 (Charging ASE), in an Application
Transport (APM, message type 65) message. The frames are Exported PDUs
(DLT 252) naming "isup" (ITU, 2 octet CIC) or "bicc" (4 octet CIC),
and two name the registered "charging_ase" dissector directly.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcharging_ase.py <output directory>

Writes:
  charging_ase-coverage.pcap            every ChargingMessageType
                                        alternative with every optional
                                        field, currency and pulse tariffs
  charging_ase-coverage-malformed.pcap  extensions (never dissected,
                                        warning), values out of range,
                                        wrong tags, truncated messages, a
                                        segmented APM
"""

import os
import struct
import sys


def L(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(t, v):
    return bytes([t]) + L(len(v)) + v


def ints(v):
    """Minimal two's complement content octets of an INTEGER."""
    n = 1
    while not -(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1)):
        n += 1
    return v.to_bytes(n, 'big', signed=True)


def oidv(s):
    a = [int(x) for x in s.split('.')]
    out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(reversed(enc))
    return out


def bits(unused, *octets):
    return bytes([unused]) + bytes(octets)


NET_A = '0.4.0.1296.1'
NET_B = '1.2.826.0.1.1234'


# ---------------------------------------------------------------- Charging ASE
def cfs(factor=None, scale=None):
    """CurrencyFactorScale { [0] factor DEFAULT 0, [1] scale DEFAULT 0 }"""
    v = b''
    if factor is not None:
        v += tlv(0x80, ints(factor))
    if scale is not None:
        v += tlv(0x81, ints(scale))
    return v


def ref(tag, net=NET_A, refid=1):
    """ChargingReferenceIdentification { [0] OID, [1] INTEGER }"""
    return tlv(tag, tlv(0x80, oidv(net)) + tlv(0x81, ints(refid)))


def tcf(charges, indicators, attempt=None, setup=None):
    """TariffCurrencyFormat"""
    v = b''
    if charges:
        v += tlv(0xa0, b''.join(tlv(0x30, tlv(0xa0, cfs(f, s)) + tlv(0x81, ints(d)) + tlv(0x82, stc))
                                for f, s, d, stc in charges))
    v += tlv(0x81, indicators)
    if attempt is not None:
        v += tlv(0xa2, attempt)
    if setup is not None:
        v += tlv(0xa3, setup)
    return v


def tpf(charges, indicators, attempt=None, setup=None):
    """TariffPulseFormat"""
    v = b''
    if charges:
        v += tlv(0xa0, b''.join(tlv(0x30, tlv(0x80, bytes([p])) + tlv(0x81, struct.pack('>H', iv))
                                          + tlv(0x82, ints(d)))
                                for p, iv, d in charges))
    v += tlv(0x81, indicators)
    if attempt is not None:
        v += tlv(0x82, bytes([attempt]))
    if setup is not None:
        v += tlv(0x83, bytes([setup]))
    return v


def crgt(cci, tariff, dest=True, currency=8, extensions=None):
    """[0] ChargingTariffInformation; tariff is the [1] CHOICE content."""
    v = tlv(0x80, cci) + tlv(0xa1, tariff)
    if extensions:
        v += tlv(0xa2, extensions)
    v += ref(0xa3, refid=1001)
    if dest:
        v += ref(0xa4, NET_B, 2002)
    v += tlv(0x85, ints(currency))
    return tlv(0xa0, v)


def aocrg(cci, addon, dest=True, currency=4, extensions=None):
    """[1] AddOnChargingInformation; addon is the [1] CHOICE element."""
    v = tlv(0x80, cci) + tlv(0xa1, addon)
    if extensions:
        v += tlv(0xa2, extensions)
    v += ref(0xa3, refid=3003)
    if dest:
        v += ref(0xa4, NET_B, 4004)
    v += tlv(0x85, ints(currency))
    return tlv(0xa1, v)


def crga(ack, extensions=None):
    v = tlv(0x80, ack)
    if extensions:
        v += tlv(0xa1, extensions)
    return tlv(0xa2, v + ref(0xa2, refid=1001) + ref(0xa3, NET_B, 2002))


def start(operators=None, extensions=None, refid=5005):
    v = b''
    if operators:
        v += tlv(0xa0, b''.join(tlv(0x06, oidv(o)) for o in operators))
    if extensions:
        v += tlv(0xa1, extensions)
    return tlv(0xa3, v + ref(0xa2, refid=refid))


def stop(ind, operators=None, extensions=None, refid=5005):
    v = tlv(0x80, ind)
    if operators:
        v += tlv(0xa1, b''.join(tlv(0x06, oidv(o)) for o in operators))
    if extensions:
        v += tlv(0xa2, extensions)
    return tlv(0xa4, v + ref(0xa3, refid=refid))


def extension(code, value=b'\x05\x00', criticality=None):
    """ExtensionField { type Code (INTEGER or OID), criticality, [1] value }"""
    v = tlv(0x02, ints(code)) if isinstance(code, int) else tlv(0x06, oidv(code))
    if criticality is not None:
        v += tlv(0x0a, bytes([criticality]))
    return tlv(0x30, v + tlv(0xa1, value))


# ---------------------------------------------------------------- ISUP / BICC
def app_transport(user_info, si_seg=0xc0, slr=None):
    """Application Transport parameter: ACI 3 (Charging ASE, 1 octet
    form), instruction indicators, SI/APM segmentation indicator [, SLR],
    APM-user information."""
    v = bytes([0x83, 0x80, si_seg])
    if slr is not None:
        v += bytes([slr])
    return v + user_info


def apm(user_info, cic=b'\x01\x00', **kw):
    """APM message: CIC, type 65, pointer to the optional part, the
    Application Transport parameter (120), end of optional parameters."""
    p = app_transport(user_info, **kw)
    return cic + bytes([65, 1]) + bytes([120, len(p)]) + p + b'\x00'


def exp_pdu(name, payload):
    n = name.encode()
    pad = (-len(n)) % 4
    return (struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
            + struct.pack('>HH', 0, 0) + payload)


def isup(user_info, **kw):
    return exp_pdu('isup', apm(user_info, **kw))


def bicc(user_info, **kw):
    return exp_pdu('bicc', apm(user_info, cic=struct.pack('<I', 77), **kw))


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1767225600 + i, 0, len(fr), len(fr)) + fr)


# ---------------------------------------------------------------- captures
CCI_ALL = bits(5, 0xe0)       # subscriberCharge, immediateChange, delayUntilStart
CCI_NONE = bits(7, 0x00)


def main_frames():
    f = []
    # 1 CRGT with a currency tariff: current tariff with two
    #   communication charges, call attempt and call setup charges, and a
    #   tariff switch; destination present; euro
    cur = tcf([(150, -2, 60, bits(7, 0x80)), (0, 0, 36000, bits(7, 0x00))],
              bits(7, 0x80), attempt=cfs(5, -1), setup=cfs())
    nxt = tcf([(999999, 3, 0, bits(7, 0x00))], bits(7, 0x00))
    tariff = tlv(0xa0, tlv(0xa0, cur) + tlv(0xa1, tlv(0xa0, nxt) + tlv(0x81, b'\x2c')))
    f.append(isup(crgt(CCI_ALL, tariff)))
    # 2 CRGT with a pulse tariff: current tariff with two communication
    #   charges and call attempt / setup pulses, a tariff switch; no
    #   destination; British pound
    cur = tpf([(1, 30, 600), (2, 0xffff, 0)], bits(7, 0x80), attempt=1, setup=2)
    nxt = tpf([(3, 60, 120)], bits(7, 0x00))
    tariff = tlv(0xa1, tlv(0xa0, cur) + tlv(0xa1, tlv(0xa0, nxt) + tlv(0x81, b'\x10')))
    f.append(isup(crgt(CCI_NONE, tariff, dest=False, currency=4)))
    # 3 CRGT with empty currency and pulse tariffs (all optional fields
    #   absent), the minimum formats, and an unknown currency (extensible)
    f.append(isup(crgt(bits(0, 0x40), tlv(0xa0, b''), currency=0)))
    f.append(isup(crgt(bits(0, 0x40), tlv(0xa1, tlv(0xa0, tpf([], bits(7, 0x00)))), currency=27)))
    f.append(isup(crgt(bits(0, 0x40), tlv(0xa0, tlv(0xa1, tlv(0xa0, tcf([], bits(7, 0x00)))
                                                               + tlv(0x81, b'\x00'))), currency=40)))
    # 6-7 AOCRG: add-on charge as currency (with destination) and as
    #     pulses (without)
    f.append(isup(aocrg(CCI_ALL, tlv(0xa0, cfs(250, -3)))))
    f.append(isup(aocrg(CCI_NONE, tlv(0x81, b'\x03'), dest=False, currency=18)))
    # 8-9 CRGA accepted and not accepted
    f.append(isup(crga(bits(7, 0x80))))
    f.append(isup(crga(bits(7, 0x00))))
    # 10-11 Start with network operators and without
    f.append(isup(start([NET_A, NET_B, '0.4.0.1296.9'])))
    f.append(isup(start()))
    # 12-13 Stop with call attempt charges applicable and two operators,
    #       and without operators
    f.append(isup(stop(bits(7, 0x80), [NET_A, NET_B])))
    f.append(isup(stop(bits(7, 0x00))))
    # 14 BICC APM with a CRGA
    f.append(bicc(crga(bits(7, 0x80))))
    # 15-16 the registered "charging_ase" dissector (no caller in the tree,
    #       reachable as an Exported PDU): a Stop, and an empty PDU
    f.append(exp_pdu('charging_ase', stop(bits(7, 0x80), [NET_B], refid=6006)))
    f.append(exp_pdu('charging_ase', b''))
    return f


def malformed_frames():
    f = []
    # 1-5 extensions (local and global codes, with criticality): the
    #     value is never dissected ("Extensions not dissected", warning)
    f.append(isup(crgt(CCI_ALL, tlv(0xa0, b''), extensions=extension(1))))
    f.append(isup(aocrg(CCI_ALL, tlv(0x81, b'\x01'), extensions=extension('0.4.0.1296.7', criticality=1))))
    f.append(isup(crga(bits(7, 0x80), extensions=extension(2, criticality=0))))
    f.append(isup(start([NET_A], extensions=extension(3))))
    f.append(isup(stop(bits(7, 0x80), [NET_A], extensions=extension(4))))
    # 6 currency scale and factor out of range, tariff duration out of range
    cur = tcf([(1000000, 4, 36001, bits(7, 0x00))], bits(7, 0x00), attempt=cfs(1, -8))
    f.append(isup(crgt(CCI_ALL, tlv(0xa0, tlv(0xa0, cur)))))
    # 7 bit strings longer than 8 bits, an empty bit string
    f.append(isup(crga(bits(0, 0x80, 0x00))))
    f.append(isup(stop(b'')))
    # 9 an unknown ChargingMessageType alternative [5]
    f.append(isup(tlv(0xa5, b'\x80\x01\x00')))
    # 10 mandatory originationIdentification missing
    f.append(isup(tlv(0xa3, b'')))
    # 11 a CRGT cut short, 12 a Stop with a length past the end
    f.append(isup(crgt(CCI_ALL, tlv(0xa0, b''))[:12]))
    f.append(isup(b'\xa4\x40\x80\x02\x07\x80'))
    # 13 pulse units of two octets, switchover time of three
    f.append(isup(aocrg(CCI_ALL, tlv(0x81, b'\x01\x02'))))
    f.append(isup(crgt(CCI_ALL, tlv(0xa1, tlv(0xa1, tlv(0xa0, tpf([], bits(7, 0)))
                                                 + tlv(0x81, b'\x01\x02\x03'))))))
    # 15-16 an APM segmented in two (SI and APM segmentation indicator,
    #       segmentation local reference): ISUP also passes the first
    #       segment alone to Charging ASE (exception), the second
    #       reassembles the CRGT
    msg = crgt(CCI_ALL, tlv(0xa1, tlv(0xa0, tpf([(1, 30, 600)] * 4, bits(7, 0x80), attempt=1, setup=2))))
    half = len(msg) // 2
    f.append(isup(msg[:half], si_seg=0x41, slr=0x85))
    f.append(isup(msg[half:], si_seg=0x00, slr=0x85))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'charging_ase-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'charging_ase-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
