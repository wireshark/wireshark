#!/usr/bin/env python3
# Generates test/captures/homeplug_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the HomePlug 1.0 dissector
(packet-homeplug.c, ethertype 0x887B).

A HomePlug 1.0 frame is a MAC control octet (number of MAC data
entries), then per entry a MAC entry header octet (version and METYPE),
a MAC entry length octet and the management message.  The dissector only
advances by what it decodes, so frames with several entries use
messages whose decoded size equals the entry length.  Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkhomeplug.py <output directory>

Writes:
  homeplug-coverage.pcap            every MME type and all the branches of
                                    the loader, host request/response,
                                    network statistics (basic/extended),
                                    bridging characteristics, channel
                                    estimation and transmit characteristics
  homeplug-coverage-malformed.pcap  entries cut short, entry lengths past
                                    the end of the frame
"""
import struct
import sys

ETYPE = 0x887B


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, pad=True):
    fr = bytes([2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]) + struct.pack('>H', ETYPE) + payload
    if pad and len(fr) < 60:
        fr += bytes(60 - len(fr))
    return fr


def ent(metype, payload, mev=1, melen=None):
    if melen is None:
        melen = len(payload)
    return bytes([(mev << 5) | metype, melen]) + payload


def frame(*entries, ne=None, rsvd=0):
    if ne is None:
        ne = len(entries)
    return bytes([(rsvd << 7) | ne]) + b''.join(entries)


# METYPE values
RCE, CER, VS, RBA, SNK, MWR, CNK, RPS, PSR = 0, 1, 2, 3, 4, 5, 6, 7, 8
LOADER, HREQ, HRSP, HTAG, SLP, NS, RES, PS, SLO, BC, STC = \
    0x10, 0x12, 0x13, 0x14, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F

MAC = lambda n: bytes([2, 0, 0, 0, 0, n])
NONE_DA = bytes([0, 0, 0x40, 0, 0, 0])   # HOMEPLUG_ADDR_INEXISTANT (octal 010000000000)


def loader(mid, length, rest=b''):
    return ent(LOADER, bytes([mid]) + struct.pack('>H', length) + rest)


def hreq(mid, extra=b''):
    p = bytes([mid]) + extra
    return ent(HREQ, p + bytes(max(0, 3 - len(p))))


def hrsp(mid, extra=b''):
    return ent(HRSP, bytes([mid]) + extra)


def ns_body(extended, missing_first=False, icid=0, ac=1):
    """Network Statistics body: 7 octets of ROBO statistics, 15 tone maps
    of 12 octets and, in the extended form, 6 TX buffer states of 2
    octets (187 and 199 octets).  A tone map that does not exist does
    not advance the dissector, so the body is padded to the length."""
    b = bytes([(ac << 7) | icid]) + struct.pack('<H', 0x1234) + struct.pack('<HH', 3, 4)
    if missing_first:
        b += NONE_DA + bytes(6)
    else:
        for n in range(15):
            b += MAC(0x10 + n) + struct.pack('<H', 0x200 + n) + struct.pack('<HH', n, n + 1)
    if extended:
        for i in range(6):
            b += bytes([0x80 | (i << 5) | i, (i << 4) | i])
    return b + bytes(max(0, (199 if extended else 187) - len(b)))


def main(out):
    f = []
    # 1: MME with no entries, only the control octet
    f.append(eth(frame(ne=0)))
    # 2: Request Channel Estimation, reserved MCTRL bit set
    f.append(eth(frame(ent(RCE, b'\x50'), rsvd=1)))
    # 3-5: Channel Estimation Response without and with the bridged
    # addresses (BP bit) and with 0 and 2 bridged addresses
    cer_hdr = b'\x30\x01' + b'\x05'                           # CERV, RSVD, RXTMI
    vts = bytes(range(0x11, 0x1b))
    f.append(eth(frame(ent(CER, cer_hdr + vts + b'\x80'))))   # rate, no BP
    f.append(eth(frame(ent(CER, cer_hdr + vts + b'\x4a' + b'\x00'))))   # BP, 0 DAs
    f.append(eth(frame(ent(CER, cer_hdr + vts + b'\x7f' + b'\x82' + MAC(1) + MAC(2)))))
    # 6: Vendor Specific
    f.append(eth(frame(ent(VS, b'\x00\x01\x02\x85'))))
    # 7: Replace Bridge Address
    f.append(eth(frame(ent(RBA, MAC(5) + MAC(6)))))
    # 8: Set Network Encryption Key
    f.append(eth(frame(ent(SNK, b'\x03' + bytes(range(8))))))
    # 9: Multicast With Response
    f.append(eth(frame(ent(MWR, b'\x01\x02\x03\x04'))))
    # 10: Confirm Network Encryption Key
    f.append(eth(frame(ent(CNK, b'\x01'))))
    # 11: Request Parameters and Statistics
    f.append(eth(frame(ent(RPS, b'\x01\x02'))))
    # 12: Parameters and Statistics Response
    f.append(eth(frame(ent(PSR, struct.pack('>9HI', 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x01020304)))))
    # 13: Set Local Parameters
    f.append(eth(frame(ent(SLP, MAC(9)))))
    # 14: Host Tag
    f.append(eth(frame(ent(HTAG, b'\xde\xad\xbe\xef'))))
    # 15-17: reserved METYPEs (unknown, shown as data)
    f.append(eth(frame(ent(RES, b'\x01\x02\x03'))))
    f.append(eth(frame(ent(PS, b'\x04\x05'))))
    f.append(eth(frame(ent(SLO, b'\x06'))))
    # 18: Set Transmit Characteristics
    f.append(eth(frame(ent(STC, b'\xff\xff\x07'))))
    # 19: STC with every flag clear
    f.append(eth(frame(ent(STC, b'\x00\x00\x00'))))
    # 20-22: bridging characteristics, local with 0 and 3 proxied
    # addresses, and network with two bridges
    f.append(eth(frame(ent(BC, b'\x00\x00'))))
    f.append(eth(frame(ent(BC, b'\x40\x03' + MAC(1) + MAC(2) + MAC(3)))))
    bn = b'\xc3' + MAC(1) + b'\x01' + MAC(2) + MAC(3) + b'\x02' + MAC(4) + MAC(5)
    f.append(eth(frame(ent(BC, bn))))
    # 23-26: Network Statistics basic and extended, other IC_IDs,
    # clear instead of return, a tone map that does not exist
    f.append(eth(frame(ent(NS, ns_body(False), melen=187))))
    f.append(eth(frame(ent(NS, ns_body(True, icid=3), melen=199))))
    f.append(eth(frame(ent(NS, ns_body(False, icid=0x10, ac=0), melen=187))))
    f.append(eth(frame(ent(NS, ns_body(False, missing_first=True, icid=4), melen=187))))
    # 27-: Loader MMEs, every message id and both request and response
    L = struct.pack
    f.append(eth(frame(loader(1, 0))))                                  # get firmware version request
    f.append(eth(frame(loader(1, 12, b'\x00' + b'INT6000-MAC-1.0\x00'))))  # response
    f.append(eth(frame(loader(2, 0))))                                  # start firmware
    f.append(eth(frame(loader(4, 7, b'\x00' + L('>IH', 0x00100000, 0)))))   # write memory response
    f.append(eth(frame(loader(4, 14, L('>IH', 0x00100000, 4) + b'\xaa\xbb\xcc\xdd'))))
    f.append(eth(frame(loader(9, 6, L('>IH', 0x00100000, 4)))))        # read memory request
    f.append(eth(frame(loader(9, 11, b'\x00' + L('>IH', 0x00100000, 4) + b'\x01\x02\x03\x04'))))
    f.append(eth(frame(loader(21, 7, L('>IH', 0x00200000, 0)))))         # read NVM request
    f.append(eth(frame(loader(21, 12, b'\x00' + L('>IH', 0x00200000, 3) + b'\x01\x02\x03'))))
    f.append(eth(frame(loader(22, 7, b'\x00' + L('>IH', 0x00200000, 0)))))   # write NVM response
    f.append(eth(frame(loader(22, 13, L('>IH', 0x00200000, 4) + b'\x01\x02\x03\x04'))))
    f.append(eth(frame(loader(127, 0))))                                # reset
    f.append(eth(frame(loader(128, 10, L('>IIH', 7, 0, 16)))))           # get module data request
    f.append(eth(frame(loader(128, 17, b'\x00' + L('>III', 7, 0, 99) + b'\x01\x02\x03\x04'))))
    f.append(eth(frame(loader(129, 13, b'\x00' + L('>III', 7, 0, 99)))))  # set module data response
    f.append(eth(frame(loader(129, 21, L('>IIH', 7, 0, 4) + b'\x01\x02\x03\x04'))))
    f.append(eth(frame(loader(130, 5, b'\x00' + L('>I', 7)))))           # commit module
    f.append(eth(frame(loader(130, 4, L('>I', 7)))))
    f.append(eth(frame(loader(132, 9, b'\x00' + L('>I', 7)))))           # erase module data
    f.append(eth(frame(loader(132, 8, L('>I', 7)))))
    f.append(eth(frame(loader(140, 9, b'\x00' + L('>II', 0x1000, 0x2000)))))  # erase NVM sectors
    f.append(eth(frame(loader(140, 8, L('>II', 0x1000, 0x2000)))))
    f.append(eth(frame(loader(141, 17, b'\x00' + L('>IIII', 1, 256, 4096, 1 << 20)))))  # get NVM params
    f.append(eth(frame(loader(141, 0))))
    f.append(eth(frame(loader(142, 17, b'\x00' + L('>IIII', 1, 256, 4096, 1 << 20)))))  # set NVM params
    f.append(eth(frame(loader(142, 16, L('>IIII', 1, 256, 4096, 1 << 20)))))
    f.append(eth(frame(loader(0x55, 0, b'\x00'))))                      # unknown loader message
    # host requests
    for mid in (1, 32, 33, 39, 64, 66, 68, 72, 103):
        f.append(eth(frame(hreq(mid))))
    f.append(eth(frame(hreq(127, b'\x00\x04\x00\x0a'), )))               # reset, length 4: delay
    f.append(eth(frame(ent(HREQ, bytes([127, 1, 2])))))                  # reset without delay
    f.append(eth(frame(hreq(0x77))))                                      # unknown host request
    # host responses
    f.append(eth(frame(hrsp(1, b'INT6000-1.0\x00'))))
    f.append(eth(frame(hrsp(32, b'MAC-4.2.0\x00'))))
    f.append(eth(frame(hrsp(33, b'\x01' + bytes(range(8))))))
    f.append(eth(frame(hrsp(128, b'\x00'))))
    f.append(eth(frame(hrsp(0x66, b'\x00'))))
    # several entries in one frame (each consumes exactly its length)
    f.append(eth(frame(ent(RCE, b'\x10'), ent(STC, b'\x01\x02\x03'),
                       ent(SLP, MAC(7)), ent(VS, b'\x01\x02\x03\x04'),
                       ent(SNK, b'\x01' + bytes(8)),
                       ent(RPS, b'\x09\x08'), ent(RES, b'\xaa'))))
    # entry version bits and a control octet with the reserved bit and ne
    f.append(eth(frame(ent(STC, b'\x80\x40\x01', mev=7), ent(RCE, b'\x00', mev=0), rsvd=1)))
    pcap(out + '/homeplug-coverage.pcap', f)

    m = []
    m.append(eth(b'', pad=False))                                       # no data at all
    m.append(eth(frame(ent(RCE, b'\x00')).replace(b'\x01', b'\x03', 1)[:1] + b'\x00', pad=False))  # ne=3, MEHDR only
    m.append(eth(bytes([0x02, 0x10]), pad=False))                      # ne=2, MEHDR then no MELEN
    m.append(eth(bytes([0x01, 0x00, 0x05]), pad=False))                # RCE, melen 5, no data
    m.append(eth(bytes([0x01, 0x1A, 0xBB]) + bytes(10), pad=False))    # NS, melen 187, data cut off
    m.append(eth(bytes([0x01, 0x1A, 0xC7]) + bytes(100), pad=False))   # extended cut off
    m.append(eth(bytes([0x01, 0x01, 0x0e]) + bytes(5), pad=False))     # CER cut off
    m.append(eth(bytes([0x01, 0x10, 0x03, 0x04, 0x00]), pad=False))    # loader, write memory short
    m.append(eth(bytes([0x01, 0x10, 0x01, 0x04]), pad=False))          # loader needs a length
    m.append(eth(bytes([0x01, 0x12, 0x02, 0x7f, 0x00]), pad=False))    # host request needs 3 octets
    m.append(eth(bytes([0x01, 0x13, 0x02, 0x21, 0x01]), pad=False))    # host response key cut off
    m.append(eth(bytes([0x01, 0x1E, 0x03, 0x80, 0x00, 0x00]), pad=False))  # BC network cut off
    m.append(eth(bytes([0x01, 0x1E, 0x03, 0x00, 0x05]) + MAC(1), pad=False))  # BC local, 5 addresses, 1 present
    m.append(eth(bytes([0x01, 0x1F, 0x02, 0xff]), pad=False))          # STC cut off
    m.append(eth(bytes([0x01, 0x08, 0x16]) + bytes(5), pad=False))     # PSR cut off
    m.append(eth(bytes([0x01, 0x02, 0x04, 0x00]), pad=False))          # VS cut off
    m.append(eth(bytes([0x01, 0x04, 0x09, 0x01]), pad=False))          # SNK key cut off
    m.append(eth(bytes([0x01, 0x19, 0x06, 0x01]), pad=False))          # SLP cut off
    m.append(eth(bytes([0x01, 0x1B, 0x20, 0x01]), pad=False))          # unknown, melen past the end
    m.append(eth(bytes([0x02, 0x00, 0x01, 0x00, 0x02, 0x01]), pad=False))  # second entry cut off
    m.append(eth(bytes([0x02, 0x00, 0x01, 0x50]), pad=False))          # ne=2, only one entry present
    pcap(out + '/homeplug-coverage-malformed.pcap', m)


if __name__ == '__main__':
    main(sys.argv[1])
