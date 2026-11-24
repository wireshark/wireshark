#!/usr/bin/env python3
# Generates test/captures/trmac_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds trmac-coverage.pcap (Token Ring, linktype 6) and trmac-coverage-malformed.pcap
import struct
import sys
import os
from pcaplib import write, tr_frame

def sv(sid, data=b'', length=None):
    return bytes([len(data) + 2 if length is None else length, sid]) + data

def mac(mv, svs=(), sc=0, dc=0, length=None):
    """MAC frame body: total length (2), classes (dst<<4 | src), major vector, subvectors."""
    body = b''.join(svs)
    n = 4 + len(body) if length is None else length
    return struct.pack('!HBB', n, (dc << 4) | sc, mv) + body

MAC48 = bytes([0x00, 0x00, 0xc0, 0x12, 0x34, 0x56])
def main(out):
    F = lambda p, **kw: tr_frame(p, **kw)
    fr = []
    # major vectors with the subvectors that belong to them
    fr.append(F(mac(0x02, [sv(0x01, b'\x00\x01'), sv(0x02, MAC48)])))                      # Beacon, signal loss, NAUN
    for t in (0, 2, 3, 4):                                                                  # every beacon type (4 is illegal)
        fr.append(F(mac(0x02, [sv(0x01, struct.pack('!H', t))])))
    fr.append(F(mac(0x03, [sv(0x03, b'\x00\x2a')])))                                       # Claim Token, local ring number
    fr.append(F(mac(0x04, [sv(0x03, b'\x0f\xff'), sv(0x02, MAC48)])))                      # Ring Purge
    fr.append(F(mac(0x05, [sv(0x02, MAC48)])))                                             # Active Monitor Present
    fr.append(F(mac(0x06, [sv(0x02, MAC48)])))                                             # Standby Monitor Present
    fr.append(F(mac(0x07)))                                                                # Duplicate Address Test, no subvectors
    fr.append(F(mac(0x09, [sv(0x2a, b'\x80\x01')], sc=0, dc=0)))                           # Transmit Forward
    fr.append(F(mac(0x0b, [sv(0x30, b'\x01\x02')])))                                       # Remove Ring Station
    fr.append(F(mac(0x0c, [sv(0x03, b'\x00\x10'), sv(0x05, b'\x01\xf4'), sv(0x04, b'\x00\x00\x00\x07'),
                           sv(0x06, b'\xff\xff'), sv(0x07, b'\x00\x03')], sc=5, dc=0)))   # Change Parameters
    fr.append(F(mac(0x0d, [sv(0x02, MAC48), sv(0x09, b'\x12\x34')], sc=4, dc=0)))          # Initialize Ring Station
    fr.append(F(mac(0x0e, [sv(0x09, b'\xab\xcd')], sc=1, dc=0)))                           # Request Ring Station Address
    fr.append(F(mac(0x0f, [sv(0x09, b'\xab\xce')], sc=1, dc=0)))                           # Request Ring Station State
    fr.append(F(mac(0x10, [sv(0x09, b'\xab\xcf')], sc=1, dc=0)))                           # Request Ring Station Attachments
    fr.append(F(mac(0x20, [sv(0x0b, b'\x00\x00\x00\x08'), sv(0x22, bytes(range(10)))], sc=0, dc=5)))   # Request Initialization
    fr.append(F(mac(0x22, [sv(0x09, b'\x00\x01'), sv(0x0b, b'\x00\x00\x00\x09'), sv(0x02, MAC48),
                           sv(0x28, MAC48), sv(0x0a, MAC48), sv(0x21, b'\x00\x02')], sc=0, dc=4)))   # Report Ring Station Address
    fr.append(F(mac(0x23, [sv(0x09, b'\x00\x02'), sv(0x26, b'wrap data'), sv(0x27, b'\xaa\xbb'), sv(0x29, b'\x01\x02\x03\x04\x05\x06'),
                           sv(0x23, b'\x01\x00\x00\x03'), sv(0x22, b'product')], sc=0, dc=4)))   # Report Ring Station State
    fr.append(F(mac(0x24, [sv(0x09, b'\x00\x03'), sv(0x2c, b'\x00\x00\x00\x80'), sv(0x2b, b'\xc0\x00\x00\x01'),
                           sv(0x2b, MAC48), sv(0x2f, b'\x00\x01')], sc=0, dc=4)))   # Report Ring Station Attachments (0x2f: unknown to the dissector)
    fr.append(F(mac(0x25, [sv(0x02, MAC48)], sc=0, dc=4)))                                 # Report New Active Monitor
    fr.append(F(mac(0x26, [sv(0x02, MAC48), sv(0x0a, MAC48)], sc=0, dc=6)))                # Report NAUN Change
    fr.append(F(mac(0x27, [sv(0x2d, bytes([1, 2, 3, 4, 5, 0])), sv(0x2e, bytes([6, 7, 8, 9, 10, 0]))], sc=0, dc=6)))  # Report Poll Error
    fr.append(F(mac(0x28, [sv(0x2d, bytes([0, 0, 0, 0, 0, 0])), sv(0x2e, bytes([255] * 6))], sc=0, dc=6)))             # Report Monitor Errors
    fr.append(F(mac(0x29, [sv(0x2d, bytes([9, 8, 7, 6, 5, 4])), sv(0x2e, bytes([1, 1, 1, 1, 1, 1])), sv(0x02, MAC48)], sc=0, dc=6)))  # Report Error
    fr.append(F(mac(0x2a, [sv(0x2a, b'\x00\x01')], sc=0, dc=1)))                           # Report Transmit Forward
    # Response with the Response Code in both lengths; each is followed by another subvector because the dissector reads past the field
    fr.append(F(mac(0x00, [sv(0x20, b'\x80\x00'), sv(0x09, b'\x11\x22'), sv(0x02, MAC48)], sc=0, dc=1)))
    fr.append(F(mac(0x00, [sv(0x20, b'\x00\x01\x02\x03'), sv(0x09, b'\x11\x23'), sv(0x02, MAC48)], sc=0, dc=1)))
    # unknown major vector and unknown subvector, classes: every defined one and undefined
    fr.append(F(mac(0x7f, [sv(0x31, b'unknown data'), sv(0x32)], sc=0x0f, dc=0x0e)))
    fr.append(F(mac(0x08, [sv(0x01, b'\x00\x00')], sc=2, dc=3)))
    # variable subvectors with no data and with a lot of data; group address in both lengths
    fr.append(F(mac(0x23, [sv(0x22), sv(0x23), sv(0x26), sv(0x27), sv(0x29), sv(0x2b, b'\x00\x00\x00\x01')], sc=0, dc=4)))
    fr.append(F(mac(0x23, [sv(0x26, bytes(range(250)))], sc=0, dc=4)))
    # a frame with FCS-like padding after the MAC frame and a major vector that is longer than the frame
    fr.append(F(mac(0x05, [sv(0x02, MAC48)]) + b'\x00' * 4))
    write(os.path.join(out, 'trmac-coverage.pcap'), fr, linktype=6)
    print('main frames', len(fr))

    m = []
    G = lambda p: tr_frame(p)
    m.append(G(mac(0x02, [sv(0x01, b'\x00')])))                                    # Beacon Type length 3
    m.append(G(mac(0x02, [sv(0x02, MAC48[:4])])))                                  # NAUN length 6
    m.append(G(mac(0x03, [sv(0x03, b'\x00\x01\x02')])))                            # Local ring length 5
    m.append(G(mac(0x0c, [sv(0x04, b'\x00\x01')])))                                # Assign Physical Drop length 4
    m.append(G(mac(0x0c, [sv(0x05, b'\x00')])))                                    # Error Report Timer length 3
    m.append(G(mac(0x0c, [sv(0x06, b'\x00')])))                                    # Authorized Function Classes
    m.append(G(mac(0x0c, [sv(0x07, b'')])))                                        # Authorized Access Priority
    m.append(G(mac(0x0e, [sv(0x09, b'\x00')])))                                    # Correlator
    m.append(G(mac(0x22, [sv(0x0a, b'\x00')])))                                    # SA of last AMP/SMP
    m.append(G(mac(0x22, [sv(0x0b, b'\x00')])))                                    # Physical Drop Number
    m.append(G(mac(0x00, [sv(0x20, b'\x00')])))                                    # Response Code length 3
    m.append(G(mac(0x22, [sv(0x21, b'\x00')])))                                    # Individual Address Count
    m.append(G(mac(0x22, [sv(0x28, b'\x00')])))                                    # Station Identifier
    m.append(G(mac(0x2a, [sv(0x2a, b'\x00')])))                                    # Transmit Status Code
    m.append(G(mac(0x24, [sv(0x2b, b'\x00\x01\x02')])))                            # Group Address length 5
    m.append(G(mac(0x24, [sv(0x2c, b'\x00')])))                                    # Functional Addresses
    m.append(G(mac(0x27, [sv(0x2d, b'\x00')])))                                    # Isolating errors
    m.append(G(mac(0x27, [sv(0x2e, b'\x00')])))                                    # Non-isolating errors
    m.append(G(mac(0x0b, [sv(0x30, b'\x00')])))                                    # Error Code
    m.append(G(mac(0x02, [bytes([1, 0x01])])))                                     # subvector length 1: stops the loop
    m.append(G(mac(0x02, [bytes([0, 0x01])])))                                     # subvector length 0
    m.append(G(mac(0x02, [sv(0x01, b'\x00\x01'), b'\x04'], length=12)))            # subvector cut at the end of the frame
    m.append(G(mac(0x00, [sv(0x20, b'\x80\x00')])))                                # response code last: reads past the subvector
    m.append(G(mac(0x00, [sv(0x20, b'\x00\x01\x02\x03')])))
    m.append(G(mac(0x23, [sv(0x26, b'abcdef')], length=0xffff)))                   # total length far beyond the frame
    m.append(G(b'\x00\x04'))                                                       # 2 octets: not MAC
    m.append(G(mac(0x02, [sv(0x01, b'\x00\x01')], length=3)))                      # length below the header
    write(os.path.join(out, 'trmac-coverage-malformed.pcap'), m, linktype=6)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
