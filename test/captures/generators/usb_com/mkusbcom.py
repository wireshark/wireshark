#!/usr/bin/env python3
# Generates test/captures/usb_com_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the USB communications (CDC) coverage captures (packet-usb-com.c).

usage: mkusbcom.py <outdir> [-v]
Writes usb-com-coverage.pcapng and usb-com-coverage-malformed.pcapng.
Linux usbmon (64 octet header, bus 1) devices:
  2  CDC ACM (serial) with call management, union, bulk data
  3  CDC ECM (Ethernet without FCS) with an ECM functional descriptor
  4  CDC NCM with NTB16 transfers
  5  CDC MBIM with MBIM functional descriptors, control messages and NTBs
and a USBPcap and a FreeBSD copy of an ACM device.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from usbgen import (
    BULK, Bus, cfg_desc, dev_desc, ep_desc, iad_desc, if_desc, INT, LT_USB_FREEBSD,
    LT_USB_LINUX_MM, LT_USBPCAP, Pcapng, setup,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []

OUT_IF = 0x21
IN_IF = 0xa1


def mark(w, name, start):
    RANGES.append((name, start + 1, w.count))


def cs(subtype, body=b'', typ=0x24):
    return bytes([3 + len(body), typ, subtype]) + body


def ip_checksum(b):
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4_udp(data=b'ping', sport=1234, dport=5678):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + struct.pack('!H', ip_checksum(ip)) + ip[12:]
    return ip + udp


def eth_frame(payload=None):
    if payload is None:
        payload = ipv4_udp()
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + payload


def ntb16(datagrams, sig=b'NCM0', seq=1):
    """NTH16 + datagrams + NDP16"""
    pos = 12
    body = b''
    entries = []
    for d in datagrams:
        entries.append((pos, len(d)))
        body += d
        pos += len(d)
        pad = -pos % 4
        body += b'\0' * pad
        pos += pad
    ndp_len = 8 + 4 * (len(entries) + 1)
    ndp = sig + struct.pack('<HH', ndp_len, 0) + b''.join(struct.pack('<HH', i, l) for i, l in entries) + b'\0\0\0\0'
    block = pos + len(ndp)
    nth = b'NCMH' + struct.pack('<HHHH', 12, seq, block, pos)
    return nth + body + ndp


def acm_config():
    b = iad_desc(0, 2, 2, 2, 1)
    b += if_desc(0, 0, 1, 2, 2, 1)
    b += cs(0, struct.pack('<H', 0x0110))                       # header functional descriptor
    b += cs(1, bytes([0x03, 1]))                                # call management (capabilities, data interface)
    b += cs(2, bytes([0x07]))                                   # abstract control management
    b += cs(6, bytes([0, 1]))                                   # union: control interface 0, subordinate 1
    b += cs(3, bytes([0x01]))                                   # direct line management: no decoder, payload
    b += cs(0x00, b'', typ=0x25)                                # CS_ENDPOINT
    b += ep_desc(0x83, 3, 16, 255)
    b += if_desc(1, 0, 2, 10, 0, 0)
    b += ep_desc(0x81, 2, 64) + ep_desc(0x02, 2, 64)
    return cfg_desc(b, nif=2)


def ecm_config():
    b = if_desc(0, 0, 1, 2, 6, 0)
    b += cs(0, struct.pack('<H', 0x0110))
    b += cs(6, bytes([0, 1]))
    b += cs(0x0f, bytes([4]) + struct.pack('<IHHB', 0x0000_00ff, 1514, 0x8010, 3))   # ECM
    b += ep_desc(0x83, 3, 16, 11)
    b += if_desc(1, 0, 0, 10, 0, 0)
    b += if_desc(1, 1, 2, 10, 0, 0)
    b += ep_desc(0x81, 2, 512) + ep_desc(0x02, 2, 512)
    return cfg_desc(b, nif=2)


def ncm_config():
    b = if_desc(0, 0, 1, 2, 0x0d, 0)
    b += cs(0, struct.pack('<H', 0x0110))
    b += cs(6, bytes([0, 1]))
    b += cs(0x0f, bytes([4]) + struct.pack('<IHHB', 0, 1514, 0, 0))
    b += cs(0x1a, struct.pack('<HB', 0x0100, 0x1f))               # NCM functional descriptor: payload
    b += ep_desc(0x83, 3, 16, 11)
    b += if_desc(1, 0, 0, 10, 0, 1)
    b += if_desc(1, 1, 2, 10, 0, 1)
    b += ep_desc(0x81, 2, 512) + ep_desc(0x02, 2, 512)
    return cfg_desc(b, nif=2)


def mbim_config():
    b = iad_desc(0, 2, 2, 0x0e, 0)
    b += if_desc(0, 0, 1, 2, 0x0e, 0)
    b += cs(0, struct.pack('<H', 0x0110))
    b += cs(6, bytes([0, 1]))
    b += cs(0x1b, struct.pack('<HHBBHB', 0x0100, 1536, 16, 128, 1500, 0x20))   # MBIM functional descriptor
    b += cs(0x1c, struct.pack('<HBH', 0x0100, 64, 1500))                       # MBIM extended functional descriptor
    b += ep_desc(0x83, 3, 64, 9)
    b += if_desc(1, 0, 0, 10, 0, 2)
    b += if_desc(1, 1, 2, 10, 0, 2)
    b += ep_desc(0x81, 2, 512) + ep_desc(0x02, 2, 512)
    return cfg_desc(b, nif=2)


def main_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_pc = w.idb(LT_USBPCAP)
    if_bsd = w.idb(LT_USB_FREEBSD)
    mm = Bus(w, 'mm', if_mm, bus=1)

    # ------------------------------------------------------------ ACM
    s0 = w.count
    mm.enumerate(2, dev_desc(cls=2, vid=0x2341, pid=0x0043), acm_config())
    mm.control(2, setup(OUT_IF, 0x20, 0, 0, 7), out_data=struct.pack('<IBBB', 115200, 0, 0, 8))      # SET_LINE_CODING
    mm.control(2, setup(IN_IF, 0x21, 0, 0, 7), struct.pack('<IBBB', 115200, 0, 0, 8))               # GET_LINE_CODING
    mm.control(2, setup(OUT_IF, 0x22, 3, 0, 0))                                                      # SET_CONTROL_LINE_STATE
    mm.control(2, setup(OUT_IF, 0x23, 100, 0, 0))                                                    # SEND_BREAK
    mm.control(2, setup(OUT_IF, 0x00, 0, 0, 4), out_data=b'AT\r\n')                                  # SEND_ENCAPSULATED_COMMAND (not MBIM)
    mm.control(2, setup(IN_IF, 0x01, 0, 0, 8), b'OK\r\n')                                            # GET_ENCAPSULATED_RESPONSE (not MBIM)
    for req in (0x02, 0x03, 0x04, 0x05, 0x10, 0x30, 0x40, 0x50, 0x60, 0x77):
        mm.control(2, setup(OUT_IF if req % 2 == 0 else IN_IF, req, 0, 0, 2), b'\x01\x02' if req % 2 else b'',
                   out_data=b'' if req % 2 else b'\x01\x02')
    # notifications on the interrupt endpoint
    mm.xfer(2, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x20, 0, 0, 2) + b'\x03\x00')               # SERIAL_STATE
    mm.xfer(2, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x00, 1, 1, 0))                              # NETWORK_CONNECTION
    mm.xfer(2, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x00, 0, 1, 0))
    mm.xfer(2, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x01, 0, 0, 0))                              # RESPONSE_AVAILABLE
    mm.xfer(2, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x2a, 0, 1, 8) + struct.pack('<II', 100000000, 50000000))   # CONNECTION_SPEED_CHANGE
    mm.xfer(2, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x08, 1, 0, 0))                              # AUX_JACK_HOOK_STATE
    mm.xfer(2, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x77, 0, 0, 3) + b'abc')                     # unknown notification
    mm.xfer(2, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x00, 1, 1, 0) + b'extra')                   # trailing payload
    # data stream (bulk): both directions, several transfers
    for i in range(3):
        mm.xfer(2, 0x02, BULK, b'AT+TEST%d\r\n' % i)
        mm.xfer(2, 0x81, BULK, b'+TEST%d: OK\r\n' % i)
    mark(w, 'ACM device 2', s0)

    # ------------------------------------------------------------ ECM
    s0 = w.count
    mm.enumerate(3, dev_desc(cls=2, vid=0x0525, pid=0xa4a2), ecm_config())
    mm.control(3, setup(0x01, 11, 1, 1))                                                             # SET_INTERFACE 1/1: bulk endpoints active
    mm.control(3, setup(OUT_IF, 0x43, 0x000f, 0, 0))                                                 # SET_ETHERNET_PACKET_FILTER
    mm.control(3, setup(OUT_IF, 0x40, 0, 0, 12), out_data=bytes(range(12)))                          # SET_ETHERNET_MULTICAST_FILTERS
    mm.control(3, setup(IN_IF, 0x44, 1, 0, 4), b'\x01\x00\x00\x00')                                  # GET_ETHERNET_STATISTIC
    mm.xfer(3, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x00, 1, 0, 0))                                # NETWORK_CONNECTION
    mm.xfer(3, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x2a, 0, 0, 8) + struct.pack('<II', 480000000, 480000000))
    mm.xfer(3, 0x02, BULK, eth_frame())                                                              # Ethernet frames
    mm.xfer(3, 0x81, BULK, eth_frame(ipv4_udp(b'pong reply')))
    mm.xfer(3, 0x81, BULK, b'')
    mark(w, 'ECM device 3', s0)

    # ------------------------------------------------------------ NCM
    s0 = w.count
    mm.enumerate(4, dev_desc(cls=2, vid=0x04e8, pid=0x6863), ncm_config())
    mm.control(4, setup(0x01, 11, 1, 1))
    mm.control(4, setup(IN_IF, 0x80, 0, 0, 28),
               struct.pack('<HHIHHHHIHHHH', 28, 3, 16384, 4, 0, 4, 0, 16384, 4, 0, 4, 32))        # GET_NTB_PARAMETERS
    mm.control(4, setup(IN_IF, 0x81, 0, 0, 6), b'\x02\x00\x00\x00\x00\x02')                          # GET_NET_ADDRESS
    mm.control(4, setup(OUT_IF, 0x82, 0, 0, 6), out_data=b'\x02\x00\x00\x00\x00\x03')                # SET_NET_ADDRESS
    mm.control(4, setup(IN_IF, 0x83, 0, 0, 2), b'\x00\x00')                                          # GET_NTB_FORMAT
    mm.control(4, setup(OUT_IF, 0x84, 1, 0, 0))                                                      # SET_NTB_FORMAT (value in wValue)
    mm.control(4, setup(IN_IF, 0x85, 0, 0, 4), struct.pack('<I', 16384))                             # GET_NTB_INPUT_SIZE (4 octets)
    mm.control(4, setup(IN_IF, 0x85, 0, 0, 8), struct.pack('<IHH', 16384, 32, 0))                    # GET_NTB_INPUT_SIZE (8 octets)
    mm.control(4, setup(OUT_IF, 0x86, 0, 0, 4), out_data=struct.pack('<I', 8192))                    # SET_NTB_INPUT_SIZE (4 octets)
    mm.control(4, setup(OUT_IF, 0x86, 0, 0, 8), out_data=struct.pack('<IHH', 8192, 16, 0))           # SET_NTB_INPUT_SIZE (8 octets)
    mm.control(4, setup(IN_IF, 0x87, 0, 0, 2), struct.pack('<H', 1514))                              # GET_MAX_DATAGRAM_SIZE
    mm.control(4, setup(OUT_IF, 0x88, 0, 0, 2), out_data=struct.pack('<H', 1500))                    # SET_MAX_DATAGRAM_SIZE
    mm.control(4, setup(IN_IF, 0x89, 0, 0, 2), struct.pack('<H', 0))                                 # GET_CRC_MODE
    mm.control(4, setup(OUT_IF, 0x8a, 1, 0, 0))                                                      # SET_CRC_MODE (value in wValue)
    mm.control(4, setup(IN_IF, 0x8b, 0, 0, 2), b'\x01\x02')                                          # not defined: default
    mm.xfer(4, 0x02, BULK, ntb16([eth_frame()]))                                                     # NTB with one datagram
    mm.xfer(4, 0x81, BULK, ntb16([eth_frame(), eth_frame(ipv4_udp(b'second datagram'))], seq=2))
    mm.xfer(4, 0x81, BULK, ntb16([eth_frame() + bytes(4)], sig=b'NCM1', seq=3))      # datagram with an FCS
    mm.xfer(4, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x00, 1, 1, 0))
    mark(w, 'NCM device 4', s0)

    # ------------------------------------------------------------ MBIM
    s0 = w.count
    mm.enumerate(5, dev_desc(cls=2, vid=0x1199, pid=0x9071), mbim_config())
    mm.control(5, setup(0x01, 11, 1, 1))
    open_msg = struct.pack('<IIII', 1, 16, 1, 4096)
    open_done = struct.pack('<IIII', 0x80000001, 16, 1, 0)
    mm.control(5, setup(OUT_IF, 0x00, 0, 0, 16), out_data=open_msg)                                  # SEND_ENCAPSULATED_COMMAND: MBIM_OPEN_MSG
    mm.xfer(5, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x01, 0, 0, 0))                                # RESPONSE_AVAILABLE
    mm.control(5, setup(IN_IF, 0x01, 0, 0, 1536), open_done)                                         # GET_ENCAPSULATED_RESPONSE: MBIM_OPEN_DONE
    mm.control(5, setup(OUT_IF, 0x00, 0, 0, 12), out_data=struct.pack('<III', 2, 12, 2))            # MBIM_CLOSE_MSG
    mm.control(5, setup(IN_IF, 0x01, 0, 0, 16), struct.pack('<IIII', 0x80000002, 16, 2, 0))          # MBIM_CLOSE_DONE
    mm.xfer(5, 0x02, BULK, ntb16([bytes([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2])], sig=b'IPS\0'))
    mm.xfer(5, 0x81, BULK, ntb16([bytes(40)], sig=b'DSS\x01', seq=2))
    mark(w, 'MBIM device 5', s0)

    # ------------------------------------------------------------ other link types
    s0 = w.count
    pc = Bus(w, 'pcap', if_pc, bus=3)
    pc.enumerate(1, dev_desc(cls=2, vid=0x2341, pid=0x0043), acm_config())
    pc.control(1, setup(OUT_IF, 0x20, 0, 0, 7), out_data=struct.pack('<IBBB', 9600, 0, 0, 8))
    pc.control(1, setup(IN_IF, 0x21, 0, 0, 7), struct.pack('<IBBB', 9600, 0, 0, 8))
    pc.xfer(1, 0x02, BULK, b'usbpcap out')
    pc.xfer(1, 0x81, BULK, b'usbpcap in')
    pc.xfer(1, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x20, 0, 0, 2) + b'\x03\x00')
    bsd = Bus(w, 'bsd', if_bsd, bus=4)
    bsd.enumerate(2, dev_desc(cls=2, vid=0x2341, pid=0x0043), acm_config())
    bsd.control(2, setup(OUT_IF, 0x20, 0, 0, 7), out_data=struct.pack('<IBBB', 38400, 0, 0, 8))
    bsd.xfer(2, 0x02, BULK, b'freebsd out')
    bsd.xfer(2, 0x81, BULK, b'freebsd in')
    mark(w, 'USBPcap and FreeBSD ACM', s0)
    return w


def malformed_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    mm = Bus(w, 'mm', if_mm, bus=1)
    # union descriptor naming another controlling interface (1 instead of 0): error expert info
    b = if_desc(0, 0, 1, 2, 2, 1) + cs(6, bytes([1, 2, 3])) + ep_desc(0x83, 3, 16, 255)
    b += if_desc(1, 0, 2, 10, 0, 0) + ep_desc(0x81, 2, 64) + ep_desc(0x02, 2, 64)
    mm.enumerate(2, dev_desc(cls=2), cfg_desc(b, nif=2))
    # descriptors cut short: header functional descriptor with one octet of data, MBIM descriptors without a body
    b = if_desc(0, 0, 1, 2, 2, 1) + cs(0, b'\x10') + cs(1, b'\x03') + cs(2, b'') + cs(0x0f, b'\x04\x01') \
        + cs(0x1b, b'\x00') + cs(0x1c, b'')
    mm.enumerate(3, dev_desc(cls=2), cfg_desc(b, nif=1))
    # notifications and control responses that are cut short
    mm.xfer(2, 0x83, INT, b'\xa1')
    mm.xfer(2, 0x83, INT, struct.pack('<BBHHH', 0xa1, 0x2a, 0, 1, 8) + b'\0\0\0\0')
    mm.xfer(2, 0x83, INT, struct.pack('<BBHH', 0xa1, 0x00, 1, 1))
    mm.control(2, setup(IN_IF, 0x21, 0, 0, 7), b'')
    # NCM requests with short data
    mm.enumerate(4, dev_desc(cls=2), ncm_config())
    mm.control(4, setup(IN_IF, 0x80, 0, 0, 28), b'\x1c\x00\x03')
    mm.control(4, setup(IN_IF, 0x81, 0, 0, 6), b'\x02\x00')
    mm.control(4, setup(OUT_IF, 0x82, 0, 0, 3), out_data=b'\x02\x00\x01')
    mm.control(4, setup(IN_IF, 0x83, 0, 0, 2), b'\x00')
    mm.control(4, setup(IN_IF, 0x87, 0, 0, 2), b'\x00')
    mm.control(4, setup(IN_IF, 0x89, 0, 0, 2), b'')
    # bad NTB: block length wrong, unaligned and out of range NDP index
    t = bytearray(ntb16([eth_frame()]))
    struct.pack_into('<H', t, 8, 7)
    mm.xfer(4, 0x02, BULK, bytes(t))
    t = bytearray(ntb16([eth_frame()]))
    struct.pack_into('<H', t, 10, 3)
    mm.xfer(4, 0x02, BULK, bytes(t))
    t = bytearray(ntb16([eth_frame()]))
    struct.pack_into('<H', t, 10, 4000)
    mm.xfer(4, 0x02, BULK, bytes(t))
    # a transfer on a data interface whose subclass is not zero, and on one that is not CDC
    b = if_desc(0, 0, 1, 2, 2, 1) + cs(6, bytes([0, 1])) + ep_desc(0x83, 3, 16, 255) + if_desc(1, 0, 2, 10, 5, 0) \
        + ep_desc(0x81, 2, 64) + ep_desc(0x02, 2, 64)
    mm.enumerate(6, dev_desc(cls=2), cfg_desc(b, nif=2))
    mm.xfer(6, 0x02, BULK, b'subclass is not zero')
    # NTBs with control signatures whose datagrams are not MBIM messages
    mm.enumerate(5, dev_desc(cls=2), mbim_config())
    mm.xfer(5, 0x81, BULK, ntb16([bytes(8)], sig=b'IPC\0', seq=3))
    mm.xfer(5, 0x81, BULK, ntb16([bytes(8)], sig=b'DSC\x02', seq=4))
    return w


if __name__ == '__main__':
    w = main_capture()
    w.write(os.path.join(OUT, 'usb-com-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'usb-com-coverage-malformed.pcapng'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-26s frames %d-%d' % (n, a, b))
        print('main', w.count, 'malformed', m.count)
