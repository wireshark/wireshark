#!/usr/bin/env python3
# ADwin-Config coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ADwin configuration protocol (packet-adwin-config.c).

The dissector is a heuristic dissector for UDP and TCP port 7000 and
accepts a packet only if the Ethernet source or destination address is in
the range assigned to ADwin (00:50:c2:0a:2x:xx or 00:22:71:xx:xx:xx) or is
the broadcast address. The UDP packet type is taken from the payload
length:

  UDPStatus (52), UDPExtStatus (432), UDPMessage (100 and the broken 104),
  UDPInitAck (96), UDPIXP425FlashUpdate (92), UDPOut (22)

Over TCP the flash update (a length, file name, path, size, times, 128
unused octets and the data) is carried; the length counts the whole PDU.

TCP port 7000 is registered to the Gryphon plugin, which accepts every
segment, so the TCP frames reach ADwin-Config only with the preference
tcp.try_heuristic_first set. UDP port 7000 is not registered and needs no
preference. The capture holds both; dissect it with

    tshark -o tcp.try_heuristic_first:TRUE -r adwin-config_coverage.pcap

The TCP flash updates with a file name or a path that has no NUL ("ADwin-Config:
Reject an unterminated file name") are an error expert info and are in the
malformed capture.

Usage: mkadwin-config.py [<output directory>]

Writes adwin-config-coverage.pcap and adwin-config-coverage-malformed.pcapng
(an error expert info, frames cut by the capture, and UDP over raw IP, which
has no Ethernet address for the heuristic to look at). Every packet is built here; nothing comes from
a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import LINKTYPE_ETHERNET, LINKTYPE_RAW, Pcapng, TcpFlow, eth, ipv4, udp, write_pcap  # noqa: E402

PC = '192.0.2.1'
DEV = '192.0.2.2'
PC_MAC = '02:00:00:00:00:01'
DEV_IAB = '00:50:c2:0a:20:01'
DEV_IAB2 = '00:50:c2:0a:2f:ff'
DEV_OUI = '00:22:71:12:34:56'
BCAST = 'ff:ff:ff:ff:ff:ff'
MAC_BYTES = bytes.fromhex('0050c20a2001')
PORT = 7000


def udp_frame(payload, smac, dmac, to_dev=True, sport=50000, dport=PORT, src=None, dst=None):
    src = src or (PC if to_dev else DEV)
    dst = dst or (DEV if to_dev else PC)
    return eth(ipv4(udp(payload, sport, dport, src, dst), 17, src=src, dst=dst),
               0x0800, dst=dmac, src=smac)


def dev_frame(payload, smac=DEV_IAB, dmac=BCAST):
    """A packet from the device, to the broadcast address."""
    return udp_frame(payload, smac, dmac, to_dev=False, sport=PORT, dport=50000)


def fixed(s, n):
    return s.encode().ljust(n, b'\0')[:n]


def status(pattern=0x73241291, version=1002, flags=0x80, beta=2, srv=3004, xilinx=0x12345678,
           port=6543, dhcp=1, masklen=24, gw='192.0.2.254', bcast=1, scan=0xdeadbeef):
    p = bytearray(52)
    struct.pack_into('>IIIHHI', p, 0, pattern, version, flags, beta, srv, xilinx)
    p[20:26] = MAC_BYTES
    struct.pack_into('>H', p, 28, port)
    p[30] = dhcp
    p[31] = masklen
    p[32:36] = bytes(int(x) for x in gw.split('.'))
    p[47] = bcast
    struct.pack_into('<I', p, 48, scan)
    return bytes(p)


def ext_status(proc='10', system='03', pattern=0x73241291, desc='ADwin Pro II'):
    p = bytearray(432)
    p[0:6] = MAC_BYTES
    struct.pack_into('>II', p, 8, pattern, 1002)
    p[16:32] = fixed(desc, 16)
    struct.pack_into('>IIII', p, 32, 5, 6, 7000, 32000)
    p[48:56] = b'20230115'
    p[56:64] = b'rev00042'
    p[64:66] = proc.encode()
    p[66:68] = system.encode()
    return bytes(p)


def message(cmd=100, size=100, dhcp=0, boot=1, proc='09', system='02'):
    p = bytearray(size)
    struct.pack_into('<II', p, 0, cmd, 1002)
    p[8:14] = MAC_BYTES
    struct.pack_into('<I', p, 16, 0xc000020a)       # 10.2.0.192 as stored little endian
    struct.pack_into('<I', p, 24, 0x00ffffff)
    struct.pack_into('<I', p, 32, 0xfe0200c0)
    struct.pack_into('<II', p, 40, dhcp, 6543)
    p[48:58] = fixed('adwin', 10)
    p[58] = boot
    p[64:80] = fixed('ADwin Gold', 16)
    p[80:88] = b'20230115'
    p[88:96] = b'rev00007'
    p[96:98] = proc.encode()
    p[98:100] = system.encode()
    return bytes(p)


def init_ack(pattern=0x12343210, reboot=1):
    p = bytearray(96)
    struct.pack_into('>I', p, 0, pattern)
    struct.pack_into('<I', p, 4, reboot)
    p[8:14] = MAC_BYTES
    return bytes(p)


def ixp_update(pattern=0x37241291, name='ixp425.bin'):
    p = bytearray(92)
    struct.pack_into('>IIIII', p, 0, pattern, 1002, 77, 0x81, 30000)
    p[20:44] = fixed(name, 24)
    p[44:50] = MAC_BYTES
    return bytes(p)


def out(flags=0x2, dhcp=1):
    p = bytearray(22)
    struct.pack_into('<I', p, 0, flags)
    p[4:10] = MAC_BYTES
    struct.pack_into('<I', p, 10, 0x00ffffff)
    p[14:18] = bytes((192, 0, 2, 254))
    struct.pack_into('<H', p, 18, dhcp)
    struct.pack_into('>H', p, 20, 6543)
    return bytes(p)


def pdu(body):
    """A TCP flash update PDU: the length covers the whole PDU."""
    return struct.pack('>I', 4 + len(body)) + body


def flash_file(name, path, size=4096, ftime=1700000000, utime=1700003600, data=b''):
    return pdu(name + b'\0' + path + b'\0' + struct.pack('>III', size, ftime, utime) + bytes(128) + data)


def build():
    f, m = [], []
    # UDPStatus: every pattern, every status flag, DHCP on and off, other masks
    flags = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff, 0]
    for i, fl in enumerate(flags):
        f.append(dev_frame(status(pattern=(0x73241291, 0x37241291, 0x12343210, 0x11111111)[i % 4], flags=fl,
                                  dhcp=i & 1, masklen=8 + i, bcast=i & 1, scan=i),
                           smac=(DEV_IAB, DEV_IAB2, DEV_OUI)[i % 3]))
    # UDPExtStatus with every processor and system type, known and unknown
    for proc, system in (('09', '01'), ('10', '02'), ('11', '03'), ('12', '04'), ('09', '05'), ('10', '99')):
        f.append(dev_frame(ext_status(proc, system), smac=DEV_OUI))
    # UDPMessage (100 and the broken 104) with every command
    for cmd in (100, 105, 110, 120, 130, 999):
        f.append(udp_frame(message(cmd, dhcp=cmd & 1, boot=cmd & 1, proc=('09', '10', '11')[cmd % 3],
                                   system=('01', '02', '03', '04', '05')[cmd % 5]),
                           PC_MAC, BCAST))
    f.append(udp_frame(message(100, size=104, proc='77', system='88'), PC_MAC, DEV_IAB))
    f.append(udp_frame(message(110, size=104), PC_MAC, DEV_OUI))
    # UDPInitAck, UDPIXP425FlashUpdate and UDPOut
    f.append(dev_frame(init_ack()))
    f.append(dev_frame(init_ack(0x73241291, 0)))
    f.append(udp_frame(ixp_update(), PC_MAC, DEV_IAB))
    f.append(udp_frame(ixp_update(0x12343210, 'a' * 24), PC_MAC, BCAST))
    f.append(dev_frame(out()))
    f.append(dev_frame(out(0xff, 0)))
    # Not ADwin-Config: a source MAC outside the ADwin ranges, a payload length
    # of none of the packet types, a port other than 7000 (both reach the
    # heuristic, which returns false)
    f.append(udp_frame(status(), PC_MAC, '02:00:00:00:00:02', to_dev=True))
    f.append(udp_frame(bytes(50), PC_MAC, BCAST))
    f.append(udp_frame(status(), PC_MAC, BCAST, sport=50000, dport=50001))
    # TCP: flash updates; the heuristic needs tcp.try_heuristic_first
    flow = TcpFlow(40001, PORT, src=PC, dst=DEV, smac=PC_MAC, dmac=DEV_IAB)
    f += flow.handshake()
    f.append(flow.send(pdu(b'eeprom_on\0')))
    f.append(flow.send(pdu(b'eeprom_off\0')))
    f.append(flow.send(flash_file(b'firmware.bin', b'/flash/', data=bytes(range(64)))))
    f.append(flow.send(flash_file(b'boot.bin', b'/', size=0, ftime=0, utime=0)))
    # Two PDUs in one segment
    f.append(flow.send(pdu(b'eeprom_on\0') + flash_file(b'a.bin', b'/a/', data=b'xyz')))
    # One PDU in two segments (reassembly)
    big = flash_file(b'big.bin', b'/data/', size=200, data=bytes(i & 0xff for i in range(200)))
    f.append(flow.send(big[:100]))
    f.append(flow.send(big[100:]))
    f += flow.close()
    # The reply direction of a connection from the device, to an OUI address
    flow2 = TcpFlow(PORT, 40002, src=DEV, dst=PC, smac=DEV_OUI, dmac=PC_MAC)
    f += flow2.handshake()
    f.append(flow2.send(pdu(b'eeprom_off\0')))
    # TCP from an address that is not an ADwin one: the heuristic refuses
    flow3 = TcpFlow(40003, PORT, src=PC, dst=DEV, smac=PC_MAC, dmac='02:00:00:00:00:02')
    f.append(flow3.send(pdu(b'eeprom_on\0')))
    # TCP on another port (the heuristic sees the connection and refuses it)
    flow4 = TcpFlow(40006, 7001, src=PC, dst=DEV, smac=PC_MAC, dmac=DEV_IAB)
    f.append(flow4.send(pdu(b'eeprom_on\0')))

    # Malformed: frames cut by the capture
    for fr in (dev_frame(status()), dev_frame(ext_status()), udp_frame(message(), PC_MAC, BCAST),
               dev_frame(init_ack()), udp_frame(ixp_update(), PC_MAC, DEV_IAB), dev_frame(out())):
        for cut in (14 + 20 + 8 + 3, 14 + 20 + 8 + 21, 14 + 20 + 8 + 50):
            if cut < len(fr):
                m.append((fr[:cut], len(fr)))
    # TCP: the reproducer of "ADwin-Config: Reject an unterminated file name"
    # (a file name without a NUL) and a path without a NUL, both an error
    flow = TcpFlow(40005, PORT, src=PC, dst=DEV, smac=PC_MAC, dmac=DEV_IAB)
    m += flow.handshake()
    m.append(flow.send(pdu(b'firmware.bin')))
    m.append(flow.send(pdu(b'file.bin\0' + b'/no/nul')))
    # TCP: PDUs whose content ends inside the path, the fixed fields and the
    # unused part (the length field is right, so every PDU is complete)
    flow = TcpFlow(40004, PORT, src=PC, dst=DEV, smac=PC_MAC, dmac=DEV_IAB)
    m += flow.handshake()
    body = b'cut.bin\0' + b'/cut/\0' + struct.pack('>III', 10, 1700000000, 1700003600) + bytes(128) + b'abcd'
    for n in (1, 9, 14, 16, 19, 22, 26, 30, 80, len(body)):
        m.append(flow.send(pdu(body[:n])))
    m.append(flow.send(pdu(b'eeprom_on')))
    m.append(flow.send(pdu(b'')))
    # Cut by the capture inside the PDU
    fr = flow.send(flash_file(b'cap.bin', b'/cap/', data=b'abcd'))
    m.append((fr[:14 + 20 + 20 + 12], len(fr)))
    # No Ethernet addresses at all (link-layer type raw IP): the heuristic
    # needs one to accept the packet
    raw = [ipv4(udp(status(), 50000, PORT, PC, DEV), 17, src=PC, dst=DEV),
           ipv4(udp(message(), 50000, PORT, PC, DEV), 17, src=PC, dst=DEV)]
    return f, m, raw


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    clean, malformed, raw = build()
    write_pcap(os.path.join(outdir, 'adwin-config-coverage.pcap'), clean)
    w = Pcapng()
    eth_if = w.interface(LINKTYPE_ETHERNET)
    raw_if = w.interface(LINKTYPE_RAW)
    for i, fr in enumerate(malformed):
        data, orig = fr if isinstance(fr, tuple) else (fr, None)
        w.packet(eth_if, data, ts=(1700000000 + i, 0), orig_len=orig)
    for i, fr in enumerate(raw):
        w.packet(raw_if, fr, ts=(1700000000 + len(malformed) + i, 0))
    w.write(os.path.join(outdir, 'adwin-config-coverage-malformed.pcapng'))
    print('%d + %d + %d frames' % (len(clean), len(malformed), len(raw)), file=sys.stderr)


if __name__ == '__main__':
    main()
