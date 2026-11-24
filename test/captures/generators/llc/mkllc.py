#!/usr/bin/env python3
# Generates test/captures/llc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the LLC coverage captures: mkllc.py <outdir> [-v]

llc-coverage.pcapng           main capture (no malformed frames)
llc-coverage-malformed.pcapng truncated headers (exceptions)
"""
import struct
import sys
import os
import zlib
from pylib import csum, eth, ip4, ipv4, mac, Pcapng, udp

DST = '02:00:00:00:00:02'
SRC = '02:00:00:00:00:01'
LT_ETH, LT_ATM, LT_SLL, LT_PPP, LT_80211 = 1, 100, 113, 9, 105


def frame8023(payload, dst=DST, src=SRC):
    """Ethernet frame with a length field (802.3), padded to 60 octets"""
    f = mac(dst) + mac(src) + struct.pack('>H', len(payload)) + payload
    return f + bytes(max(0, 60 - len(f)))


def llc(dsap, ssap, ctrl, payload=b''):
    return bytes((dsap, ssap)) + ctrl + payload


def uctl(modifier, pf=0):
    """U control octet; modifier is the 0xEC mask part"""
    return bytes((modifier | 0x03 | (0x10 if pf else 0),))


def ictl(ns, nr, pf=0):
    return struct.pack('<BB', ns << 1, (nr << 1) | pf)


def sctl(stype, nr, pf=0):
    return struct.pack('<BB', 0x01 | (stype << 2), (nr << 1) | pf)


def snap(oui, pid, payload=b'', ctrl=b'\x03'):
    return llc(0xAA, 0xAA, ctrl, bytes.fromhex(oui) + struct.pack('>H', pid) + payload)


def ip_packet(sport=33000, dport=33001, data=b'llc-test'):
    return ipv4('192.0.2.1', '192.0.2.2', 17, udp(sport, dport, data))


def bpdu_config():
    # Configuration BPDU: protocol 0, version 0, type 0
    return (struct.pack('>HBBB', 0, 0, 0, 0x01) + struct.pack('>H', 0x8000) + mac(SRC)
            + struct.pack('>I', 4) + struct.pack('>H', 0x8000) + mac(SRC)
            + struct.pack('>HHHHH', 0x8001, 0, 20 * 256, 2 * 256, 15 * 256))


def netbios():
    return struct.pack('<HHB', 44, 0xEFFF, 0x0A) + bytes(40)


def ipx_packet():
    # IPX header, checksum 0xffff, length 30, hops 0, type 0 (unknown packet type), sockets
    return (struct.pack('>HHBB', 0xFFFF, 34, 0, 0) + struct.pack('>I', 1) + bytes.fromhex('ffffffffffff')
            + struct.pack('>H', 0x5555) + struct.pack('>I', 2) + bytes.fromhex('020000000001')
            + struct.pack('>H', 0x5556) + b'data')


def cdp_packet():
    body = struct.pack('>BBH', 2, 180, 0)
    dev = b'sw11'
    body += struct.pack('>HH', 1, 4 + len(dev)) + dev
    body += struct.pack('>HH', 3, 4 + 4) + b'Fa01'
    c = csum(body)
    return body[:2] + struct.pack('>H', c) + body[4:]


def eth_with(payload, etype=0x0800, dst=DST, src=SRC):
    return mac(dst) + mac(src) + struct.pack('>H', etype) + payload


def main(out, verbose=False):
    main_ng = Pcapng()
    eth_if = main_ng.add_if(LT_ETH)
    atm_if = main_ng.add_if(LT_ATM)
    sll_if = main_ng.add_if(LT_SLL)
    ppp_if = main_ng.add_if(LT_PPP)
    marks = []

    def add(data, ifid=eth_if):
        return main_ng.add(ifid, data)

    def mark(name):
        marks.append((len(main_ng.pkts) + 1, name))

    def e(payload, **kw):
        return add(frame8023(payload, **kw))

    # ---- 1. U frames without payload: every modifier, command and response
    mark('U frames, all modifier values, command (P=0) and response (F=1)')
    mods = [m for m in range(256) if (m & 0xEC) == m]
    for m in mods:
        e(llc(0x00, 0x00, uctl(m, 0)))              # command, P clear
        e(llc(0x00, 0x01, uctl(m, 1)))              # response, F set
    # ---- 2. S frames
    mark('S frames: RR, RNR, REJ, SREJ as command and response, N(R), P/F')
    for st in range(4):
        e(llc(0x04, 0x04, sctl(st, 5 + st, 1)))
        e(llc(0x04, 0x05, sctl(st, 100 + st, 0)))
    e(llc(0x04, 0x04, sctl(0, 127, 0)))
    # ---- 3. I frames with the registered DSAPs
    mark('I frames: sequence numbers, P bit, payload of IP, BPDU, IPX, NetBIOS, unknown SAP')
    e(llc(0x06, 0x06, ictl(0, 0, 0), ip_packet()))
    e(llc(0x06, 0x06, ictl(1, 3, 1), ip_packet(33001)))
    e(llc(0x06, 0x07, ictl(127, 127, 0), ip_packet(33002)))
    e(llc(0x42, 0x42, ictl(2, 1, 0), bpdu_config()))
    e(llc(0xE0, 0xE0, ictl(3, 1, 0), ipx_packet()))
    e(llc(0xF0, 0xF0, ictl(4, 1, 0), netbios()))
    e(llc(0x30, 0x31, ictl(5, 1, 0), b'Unknown SAP payload'))
    e(llc(0x30, 0x31, ictl(6, 1, 0), b''))          # I frame without payload
    # ---- 4. UI frames
    mark('UI frames: DSAP/SSAP values with and without names, group DSAP, P bit')
    e(llc(0x06, 0x06, uctl(0x00), ip_packet(33000)))
    e(llc(0x06, 0x06, uctl(0x00, 1), ip_packet(33001)))
    e(llc(0x42, 0x42, uctl(0x00), bpdu_config()))
    e(llc(0xE0, 0xE0, uctl(0x00), ipx_packet()))
    e(llc(0xF0, 0xF0, uctl(0x00), netbios()))
    e(llc(0x07, 0x06, uctl(0x00), ip_packet(33002)))   # group DSAP (not registered)
    # every named SAP once (UI, no registered dissector or unknown contents)
    named = [0x00, 0x02, 0x04, 0x05, 0x08, 0x0C, 0x0E, 0x10, 0x14, 0x18, 0x20, 0x34, 0x42, 0x4E, 0x54, 0x7E,
             0x7F, 0x80, 0x82, 0x86, 0x8E, 0xAA, 0xBA, 0xBC, 0xE0, 0xF0, 0xF4, 0xF8, 0xFA, 0xFC, 0xFE]
    for s in named:
        if s in (0xAA,):
            continue
        e(llc(s, s ^ 0x00, uctl(0x00)))
    e(llc(0x01, 0x03, uctl(0x00)))
    e(llc(0x03, 0x02, uctl(0x00)))
    # ---- 5. XID
    mark('XID: basic format (types 1-7, window sizes), unknown format, SNA XID')
    for t in range(0, 9):
        e(llc(0x00, 0x00, uctl(0xAC, 1), bytes((0x81, t, (t * 8 + 2) & 0xFE))))
    e(llc(0x00, 0x01, uctl(0xAC, 1), bytes((0x81, 3, 0x7E))))
    e(llc(0x30, 0x30, uctl(0xAC, 1), bytes((0x82, 1, 2, 3))))      # not basic, unknown SAP: data
    e(llc(0x04, 0x04, uctl(0xAC, 1), bytes((0x11, 0, 0, 0, 0, 0, 0, 0))))   # SNA XID type 1
    # ---- 6. TEST and other control values
    mark('TEST with the Allied Telesis LDF dissector, TEST/other U with payload, S frame with payload')
    ldf = (bytes((1,)) + struct.pack('>HIB', 10, 3, 120) + bytes.fromhex('00112233445566')
           + b'link discovery'.ljust(64, b'\x00'))
    e(llc(0x00, 0x00, bytes((0xE3,)), ldf), dst='00:00:f4:27:71:01')
    e(llc(0x00, 0x00, bytes((0xE3,)), b'test frame data'))          # AT LDF declines (wrong address): data
    e(llc(0x00, 0x00, bytes((0xF3,)), b'test frame data'))          # TEST with F bit
    e(llc(0x04, 0x04, uctl(0x6C, 1), b'SABME with a payload'))      # U, not I or XID, no table entry: data
    e(llc(0x04, 0x04, uctl(0x40, 1), b'DISC payload'))
    e(llc(0x04, 0x04, sctl(0, 1, 0), b'RR payload'))                # S frame with payload
    # ---- 7. SNAP
    mark('SNAP: OUI 0 and Cisco 90 with Ethertypes, unknown Ethertype, non-information frames')
    e(snap('000000', 0x0800, ip_packet(33000)))
    e(snap('000000', 0x0806, bytes.fromhex('0001080006040001') + mac(SRC) + ip4('192.0.2.1') + bytes(6) + ip4('192.0.2.2')))
    e(snap('000000', 0x9999, b'Unknown ethertype'))
    e(snap('0000f8', 0x0800, ip_packet(33001)))
    e(snap('000000', 0x0800, ip_packet(33002), ctrl=ictl(0, 0, 0)))    # I frame with SNAP
    e(snap('000000', 0x0800, b'x' * 10, ctrl=bytes((0xAF,))))          # XID with SNAP: not information
    e(snap('0000f8', 0x0800, b'x' * 10, ctrl=bytes((0xE3,))))          # TEST with SNAP and Cisco 90: data
    mark('SNAP: Cisco OUI (PID table), HP team, IEEE 802.1 bridged formats, cable BPDU, Turbocell, Marvell/OLPC')
    e(snap('00000c', 0x2000, cdp_packet()))
    e(snap('00000c', 0x1234, b'unknown Cisco PID'))
    e(snap('00000c', 0x2000, b'x' * 10, ctrl=bytes((0xE3,))))          # not information: data
    e(snap('00805f', 0x0002, bytes.fromhex('0102030405060708'), ctrl=bytes((0xE3,))))  # HP heartbeat (TEST)
    e(snap('00805f', 0x0003, b'other HP PID', ctrl=bytes((0xE3,))))
    bpad = b'\x00\x00'
    inner_eth = eth_with(ip_packet(33003))
    e(snap('0080c2', 0x0007, bpad + inner_eth))                      # bridged Ethernet, no FCS
    e(snap('0080c2', 0x0001, bpad + inner_eth + struct.pack('>I', zlib.crc32(inner_eth))))   # with FCS
    # 802.5 with and without FCS: pad, AC, FC, dst, src, LLC SNAP IP
    tr = bytes((0x10, 0x40)) + mac(DST) + mac(SRC) + snap('000000', 0x0800, ip_packet(33004))
    e(snap('0080c2', 0x0009, bpad + tr))
    e(snap('0080c2', 0x0003, bpad + tr + bytes(4)))
    # FDDI: pad, FC byte, dst, src, LLC
    fddi = bytes((0x50,)) + mac(DST) + mac(SRC) + snap('000000', 0x0800, ip_packet(33005))
    e(snap('0080c2', 0x000A, bpad + b'\x00' + fddi))
    e(snap('0080c2', 0x0004, bpad + b'\x00' + fddi + bytes(4)))
    e(snap('0080c2', 0x000E, bpdu_config()))                         # 802.1 BPDU
    e(snap('0080c2', 0x000D, b'fragments: no dissector'))
    e(snap('00e02f', 0x0001, bpdu_config()))                         # DOCSIS cable BPDU
    turbo = bytes((0x01, 0x03)) + struct.pack('>H', 7) + mac(DST) + bytes(3) + bytes(3) + bytes(2) + ip4('192.0.2.3')
    turbo += b'Turbocell net'.ljust(30, b'\x00') + bytes(8) + bytes(8)
    e(llc(0xAA, 0xAA, b'\x03', bytes.fromhex('0020f6') + turbo))
    beacon = bytes((0x00, 0x03)) + struct.pack('>H', 7) + mac(DST) + bytes(3) + bytes(1) + bytes(2) + ip4('192.0.2.3')
    beacon += b'Turbocell net'.ljust(30, b'\x00') + bytes(2) + (b'\x00' + mac(SRC) + b'\x00') * 2 + b'\x01' * 8
    e(llc(0xAA, 0xAA, b'\x03', bytes.fromhex('0020f6') + beacon))
    mesh = bytes((0, 0, 5)) + struct.pack('>H', 9)
    e(snap('005043', 0x0800, mesh + ip_packet(33006)))              # Marvell OLPC mesh header, ethertype IP
    e(snap('005043', 0x0800, b'x' * 12, ctrl=bytes((0xAF,))))      # Marvell, not information
    e(snap('005043', 0x9999, mesh + b'unknown ethertype after the mesh header'))   # Marvell, no dissector for the Ethertype
    # ---- 8. SNAP with the OUI PID tables of other dissectors, and unknown OUI
    mark('SNAP: other OUI tables (Apple AppleTalk, Foundry, Extreme, Nortel, IANA, Cimetrics), unknown OUI, unknown PID')
    e(snap('080007', 0x809B, bytes.fromhex('0010000100000000000000000000')))  # AppleTalk DDP (ethertype 809B)
    e(snap('080007', 0x80F3, bytes.fromhex('0001809b06040001') + mac(SRC) + bytes(4) + bytes(6) + bytes(4)))
    e(snap('080007', 0x1111, b'unknown Apple PID'))
    e(snap('00e052', 0x2111, b'foundry data' * 2))
    e(snap('00e02b', 0x2111, b'extreme data' * 2))
    e(snap('000081', 0x2111, b'nortel data' * 2))
    e(snap('00005e', 0x2111, b'iana oui data' * 2))
    e(snap('00005e', 0x0001, b'iana oui data', ctrl=bytes((0xAF,))))   # table OUI, not information
    e(snap('123456', 0x0001, b'unknown OUI payload'))
    e(snap('123456', 0x0001, b'unknown OUI payload', ctrl=bytes((0xE3,))))

    # ---- 9. UDP 12000 (RFC 2353), Jumbo LLC, ATM RFC 1483, Linux cooked, PPP
    mark('Other carriers: UDP 12000-12004, Ethertype 0x8870 (jumbo LLC), ATM RFC 1483, Linux cooked (SLL), PPP 0x004b')
    for p in (12000, 12004):
        add(eth(DST, SRC, 0x0800, ipv4('192.0.2.1', '192.0.2.2', 17,
                                       udp(40000, p, llc(0x06, 0x06, uctl(0x00), ip_packet(33000))))))
    add(eth(DST, SRC, 0x8870, llc(0xAA, 0xAA, b'\x03', bytes(3) + struct.pack('>H', 0x0800) + ip_packet(33001))))
    add(llc(0xAA, 0xAA, b'\x03', bytes(3) + struct.pack('>H', 0x0800) + ip_packet(33002)), atm_if)
    add(llc(0x42, 0x42, b'\x03', bpdu_config()), atm_if)
    sllh = struct.pack('>HHH8sH', 0, 1, 6, mac(SRC) + bytes(2), 0x0004)
    add(sllh + llc(0x06, 0x06, b'\x03', ip_packet(33003)), sll_if)
    add(b'\xff\x03' + struct.pack('>H', 0x004B) + llc(0x06, 0x06, b'\x03', ip_packet(33004)), ppp_if)

    # ---- 10. EPD (Ethertype protocol discrimination) in an 802.11 mesh data frame
    # added by mk_epd below when requested
    if os.environ.get('LLC_EPD', '1') == '1':
        mark('EPD LLC: 802.11 mesh QoS data frames carrying an Ethertype directly (and LPD for comparison)')
        wl_if = main_ng.add_if(LT_80211)
        da, sa, ta, ra = mac('02:aa:00:00:00:02'), mac('02:aa:00:00:00:01'), mac('02:aa:00:00:00:03'), mac('02:aa:00:00:00:04')

        def mesh_data(payload, seq=1):  # noqa
            # QoS data (0x88), ToDS=1 FromDS=1: 4 addresses; QoS control bit 8 = mesh control present
            fc = struct.pack('<BB', 0x88, 0x03)
            h = fc + struct.pack('<H', 0) + ra + ta + da + struct.pack('<H', seq << 4) + sa
            h += struct.pack('<H', 0x0100)               # QoS control, mesh control present
            h += struct.pack('<BBI', 0x00, 5, 7)         # mesh control: flags 0, TTL 5, seq 7
            return h + payload
        add(mesh_data(struct.pack('>H', 0x0800) + ip_packet(33000)), wl_if)
        add(mesh_data(struct.pack('>H', 0x0806) + bytes.fromhex('0001080006040001') + sa + ip4('192.0.2.9') + bytes(6) + ip4('192.0.2.2'), 2), wl_if)
        add(mesh_data(llc(0xAA, 0xAA, b'\x03', bytes(3) + struct.pack('>H', 0x0800) + ip_packet(33001), ), 3), wl_if)

    main_ng.write(os.path.join(out, 'llc-coverage.pcapng'))
    if verbose:
        for i, (n, name) in enumerate(marks):
            end = marks[i + 1][0] - 1 if i + 1 < len(marks) else len(main_ng.pkts)
            print('%d-%d: %s' % (n, end, name))
        print('total', len(main_ng.pkts))

    # ------------------------------------------------------------------ malformed
    mal = Pcapng()
    ei = mal.add_if(LT_ETH)
    ai = mal.add_if(LT_ATM)

    def m(data, ifid=ei):
        mal.add(ifid, data)

    def me(payload):
        m(frame8023(payload))
        return
    # truncated frames must keep their reported length: use captured-length < reported length
    # via the ATM linktype (the frame is the LLC PDU itself, no padding)
    m(b'\x06', ai)                                     # DSAP only
    m(b'\x06\x06', ai)                                 # no control field
    m(b'\x06\x06\x01', ai)                             # S frame, second control octet missing
    m(b'\x06\x06\x00', ai)                             # I frame, second control octet missing
    m(b'\xaa\xaa\x03', ai)                             # SNAP without OUI and PID
    m(b'\xaa\xaa\x03\x00\x00\x00\x08', ai)             # SNAP, PID cut short
    m(b'\xaa\xaa\x03\x00\x80\xc2\x00\x07', ai)         # 802.1 bridged Ethernet, PID cut short
    m(b'\xaa\xaa\x03\x00\x80\xc2\x00\x07\x00', ai)     # pad cut short
    m(b'\xaa\xaa\x03\x00\x80\xc2\x00\x0e', ai)         # BPDU without data
    m(b'\xaa\xaa\x03\x00\x00\x0c\x20\x00', ai)         # CDP without data
    m(b'\xaa\xaa\x03\x00\x50\x43\x08\x00', ai)         # Marvell without mesh header
    m(b'\xaa\xaa\x03\x00\x50\x43\x08\x00\x00\x00\x05', ai)   # Marvell with a short mesh header
    m(b'\x00\x00\xaf', ai)                             # XID without data (no format)
    m(b'\x00\x00\xaf\x81', ai)                         # basic XID cut short
    m(b'\x00\x00\xaf\x81\x03', ai)                     # basic XID without window size
    m(b'\x04\x04\xaf\x11', ai)                         # SNA XID cut short
    m(b'\x00\x00\xe3' + bytes(5), ai)                  # TEST: AT LDF (wrong address -> data)
    # 802.3 frame whose length field is longer than the data
    f = mac(DST) + mac(SRC) + struct.pack('>H', 40) + llc(0x06, 0x06, b'\x03') + b'\x45\x00'
    m(f)
    f = mac('00:00:f4:27:71:01') + mac(SRC) + struct.pack('>H', 20) + llc(0x00, 0x00, b'\xe3', b'\x01\x00\x0a\x00\x00')
    m(f)                                               # AT LDF short frame
    m(snap('000000', 0x0800, b''), ai)
    wi = mal.add_if(LT_80211)
    da, sa, ta, ra = mac('02:aa:00:00:00:02'), mac('02:aa:00:00:00:01'), mac('02:aa:00:00:00:03'), mac('02:aa:00:00:00:04')
    h = (struct.pack('<BB', 0x88, 0x03) + struct.pack('<H', 0) + ra + ta + da + struct.pack('<H', 5 << 4) + sa
         + struct.pack('<H', 0x0100) + struct.pack('<BBI', 0, 5, 7))
    m(h + struct.pack('>H', 0x0800) + ip_packet(33002)[:-8], wi)       # EPD frame, IP cut short
    mal.write(os.path.join(out, 'llc-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
