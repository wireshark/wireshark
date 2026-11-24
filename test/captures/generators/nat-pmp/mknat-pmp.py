#!/usr/bin/env python3
# Generates test/captures/nat-pmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic NAT-PMP / PCP (RFC 6886, RFC 6887, RFC 7225) coverage captures.

    mknat-pmp.py <outdir>

writes nat-pmp-coverage.pcap (Ethernet/IPv4/UDP, ports 5350/5351, all
decode cleanly) and nat-pmp-coverage-malformed.pcap (truncated and
inconsistent PDUs). Nothing is captured from a real network.
"""
import os
import struct
import sys

CLIENT = bytes([10, 0, 0, 2])
SERVER = bytes([10, 0, 0, 1])


def ip4mapped(a, b, c, d):
    return b'\0' * 10 + b'\xff\xff' + bytes([a, b, c, d])


IP6 = bytes.fromhex('20010db8000000000000000000000042')


def frame(payload, to_server=True, ident=[0], sport=None, dport=None, dst=None):
    ident[0] += 1
    sp, dp = (40000 + ident[0] % 1000, 5351) if to_server else (5351, 40000 + ident[0] % 1000)
    if sport is not None:
        sp = sport
    if dport is not None:
        dp = dport
    src_ip, dst_ip = (CLIENT, SERVER) if to_server else (SERVER, CLIENT)
    if dst:
        dst_ip = dst
    udp = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ident[0], 0, 64, 17, 0, src_ip, dst_ip)
    ck = sum((ip[i] << 8) | ip[i + 1] for i in range(0, 20, 2))
    ck = ~((ck & 0xffff) + (ck >> 16)) & 0xffff
    ip = ip[:10] + struct.pack('>H', ck) + ip[12:]
    mac_s, mac_d = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    eth = (mac_s + mac_d if not to_server else mac_d + mac_s) + b'\x08\x00'
    return eth + ip + udp


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


# --- NAT-PMP (version 0)
def pmp_ext_req():
    return struct.pack('>BB', 0, 0)


def pmp_ext_rsp(result=0, sssoe=123456, ip=(203, 0, 113, 9)):
    return struct.pack('>BBHI4s', 0, 128, result, sssoe, bytes(ip))


def pmp_map_req(tcp, iport, eport, life):
    return struct.pack('>BBHHHI', 0, 2 if tcp else 1, 0, iport, eport, life)


def pmp_map_rsp(tcp, result, sssoe, iport, eport, life):
    return struct.pack('>BBHIHHI', 0, 130 if tcp else 129, result, sssoe, iport, eport, life)


# --- PCP (versions 1 and 2)
def pcp_req_hdr(ver, op, life=7200, client=None):
    return struct.pack('>BBHI', ver, op, 0, life) + (client or ip4mapped(10, 0, 0, 2))


def pcp_rsp_hdr(ver, op, result=0, life=7200, epoch=5000):
    return struct.pack('>BBBBII', ver, 0x80 | op, 0, result, life, epoch) + b'\0' * 12


def pcp_map(ver, rsp, nonce, proto, iport, eport, ext_ip, **hdr):
    h = pcp_rsp_hdr(ver, 1, **hdr) if rsp else pcp_req_hdr(ver, 1, **hdr)
    b = (nonce if ver > 1 else b'') + struct.pack('>B3sHH', proto, b'\0\0\0', iport, eport) + ext_ip
    return h + b


def pcp_peer(ver, rsp, nonce, proto, iport, eport, ext_ip, rport, rip, **hdr):
    h = pcp_rsp_hdr(ver, 2, **hdr) if rsp else pcp_req_hdr(ver, 2, **hdr)
    b = (nonce if ver > 1 else b'') + struct.pack('>B3sHH', proto, b'\0\0\0', iport, eport) + ext_ip
    return h + b + struct.pack('>HH', rport, 0) + rip


def opt(code, data, length=None):
    """option with padding to a multiple of four"""
    n = len(data) if length is None else length
    return struct.pack('>BBH', code, 0, n) + data + b'\0' * (-len(data) % 4)


NONCE = bytes(range(0xa0, 0xac))


def prefix64(plen, ipv4=()):
    b = struct.pack('>H', plen) + bytes(range(1, 13))
    if ipv4:
        b += struct.pack('>H', len(ipv4))
        for plen4, a in ipv4:
            b += struct.pack('>H4s', plen4, bytes(a))
    return b


def main_frames():
    f = []
    T, F = True, False
    # NAT-PMP
    f.append(frame(pmp_ext_req()))
    for r in (0, 1, 2, 3, 4, 5, 77):
        f.append(frame(pmp_ext_rsp(r), F))
    for tcp in (F, T):
        f.append(frame(pmp_map_req(tcp, 22, 2222, 3600)))
        f.append(frame(pmp_map_rsp(tcp, 0, 777, 22, 2222, 3600), F))
        f.append(frame(pmp_map_rsp(tcp, 4, 777, 22, 0, 0), F))
    f.append(frame(pmp_ext_rsp(0), F, sport=5350, dst=bytes([224, 0, 0, 1])))     # announcement
    f.append(frame(bytes([0, 9, 1, 2, 3]), T))                                # unknown opcode
    f.append(frame(pmp_map_req(F, 53, 5353, 60), T, sport=5351, dport=40001))  # on another port, still 5351
    # PCP announce, map, peer, version 1 and 2
    for ver in (1, 2):
        f.append(frame(pcp_req_hdr(ver, 0)))
        f.append(frame(pcp_rsp_hdr(ver, 0), F))
        f.append(frame(pcp_map(ver, F, NONCE, 6, 22, 2222, ip4mapped(0, 0, 0, 0)), T))
        f.append(frame(pcp_map(ver, F, NONCE, 17, 53, 0, IP6, life=0), T))
        f.append(frame(pcp_map(ver, F, NONCE, 0, 0, 0, b'\0' * 16), T))
        f.append(frame(pcp_map(ver, T, NONCE, 6, 22, 2222, ip4mapped(203, 0, 113, 9)), F))
        f.append(frame(pcp_map(ver, T, NONCE, 33, 22, 0, IP6, result=2), F))
        f.append(frame(pcp_map(ver, T, NONCE, 132, 22, 2222, IP6, result=8, life=0), F))
        f.append(frame(pcp_peer(ver, F, NONCE, 17, 4000, 4000, ip4mapped(0, 0, 0, 0), 5060, ip4mapped(198, 51, 100, 7)), T))
        f.append(frame(pcp_peer(ver, T, NONCE, 17, 4000, 4000, ip4mapped(203, 0, 113, 9), 5060, ip4mapped(198, 51, 100, 7)), F))
        f.append(frame(pcp_rsp_hdr(ver, 0, result=3), F))
        f.append(frame(pcp_rsp_hdr(ver, 0, result=14), F))
    # unknown opcodes (request, response): no opcode tree, no options
    f.append(frame(pcp_req_hdr(2, 5) + b'\x01\x02', T))
    f.append(frame(pcp_rsp_hdr(2, 6), F))
    # options
    base_req = pcp_map(2, F, NONCE, 6, 22, 2222, ip4mapped(0, 0, 0, 0))
    base_rsp = pcp_map(2, T, NONCE, 6, 22, 2222, ip4mapped(203, 0, 113, 9))
    f.append(frame(base_req + opt(1, IP6), T))                                   # THIRD_PARTY
    f.append(frame(base_req + opt(2, b''), T))                                   # PREFER_FAILURE
    f.append(frame(base_req + opt(2, b'\0\0\0\0'), T))                          # with a (meaningless) value
    flt = struct.pack('>BBH', 0, 24, 5060) + ip4mapped(198, 51, 100, 0)
    f.append(frame(base_req + opt(3, flt), T))                                   # FILTER
    f.append(frame(base_req + opt(128, b'web server'), T))                       # DESCRIPTION
    f.append(frame(base_req + opt(128, b'abcd'), T))
    f.append(frame(base_req + opt(129, prefix64(96)), F))                        # PREFIX64
    f.append(frame(base_rsp + opt(129, prefix64(64, [(24, (192, 0, 2, 0)), (32, (198, 51, 100, 0))])), F))
    f.append(frame(base_rsp + opt(129, prefix64(0)), F))
    f.append(frame(base_rsp + opt(129, prefix64(12, [(24, (10, 0, 0, 0))])), F))
    f.append(frame(base_req + opt(130, struct.pack('>HHBBBB', 16, 40000, 1, 0, 0, 0)), T))   # PORT_SET, parity
    f.append(frame(base_rsp + opt(130, struct.pack('>HHBBBB', 8, 41000, 0, 0, 0, 0)), F))
    f.append(frame(base_req + opt(131, b'1234'), T))                             # unknown option
    f.append(frame(base_req + opt(7, b'\x01\x02\x03'), T))                       # unknown option, padded
    # the reproducer of "NAT-PMP: Reset the PCP option padding per option":
    # a description of 5 octets (3 padding) followed by options that are multiples of four
    f.append(frame(base_req + opt(128, b'hello') + opt(128, b'wxyz') + opt(2, b''), T))
    f.append(frame(base_req + opt(128, b'abc') + opt(3, flt) + opt(1, IP6), T))
    # several options and the information column of a MAP with a port set
    f.append(frame(base_req + opt(2, b'') + opt(128, b'two') + opt(130, struct.pack('>HHBBBB', 4, 50000, 0, 0, 0, 0)), T))
    f.append(frame(pcp_peer(2, F, NONCE, 6, 1, 2, ip4mapped(0, 0, 0, 0), 3, ip4mapped(1, 2, 3, 4)) + opt(2, b'') + opt(128, b'peer!'), T))
    f.append(frame(pcp_peer(1, T, NONCE, 6, 1, 2, ip4mapped(1, 2, 3, 4), 3, ip4mapped(1, 2, 3, 4)) + opt(3, flt), F))
    f.append(frame(pcp_req_hdr(2, 0) + opt(128, b'announce with an option'), T))   # options after ANNOUNCE
    return f


def malformed_frames():
    f = []
    T, F = True, False
    base_req = pcp_map(2, F, NONCE, 6, 22, 2222, ip4mapped(0, 0, 0, 0))
    base_rsp = pcp_map(2, T, NONCE, 6, 22, 2222, ip4mapped(203, 0, 113, 9))
    flt = struct.pack('>BBH', 0, 24, 5060) + ip4mapped(198, 51, 100, 0)
    f.append(frame(bytes([3, 0, 0, 0]), T))                    # unknown version -> not dissected
    f.append(frame(bytes([0]), T))                             # NAT-PMP, only the version
    f.append(frame(bytes([0, 128, 0]), F))                     # truncated response
    f.append(frame(pmp_map_rsp(F, 0, 1, 2, 3, 4)[:10], F))
    f.append(frame(pmp_map_req(F, 22, 22, 22)[:6], T))
    f.append(frame(bytes([1]), T))                             # PCP, only the version
    f.append(frame(pcp_req_hdr(2, 1)[:20], T))
    f.append(frame(pcp_rsp_hdr(2, 1)[:14], F))
    f.append(frame(base_req[:50], T))
    f.append(frame(base_rsp[:30], F))
    # option errors
    f.append(frame(base_req + struct.pack('>BBH', 128, 0, 1000) + b'xx', T))    # length beyond the end
    f.append(frame(base_req + struct.pack('>BBH', 1, 0, 16) + b'\0' * 8, T))     # third party, cut
    f.append(frame(base_req + b'\x03\x00', T))                                   # option header cut
    f.append(frame(base_req + struct.pack('>BBH', 3, 0, 20) + flt[:10], T))      # filter, cut
    f.append(frame(base_req + struct.pack('>BBH', 130, 0, 5) + b'\0\0\0\0\0\0\0\0', T))
    f.append(frame(base_req + struct.pack('>BBH', 130, 0, 2) + b'\0\0', T))      # port set cut
    # PREFIX64 with every "TODO: report an error" path
    f.append(frame(base_rsp + opt(129, b'\x00'), F))                              # < 2 octets
    f.append(frame(base_rsp + opt(129, struct.pack('>H', 96) + b'\x01\x02\x03'), F))   # < 12 after the length
    f.append(frame(base_rsp + opt(129, struct.pack('>H', 200) + bytes(range(12))), F))  # length > 12
    f.append(frame(base_rsp + opt(129, struct.pack('>H', 64) + bytes(range(12)) + b'\x00'), F))   # count cut
    f.append(frame(base_rsp + opt(129, prefix64(64)[:14] + struct.pack('>H', 3) + b'\x00\x18'), F))   # prefix length, no address
    f.append(frame(base_rsp + opt(129, prefix64(64)[:14] + struct.pack('>H', 3) + b'\x00\x18\x01\x02\x03\x04'), F))  # count > entries
    f.append(frame(base_rsp + opt(129, prefix64(64)[:14] + struct.pack('>H', 3) + b'\x00'), F))   # cut inside the loop
    f.append(frame(base_rsp + opt(129, prefix64(64)[:14] + struct.pack('>H', 3)), F))
    # truncations of valid options
    for n in range(1, 24):
        f.append(frame((base_req + opt(128, b'hello') + opt(3, flt))[:len(base_req) + n], T))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m = main_frames()
    write_pcap(os.path.join(out, 'nat-pmp-coverage.pcap'), m)
    x = malformed_frames()
    write_pcap(os.path.join(out, 'nat-pmp-coverage-malformed.pcap'), x)
    print(len(m), 'frames,', len(x), 'malformed-capture frames')


if __name__ == '__main__':
    main()
