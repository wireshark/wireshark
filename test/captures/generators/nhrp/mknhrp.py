#!/usr/bin/env python3
# Generates test/captures/nhrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the NHRP coverage captures: mknhrp.py <outdir>
import struct
import os
import sys

out = sys.argv[1] if len(sys.argv) > 1 else '.'
ETH_C = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01'
SRC = bytes([192, 0, 2, 1]); DST = bytes([192, 0, 2, 2])

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def ipv4(payload, proto, src=SRC, dst=DST):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload

# ---- NHRP -----------------------------------------------------------------
RES_REQ, RES_REP, REG_REQ, REG_REP, PUR_REQ, PUR_REP, ERR, TRAFFIC = range(1, 9)

def cie(code=0, prefix=32, mtu=1400, hold=300, addr=b'', saddr=b'', prot=b'', pref=0, atl=None, stl=None):
    return struct.pack('>BBHHHBBBB', code, prefix, 0, mtu, hold,
        len(addr) if atl is None else atl, len(saddr) if stl is None else stl, len(prot), pref) + addr + saddr + prot

def ext(typ, data=b'', c=False, length=None):
    t = typ | (0x8000 if c else 0)
    return struct.pack('>HH', t, len(data) if length is None else length) + data

def nhrp(op, mand, exts=b'', afn=1, pro=0x0800, snap=None, hop=255, shtl=4, sstl=0,
         version=1, extoff=None, pktsz=None, badsum=False, protbytes=bytes(5)):
    """mand: the mandatory part; exts: the extensions."""
    if snap is not None:
        pro = 0x0080
        protbytes = snap[0].to_bytes(3, 'big') + struct.pack('>H', snap[1])
    total = 20 + len(mand) + len(exts)
    if extoff is None:
        extoff = (20 + len(mand)) if exts else 0
    hdr = struct.pack('>HH5sBHHHBBBB', afn, pro, protbytes, hop, total if pktsz is None else pktsz, 0, extoff,
                      version, op, shtl, sstl)
    pkt = hdr + mand + exts
    c = csum(pkt)
    if badsum: c ^= 0x1234
    return pkt[:12] + struct.pack('>H', c) + pkt[14:]

def mand(op, srcnbma=SRC, srcsub=b'', src=SRC, dst=DST, cies=b'', flags=0, rid=1, extra=None, srclen=None, dstlen=None):
    sl = len(src) if srclen is None else srclen
    dl = len(dst) if dstlen is None else dstlen
    if op in (ERR,):
        mid = struct.pack('>HHH', 0, 7, 0) if extra is None else extra
    elif op == TRAFFIC:
        mid = struct.pack('>HHH', 0, 0, 0)
    elif op in (RES_REQ, RES_REP, REG_REQ, REG_REP, PUR_REQ, PUR_REP):
        mid = struct.pack('>HI', flags, rid)
    else:
        mid = bytes(6)
    return bytes([sl, dl]) + mid + srcnbma + srcsub + src + dst + cies

frames = []
def eth_ip(nhrp_pkt, **kw):
    frames.append(ETH_C + b'\x08\x00' + ipv4(nhrp_pkt, 54, **kw))

def eth_ip6(pkt):
    s = bytes(range(0x20, 0x30)); d = bytes(range(0x30, 0x40))
    frames.append(ETH_C + b'\x86\xdd' + struct.pack('>IHBB16s16s', 0x60000000, len(pkt), 54, 64, s, d) + pkt)

def eth_gre(pkt):
    gre = struct.pack('>HH', 0, 0x2001)
    frames.append(ETH_C + b'\x08\x00' + ipv4(gre + pkt, 47))

def eth_llc(pkt):
    llc = b'\xaa\xaa\x03' + b'\x00\x00\x5e' + struct.pack('>H', 0x0003)
    frames.append(ETH_C[:12] + struct.pack('>H', len(llc) + len(pkt)) + llc + pkt)

def main_frames():
    A4 = lambda n: bytes([10, 0, 0, n])
    # --- resolution request / reply: flags, CIEs with every address length
    flags = 0x8000 | 0x2000 | 0x1000 | 0x0800 | 0x0100 | 0x0004
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, flags=flags, rid=1001, cies=cie(0, 24, addr=A4(1), prot=A4(2), pref=3) +
        cie(0, 32, addr=A4(3), saddr=b'\xaa\xbb', prot=A4(4)) + cie(0, 32, prot=A4(5)))))
    eth_ip(nhrp(RES_REP, mand(RES_REP, flags=0x8000, rid=1001, cies=cie(0, 24, addr=A4(1), prot=A4(2)) +
        cie(4, 24) + cie(5, 24) + cie(12, 24) + cie(13, 24) + cie(14, 24) + cie(99, 24))))
    # --- registration, purge
    eth_ip(nhrp(REG_REQ, mand(REG_REQ, flags=0x8000 | 0x0004, rid=2001, cies=cie(0, 32, addr=A4(7), prot=A4(7)))))
    eth_ip(nhrp(REG_REP, mand(REG_REP, flags=0x0004, rid=2001, cies=cie(0, 32, addr=A4(7), prot=A4(7)))))
    eth_ip(nhrp(PUR_REQ, mand(PUR_REQ, flags=0x8000 | 0x0004, rid=3001, cies=cie(0, 32, prot=A4(7)))))
    eth_ip(nhrp(PUR_REP, mand(PUR_REP, flags=0x8000, rid=3001, cies=cie(0, 32, prot=A4(7)))))
    # --- unknown packet type
    eth_ip(nhrp(0x42, bytes([4, 4, 0, 0, 0, 0, 0, 0]) + SRC + A4(1) + A4(2)))
    # --- error indication with each error code, the offending packet follows
    bad = nhrp(REG_REQ, mand(REG_REQ, rid=7, cies=cie(0, 32, prot=A4(7))))
    for code in (1, 3, 6, 7, 8, 9, 10, 11, 15, 16, 17, 99):
        eth_ip(nhrp(ERR, mand(ERR, extra=struct.pack('>HHH', 0, code, 20) , cies=bad)))
    # an error indication inside an error indication inside ...
    pk = bad
    for _ in range(4):
        pk = nhrp(ERR, mand(ERR, cies=pk))
    eth_ip(pk)
    # --- traffic indication: the packet that caused it, by every kind of protocol type
    ip_pkt = ipv4(b'\x08\x00' + bytes(10), 1)
    eth_ip(nhrp(TRAFFIC, mand(TRAFFIC, cies=ip_pkt)))                                  # ethertype 0x0800
    eth_ip(nhrp(TRAFFIC, mand(TRAFFIC, cies=ip_pkt), pro=0x00cc))                      # NLPID IP
    eth_ip(nhrp(TRAFFIC, mand(TRAFFIC, cies=b'\x01\x02\x03\x04'), pro=0x0081))         # NLPID without payload dissector
    eth_ip(nhrp(TRAFFIC, mand(TRAFFIC, cies=ip_pkt), snap=(0x000000, 0x0800)))         # SNAP, OUI 0: ethertype
    cdp = b'\x02\xb4\x00\x00' + struct.pack('>HH', 1, 10) + b'rtr1'
    cdp = cdp[:2] + struct.pack('>H', csum(cdp)) + cdp[4:]
    eth_ip(nhrp(TRAFFIC, mand(TRAFFIC, cies=cdp), snap=(0x00000c, 0x2000)))  # SNAP Cisco (CDP)
    eth_ip(nhrp(TRAFFIC, mand(TRAFFIC, cies=b'\x01\x02\x03\x04'), snap=(0x123456, 0x0001)))  # SNAP, no OUI table
    for pro in (0x0100, 0x0410, 0x0510):                                               # reserved, ATM Forum, local
        eth_ip(nhrp(TRAFFIC, mand(TRAFFIC, cies=b'\x01\x02\x03\x04'), pro=pro))
    ip6_pkt = struct.pack('>IHBB16s16s', 0x60000000, 4, 59, 64, bytes(range(1, 17)), bytes(range(17, 33))) + bytes(4)
    eth_ip(nhrp(TRAFFIC, mand(TRAFFIC, cies=ip6_pkt), pro=0x86dd))                       # IPv6
    # --- SNAP long form (reproducers: OUI as a big endian value, PID skipped, header fields after it)
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, flags=0x8000, rid=5, cies=cie(0, 32, prot=A4(1))), snap=(0x00005e, 0x0800), hop=7))
    # --- client NBMA subaddress in a CIE followed by the protocol address (reproducer)
    eth_ip(nhrp(RES_REP, mand(RES_REP, rid=9, cies=cie(0, 32, addr=A4(1), saddr=b'\x11\x22\x33', prot=A4(2)) +
        cie(0, 32, addr=A4(3), saddr=b'\x44', prot=A4(4)))))
    # --- extensions
    nat_cies = cie(0, 32, addr=A4(9), prot=A4(9))
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, rid=11, cies=cie(0, 32, prot=A4(1))),
        exts=ext(3, cie(0, 32, addr=A4(1), prot=A4(1))) + ext(4, cie(0, 32, addr=A4(2), prot=A4(2))) +
             ext(5, cie(0, 32, addr=A4(3), prot=A4(3))) + ext(9, nat_cies, c=True) +
             ext(9, struct.pack('>II', 1, 0)) + ext(20, b'\x01\x02\x03') + ext(0)))
    spi = struct.pack('>HH', 0, 77)
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, rid=12, cies=cie(0, 32, prot=A4(1))),
        exts=ext(7, spi + SRC + b'\xde\xad\xbe\xef') + ext(10, spi + SRC + b'\x01\x02') + ext(7, spi + SRC) +
             ext(10, spi) + ext(0)))
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, rid=13, cies=cie(0, 32, prot=A4(1))),
        exts=ext(8, b'\x00\x00\x5e' + b'vendor data') + ext(8, b'\x00\x00\x5e') + ext(8, b'\x12\x34\x56\x78') + ext(0)))
    # --- extension after which there is extra data (superfluous data follows the end extension)
    # (in the malformed capture)
    # --- IPv6 address family, protocol addresses of 16 bytes (the authentication extension at offset 4)
    s6 = bytes(range(0x40, 0x50)); d6 = bytes(range(0x50, 0x60)); n6 = bytes(range(0x60, 0x70))
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, rid=14, srcnbma=n6, src=s6, dst=d6,
        cies=cie(0, 128, addr=n6, prot=s6) + cie(0, 128, addr=A4(1), prot=b'\x01\x02\x03')),
        afn=2, pro=0x86dd, shtl=16, exts=ext(7, spi + s6 + b'\xca\xfe') + ext(3, cie(0, 128, addr=n6, prot=d6)) + ext(0)))
    eth_ip(nhrp(RES_REP, mand(RES_REP, rid=15, srcnbma=n6, src=s6, dst=d6, cies=cie(0, 128, addr=b'\x01\x02\x03', prot=d6)),
        afn=2, pro=0x86dd, shtl=16))
    # --- other address families and odd lengths (address as bytes)
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, rid=16, srcnbma=b'\x01\x02\x03\x04\x05\x06\x07\x08', srcsub=b'\xaa\xbb\xcc', src=b'\x01\x02\x03\x04\x05\x06',
        dst=b'\x07\x08\x09', cies=cie(0, 32, addr=b'\x01\x02\x03', prot=b'\x01\x02\x03\x04\x05\x06')),
        afn=3, pro=0x0800, shtl=8, sstl=3))
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, rid=17, srcnbma=b'\x01\x02\x03\x04\x05\x06', src=b'\x01\x02\x03\x04\x05', dst=A4(1),
        cies=cie(0, 32, addr=b'\x01\x02\x03\x04\x05')), afn=1, shtl=6))
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, rid=18, srcnbma=b'', src=A4(1), dst=A4(2)), shtl=0))
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, rid=19, srcnbma=b'\x01\x02\x03\x04\x05\x06\x07\x08', src=b'\x01\x02\x03\x04\x05\x06', dst=A4(1)),
        afn=2, shtl=8, exts=ext(7, spi + b'\x01\x02\x03\x04\x05\x06' + b'\x99') + ext(0)))
    # --- authentication extension without the address (preference auth_ext_has_addr off is in runcov.sh)
    # --- other transports: GRE, LLC/SNAP, IPv6
    eth_gre(nhrp(RES_REQ, mand(RES_REQ, rid=21, cies=cie(0, 32, prot=A4(1)))))
    eth_llc(nhrp(RES_REQ, mand(RES_REQ, rid=22, cies=cie(0, 32, prot=A4(1)))))
    eth_ip6(nhrp(RES_REQ, mand(RES_REQ, rid=23, cies=cie(0, 32, prot=A4(1)))))
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, rid=24, cies=cie(0, 32, prot=A4(1))), version=2))
    # --- extension offset equal to the packet size (no extensions) and unused CIE bytes
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, rid=25, cies=cie(0, 32, prot=A4(1)) + b'\x00\x01\x02')))

def malformed_frames():
    A4 = lambda n: bytes([10, 0, 0, n])
    m = mand(RES_REQ, rid=1, cies=cie(0, 32, prot=A4(1)))
    eth_ip(nhrp(RES_REQ, m, badsum=True))                       # bad checksum
    eth_ip(nhrp(RES_REQ, m, pktsz=19))                          # packet length below the header length
    eth_ip(nhrp(RES_REQ, m, exts=ext(0), extoff=10))            # extension offset too small
    eth_ip(nhrp(RES_REQ, m, exts=ext(0), extoff=1000))          # extension offset beyond the packet
    eth_ip(nhrp(ERR, mand(ERR, cies=nhrp(RES_REQ, m)), exts=ext(0), extoff=20 + len(mand(ERR, cies=nhrp(RES_REQ, m)))))  # extensions in an error indication
    eth_ip(nhrp(RES_REQ, m, exts=ext(7, b'\x01') + ext(10, b'') + ext(8, b'\x01\x02') + ext(0)))  # short auth / vendor extensions
    eth_ip(nhrp(RES_REQ, m, exts=ext(0) + b'\x01\x02\x03\x04\x05'))      # superfluous data after the end extension
    eth_ip(nhrp(RES_REQ, m, exts=ext(3, b'\x01\x02\x03\x04\x05', length=40)))   # extension longer than the packet
    eth_ip(nhrp(RES_REQ, m)[:19])                               # truncated header
    eth_ip(nhrp(RES_REQ, m)[:30])                               # truncated mandatory part
    eth_ip(nhrp(RES_REQ, mand(RES_REQ, srclen=200, dstlen=200, cies=b'')))   # protocol lengths past the end
    # reproducer: Error Indications nested ~2300 levels in one packet (bounded by the 16 bit packet length)
    pk = nhrp(RES_REQ, m)
    n = 0
    while len(pk) + 28 < 65000:
        pk = nhrp(ERR, mand(ERR, cies=pk)); n += 1
    eth_ip(pk)

def write_pcap(name, frs):
    with open(os.path.join(out, name), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frs):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

if __name__ == '__main__':
    main_frames()
    write_pcap('nhrp-coverage.pcap', frames)
    n = len(frames)
    frames.clear()
    malformed_frames()
    write_pcap('nhrp-coverage-malformed.pcap', frames)
    print(n, 'main frames,', len(frames), 'malformed frames')
