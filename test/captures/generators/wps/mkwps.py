#!/usr/bin/env python3
# Generates test/captures/wps_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the WPS coverage captures: usage mkwps.py <outdir> [-v]
# Wi-Fi Protected Setup TLVs travel in the Microsoft vendor IE (type 4) of
# 802.11 management frames, in EAP-WSC (EAP expanded type, WFA vendor ID,
# vendor type 1) over EAPOL, and the WFA Multi-AP extension in the WFA vendor
# IE (subtype 27). Keys, hashes, nonces and encrypted settings are opaque
# made-up bytes; nothing is encrypted or derived.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from wlanlib import (
    assoc_req, assoc_resp, beacon, MS, PcapNg, probe_req, probe_resp, tag, vendor_ie, wfa_ie,
)

def pat(n, b=0x40):
    return bytes((b + i) & 0xff for i in range(n))

def T(t, data):
    return struct.pack('>HH', t, len(data)) + data

# (type, kind, size): kind 'f' fixed size, 'v' variable up to size (sample length used)
TLVS = [
    (0x1001, 'f', 2), (0x1002, 'f', 2), (0x1003, 'f', 2), (0x1004, 'f', 2), (0x1005, 'f', 8),
    (0x1008, 'f', 2), (0x1009, 'f', 2), (0x100a, 'v', 64), (0x100b, 'v', 76), (0x100c, 'f', 1),
    (0x100d, 'f', 1), (0x100e, 'v', 40), (0x100f, 'f', 2), (0x1010, 'f', 2), (0x1011, 'v', 32),
    (0x1012, 'f', 2), (0x1014, 'f', 32), (0x1015, 'f', 32), (0x1016, 'f', 16), (0x1017, 'f', 16),
    (0x1018, 'v', 48), (0x101a, 'f', 16), (0x101b, 'f', 4), (0x101c, 'v', 80), (0x101d, 'v', 20),
    (0x101e, 'f', 8), (0x101f, 'f', 16), (0x1020, 'f', 6), (0x1021, 'v', 64), (0x1022, 'f', 1),
    (0x1023, 'v', 32), (0x1024, 'v', 32), (0x1026, 'f', 1), (0x1027, 'v', 64), (0x1028, 'f', 1),
    (0x1029, 'v', 32), (0x102a, 'v', 64), (0x102c, 'v', 56), (0x102d, 'f', 4), (0x102f, 'f', 1),
    (0x1030, 'f', 1), (0x1031, 'f', 1), (0x1032, 'f', 192), (0x1033, 'f', 1), (0x1034, 'f', 1),
    (0x1035, 'f', 1), (0x1036, 'f', 1), (0x1037, 'v', 21), (0x1038, 'f', 1), (0x1039, 'f', 16),
    (0x103a, 'f', 1), (0x103b, 'f', 1), (0x103c, 'f', 1), (0x103d, 'f', 32), (0x103e, 'f', 32),
    (0x103f, 'f', 16), (0x1040, 'f', 16), (0x1041, 'f', 1), (0x1042, 'v', 32), (0x1044, 'f', 1),
    (0x1045, 'v', 32), (0x1046, 'f', 1), (0x1047, 'f', 16), (0x1048, 'f', 16), (0x104a, 'f', 1),
    (0x104b, 'v', 30), (0x104c, 'v', 60), (0x104d, 'v', 64), (0x104e, 'f', 8), (0x104f, 'f', 20),
    (0x1050, 'f', 32), (0x1051, 'f', 4), (0x1052, 'f', 2), (0x1053, 'f', 2), (0x1055, 'v', 128),
    (0x1056, 'f', 1), (0x1057, 'f', 1), (0x1058, 'v', 100), (0x1059, 'v', 8), (0x1060, 'f', 32),
    (0x1061, 'f', 1), (0x1062, 'f', 1), (0x1063, 'v', 128), (0x1064, 'f', 1), (0x106a, 'f', 8),
    (0x1bbb, 'v', 60), (0x1bbc, 'f', 1),
]
OUI_WFA_DEV = bytes.fromhex('0050f204')

def wfa_ext(i, data):
    return bytes([i, len(data)]) + data

def vext(*exts, vendor=b'\x00\x37\x2a'):
    return T(0x1049, vendor + b''.join(exts))

def ptype(cat, sub, oui=OUI_WFA_DEV):
    return struct.pack('>H', cat) + oui + struct.pack('>H', sub)

V2 = wfa_ext(0x00, b'\x20')

def tlv_fixed_all():
    return [T(t, pat(n, t & 0xff)) for t, k, n in TLVS if k == 'f' and t not in (0x1054,)]
def tlv_var_all():
    return [T(t, (b'x' * n if t in (0x100a, 0x100b, 0x1011, 0x101c, 0x1021, 0x1023, 0x1024, 0x1029, 0x1042, 0x1045, 0x104d, 0x1bbb) else pat(n, t & 0xff)))
            for t, k, n in TLVS if k == 'v']

def wps_ie(*tlvs):
    return vendor_ie(MS, 4, b''.join(tlvs))

# EAPOL / EAP-WSC
EA = bytes.fromhex('02bb00000001'); EB = bytes.fromhex('02bb00000002')
def eapol_eap(code, ident, etype, data, a=EA, b=EB, length=None):
    eap = struct.pack('>BBH', code, ident, 4 + (1 + len(data) if etype is not None else 0) if length is None else length) + \
          ((bytes([etype]) + data) if etype is not None else b'')
    return b + a + b'\x88\x8e' + struct.pack('>BBH', 2, 0, len(eap)) + eap

def wsc(code, ident, opcode, flags, tlvs, msglen=None, a=EA, b=EB, vtype=1):
    d = b'\x00\x37\x2a' + struct.pack('>I', vtype) + bytes([opcode, flags])
    if msglen is not None:
        d += struct.pack('>H', msglen)
    d += tlvs
    return eapol_eap(code, ident, 254, d, a, b)

main = PcapNg(); mal = PcapNg(); ranges = []
def mark(p, name, n0):
    ranges.append((name, n0 + 1, len(p.frames)))
def addw(p, f): p.add(f, 127)
def adde(p, f): p.add(f, 1)

# ---- 802.11 frames with the WPS IE ----
n0 = len(main.frames)
beacon_tl = [T(0x104a, b'\x10'), T(0x1044, b'\x02'), T(0x1057, b'\x01'), T(0x1041, b'\x01'),
             T(0x1012, b'\x00\x04'), T(0x1053, b'\xff\xff'), T(0x1047, pat(16)), T(0x103c, b'\x03'),
             T(0x1021, b'Example Corp'), T(0x1023, b'Model-X'), T(0x1024, b'1234'), T(0x1042, b'0001'),
             T(0x1054, ptype(6, 1)), T(0x1011, b'Example AP'), T(0x1008, b'\x01\x88'),
             T(0x1002, b'\x00\x00'), T(0x1009, b'\x00\x00'), T(0x1045, b'wps-ssid'), vext(V2)]
addw(main, beacon(tag(0, b'wps-ssid') + wps_ie(*beacon_tl)))
addw(main, probe_resp(tag(0, b'wps-ssid') + wps_ie(*beacon_tl)))
addw(main, probe_req(tag(0, b'wps-ssid') + wps_ie(T(0x104a, b'\x10'), T(0x103a, b'\x01'), T(0x1008, b'\x00\x80'),
        T(0x1047, pat(16)), T(0x1054, ptype(1, 1)), T(0x103c, b'\x01'), T(0x1002, b'\x00\x00'),
        T(0x1009, b'\x00\x00'), T(0x1012, b'\x00\x00'), T(0x1021, b'Acme'), T(0x1023, b'Phone'),
        T(0x1024, b'7'), T(0x1011, b'My Phone'), T(0x106a, ptype(1, 1)),
        vext(V2, wfa_ext(0x03, b'\x01'), wfa_ext(0x02, b'\x00'), wfa_ext(0x04, b'\x05'),
             wfa_ext(0x01, pat(12)), wfa_ext(0x05, b'\x01\x88')))))
addw(main, assoc_req(wps_ie(T(0x104a, b'\x10'), T(0x103a, b'\x02'))))
addw(main, assoc_resp(wps_ie(T(0x104a, b'\x10'), T(0x103b, b'\x03'))))
# the IE with a trailing fragment shorter than a TLV header: no expert info without EAP details
addw(main, probe_req(wps_ie(T(0x104a, b'\x10'), b'\x10\x08\x00')))
addw(main, probe_req(wps_ie(T(0x4242, b'\x01\x02\x03\x04'))))   # unknown TLV type
mark(main, 'WPS IE (Microsoft OUI type 4) in beacon, probe, association frames', n0)

# ---- WFA Multi-AP extension (WFA vendor IE subtype 27) and vendor extension TLV variants ----
n0 = len(main.frames)
def mapie(*e): return wfa_ie(27, b''.join(e))
addw(main, beacon(mapie(wfa_ext(0x06, b'\x00'), wfa_ext(0x07, b'\x02'), wfa_ext(0x08, b'\x00\x64'))))
for bits in (0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01, 0xff):
    addw(main, probe_resp(mapie(wfa_ext(0x06, bytes([bits])))))
addw(main, probe_resp(mapie(wfa_ext(0x00, b'\x20'), wfa_ext(0x01, pat(18)), wfa_ext(0x02, b'\x01'),
                            wfa_ext(0x03, b'\x00'), wfa_ext(0x04, b'\x0a'), wfa_ext(0x05, b'\x01\x88'))))
# the reproducer of the fix: an extension of length 0 as the last two octets
addw(main, probe_resp(mapie(wfa_ext(0x06, b'\x00'), bytes([0x7f, 0x00]))))
addw(main, probe_resp(mapie(bytes([0x7e, 0x00]))))
addw(main, probe_resp(mapie(wfa_ext(0x7d, b'\x01\x02'), bytes([0x09]))))     # a lone octet at the end
addw(main, probe_resp(mapie(wfa_ext(0x06, b'\x00'), bytes([0x08, 0x05, 0x00]))))   # length past the end
addw(main, probe_resp(wps_ie(vext(wfa_ext(0x00, b'\x20'), bytes([0x7f, 0x00])))))   # same in the vendor extension TLV
addw(main, probe_resp(wps_ie(vext(wfa_ext(0x06, b'\x00'), wfa_ext(0x07, b'\x01'), wfa_ext(0x08, b'\x00\x01')))))
addw(main, probe_resp(wps_ie(vext(b'', vendor=b'\x00\x37\x2a'))))                  # no extensions
addw(main, probe_resp(wps_ie(vext(V2, vendor=b'\x00\x01\x02'))))                    # another vendor
addw(main, probe_resp(wps_ie(T(0x1049, b'\x00\x37'))))                              # vendor extension under 3 octets
mark(main, 'Multi-AP IE (every flag), WFA extension entries, trailing zero-length entry (fix)', n0)

# ---- EAP-WSC over EAPOL ----
n0 = len(main.frames)
adde(main, eapol_eap(1, 1, 1, b''))                                           # EAP Request Identity
adde(main, eapol_eap(2, 1, 1, b'WFA-SimpleConfig-Enrollee-1-0', EB, EA))      # Response Identity
adde(main, wsc(1, 2, 1, 0, b''))                                              # WSC_Start
m1 = [T(0x104a, b'\x10'), T(0x1022, b'\x04'), T(0x1047, pat(16)), T(0x1020, EB), T(0x101a, pat(16, 1)),
      T(0x1032, pat(192, 2)), T(0x1004, b'\x00\x3f'), T(0x1010, b'\x00\x0f'), T(0x100d, b'\x03'),
      T(0x1008, b'\x21\x48'), T(0x1044, b'\x01'), T(0x1021, b'Acme'), T(0x1023, b'Model'),
      T(0x1024, b'1'), T(0x1042, b'SN1'), T(0x1054, ptype(2, 1)), T(0x1011, b'Printer'),
      T(0x103c, b'\x03'), T(0x1002, b'\x00\x00'), T(0x1012, b'\x00\x00'), T(0x1009, b'\x00\x00'),
      T(0x102d, b'\x80\x00\x00\x01'), vext(V2)]
adde(main, wsc(2, 2, 4, 0, b''.join(m1), a=EB, b=EA))
m2 = [T(0x104a, b'\x10'), T(0x1022, b'\x05'), T(0x101a, pat(16, 1)), T(0x1039, pat(16, 3)), T(0x1048, pat(16, 4)),
      T(0x1032, pat(192, 5)), T(0x1004, b'\x00\x3f'), T(0x1010, b'\x00\x0f'), T(0x100d, b'\x03'),
      T(0x1008, b'\x01\x88'), T(0x1021, b'Acme'), T(0x1023, b'AP'), T(0x1024, b'2'), T(0x1042, b'SN2'),
      T(0x1054, ptype(6, 1)), T(0x1011, b'AP'), T(0x103c, b'\x03'), T(0x1002, b'\x00\x00'),
      T(0x1012, b'\x00\x00'), T(0x1009, b'\x00\x00'), T(0x102d, b'\x80\x00\x00\x01'), vext(V2),
      T(0x1005, pat(8, 6))]
adde(main, wsc(1, 3, 4, 0, b''.join(m2)))
adde(main, wsc(2, 3, 4, 0, T(0x104a, b'\x10') + T(0x1022, b'\x07') + T(0x1039, pat(16, 3)) + T(0x103d, pat(32, 1)) +
               T(0x103e, pat(32, 2)) + T(0x1005, pat(8)), a=EB, b=EA))              # M3
adde(main, wsc(1, 4, 4, 0, T(0x104a, b'\x10') + T(0x1022, b'\x08') + T(0x101a, pat(16)) + T(0x1014, pat(32)) +
               T(0x1015, pat(32)) + T(0x1018, pat(48)) + T(0x1005, pat(8))))         # M4
adde(main, wsc(2, 4, 4, 0, T(0x104a, b'\x10') + T(0x1022, b'\x09') + T(0x1039, pat(16)) + T(0x1018, pat(48)) +
               T(0x1005, pat(8)), a=EB, b=EA))                                       # M5
adde(main, wsc(1, 5, 4, 0, T(0x104a, b'\x10') + T(0x1022, b'\x0a') + T(0x101a, pat(16)) + T(0x1018, pat(48)) +
               T(0x1005, pat(8))))                                                   # M6
adde(main, wsc(2, 5, 4, 0, T(0x104a, b'\x10') + T(0x1022, b'\x0b') + T(0x1039, pat(16)) + T(0x1018, pat(96)) +
               T(0x1005, pat(8)), a=EB, b=EA))                                       # M7
adde(main, wsc(1, 6, 4, 0, T(0x104a, b'\x10') + T(0x1022, b'\x0c') + T(0x101a, pat(16)) + T(0x1018, pat(120)) +
               T(0x1005, pat(8))))                                                   # M8
adde(main, wsc(2, 6, 5, 0, T(0x104a, b'\x10') + T(0x1022, b'\x0f') + T(0x101a, pat(16)) + T(0x1039, pat(16)), a=EB, b=EA))   # WSC_Done
adde(main, wsc(2, 7, 2, 0, T(0x104a, b'\x10') + T(0x1022, b'\x0d') + T(0x101a, pat(16)) + T(0x1039, pat(16)), a=EB, b=EA))   # WSC_ACK
adde(main, wsc(2, 8, 3, 0, T(0x104a, b'\x10') + T(0x1022, b'\x0e') + T(0x101a, pat(16)) + T(0x1039, pat(16)) +
               T(0x1009, b'\x00\x0f'), a=EB, b=EA))                                 # WSC_NACK
adde(main, wsc(1, 9, 6, 0, b''))                                                      # FRAG_ACK
# fragmented message: first fragment with the length field and more fragments
full = b''.join(m2)
p1 = b''.join(m2[:6]); p2 = b''.join(m2[6:14]); p3 = b''.join(m2[14:])   # split at TLV boundaries: the dissector does not reassemble
adde(main, wsc(1, 10, 4, 0x03, p1, msglen=len(full)))
adde(main, wsc(2, 10, 6, 0, b'', a=EB, b=EA))
adde(main, wsc(1, 11, 4, 0x01, p2))
adde(main, wsc(2, 11, 6, 0, b'', a=EB, b=EA))
adde(main, wsc(1, 12, 4, 0x00, p3))
adde(main, wsc(1, 13, 4, 0x02, T(0x104a, b'\x10'), msglen=7))                         # length field without more fragments
adde(main, wsc(1, 14, 7, 0, b''))                                                     # unknown opcode
mark(main, 'EAP-WSC over EAPOL: identity, WSC_Start, M1-M8, Done, ACK, NACK, FRAG_ACK, fragmentation', n0)

n0 = len(main.frames)
# every TLV type with a valid length (fixed sizes; variable ones at their maximum), in EAP-WSC
fixed = tlv_fixed_all(); var = tlv_var_all()
allt = fixed + var
for i in range(0, len(allt), 6):
    adde(main, wsc(1, 20 + i // 6, 4, 0, b''.join(allt[i:i + 6])))
# every primary device type category and WFA / non-WFA OUI
for cat in range(0, 14):
    adde(main, wsc(1, 60 + cat, 4, 0, T(0x1054, ptype(cat, cat * 3 % 7 + 1)) + T(0x1054, ptype(cat, 1, bytes.fromhex('00112233')))))
for cat in range(1, 12):
    for sub in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12):
        pass
subs = [(1, (1, 2, 3, 4, 5)), (2, (1, 2, 3, 4)), (3, (1, 2, 3, 4, 5, 6)), (4, (1, 2, 3, 4, 5)), (5, (1, 2, 3, 4, 5, 6)), (6, (1, 2, 3, 4)),
        (7, (1, 2, 3, 4, 5, 6, 7, 8)), (8, (1, 2, 3, 4)), (9, (1, 2, 3)), (10, (1, 2, 3, 4, 5, 6, 7, 8, 9)), (11, (1, 2, 3, 4, 5, 6, 7))]
for cat, ss in subs:
    adde(main, wsc(1, 80 + cat, 4, 0, b''.join(T(0x1054, ptype(cat, s)) for s in ss)))
# every bit of the bit fields
for t in (0x1004, 0x1008, 0x1010, 0x1052, 0x1053):
    for bit in range(16):
        pass
    adde(main, wsc(1, 100, 4, 0, b''.join(T(t, struct.pack('>H', 1 << b)) for b in range(16))))
adde(main, wsc(1, 101, 4, 0, b''.join(T(0x100d, bytes([1 << b])) for b in range(4))))
adde(main, wsc(1, 102, 4, 0, T(0x100c, b'\x01') + T(0x100d, b'\x03') + T(0x1012, b'\x00\x10') + T(0x4242, b'xyz') + T(0x1049, b'\x00\x37\x2a' + V2)))
mark(main, 'every TLV type, primary device type categories and bit fields (EAP-WSC)', n0)

# ---- malformed ----
n0 = len(mal.frames)
over = [(0x100a, 65), (0x100b, 77), (0x1011, 33), (0x101c, 81), (0x1021, 65), (0x1023, 33), (0x1024, 33), (0x1029, 33),
        (0x102a, 65), (0x102c, 57), (0x1042, 33), (0x1045, 33), (0x1027, 65), (0x104d, 65), (0x1055, 129), (0x1058, 513),
        (0x1059, 9), (0x1063, 129), (0x1047, 17), (0x1048, 17)]
for t, n in over:
    adde(mal, wsc(1, 1, 4, 0, T(t, b'A' * n)))
for t, n in ((0x1014, 31), (0x1014, 33), (0x1015, 33), (0x1016, 15), (0x1016, 17), (0x1017, 17), (0x101a, 15), (0x101a, 17), (0x1032, 191), (0x1032, 193)):
    adde(mal, wsc(1, 1, 4, 0, T(t, b'B' * n)))
adde(mal, wsc(1, 1, 4, 0, T(0x104a, b'\x10') + b'\x10\x22\x00'))        # trailing fragment of 3 octets
adde(mal, wsc(1, 1, 4, 0, T(0x104a, b'\x10') + b'\x10'))                 # 1 octet
adde(mal, wsc(1, 1, 4, 0, T(0x104a, b'\x10') + b'\x10\x22\x00\x01'))   # TLV without its value (exception)
adde(mal, wsc(1, 1, 4, 0, T(0x1008, b'\x01')))                            # config methods of 1 octet (exception)
adde(mal, wsc(1, 1, 4, 0, T(0x1054, b'\x00\x01')))                       # primary device type cut
adde(mal, wsc(1, 1, 4, 0, T(0x1049, b'\x00\x37\x2a\x06\x01')))           # WFA extension past the TLV
adde(mal, wsc(1, 1, 4, 0, b'')[:-3])
adde(mal, wsc(1, 1, 4, 0x02, b''))                                        # length flag without the length field
adde(mal, eapol_eap(1, 1, 254, b'\x00\x37\x2a\x00\x00\x00'))           # expanded type cut in the vendor type
adde(mal, eapol_eap(1, 1, 254, b'\x00\x37\x2a\x00\x00\x00\x01'))      # no opcode
addw(mal, probe_req(wps_ie(T(0x1054, b'\x00\x01'))))
addw(mal, probe_req(wps_ie(T(0x1008, b'\x01'))))
addw(mal, probe_req(wps_ie(T(0x1049, b'\x00\x37\x2a\x06\x09'))))
addw(mal, probe_req(wfa_ie(27, b'\x06\x01')))                             # flags missing
addw(mal, probe_req(wfa_ie(27, b'\x00\x01')))
mark(mal, 'malformed', n0)

out = sys.argv[1]
main.write(os.path.join(out, 'wps-coverage.pcapng'))
mal.write(os.path.join(out, 'wps-coverage-malformed.pcapng'))
if '-v' in sys.argv:
    for r in ranges: print(*r)
