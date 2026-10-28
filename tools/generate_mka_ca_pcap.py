#!/usr/bin/env python3
#
# Generate a synthetic EAPOL-MKA capture for the mka,ca statistics test.
#
# Copyright (c) 2026 by the Wireshark developers
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# The capture contains no real traffic: every frame is built here from
# constants and converted to pcapng with text2pcap:
#
#   python3 tools/generate_mka_ca_pcap.py | \
#       text2pcap -l 1 -t "%Y-%m-%d %H:%M:%S" - test/captures/mka_ca.pcapng
#
# It models one Connectivity Association in which a key server (KS) and two
# peers (A, B) agree on a SAK. The frames are enough for the mka,ca analysis
# to list the CA, its peers, the key server, and one "Key Server Startup"
# peer group formation. CKN/CAK are not needed: the analysis lists a CA
# whenever an MKPDU carries a CKN.

import struct
import sys

# EAPOL (802.1X) constants.
ETH_P_PAE = 0x888E          # Port Access Entity ethertype
EAPOL_VERSION = 3           # 802.1X-2010
EAPOL_TYPE_MKA = 5          # EAPOL-MKA
PAE_GROUP_MAC = bytes.fromhex("0180c2000003")

# MKA parameter set types.
PS_LIVE_PEER_LIST = 1
PS_POTENTIAL_PEER_LIST = 2
PS_SAK_USE = 3
PS_DISTRIBUTED_SAK = 4
PS_ICV = 255

CKN = bytes.fromhex("00" * 15 + "01")      # 16-byte CA Key Name
ICV = bytes(16)                             # placeholder ICV (not verified)

# Actors: MAC / SCI system-id, MI (12 bytes), SCI = MAC + port 0x0001.
KS = dict(mac="020000000001", mi="aa" * 12)
A = dict(mac="020000000002", mi="bb" * 12)
B = dict(mac="020000000003", mi="cc" * 12)

KN = 1                       # key number
SAK_AN = 0                   # association number


def ps(set_type, flags_hi, body):
    '''A parameter set: type(1), flags(1), 12-bit body length, body padded to
    a 4-byte boundary. The length occupies the low 12 bits of the 2-byte
    field at offset+2; the top 4 bits (high nibble of the flags octet) are
    reserved/flags.  @p flags_hi supplies the high nibble (e.g. 0x8 for the
    key-server bit of the Basic Parameter Set, 0x0 otherwise).'''
    n = len(body)
    byte2 = (flags_hi << 4) | ((n >> 8) & 0x0f)
    hdr = struct.pack("!BBB", set_type, 0, byte2) + struct.pack("!B", n & 0xff)
    pad = (-n) % 4
    return hdr + body + bytes(pad)


def ki(actor):
    '''Key Identifier: 12-byte MI of the distributing actor + 4-byte KN.'''
    return bytes.fromhex(actor["mi"]) + struct.pack("!I", KN)


def basic_param_set(actor, key_server):
    '''Basic Parameter Set (the first, mandatory parameter set): MKA version,
    key-server priority, flags + 12-bit length, SCI, actor MI, message
    number, algorithm agility, and the CKN. Body length counts the 28 fixed
    bytes plus the CKN.'''
    sci = bytes.fromhex(actor["mac"]) + struct.pack("!H", 1)   # 8-byte SCI
    mi = bytes.fromhex(actor["mi"])                            # 12-byte MI
    fixed = sci + mi + struct.pack("!I", 1) + bytes.fromhex("0080c201")
    body = fixed + CKN                      # 28 fixed + CKN
    n = len(body)
    ks_flag = 0x80 if key_server else 0x00
    # Byte0 MKA version, byte1 key-server priority, byte2 flags|len-hi,
    # byte3 len-lo.
    hdr = struct.pack("!BB", EAPOL_VERSION, 0)
    hdr += struct.pack("!B", ks_flag | ((n >> 8) & 0x0f))
    hdr += struct.pack("!B", n & 0xff)
    return hdr + body


def distributed_sak():
    '''Distributed SAK parameter set: KN plus a wrapped-key placeholder. The
    association number is carried in the high nibble of the flags octet.'''
    body = struct.pack("!I", KN) + bytes(24)
    return ps(PS_DISTRIBUTED_SAK, SAK_AN & 0x0f, body)


def sak_use(actor):
    '''SAK Use parameter set referencing the latest key by its KI, with the
    latest-AN rx/tx flags set in the high nibble.'''
    body = ki(actor)                        # latest KI (MI + KN)
    body += struct.pack("!I", 1)            # latest lowest PN
    body += bytes(16)                       # old KI (none)
    body += struct.pack("!I", 0)            # old lowest PN
    return ps(PS_SAK_USE, 0x0f, body)       # latest rx+tx, AN valid


def peer_list(set_type, members):
    '''Live/Potential Peer List: repeated (MI, message number) tuples.'''
    body = b""
    for m in members:
        body += bytes.fromhex(m["mi"]) + struct.pack("!I", 1)
    return ps(set_type, 0x0, body)


def mkpdu(actor, param_sets):
    '''Assemble an EAPOL-MKA frame: Ethernet + EAPOL header + Basic Parameter
    Set + parameter sets + ICV.'''
    eapol_body = basic_param_set(actor, actor is KS)
    for p in param_sets:
        eapol_body += p
    eapol_body += ps(PS_ICV, 0x0, ICV)
    eapol = struct.pack("!BBH", EAPOL_VERSION, EAPOL_TYPE_MKA, len(eapol_body))
    eapol += eapol_body
    eth = PAE_GROUP_MAC + bytes.fromhex(actor["mac"]) + struct.pack("!H", ETH_P_PAE)
    return eth + eapol


def dump(frame, ts):
    '''Emit a text2pcap hex dump with a per-frame timestamp offset.'''
    print(f"{ts}")
    for off in range(0, len(frame), 16):
        chunk = frame[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        print(f"{off:06x}  {hexpart}")
    print()


def main():
    # Whole-second spacing keeps the text2pcap timestamps unambiguous and
    # gives the formation measurable install/formation times.
    # 1: KS announces (key server, no key yet).
    dump(mkpdu(KS, [peer_list(PS_POTENTIAL_PEER_LIST, [A, B])]),
         "2026-01-01 00:00:01")
    # 2,3: peers announce.
    dump(mkpdu(A, [peer_list(PS_POTENTIAL_PEER_LIST, [KS])]),
         "2026-01-01 00:00:02")
    dump(mkpdu(B, [peer_list(PS_POTENTIAL_PEER_LIST, [KS])]),
         "2026-01-01 00:00:03")
    # 4: KS distributes the SAK to its live peers (startup).
    dump(mkpdu(KS, [peer_list(PS_LIVE_PEER_LIST, [A, B]),
                    distributed_sak(), sak_use(KS)]),
         "2026-01-01 00:00:04")
    # 5,6: peers install and activate the SAK.
    dump(mkpdu(A, [peer_list(PS_LIVE_PEER_LIST, [KS, B]), sak_use(A)]),
         "2026-01-01 00:00:05")
    dump(mkpdu(B, [peer_list(PS_LIVE_PEER_LIST, [KS, A]), sak_use(B)]),
         "2026-01-01 00:00:06")


if __name__ == "__main__":
    sys.exit(main())
