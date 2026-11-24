#!/usr/bin/env python3
# Generates test/captures/btmesh_proxy_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic Bluetooth Mesh Proxy coverage captures for
packet-btmesh-proxy.c.

Usage: mkbtmesh_proxy.py <outdir>

Writes btmesh_proxy-coverage.pcapng (main capture) and
btmesh_proxy-coverage-malformed.pcap.

Every packet is built with struct; the Mesh security uses the Mesh Profile
sample-data keys (NetKey 7dd7364cd842ad18c17c2b820c84c3d6, AppKey
63964771734fbd76e3b40519d1d94a48, IV Index 0x12345678).

The main capture (interface 0) and the malformed capture are Bluetooth
HCI H4 with the Linux direction header (DLT 201): an LE Connection
Complete event, a GATT
discovery of the Mesh Provisioning Service (0x1827) and the Mesh Proxy
Service (0x1828) and then Proxy PDUs: Write Commands from the local client
to the Data In characteristics (proxy side "client") and Handle Value
Notifications from the remote server on Data Out (proxy side "server").
The last frame of the main capture is on interface 1, Exported PDU
(DLT 252), and names the "btmesh.proxy" dissector.
"""
import os
import struct
import sys

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

SENT = 0
RECV = 1

# ---------------------------------------------------------------------------
# Mesh security (Mesh Profile 3.8)
# ---------------------------------------------------------------------------
NETKEY = bytes.fromhex("7dd7364cd842ad18c17c2b820c84c3d6")
APPKEY = bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
IVINDEX = bytes.fromhex("12345678")
OTHER_NETKEY = bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")


def cmac(k, m):
    c = CMAC(algorithms.AES(k))
    c.update(m)
    return c.finalize()


def s1(m):
    return cmac(b"\0" * 16, m)


def k2(n, p=b"\0"):
    t = cmac(s1(b"smk2"), n)
    t1 = cmac(t, p + b"\x01")
    t2 = cmac(t, t1 + p + b"\x02")
    t3 = cmac(t, t2 + p + b"\x03")
    return t1[15] & 0x7f, t2, t3


def k4(a):
    t = cmac(s1(b"smk4"), a)
    return cmac(t, b"id6\x01")[15] & 0x3f


NID, ENCKEY, PRIVKEY = k2(NETKEY)
AID = k4(APPKEY)


def ccm(key, nonce, data, mic):
    return AESCCM(key, tag_length=mic).encrypt(nonce, data, None)


def obfuscate(hdr, enc, privkey=None):
    e = Cipher(algorithms.AES(privkey or PRIVKEY), modes.ECB()).encryptor()
    pecb = e.update(b"\0" * 5 + IVINDEX + enc[:7]) + e.finalize()
    return bytes(a ^ b for a, b in zip(hdr, pecb))


def network_pdu(transport, seq, src, dst, ctl=0, ttl=5, nonce_type=0, netkey=None):
    """Network PDU (nonce type 0) or Proxy Configuration PDU (type 3)."""
    nid, enckey, privkey = k2(netkey) if netkey else (NID, ENCKEY, PRIVKEY)
    hdr = bytes([(ctl << 7) | ttl]) + seq.to_bytes(3, "big") + src.to_bytes(2, "big")
    mic = 8 if ctl else 4
    if nonce_type == 3:
        nonce = b"\x03\x00" + hdr[1:] + b"\0\0" + IVINDEX
    else:
        nonce = b"\x00" + hdr + b"\0\0" + IVINDEX
    enc = ccm(enckey, nonce, dst.to_bytes(2, "big") + transport, mic)
    ivi = IVINDEX[3] & 1
    return bytes([(ivi << 7) | nid]) + obfuscate(hdr, enc, privkey) + enc


def proxy_config(opcode_params, seq, src=0x0001, dst=0x0000, ctl=1, ttl=0, netkey=None):
    return network_pdu(opcode_params, seq, src, dst, ctl=ctl, ttl=ttl, nonce_type=3,
                       netkey=netkey)


def unseg_access(payload, seq, src=0x0003, dst=0x1201):
    nonce = bytes([1, 0]) + seq.to_bytes(3, "big") + src.to_bytes(2, "big") + \
        dst.to_bytes(2, "big") + IVINDEX
    up = ccm(APPKEY, nonce, payload, 4)
    return network_pdu(bytes([0x40 | AID]) + up, seq, src, dst)


def secure_beacon(flags=0x00, ivindex=0x12345678):
    return bytes([0x01, flags]) + bytes.fromhex("3ecaff672f673370") + \
        struct.pack(">I", ivindex) + bytes.fromhex("8ea261582f364f6f")


def unprov_beacon(oob=0x0000, uri_hash=None):
    b = bytes([0x00]) + bytes.fromhex("70cf7c9732a345b691494810d2e9cbf4") + struct.pack(">H", oob)
    return b + (uri_hash or b"")


# ---------------------------------------------------------------------------
# HCI H4 / ATT framing
# ---------------------------------------------------------------------------
def u8(v):
    return struct.pack('<B', v & 0xff)


def u16(v):
    return struct.pack('<H', v & 0xffff)


class Capture:
    def __init__(self, chandle=0x0040):
        self.frames = []
        self.chandle = chandle

    def raw(self, direction, h4):
        self.frames.append(struct.pack('>I', direction) + h4)

    def le_connect(self, chandle=None, peer=b'\x11\x22\x33\x44\x55\x66'):
        chandle = self.chandle if chandle is None else chandle
        ev = bytes([0x01, 0x00]) + u16(chandle) + bytes([0x00, 0x00]) + peer[::-1] + \
            u16(0x0018) + u16(0) + u16(0x00c8) + bytes([0x00])
        self.raw(RECV, bytes([0x04, 0x3e, len(ev)]) + ev)

    def att(self, direction, pdu, chandle=None):
        chandle = self.chandle if chandle is None else chandle
        l2 = struct.pack('<HH', len(pdu), 0x0004) + pdu
        self.raw(direction, struct.pack('<BHH', 0x02, 0x2000 | chandle, len(l2)) + l2)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 201))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 10000,
                                    len(fr), len(fr)))
                f.write(fr)

    def write_pcapng(self, path, exported):
        """pcapng with interface 0 HCI H4 (DLT 201) for the frames and
        interface 1 Exported PDU (DLT 252) for the exported PDUs, which
        follow the other frames."""
        def block(btype, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            n = len(body) + 12
            return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
        out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += block(1, struct.pack('<HHI', 201, 0, 262144))
        out += block(1, struct.pack('<HHI', 252, 0, 262144))
        frames = [(0, fr) for fr in self.frames] + [(1, fr) for fr in exported]
        for i, (ifc, fr) in enumerate(frames):
            ts = (1700000000 + i // 100) * 1000000 + (i % 100) * 10000
            out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
        with open(path, 'wb') as f:
            f.write(out)

    # Proxy PDU helpers ---------------------------------------------------
    def data_in(self, handle, pdu):
        """Write Command (proxy side "client").  BT ATT stores the handles
        of Data In (0x2ADB, 0x2ADD) for the opposite direction, so the
        Write Command is sent by the remote device to be recognised."""
        self.att(RECV, u8(0x52) + u16(handle) + pdu)

    def data_out(self, handle, pdu):
        """Notification from the remote proxy server (side "server")."""
        self.att(RECV, u8(0x1b) + u16(handle) + pdu)

    def write_req(self, handle, pdu):
        """Write Request: neither Write Command nor Notification, side
        "unknown"."""
        self.att(RECV, u8(0x12) + u16(handle) + pdu)
        self.att(SENT, u8(0x13))


# GATT database of the remote device
PROV_SVC = (0x0001, 0x0006)
PROV_IN, PROV_OUT = 0x0003, 0x0005
PROXY_SVC = (0x0007, 0x000c)
PROXY_IN, PROXY_OUT = 0x0009, 0x000b


def discovery(c):
    c.att(SENT, u8(0x02) + u16(185))                                  # Exchange MTU
    c.att(RECV, u8(0x03) + u16(185))
    c.att(SENT, u8(0x10) + u16(0x0001) + u16(0xffff) + u16(0x2800))   # Primary services
    c.att(RECV, u8(0x11) + u8(6) + u16(PROV_SVC[0]) + u16(PROV_SVC[1]) + u16(0x1827) +
          u16(PROXY_SVC[0]) + u16(PROXY_SVC[1]) + u16(0x1828))
    c.att(SENT, u8(0x10) + u16(PROXY_SVC[1] + 1) + u16(0xffff) + u16(0x2800))
    c.att(RECV, u8(0x01) + u8(0x10) + u16(PROXY_SVC[1] + 1) + u8(0x0a))
    c.att(SENT, u8(0x08) + u16(PROV_SVC[0]) + u16(PROV_SVC[1]) + u16(0x2803))
    c.att(RECV, u8(0x09) + u8(7) + u16(0x0002) + u8(0x04) + u16(PROV_IN) + u16(0x2adb) +
          u16(0x0004) + u8(0x10) + u16(PROV_OUT) + u16(0x2adc))
    c.att(SENT, u8(0x08) + u16(PROXY_SVC[0]) + u16(PROXY_SVC[1]) + u16(0x2803))
    c.att(RECV, u8(0x09) + u8(7) + u16(0x0008) + u8(0x04) + u16(PROXY_IN) + u16(0x2add) +
          u16(0x000a) + u8(0x10) + u16(PROXY_OUT) + u16(0x2ade))
    c.att(SENT, u8(0x04) + u16(0x0006) + u16(0x0006))
    c.att(RECV, u8(0x05) + u8(1) + u16(0x0006) + u16(0x2902))
    c.att(SENT, u8(0x04) + u16(0x000c) + u16(0x000c))
    c.att(RECV, u8(0x05) + u8(1) + u16(0x000c) + u16(0x2902))
    c.att(SENT, u8(0x12) + u16(0x0006) + u16(0x0001))                 # enable notifications
    c.att(RECV, u8(0x13))
    c.att(SENT, u8(0x12) + u16(0x000c) + u16(0x0001))
    c.att(RECV, u8(0x13))


def proxy_hdr(sar, ptype):
    return bytes([(sar << 6) | ptype])


def segments(ptype, data, sizes):
    """Split data into SAR first/continuation/last segments of the given
    sizes (the last segment takes the rest)."""
    out = []
    pos = 0
    for i, n in enumerate(sizes):
        sar = 1 if i == 0 else 2
        out.append(proxy_hdr(sar, ptype) + data[pos:pos + n])
        pos += n
    out.append(proxy_hdr(3, ptype) + data[pos:])
    return out


# Provisioning PDUs (Provisioning Invite, Capabilities, Public Key, Data)
PROV_INVITE = bytes([0x00, 0x05])
PROV_CAPS = bytes([0x01, 0x02]) + struct.pack('>H', 1) + bytes([0, 1, 4]) + \
    struct.pack('>H', 0x0018) + bytes([4]) + struct.pack('>H', 0x000c)
PROV_PUBKEY = bytes([0x03]) + bytes(range(0x20, 0x60))
PROV_DATA = bytes([0x07]) + bytes(range(0x80, 0xa1))
PROV_COMPLETE = bytes([0x08])


PEER_A = b'\x11\x22\x33\x44\x55\x66'
PEER_B = b'\x11\x22\x33\x44\x55\x77'
PEER_C = b'\x11\x22\x33\x44\x55\x88'


def connect(c, chandle, peer):
    c.chandle = chandle
    c.le_connect(chandle, peer)
    discovery(c)


def main_capture(path):
    c = Capture()
    # Connection A: complete messages of every type, then the client side
    # (Write Command) segmented messages
    connect(c, 0x0040, PEER_A)                                      # 1-19
    c.data_in(PROXY_IN, proxy_hdr(0, 0) + unseg_access(bytes.fromhex("82020107"), 0x000100))
    c.data_out(PROXY_OUT, proxy_hdr(0, 0) + unseg_access(bytes.fromhex("8204010000"), 0x000101,
                                                        src=0x1201, dst=0x0003))
    c.data_out(PROXY_OUT, proxy_hdr(0, 1) + secure_beacon(0x00))
    c.data_out(PROXY_OUT, proxy_hdr(0, 1) + unprov_beacon(0x0000))
    c.data_in(PROXY_IN, proxy_hdr(0, 2) + proxy_config(bytes([0x00, 0x00]), 0x000001))   # Set Filter Type white
    c.data_out(PROXY_OUT, proxy_hdr(0, 2) + proxy_config(bytes([0x03, 0x00]) + struct.pack('>H', 0),
                                                        0x000001, src=0x1201))           # Filter Status
    c.data_in(PROXY_IN, proxy_hdr(0, 2) + proxy_config(bytes([0x01]) + struct.pack('>HH', 0x0003, 0xc001),
                                                       0x000002))                       # Add Addresses
    c.data_out(PROXY_OUT, proxy_hdr(0, 2) + proxy_config(bytes([0x03, 0x00]) + struct.pack('>H', 2),
                                                        0x000002, src=0x1201))
    c.data_in(PROXY_IN, proxy_hdr(0, 2) + proxy_config(bytes([0x02]) + struct.pack('>H', 0xc001),
                                                       0x000003))                       # Remove Addresses
    c.data_in(PROXY_IN, proxy_hdr(0, 2) + proxy_config(bytes([0x00, 0x01]), 0x000004))   # Set Filter Type black
    c.data_out(PROXY_OUT, proxy_hdr(0, 2) + proxy_config(bytes([0x03, 0x01]) + struct.pack('>H', 0),
                                                        0x000003, src=0x1201))
    c.data_in(PROV_IN, proxy_hdr(0, 3) + PROV_INVITE)
    c.data_out(PROV_OUT, proxy_hdr(0, 3) + PROV_CAPS)
    c.data_out(PROV_OUT, proxy_hdr(0, 3) + PROV_COMPLETE)
    # Unknown Proxy PDU type, complete: shown as data
    c.data_in(PROXY_IN, proxy_hdr(0, 0x3e) + b'\x01\x02\x03\x04')
    # Proxy Configuration with a key that is not in the UAT, and one whose
    # NID matches but whose NetMIC is wrong: no decryption, data only
    c.data_in(PROXY_IN, proxy_hdr(0, 2) + proxy_config(bytes([0x00, 0x00]), 0x000006, netkey=OTHER_NETKEY))
    bad = bytearray(proxy_config(bytes([0x00, 0x00]), 0x000007))
    bad[-1] ^= 0xff
    c.data_in(PROXY_IN, proxy_hdr(0, 2) + bytes(bad))
    # Client side segmented messages: Public Key in two and in three
    # segments, Provisioning Data, Network PDU, Proxy Configuration, an
    # unknown type
    for seg in segments(3, PROV_PUBKEY, [19]):
        c.data_in(PROV_IN, seg)
    for seg in segments(3, PROV_PUBKEY, [20, 20]):
        c.data_in(PROV_IN, seg)
    for seg in segments(3, PROV_DATA, [10]):
        c.data_in(PROV_IN, seg)
    for seg in segments(0, unseg_access(bytes.fromhex("8202000a"), 0x000102), [8]):
        c.data_in(PROXY_IN, seg)
    for seg in segments(2, proxy_config(bytes([0x01]) + struct.pack('>HHHH', 0x0004, 0x0005, 0xc002, 0xfffd),
                                        0x000005), [6, 6]):
        c.data_in(PROXY_IN, seg)
    for seg in segments(0x3e, b'unknown-type', [5]):
        c.data_in(PROXY_IN, seg)
    # Connection B: server side (Notification) segmented messages
    connect(c, 0x0041, PEER_B)
    for seg in segments(3, PROV_PUBKEY, [20, 20]):
        c.data_out(PROV_OUT, seg)
    for seg in segments(1, secure_beacon(0x03, 0x12345679), [10]):
        c.data_out(PROXY_OUT, seg)
    for seg in segments(1, unprov_beacon(0x0000, bytes.fromhex("d97478b3")), [9]):
        c.data_out(PROXY_OUT, seg)
    for seg in segments(2, proxy_config(bytes([0x03, 0x00]) + struct.pack('>H', 4), 0x000004, src=0x1201), [7]):
        c.data_out(PROXY_OUT, seg)
    for seg in segments(0, unseg_access(bytes.fromhex("8204000100"), 0x000103, src=0x1201, dst=0x0003), [12]):
        c.data_out(PROXY_OUT, seg)
    # Connection C: Write Requests on Data In (proxy side "unknown"),
    # complete and segmented
    connect(c, 0x0042, PEER_C)
    c.write_req(PROXY_IN, proxy_hdr(0, 1) + secure_beacon(0x01))
    for seg in segments(3, PROV_DATA, [16]):
        c.write_req(PROV_IN, seg)
    # Exported PDU naming btmesh.proxy (no proxy context): the reproducer
    # of btmesh_proxy_null_data.py
    c.write_pcapng(path, [exp_pdu('btmesh.proxy', bytes([0x03, 0x00, 0x05]))])


def malformed_capture(path):
    c = Capture()
    c.le_connect()
    discovery(c)
    cfg = lambda op, seq, **kw: c.data_in(PROXY_IN, proxy_hdr(0, 2) + proxy_config(op, seq, **kw))
    cfg(bytes([0x00, 0x02]), 0x000010)                            # unknown filter type
    c.data_out(PROXY_OUT, proxy_hdr(0, 2) + proxy_config(bytes([0x03, 0x05]) + struct.pack('>H', 0),
                                                        0x000010, src=0x1201))
    cfg(bytes([0x07, 0xaa, 0xbb]), 0x000011)                      # unknown opcode
    cfg(bytes([0x01]) + struct.pack('>HH', 0x0003, 0x0004), 0x000012, ctl=0)   # CTL 0 (4 octet NetMIC)
    cfg(bytes([0x00, 0x00]), 0x000013, ttl=5)                     # TTL not 0
    cfg(bytes([0x00, 0x00]), 0x000014, dst=0x0003)                # DST not 0
    cfg(bytes([0x00, 0x00]), 0x000015, src=0xc001)                # SRC not unicast
    cfg(bytes([0x01]) + struct.pack('>HH', 0x0000, 0x0003), 0x000016)   # address 0
    cfg(bytes([0x02]) + struct.pack('>H', 0x0000), 0x000017)      # address 0
    cfg(bytes([0x00, 0x00, 0x99]), 0x000018)                      # octet after the filter type
    cfg(bytes([0x01]) + struct.pack('>H', 0x0003) + b'\x07', 0x000019)  # odd address list
    cfg(bytes([0x03, 0x00, 0x00]), 0x00001a)                      # Filter Status cut short
    # Proxy PDU with only the header octet, complete and as a last segment
    c.data_in(PROXY_IN, proxy_hdr(0, 2))
    c.data_in(PROXY_IN, proxy_hdr(0, 3))
    c.data_out(PROXY_OUT, proxy_hdr(3, 1) + b'\x01')              # last segment, no first
    c.data_out(PROXY_OUT, proxy_hdr(2, 1) + b'\x02')              # continuation, no first
    # Truncated / malformed contents of the subdissectors
    c.data_out(PROXY_OUT, proxy_hdr(0, 1) + b'\x07\x01')         # unknown beacon type
    c.data_out(PROXY_OUT, proxy_hdr(0, 3) + b'\x3f\x00')         # unknown provisioning PDU
    c.data_in(PROXY_IN, proxy_hdr(0, 0) + b'\x00\x01')           # too short Network PDU
    c.write(path)


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


def main(outdir):
    main_capture(os.path.join(outdir, 'btmesh_proxy-coverage.pcapng'))
    malformed_capture(os.path.join(outdir, 'btmesh_proxy-coverage-malformed.pcap'))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
