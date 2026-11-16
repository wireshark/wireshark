# SPDX-License-Identifier: GPL-2.0-or-later
"""pcapng blocks, checksums and link headers shared by the gen-*-test-capture.py generators."""

import struct

DLT_EN10MB = 1
DLT_LINUX_SLL = 113
DLT_LINUX_I2C = 209
DLT_LINUX_SLL2 = 276
LINUX_SLL_P_MCTP = 0x00FA

_CRC32C_POLY = 0x82F63B78


def crc32c(data):
    """CRC-32C: reflected, seed FFFFFFFFh, final exclusive-or FFFFFFFFh."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            mask = -(crc & 1) & 0xFFFFFFFF
            crc = (crc >> 1) ^ (_CRC32C_POLY & mask)
    return crc ^ 0xFFFFFFFF


def smbus_pec(data):
    """SMBus 3.3 6.4.1.3 PEC: CRC-8 x^8+x^2+x+1, MSB first, seed 0."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def pad4(n):
    """Round n up to a multiple of 4."""
    return (n + 3) & ~3


def block(block_type, body):
    """A pcapng block: type, total length, padded body, total length."""
    padded = body + b'\x00' * (pad4(len(body)) - len(body))
    total = 12 + len(padded)
    return struct.pack('<II', block_type, total) + padded + struct.pack('<I', total)


def shb():
    """Section Header Block of unknown section length."""
    return block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))


def idb(link_type=DLT_LINUX_SLL, snaplen=65535, name=None):
    """Interface Description Block, with an if_name option when name is given."""
    body = struct.pack('<HHI', link_type, 0, snaplen)
    if name is not None:
        raw = name.encode('utf-8')
        body += struct.pack('<HH', 2, len(raw))
        body += raw + b'\x00' * (pad4(len(raw)) - len(raw))
        body += struct.pack('<HH', 0, 0)
    return block(0x00000001, body)


def epb(packet_bytes, ts_us, interface_id=0, origlen=None, caplen=None):
    """Enhanced Packet Block; caplen keeps a prefix, origlen overrides the reported length."""
    if origlen is None:
        origlen = len(packet_bytes)
    if caplen is not None:
        packet_bytes = packet_bytes[:caplen]
    n = len(packet_bytes)
    padded = packet_bytes + b'\x00' * (pad4(n) - n)
    body = struct.pack('<IIIII', interface_id, (ts_us >> 32) & 0xFFFFFFFF,
                       ts_us & 0xFFFFFFFF, n, origlen) + padded
    return block(0x00000006, body)


def sll_header(src_eid, outgoing=False):
    """Linux SLL header of an MCTP frame, with the source EID as address."""
    return struct.pack('>HHH8sH', 4 if outgoing else 0, 0, 1,
                       bytes([src_eid]) + b'\x00' * 7, LINUX_SLL_P_MCTP)


def sll2_header(src_eid, outgoing=False, ifindex=1):
    """Linux SLL v2 header of an MCTP frame, with the source EID as address."""
    return (struct.pack('>HHIHBB', LINUX_SLL_P_MCTP, 0, ifindex, 0,
                        4 if outgoing else 0, 1)
            + bytes([src_eid]) + b'\x00' * 7)


def i2c_phdr(bus=0, flags=0, is_event=False):
    """Linux I2C pseudo-header: bus byte and 4-byte flags."""
    return bytes([(bus & 0x7F) | (0x80 if is_event else 0)]) + struct.pack('>I', flags)


def ip_checksum(data):
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth(dst_mac, src_mac, payload):
    """Ethernet II frame carrying IPv4."""
    return dst_mac + src_mac + struct.pack('>H', 0x0800) + payload


def ipv4(src, dst, payload, ident):
    """IPv4 header (DF, TTL 64, TCP) with its checksum."""
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0x00, 20 + len(payload), ident,
                      0x4000, 64, 6, 0, src, dst)
    return hdr[:10] + struct.pack('>H', ip_checksum(hdr)) + hdr[12:] + payload


def tcp(sport, dport, seq, ack, payload):
    """TCP header with PSH|ACK and a zero checksum."""
    return struct.pack('>HHIIHHHH', sport, dport, seq, ack,
                       (5 << 12) | 0x018, 65535, 0, 0) + payload
