# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers shared by the DVB table coverage generators: MPEG-2 section
CRC, sections, MPEG-TS packetisation and pcap writing. Everything is
built with struct; nothing comes from a real network."""
import struct

LINKTYPE_MPEG_2_TS = 243
LINKTYPE_WIRESHARK_UPPER_PDU = 252


def crc32_mpeg2(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def section(table_id, body, ssi=True, reserved=3, crc=True, length=None):
    """A section: table_id, flags and length, body (everything after the
    length field up to the CRC) and the CRC."""
    blen = len(body) + (4 if crc else 0)
    if length is None:
        length = blen
    hdr = bytes([table_id]) + struct.pack(
        ">H", (0x8000 if ssi else 0) | (reserved << 12) | (length & 0xFFF))
    s = hdr + body
    if crc:
        s += struct.pack(">I", crc32_mpeg2(s))
    return s


def ext_header(id16, version, cur_next=1, sect=0, last=0):
    """table_id_extension, version/current_next, section numbers."""
    return struct.pack(">HBBB", id16, 0xC0 | (version << 1) | cur_next,
                       sect, last)


def descr(tag, data):
    return bytes([tag, len(data)]) + data


class TS:
    """Packetise sections into 188 octet TS packets, keeping a continuity
    counter per PID."""

    def __init__(self):
        self.cc = {}

    def _pkt(self, pid, pusi, payload):
        cc = self.cc.get(pid, 0)
        self.cc[pid] = (cc + 1) & 0xF
        hdr = struct.pack(">BHB", 0x47, (0x4000 if pusi else 0) | pid,
                          0x10 | cc)
        assert len(payload) <= 184
        return hdr + payload + b"\xff" * (184 - len(payload))

    def sections(self, pid, sects):
        """Return the TS packets that carry the sections back to back,
        starting each run with a pointer field of 0."""
        data = b"".join(sects)
        pkts = []
        first = True
        while data or first:
            if first:
                chunk = data[:183]
                data = data[183:]
                pkts.append(self._pkt(pid, True, b"\x00" + chunk))
                first = False
            else:
                chunk = data[:184]
                data = data[184:]
                pkts.append(self._pkt(pid, False, chunk))
        return pkts


def write_pcap(path, frames, linktype, t0=1700000000):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                            linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t0 + i, 0, len(fr), len(fr)))
            f.write(fr)


def exp_pdu(name, payload):
    """Exported PDU with a dissector name tag."""
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return (struct.pack("!HH", 12, len(n) + pad) + n + b"\0" * pad +
            struct.pack("!HH", 0, 0) + payload)
