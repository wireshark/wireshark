#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate a pcapng test capture for the BACnet MS/TP dissector
(epan/dissectors/packet-mstp.c), in particular its decoding of
COBS-encoded frames (Frame Types 32 through 127) and of IPv6 over MS/TP
(Frame Type 34, RFC 8163).

Produces test/captures/mstp-6lobac.pcapng (LINKTYPE_BACNET_MS_TP, 165).
Every frame is synthetic except frame 11, which is the example frame of
RFC 8163 Appendix D. Each frame is checked with an independent decoder
before it is written.

Valid frames:
  1     Token (0)
  2     Poll For Manager (1)
  3     Reply To Poll For Manager (2)
  4/5   Test_Request (3) / Test_Response (4) with data
  6     BACnet Data Expecting Reply (5): ReadProperty, Max_Manager
  7     BACnet Data Not Expecting Reply (6): Who-Is
  8     Reply Postponed (7)
  9     BACnet Extended Data Expecting Reply (32): 520-octet NPDU
        (a vendor-proprietary network layer message)
  10    BACnet Extended Data Not Expecting Reply (33): likewise
  11    IPv6 over MS/TP (34): RFC 8163 Appendix D, verbatim (addresses
        inline: needs 6lowpan.context0 = aaaa::/64)
  12/13 IPv6 over MS/TP (34): ICMPv6 echo request 2->3 / reply 3->2 with
        both IIDs elided (SAM=DAM=11, context 0); the IPv6 addresses, and
        so the ICMPv6 checksum, are only right if the IIDs are derived
        from the MS/TP addresses (RFC 8163: 00 00 00 ff fe 00 00 XX)
  14    Unregistered COBS type (35): decoded, shown as data
  15    Proprietary frame type (128) with a Vendor ID

COBS corner cases (type 35, so only the MS/TP decoding is involved):
  16    a run of exactly 254 non-zero octets in the middle (code 0xFF)
  17    a run of exactly 254 non-zero octets at the end of the data
  18    a run of 253 at the end;  19  a run of 255 at the end
  20    a run of 254 immediately followed by a zero octet
  21    508 non-zero octets (two 0xFF blocks), then the end
  22    a single zero octet;  23  only zero octets

Frames that must be flagged:
  24    bad Header CRC (Token)
  25    bad Data CRC (Who-Is, type 6)
  26    bad CRC-32K (frame 11 with one data octet altered): dissected anyway
  27    one octet lost, Length count completed by the 0xFF pad
        (COBS code octet runs past the end)
  28    two octets lost, completed by the pad and the next frame's 0x55
        (Octet 0x55 in the Encoded CRC-32K field)
  29    0x55 in the middle of the Encoded Data field
  30    frame shorter than its Length field (decoded as far as captured)
  31    Length too small for a COBS-encoded frame (Length 2)
  32    Frame Type 32 with a 13-octet NPDU (ReadProperty), which belongs in
        Frame Type 5: warning
  33    IPv6 over MS/TP with Length above 1510: warning
  34    Frame Type 35 with Length 0, below Nmin_COBS_length: error, no data
  35    Frame Type 35 with Length above Nmax_COBS_length (2043): error,
        decoded anyway
"""

import os
import struct
import sys

MASK = 0x55

# ---------------------------------------------------------------- CRCs
def header_crc(octets):
    """BACnet MS/TP Header CRC (ANSI/ASHRAE 135 Annex G.1)."""
    crc = 0xFF
    for d in octets:
        t = crc ^ d
        t ^= (t << 1) ^ (t << 2) ^ (t << 3) ^ (t << 4) ^ (t << 5) ^ (t << 6) ^ (t << 7)
        crc = ((t & 0xFE) ^ ((t >> 8) & 1)) & 0xFF
    return (~crc) & 0xFF


def data_crc16(octets):
    """BACnet MS/TP Data CRC (Annex G.2): CRC-CCITT, LSB first, inverted."""
    crc = 0xFFFF
    for d in octets:
        crc ^= d
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return struct.pack('<H', (~crc) & 0xFFFF)


def crc32k(octets, crc=0xFFFFFFFF):
    """CRC-32K (Koopman), reflected, as in Annex G.3 and RFC 8163."""
    for d in octets:
        for _ in range(8):
            if (d ^ crc) & 1:
                crc = (crc >> 1) ^ 0xEB31D82E
            else:
                crc >>= 1
            d >>= 1
    return crc


# ---------------------------------------------------------------- COBS
def cobs_encode(data, mask=MASK):
    """COBS encoder of RFC 8163 Appendix B / draft-ietf-6lo-rfc8163-bis."""
    out = bytearray(len(data) + len(data) // 254 + 2)
    code_index, write_index, code, last_code = 0, 1, 1, 0
    for d in data:
        if d:
            out[write_index] = d ^ mask
            write_index += 1
            code += 1
            if code != 255:
                continue
        last_code = code
        out[code_index] = code ^ mask
        code_index = write_index
        write_index += 1
        code = 1
    if last_code == 255 and code == 1:
        write_index -= 1
    else:
        out[code_index] = code ^ mask
    return bytes(out[:write_index])


def cobs_decode(enc, mask=MASK):
    """Independent decoder: returns the data, or None if the encoding is invalid."""
    out, r = bytearray(), 0
    while r < len(enc):
        code = enc[r] ^ mask
        if code == 0 or r + code > len(enc):
            return None
        block = [b ^ mask for b in enc[r + 1:r + code]]
        if 0 in block:
            return None
        out += bytes(block)
        r += code
        if code != 0xFF and r < len(enc):
            out.append(0)
    return bytes(out)

# ------------------------------------------------------------- frames
def mstp_header(frame_type, dst, src, length, good_crc=True):
    hdr = bytes([frame_type, dst, src]) + struct.pack('>H', length)
    crc = header_crc(hdr)
    if not good_crc:
        crc ^= 0x01
    return b'\x55\xff' + hdr + bytes([crc])


def mstp_frame(frame_type, dst, src, data=b'', good_header_crc=True,
               good_data_crc=True):
    """A frame with an unencoded Data field (Frame Types 0-31, 128-255)."""
    frame = mstp_header(frame_type, dst, src, len(data), good_header_crc)
    if data:
        crc = data_crc16(data)
        if not good_data_crc:
            crc = bytes([crc[0] ^ 0x01, crc[1]])
        frame += data + crc
    return frame


def cobs_frame(frame_type, dst, src, msdu):
    """A COBS-encoded frame (Frame Types 32-127): Encoded Data, then the
    CRC-32K of the encoded data, sent LSB first and COBS-encoded. The Length
    field is two less than the two encoded fields."""
    enc = cobs_encode(msdu)
    enc_crc = cobs_encode(struct.pack('<I', (~crc32k(enc)) & 0xFFFFFFFF))
    assert len(enc_crc) == 5
    body = enc + enc_crc
    return mstp_header(frame_type, dst, src, len(body) - 2) + body


def check_cobs_frame(frame):
    """Independent check of a COBS-encoded frame. Returns the decoded data,
    or None if the encoding or the CRC-32K is bad."""
    length = struct.unpack('>H', frame[5:7])[0]
    body = frame[8:8 + length + 2]
    if len(body) != length + 2 or MASK in body:
        return None
    enc, enc_crc = body[:-5], body[-5:]
    data, crc = cobs_decode(enc), cobs_decode(enc_crc)
    if data is None or crc is None or len(crc) != 4:
        return None
    if crc != struct.pack('<I', (~crc32k(enc)) & 0xFFFFFFFF):
        return None
    return data


def ipv6_mstp_address(mac):
    """aaaa::/64 (context 0) + the RFC 8163 IID for an MS/TP address."""
    return bytes.fromhex('aaaa000000000000') + bytes([0, 0, 0, 0xff, 0xfe, 0, 0, mac])


def echo_msdu(src_mac, dst_mac, icmp_type, payload_len=64):
    """LOWPAN_IPHC ICMPv6 echo with both IIDs elided (SAC=DAC=1, SAM=DAM=11,
    context 0), traffic class and flow label elided, hop limit 64."""
    payload = bytes(i & 0xff for i in range(payload_len))
    icmp = struct.pack('>BBHHH', icmp_type, 0, 0, 0x1234, 1) + payload
    pseudo = (ipv6_mstp_address(src_mac) + ipv6_mstp_address(dst_mac) +
              struct.pack('>I', len(icmp)) + b'\x00\x00\x00\x3a')
    total = sum(struct.unpack('>%dH' % ((len(pseudo) + len(icmp)) // 2), pseudo + icmp))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    icmp = icmp[:2] + struct.pack('>H', (~total) & 0xFFFF) + icmp[4:]
    return bytes([0x7a, 0x77, 0x3a]) + icmp


APPENDIX_D = bytes.fromhex(
    "55ff22010202191c562d83566f6a54545454545457545654d5502d6a7bb05c57"
    "b18ebd006ef551ac5d5c5f5e59585b5a45444746414043424d4c4f4e49484b4a"
    "75747776717073727d7c7f7e79787b7a65646766616063626d6c6f6e69686b6a"
    "15141716111013121d1c1f1e19181b1a05040706010003020d0c0f0e09080b0a"
    "35343736313033323d3c3f3e39383b3a25242726212023222d2c2f2e29282b2a"
    "d5d4d7d6d1d0d3d2dddcdfded9d8dbdac5c4c7c6c1c0c3c2cdcccfcec9c8cbca"
    "f5f4f7f6f1f0f3f2fdfcfffef9f8fbfae5e4e7e6e1e0e3e2edecefeee9e8ebea"
    "95949796919093929d9c9f9e99989b9a85848786818083828d8c8f8e89888b8a"
    "b5b4b7b6b1b0b3b2bdbcbfbeb9b8bbbaa5a4a7a6a1a0a3a2adacafaea9a8abaa"
    "ab545756515053525d5c5f5e59585b5a45444746414043424d4c4f4e49484b4a"
    "75747776717073727d7c7f7e79787b7a65646766616063626d6c6f6e69686b6a"
    "15141716111013121d1c1f1e19181b1a05040706010003020d0c0f0e09080b0a"
    "35343736313033323d3c3f3e39383b3a25242726212023222d2c2f2e29282b2a"
    "d5d4d7d6d1d0d3d2dddcdfded9d8dbdac5c4c7c6c1c0c3c2cdcccfcec9c8cbca"
    "f5f4f7f6f1f0f3f2fdfcfffef9f8fbfae5e4e7e6e1e0e3e2edecefeee9e8ebea"
    "95949796919093929d9c9f9e99989b9a85848786818083828d8c8f8e89888b8a"
    "b5b4b7b6b1b0b3b2bdbcbfbeb9b8bbbaa5a4a7a6a1a0a3a2adacafaea9a850cb"
    "270cb7")

READ_PROPERTY = bytes.fromhex('0104' '0005010c' '0c02000001' '1940')  # Device 1, Max_Manager
WHO_IS = bytes.fromhex('0120ffff00ff' '1008')
# Vendor-proprietary network layer messages (type 0x80, vendor 260), 520 octets
NET_MSG_EXPECTING = bytes.fromhex('0184' '80' '0104') + bytes(i & 0xff for i in range(515))
NET_MSG = bytes.fromhex('0180' '80' '0104') + bytes(i & 0xff for i in range(515))
BIG_ECHO = echo_msdu(2, 3, 128, 1500)
TOO_LONG = bytes(i & 0xff for i in range(2100))
RUN = lambda n: bytes((i % 255) + 1 for i in range(n))  # n non-zero octets


def build_frames():
    f = []
    # Valid frames
    f.append(mstp_frame(0, 3, 2))
    f.append(mstp_frame(1, 4, 2))
    f.append(mstp_frame(2, 2, 4))
    f.append(mstp_frame(3, 3, 2, b'MS/TP test data'))
    f.append(mstp_frame(4, 2, 3, b'MS/TP test data'))
    f.append(mstp_frame(5, 3, 2, READ_PROPERTY))
    f.append(mstp_frame(6, 255, 2, WHO_IS))
    f.append(mstp_frame(7, 2, 3))
    f.append(cobs_frame(32, 3, 2, NET_MSG_EXPECTING))
    f.append(cobs_frame(33, 255, 2, NET_MSG))
    f.append(APPENDIX_D)
    f.append(cobs_frame(34, 3, 2, echo_msdu(2, 3, 128)))
    f.append(cobs_frame(34, 2, 3, echo_msdu(3, 2, 129)))
    f.append(cobs_frame(35, 3, 2, bytes(range(32))))
    f.append(mstp_frame(128, 3, 2, struct.pack('>H', 260) + b'vendor data'))
    # COBS corner cases
    f.append(cobs_frame(35, 3, 2, b'\x10\x00' + RUN(254) + b'\x30\x40\x50'))
    f.append(cobs_frame(35, 3, 2, b'\x10\x00' + RUN(254)))
    f.append(cobs_frame(35, 3, 2, b'\x10\x00' + RUN(253)))
    f.append(cobs_frame(35, 3, 2, b'\x10\x00' + RUN(255)))
    f.append(cobs_frame(35, 3, 2, RUN(254) + b'\x00\x60'))
    f.append(cobs_frame(35, 3, 2, RUN(508)))
    f.append(cobs_frame(35, 3, 2, b'\x00'))
    f.append(cobs_frame(35, 3, 2, bytes(10)))
    # Frames that must be flagged
    f.append(mstp_frame(0, 3, 2, good_header_crc=False))
    f.append(mstp_frame(6, 255, 2, WHO_IS, good_data_crc=False))
    bad = bytearray(APPENDIX_D)
    bad[8 + 200] ^= 0x01
    f.append(bytes(bad))
    lost1 = APPENDIX_D[:8 + 19] + APPENDIX_D[8 + 20:] + b'\xff'
    f.append(lost1)
    lost2 = (APPENDIX_D[:8 + 52] + APPENDIX_D[8 + 53:8 + 111] +
             APPENDIX_D[8 + 112:] + b'\xff\x55')
    f.append(lost2)
    x55 = bytearray(APPENDIX_D)
    x55[8 + 100] = 0x55
    f.append(bytes(x55))
    f.append(APPENDIX_D[:8 + 300])
    f.append(mstp_header(34, 3, 2, 2) + b'\x01\x02\x03\x04')
    # Length limits
    f.append(cobs_frame(32, 3, 2, READ_PROPERTY))
    f.append(cobs_frame(34, 3, 2, BIG_ECHO))
    f.append(mstp_header(35, 3, 2, 0))
    f.append(cobs_frame(35, 3, 2, TOO_LONG))
    return f


def self_check(frames):
    """Checks every frame with the independent decoder above."""
    valid_cobs = {9: NET_MSG_EXPECTING, 10: NET_MSG, 32: READ_PROPERTY,
                  33: BIG_ECHO, 35: TOO_LONG, 12: echo_msdu(2, 3, 128),
                  13: echo_msdu(3, 2, 129), 14: bytes(range(32)),
                  16: b'\x10\x00' + RUN(254) + b'\x30\x40\x50',
                  17: b'\x10\x00' + RUN(254), 18: b'\x10\x00' + RUN(253),
                  19: b'\x10\x00' + RUN(255), 20: RUN(254) + b'\x00\x60',
                  21: RUN(508), 22: b'\x00', 23: bytes(10)}
    for n, frame in enumerate(frames, 1):
        hdr_ok = header_crc(frame[2:7]) == frame[7]
        assert hdr_ok == (n != 24), 'frame %d: header CRC' % n
        if n in valid_cobs:
            assert check_cobs_frame(frame) == valid_cobs[n], 'frame %d' % n
    assert len(check_cobs_frame(frames[10])) == 533      # Appendix D
    for n in (16, 17, 19, 20, 21):                        # code 0xFF present
        assert 0xFF ^ MASK in frames[n - 1][8:], 'frame %d: no 0xFF code' % n
    w = frames[24]
    assert data_crc16(w[8:-2]) != w[-2:], 'frame 25: data CRC is good'
    assert check_cobs_frame(frames[25]) is None           # bad CRC-32K ...
    assert cobs_decode(frames[25][8:-5]) is not None      # ... but valid COBS
    assert MASK not in frames[26][8:] and cobs_decode(frames[26][8:-5]) is None
    assert frames[27][-1] == MASK
    assert frames[28][8 + 100] == MASK
    assert len(frames[29]) < 8 + 539
    assert frames[30][5:7] == b'\x00\x02'
    length = lambda n: struct.unpack('>H', frames[n - 1][5:7])[0]
    assert all(502 <= len(check_cobs_frame(frames[n - 1])) <= 1497 for n in (9, 10))
    assert len(check_cobs_frame(frames[31])) < 502
    assert 1510 < length(33) <= 2043
    assert length(34) == 0 and len(frames[33]) == 8
    assert length(35) > 2043


# ------------------------------------------------------------- pcapng
def _block(block_type, body):
    body += b'\x00' * ((4 - len(body) % 4) % 4)
    total = len(body) + 12
    return struct.pack('<II', block_type, total) + body + struct.pack('<I', total)


def write_pcapng(path, frames):
    out = _block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += _block(0x00000001, struct.pack('<HHI', 165, 0, 65535))  # LINKTYPE_BACNET_MS_TP
    ts = 1792886400 * 1000000                                       # 2026-10-25 00:00 UTC
    for frame in frames:
        out += _block(0x00000006, struct.pack('<IIIII', 0, ts >> 32, ts & 0xFFFFFFFF,
                                              len(frame), len(frame)) + frame)
        ts += 10000
    with open(path, 'wb') as f:
        f.write(out)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', 'test', 'captures',
        'mstp-6lobac.pcapng')
    frames = build_frames()
    self_check(frames)
    write_pcapng(out, frames)
    print('Wrote %d frames to %s' % (len(frames), out))


if __name__ == '__main__':
    main()
