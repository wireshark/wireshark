# Generates the v52 captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import struct
import sys

def esc(b):
    """EyeSDN escaping: 0xff and 0xfe become 0xfe and the value - 2."""
    out = bytearray()
    for c in b:
        if c in (0xff, 0xfe):
            out += bytes([0xfe, c - 2])
        else:
            out.append(c)
    return bytes(out)


def eyesdn(path, records):
    """records: (encap, uton, channel, payload)."""
    with open(path, 'wb') as f:
        f.write(b'EyeSDN')
        for i, (encap, uton, channel, payload) in enumerate(records):
            hdr = struct.pack('>I', 1000 * i)[1:] + struct.pack('>Q', 1700000000 + i)[3:]
            hdr += bytes([channel, (encap << 1) | uton]) + struct.pack('>H', len(payload))
            f.write(b'\xff' + esc(hdr + payload))


def pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


def exppdu(name, payload):
    """Exported PDU frame (linktype 252) naming a dissector."""
    b = name.encode()
    b += b'\0' * ((4 - len(b) % 4) % 4)
    return struct.pack('>HH', 12, len(b)) + b + struct.pack('>HH', 0, 0) + payload


def inet_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ether(payload, etype=0x0800, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('>H', etype) + payload


def ip4(proto, src, dst, payload, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                      bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    hdr = hdr[:10] + struct.pack('>H', inet_csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, ack, flags, payload=b'', win=8192, opts=b''):
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0) + opts + payload


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (~crc) & 0xffffffff


def sctp(sport, dport, vtag, chunks):
    body = b''.join(chunks)
    hdr = struct.pack('>HHII', sport, dport, vtag, 0)
    c = crc32c(hdr + body)
    return hdr[:8] + struct.pack('<I', c) + body


def sctp_data(tsn, sid, ssn, ppid, data, flags=3):
    ln = 16 + len(data)
    ch = struct.pack('>BBHIHHI', 0, flags, ln, tsn, sid, ssn, ppid) + data
    return ch + b'\0' * ((4 - ln % 4) % 4)


def sctp_init(tag, chunk_type=1):
    return struct.pack('>BBHIIHHI', chunk_type, 0, 20, tag, 65535, 4, 4, 1000)




def pcapng(path, linktypes, frames):
    """frames: (interface id, data). Writes SHB, one IDB per link type, EPBs."""
    def blk(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifid, data) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)
#!/usr/bin/env python3
"""Generate the synthetic captures for the V5.2 dissector (packet-v52.c).

V5.2 messages are carried in I frames of the V5 data link (packet-v5dl.c),
which an EyeSDN file delivers as V5 envelope function records (packet-v5ef.c,
EYESDN_ENCAP_V5_EF, envelope function addresses 8175-8191), and in the
protocol data of V5UA messages over SCTP (packet-v5ua.c).  Every record and
packet is built from scratch with struct; no captured traffic is used.

Usage: mkv52.py <output directory>

Writes:
  v52-coverage.eyesdn            I frames with every V5.2 message type and
                                 information element, in both directions
  v52-coverage-v5ua.pcap         V5UA Data Request/Indication messages (SCTP
                                 port 5675) with V5.2 protocol data
  v52-coverage-malformed.eyesdn  messages and information elements cut short
"""

ENC_V5EF = 8
EF_ISDN, EF_PSTN, EF_CTRL, EF_BCC, EF_PROT, EF_LINK = 8175, 8176, 8177, 8178, 8179, 8180


def v5addr(ef, cr=0):
    return struct.pack('>H', ((ef >> 7) << 10) | (cr << 9) | ((ef & 0x7f) << 1) | 1)


def dlh(ef, cr=0):
    """V5 envelope function address followed by the data link (LAPV5) address."""
    return v5addr(ef, 0) + v5addr(ef, cr)


def iframe(ns, nr, p=0):
    return bytes([ns << 1, (nr << 1) | p])


def ie(code, *data):
    return bytes([code, len(data)]) + bytes(data)


def msg(mtype, hi, lo, *ies):
    return bytes([0x48, hi, lo, mtype]) + b''.join(ies)


def pstn(mtype, n, *ies):      # PSTN address: 15 bits, bit 0 of the first octet set
    return msg(mtype, ((n >> 8) << 1) | 1, n & 0xff, *ies)


def isdn(mtype, n, *ies):      # ISDN address: 13 bits (6 + 7)
    return msg(mtype, (n >> 7) << 2, (n & 0x7f) << 1, *ies)


# single octet information elements dispatched on the exact value
LINE_INFO, STATE, AUTO_SEQ, SEQ_RESP, PULSE_NOTIF = b'\x80', b'\x90', b'\xa0', b'\xb0', b'\xc0'
PERF_GRADING, CP_REJECT = b'\xe0', b'\xf0'


def build_messages():
    """(protocol EF, message bytes) pairs, every message type of V5.2."""
    m = []
    P, C, B, R, L = EF_PSTN, EF_CTRL, EF_BCC, EF_PROT, EF_LINK
    # PSTN protocol: message types 0x00-0x0e with every IE of the PSTN protocol
    m.append((P, pstn(0x00, 5, ie(0x00, 0x85))))                                   # ESTABLISH + sequence number
    m.append((P, pstn(0x01, 5, ie(0x00, 0x86))))                                   # ESTABLISH ACK
    m.append((P, pstn(0x02, 0x1234, ie(0x00, 0x87), ie(0x01, 0x83),                 # SIGNAL: SN, cadenced ring
                      ie(0x02, 0xed), ie(0x02, 0xf5, 0x25), ie(0x02, 0xf8, 0x1a, 0x62),   # pulsed signal, 1-3 octets
                      ie(0x03, 0x84), ie(0x04, 0x65))))                              # steady, digit
    m.append((P, pstn(0x03, 0x1234, ie(0x00, 0x88))))                              # SIGNAL ACK
    m.append((P, pstn(0x02, 6, ie(0x10, 0xeb, 0x05),                                 # recognition time: pulse type
                      ie(0x10, 0x84, 0x06),                                         # steady type
                      ie(0x10, 0x8a, 0x07),                                         # neither (0x0a & 0x7f)
                      ie(0x10, 0xff, 0x01))))
    m.append((P, pstn(0x02, 7, ie(0x11, 0x84, 0xf5),                                 # enable autonomous ack: steady + pulse
                      ie(0x11, 0xed, 0x85, 0x13),                                    # pulse + steady + suppression
                      ie(0x11, 0x9c, 0x9d, 0x42, 0x86),                              # neither + neither + both extra
                      ie(0x11, 0x84, 0x85))))
    m.append((P, pstn(0x02, 8, ie(0x12, 0xed), ie(0x12, 0x84), ie(0x12, 0x9e))))      # disable autonomous ack
    m.append((P, pstn(0x08, 9, ie(0x13, 0x81), ie(0x13, 0x82, 0x0c))))               # DISCONNECT + cause (+ diagnostic)
    m.append((P, pstn(0x09, 9, ie(0x14, 0x41, 0x42, 0x43), ie(0x14, 0x30))))         # DISCONNECT COMPLETE + resource unavailable
    m.append((P, pstn(0x0c, 10, LINE_INFO, STATE, AUTO_SEQ, SEQ_RESP, PULSE_NOTIF))) # STATUS ENQUIRY with single octet IEs
    m.append((P, pstn(0x0d, 10, STATE + LINE_INFO)))                                 # STATUS
    m.append((P, pstn(0x0e, 11, ie(0x00, 0x80))))                                    # PROTOCOL PARAMETER
    m.append((P, pstn(0x0f, 12, ie(0x00, 0x81))))                                    # unknown PSTN-range type (address by flag)
    # Control protocol 0x10-0x13: PSTN-style and ISDN-style addresses
    m.append((C, pstn(0x10, 33, ie(0x20, 0x81), ie(0x21, 0x84))))                   # PORT CONTROL (PSTN address)
    m.append((C, isdn(0x10, 0x0123, ie(0x20, 0x91), ie(0x20, 0x99), ie(0x20, 0x9a))))  # ISDN address
    m.append((C, pstn(0x11, 33, ie(0x20, 0x81), PERF_GRADING, CP_REJECT)))           # PORT CONTROL ACK: no CFE info
    m.append((C, isdn(0x11, 0x0001, ie(0x20, 0x96), CP_REJECT)))
    m.append((C, msg(0x12, 0x01, 0x00, ie(0x21, 0x90), ie(0x22, 0x85), ie(0x23, 0x01, 0x02, 0x03))))   # COMMON CONTROL
    m.append((C, msg(0x13, 0x01, 0x00, ie(0x21, 0x87), ie(0x22, 0x81), ie(0x23, 0x10, 0x20, 0x30))))   # COMMON CONTROL ACK
    m.append((C, msg(0x14, 0x02, 0x03, ie(0x21, 0x82))))                              # unknown type in the control range
    # PROT protocol 0x18-0x1f
    for t in range(0x18, 0x20):
        m.append((R, msg(t, 0x00, 0x01 + t, ie(0x50, 0x80 + t), ie(0x51, 0x02, 0x1f), ie(0x52, 0x80 + (t & 3)),
                         ie(0x53, 0x81, 0x1c, 0x51))))
    # BCC 0x20-0x2a, 0x2b
    for i, t in enumerate(range(0x20, 0x2c)):
        hi = 0x80 | i if i % 2 else i
        m.append((B, msg(t, hi, 0x10 + i,
                         ie(0x40, 0x03, 0x84), ie(0x40, 0x04, 0x20),            # user port: PSTN-flag set / clear
                         ie(0x41, 0x80 + i), ie(0x42, 0x01, 0x82), ie(0x42, 0x02, 0xe1), ie(0x42, 0x03, 0xc4),
                         ie(0x43, 0x01, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19),
                         ie(0x44, 0x80 + i), ie(0x45, 0x81, 0x22, 0x33), ie(0x46, 0x80 + i))))
    # Link control 0x30, 0x31
    m.append((L, msg(0x30, 0x01, 0x05, ie(0x30, 0x82))))
    m.append((L, msg(0x31, 0x01, 0x05, ie(0x30, 0x83))))
    m.append((L, msg(0x32, 0x01, 0x06, ie(0x30, 0x84))))
    return m


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    r = []
    # the data links of the V5.2 interface: SABME / UA first
    r.append((ENC_V5EF, 1, 0, dlh(EF_PSTN, 1) + b'\x7f'))
    r.append((ENC_V5EF, 0, 0, dlh(EF_PSTN, 1) + b'\x73'))
    ns = {}
    k = 0
    for ef, mm in build_messages():
        # alternate direction (uton), C/R and the poll bit
        d = k & 1
        s = ns.get((ef, d), 0)
        ns[(ef, d)] = s + 1
        r.append((ENC_V5EF, d, 0, dlh(ef, d) + iframe(s, k % 5, (k >> 1) & 1) + mm))
        k += 1
    # PSTN message while the sender is unknown to the PSTN sequencing: plain I frame
    # (information frames of other envelope function addresses)
    r.append((ENC_V5EF, 1, 0, dlh(EF_ISDN, 0) + iframe(0, 0) + pstn(0x00, 1, ie(0x00, 0x80))))
    r.append((ENC_V5EF, 0, 0, dlh(8191, 1) + iframe(0, 0) + pstn(0x00, 2, ie(0x00, 0x80))))
    # message with a discriminator other than 0x48 is still shown (reserved)
    r.append((ENC_V5EF, 1, 0, dlh(EF_PSTN, 0) + iframe(1, 0) + bytes([0x08, 0x01, 0x05, 0x00])))
    # unknown information element codes are skipped one octet at a time
    r.append((ENC_V5EF, 0, 0, dlh(EF_PSTN, 1) + iframe(2, 1) + pstn(0x02, 3, b'\xff\x55\x66', ie(0x03, 0x84))))
    # a message with no information elements at all
    r.append((ENC_V5EF, 1, 0, dlh(EF_PSTN, 0) + iframe(3, 1) + pstn(0x0c, 4)))
    # S frames and U frames of the data link (no V5.2 message)
    r.append((ENC_V5EF, 1, 0, dlh(EF_PSTN, 0) + bytes([0x01, 0x0a])))         # RR
    r.append((ENC_V5EF, 0, 0, dlh(EF_PSTN, 1) + bytes([0x05, 0x0b])))         # RNR
    r.append((ENC_V5EF, 1, 0, dlh(EF_CTRL, 0) + bytes([0x09, 0x0d])))         # REJ
    r.append((ENC_V5EF, 0, 0, dlh(EF_BCC, 1) + b'\x43'))                      # DISC
    r.append((ENC_V5EF, 1, 0, dlh(EF_BCC, 0) + b'\x0f'))                      # DM
    r.append((ENC_V5EF, 0, 0, dlh(EF_PROT, 1) + b'\x63'))                     # UA
    r.append((ENC_V5EF, 1, 0, dlh(EF_LINK, 0) + b'\x03' + b'unnumbered'))     # UI
    # EF addresses up to 8175 are LAPD frames (D channel of the ISDN user ports):
    # SAPI 0, TEI 0 and a UI frame with a Q.931 message, I frame, RR
    r.append((ENC_V5EF, 1, 0, v5addr(100, 0) + bytes([0x00, 0x01, 0x03, 0x08, 0x01, 0x00, 0x05, 0x04, 0x03, 0x80, 0x90, 0xa2])))
    r.append((ENC_V5EF, 0, 0, v5addr(8000, 0) + bytes([0x02, 0x01, 0x00, 0x00, 0x08, 0x01, 0x80, 0x0d])))
    r.append((ENC_V5EF, 1, 0, v5addr(0, 0) + bytes([0x00, 0x01, 0x01, 0x00])))
    eyesdn(os.path.join(out, 'v52-coverage.eyesdn'), r)

    # --- V5UA carrying V5.2: used for the runcov number only
    frames = []
    tsn = [1]

    def dr(cls, typ, body):
        return struct.pack('>BBBBI', 1, 0, cls, typ, 8 + len(body)) + body

    for i, (ef, mm) in enumerate(build_messages()[:20]):
        ifid = struct.pack('>HHI', 0x01, 8, (7 << 5) | 3)
        dlci = struct.pack('>HHBBH', 0x81, 8, 0x00, 0x01, ef)
        pdata = struct.pack('>HH', 0x0e, 4 + len(mm)) + mm
        pdata += b'\0' * ((4 - len(pdata) % 4) % 4)
        v = dr(14, 1 if i & 1 else 2, ifid + dlci + pdata)
        pkt = sctp(10000, 5675, 0x11111111, [sctp_data(tsn[0], 0, tsn[0], 6, v)])
        tsn[0] += 1
        frames.append(ether(ip4(132, '192.0.2.30', '192.0.2.31', pkt, i + 1)))
    pcap(os.path.join(out, 'v52-coverage-v5ua.pcap'), 1, frames)

    m = []
    base = dlh(EF_PSTN, 1) + iframe(0, 0)
    good = pstn(0x02, 5, ie(0x03, 0x84))
    # message too short for the type octet
    m.append((ENC_V5EF, 1, 0, base + b'\x48\x01'))
    m.append((ENC_V5EF, 1, 0, base + b'\x48'))
    # an IE with a length that runs past the message end, for each reader
    for code in (0x00, 0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x13, 0x14, 0x20, 0x21, 0x22, 0x23, 0x30,
                 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x50, 0x51, 0x52, 0x53):
        m.append((ENC_V5EF, 0, 0, base + pstn(0x02, 5, bytes([code, 9, 0x80]))))
    # an IE with length 0: the data octet is read from the next IE instead (or past the end)
    for code in (0x00, 0x03, 0x13, 0x22, 0x23, 0x51, 0x53):
        m.append((ENC_V5EF, 0, 0, base + pstn(0x02, 5, bytes([code, 0]))))
    # single octet IE and a one octet message body
    m.append((ENC_V5EF, 0, 0, base + pstn(0x02, 5, b'\x40')))
    # the data link address cut short
    m.append((ENC_V5EF, 1, 0, b'\x00'))
    m.append((ENC_V5EF, 1, 0, dlh(EF_PSTN, 1)))
    m.append((ENC_V5EF, 1, 0, dlh(EF_PSTN, 1) + b'\x00'))
    # a V5EF record with an address that selects LAPD
    m.append((ENC_V5EF, 0, 0, v5addr(5, 0) + b'\x00\x00\x00\x00'))
    m.append((ENC_V5EF, 1, 0, b'\x00'))
    eyesdn(os.path.join(out, 'v52-coverage-malformed.eyesdn'), m)


main()
