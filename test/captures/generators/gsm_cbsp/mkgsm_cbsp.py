#!/usr/bin/env python3
# Generates test/captures/gsm_cbsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the GSM CBSP coverage captures.  Usage: mkgsm_cbsp.py <outdir>
# Synthetic TCP traffic between 192.0.2.1 (the CBC) and 192.0.2.2 (the
# BSC) on the CBSP port 48049, which reaches the cbsp dissector by default.
import os
import struct
import socket
import sys

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth_tcp(payload, sport, dport, seq, ack, flags, src, dst):
    opts = bytes.fromhex('020405b4010303070402') + b'\x01\x01' if flags & 2 else b''
    s = socket.inet_aton(src)
    d = socket.inet_aton(dst)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    ph = s + d + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + tcp + payload

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

class Conn:
    """A TCP connection CBC (client) -> BSC (server, port 48049)."""
    def __init__(self, frames, cport=40000, c='192.0.2.1', s='192.0.2.2', handshake=True):
        self.f, self.cp, self.c, self.s = frames, cport, c, s
        self.cseq, self.sseq = 1000, 5000
        if not handshake:
            return
        self.f.append(eth_tcp(b'', cport, 48049, self.cseq, 0, 0x02, c, s))
        self.cseq += 1
        self.f.append(eth_tcp(b'', 48049, cport, self.sseq, self.cseq, 0x12, s, c))
        self.sseq += 1
        self.f.append(eth_tcp(b'', cport, 48049, self.cseq, self.sseq, 0x10, c, s))
    def send(self, data, down=False):
        """data from the CBC (down=False) or the BSC (down=True)"""
        if down:
            self.f.append(eth_tcp(data, 48049, self.cp, self.sseq, self.cseq, 0x18, self.s, self.c))
            self.sseq += len(data)
        else:
            self.f.append(eth_tcp(data, self.cp, 48049, self.cseq, self.sseq, 0x18, self.c, self.s))
            self.cseq += len(data)

def msg(mtype, *ies):
    body = b''.join(ies)
    return bytes([mtype]) + struct.pack('>I', len(body))[1:] + body

# --- information elements
def serial(iei, v): return bytes([iei]) + struct.pack('>H', v)
def old_serial(v): return serial(2, v)
def new_serial(v): return serial(3, v)
def msg_id(v): return serial(0x0e, v)
def tv(iei, v): return bytes([iei, v])
def category(v): return tv(5, v)
def rep_period(v): return b'\x06' + struct.pack('>H', v)
def num_bcast_req(v): return b'\x07' + struct.pack('>H', v)
def cause(v): return tv(0x0b, v)
def dcs(v): return tv(0x0c, v)
def recovery(v): return tv(0x0d, v)
def emerg(v): return tv(0x0f, v)
def warn_type(v): return b'\x10' + struct.pack('>H', v)
def warn_sec(): return b'\x11' + bytes(range(50))
def channel(v): return tv(0x12, v)
def pages(v): return tv(0x13, v)
def sched(v): return tv(0x14, v)
def res_slots(v): return tv(0x15, v)
def bcast_type(v): return tv(0x16, v)
def warn_period(v): return tv(0x17, v)
def ka_period(v): return tv(0x18, v)
def tl16(iei, v): return bytes([iei]) + struct.pack('>H', len(v)) + v

def content(raw):
    """Message Content: user information length + 82 octets of page"""
    assert len(raw) <= 82
    return b'\x01' + bytes([82 if len(raw) == 82 else len(raw)]) + raw + b'\0' * (82 - len(raw))

def pack7(text):
    """GSM 7 bit packing of plain ASCII text (default alphabet, no escapes)"""
    bits = 0
    nbits = 0
    out = bytearray()
    for ch in text.encode('ascii'):
        bits |= (ch & 0x7f) << nbits
        nbits += 7
        while nbits >= 8:
            out.append(bits & 0xff)
            bits >>= 8
            nbits -= 8
    if nbits:
        out.append(bits & 0xff)
    return bytes(out)

def text7(text):
    """text padded with CR to the 82 octets of a page"""
    return pack7(text + '\r' * 93)[:82]

PLMN = bytes([0x00, 0xf1, 0x10])      # MCC 001 MNC 01
def cgi(lac, ci): return PLMN + struct.pack('>HH', lac, ci)
def lai(lac): return PLMN + struct.pack('>H', lac)

CELLS = {
    0: [cgi(0x1001, 1), cgi(0x1001, 2)],
    1: [struct.pack('>HH', 0x2001, 5), struct.pack('>HH', 0x2002, 6)],
    2: [struct.pack('>H', 7), struct.pack('>H', 8)],
    4: [lai(0x3001), lai(0x3002)],
    5: [struct.pack('>H', 0x4001), struct.pack('>H', 0x4002)],
    6: [],
}

def cell_list(d, n=2):
    return tl16(4, bytes([d]) + b''.join(CELLS[d][:n]))
def bc_compl(d):
    items = b''
    for i, c in enumerate(CELLS[d] or [b'']):
        items += c + struct.pack('>HB', 100 + i, i % 3)
    return tl16(8, bytes([d]) + items)
def rr_load(d):
    items = b''
    for i, c in enumerate(CELLS[d] or [b'']):
        items += c + bytes([10 + i, 50 + i])
    return tl16(0x0a, bytes([d]) + items)
def fail_list(ds, causes=(0, 1, 2, 3)):
    items = b''
    for i, d in enumerate(ds):
        c = (CELLS[d] or [b''])[0]
        items += bytes([d]) + c + bytes([causes[i % len(causes)]])
    return tl16(9, items)

def build(outdir):
    f = []
    cn = Conn(f)
    sn = 0x1234
    # --- WRITE-REPLACE with every IE and 7 bit text
    wr = msg(1, new_serial(sn), msg_id(0x1112), old_serial(0x1230),
             cell_list(0), category(2), rep_period(0x1fff), num_bcast_req(5),
             dcs(0x0f), content(text7('Hello from the CBC, testing CBSP')),
             channel(1), pages(1), emerg(1), warn_type(0x4001), warn_sec(),
             sched(3), res_slots(2), bcast_type(1), warn_period(0x05))
    cn.send(wr)
    # WRITE-REPLACE COMPLETE with the number of broadcasts completed
    cn.send(msg(2, new_serial(sn), msg_id(0x1112), bc_compl(0), cell_list(1),
                channel(0)), down=True)
    # --- each cell list type in WRITE-REPLACE with other categories/DCS
    for i, (d, cat, dc) in enumerate([(1, 0, 0x01), (2, 1, 0x11), (4, 2, 0x48),
                                      (5, 0, 0x44), (6, 1, 0x1f)]):
        raw = {0x01: text7('Switch to the German language text'),
               0x11: pack7('fr\r')[:2] + 'Bonjour'.encode('utf-16-be'),
               0x48: 'Grüße Ünï'.encode('utf-16-be'),
               0x44: b'8 bit text \x01\x02',
               0x1f: 'Reserved'.encode('utf-16-be')}[dc]
        cn.send(msg(1, new_serial(sn + 1 + i), msg_id(0x1000 + i),
                    cell_list(d), category(cat), rep_period(1), num_bcast_req(1),
                    dcs(dc), content(raw)))
    # language indication UCS2 (group 0001, 0001), the language "en" CR
    # packed into two octets
    cn.send(msg(1, new_serial(sn + 7), msg_id(0x1010), cell_list(0, 1),
                category(1), rep_period(2), num_bcast_req(2),
                dcs(0x11), content(text7('en\r')[:2] + 'Hej'.encode('utf-16-be'))))
    # coding group 0001, 0000: language prefix in the 7 bit text
    cn.send(msg(1, new_serial(sn + 8), msg_id(0x1011), cell_list(2),
                category(2), rep_period(2), num_bcast_req(2),
                dcs(0x10), content(text7('sv\rHello Svenska'))))
    # fix reproducer: a reserved coding group (0xA0) means that the
    # content cannot be decoded
    cn.send(msg(1, new_serial(sn + 9), msg_id(0x1012), cell_list(0, 1),
                category(2), rep_period(2), num_bcast_req(2),
                dcs(0xa0), content(b'HELLO')))
    # other messages
    cn.send(msg(3, new_serial(sn), msg_id(0x1112), fail_list([0, 1, 2, 4, 5, 6]),
                cell_list(6), cause(2), channel(0)), down=True)
    cn.send(msg(4, old_serial(sn), msg_id(0x1112), cell_list(2), channel(1)))
    cn.send(msg(5, old_serial(sn), msg_id(0x1112), bc_compl(1), cell_list(4)), down=True)
    cn.send(msg(6, old_serial(sn), msg_id(0x1112), fail_list([2, 4, 5], (4, 5, 6)),
                cause(0x0e)), down=True)
    cn.send(msg(7, cell_list(5), channel(0)))
    cn.send(msg(8, rr_load(0), cell_list(0, 1)), down=True)
    cn.send(msg(8, rr_load(1)), down=True)
    cn.send(msg(8, rr_load(2)), down=True)
    cn.send(msg(8, rr_load(4)), down=True)
    cn.send(msg(8, rr_load(5)), down=True)
    cn.send(msg(8, rr_load(6)), down=True)
    cn.send(msg(9, fail_list([0, 0, 0]), cause(7)), down=True)
    cn.send(msg(10, msg_id(0x1112), new_serial(sn), cell_list(1), channel(0)))
    cn.send(msg(11, msg_id(0x1112), new_serial(sn), bc_compl(2), cell_list(2), channel(0)), down=True)
    cn.send(msg(12, msg_id(0x1112), new_serial(sn), fail_list([2]), cause(9)), down=True)
    cn.send(msg(13, cell_list(0), tv(0x0c, 0x0f), channel(0)))
    cn.send(msg(14, cell_list(0)), down=True)
    cn.send(msg(15, cell_list(0), cause(0x0b)), down=True)
    cn.send(msg(16, cell_list(6)))
    cn.send(msg(17, cell_list(6)), down=True)
    cn.send(msg(18, cause(0x0c), cell_list(6)), down=True)
    cn.send(msg(19, recovery(0)), down=True)
    cn.send(msg(0x14, cause(0x0a)), down=True)
    cn.send(msg(0x15, cause(5), msg_id(0x1112)), down=True)
    for w in (0x00, 0x0a, 0x0b, 0x14, 0x15, 0x26, 0x27, 0x56, 0x57, 0xba):
        cn.send(msg(0x16, ka_period(w)))
        cn.send(msg(0x17, bytes([0x17, w])), down=True)   # KEEP-ALIVE COMPLETE with a warning period tag
    cn.send(msg(0x17), down=True)
    # unknown message type
    cn.send(msg(0x42, cause(1)), down=True)
    # --- TCP: two messages in one segment, a message in three segments
    cn.send(msg(0x16, ka_period(5)) + msg(0x17), False)
    big = msg(1, new_serial(sn + 20), msg_id(0x1020), cell_list(0), category(2),
              rep_period(3), num_bcast_req(3), dcs(0x0f), content(text7('A segmented message')))
    cn.send(big[:10])
    cn.send(big[10:30])
    cn.send(big[30:])
    # TL16V cell list with 8 cells, to have a larger list
    cn.send(msg(1, new_serial(sn + 21), msg_id(0x1021),
                tl16(4, bytes([1]) + b''.join(struct.pack('>HH', 0x5000 + i, i) for i in range(8))),
                category(2), rep_period(3), num_bcast_req(3), dcs(0x0f), content(text7('Eight cells'))))

    # ---- malformed capture
    b = []
    cb = Conn(b, 40001)
    # unknown IE: stops the IE loop
    cb.send(msg(1, new_serial(1), bytes([0x00, 1, 2, 3])))
    cb.send(msg(1, new_serial(1), bytes([0x30, 1, 2, 3])))
    # a cell list with an unknown discriminator (3) and an item that is cut
    cb.send(msg(1, new_serial(2), tl16(4, bytes([3, 1, 2, 3, 4]))))
    cb.send(msg(1, new_serial(2), tl16(4, bytes([0x07]) + b'\x01\x02')))
    cb.send(msg(8, tl16(0x0a, bytes([3, 1, 2, 3, 4]))))
    cb.send(msg(9, tl16(9, bytes([3, 1, 2, 3, 4]))))
    cb.send(msg(5, tl16(8, bytes([3, 1, 2, 3, 4]))))
    cb.send(msg(5, tl16(8, bytes([2, 1, 2]))))
    cb.send(msg(9, tl16(9, bytes([2, 1]))))
    cb.send(msg(8, tl16(0x0a, bytes([2, 1]))))
    # empty lists
    cb.send(msg(1, tl16(4, b''), tl16(8, b'')))
    # IE length running over the end of the message
    # (each in a connection of its own: a PDU that is shorter than its
    # length field waits for more data)
    Conn(b, 40010, handshake=False).send(bytes([1, 0, 0, 8]) + new_serial(1) + bytes([4, 0xff, 0xff, 0, 0, 0]))
    Conn(b, 40011, handshake=False).send(bytes([1, 0, 0, 2]) + bytes([4, 0xff]))
    Conn(b, 40012, handshake=False).send(bytes([1, 0, 0, 1]) + bytes([2]))
    Conn(b, 40013, handshake=False).send(bytes([1, 0, 0, 6]) + bytes([4, 0, 20, 0, 1, 2]))
    # content with a length of 1 and larger DCS combinations
    cb.send(msg(1, dcs(0x0f), b'\x01\x01' + b'\x00' * 82))
    cb.send(msg(1, dcs(0x48), b'\x01\x01' + b'\x00' * 82))
    cb.send(msg(1, dcs(0x44), b'\x01\x01' + b'\x00' * 82))
    cb.send(msg(1, dcs(0x11), b'\x01\x00' + b'\x00' * 82))
    cb.send(msg(1, dcs(0x11), b'\x01\x01' + b'\x00' * 82))
    # reserved DCS groups
    for d in (0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0x90, 0x80, 0x60, 0x70, 0x30, 0x20, 0x40, 0xf4, 0xf0):
        cb.send(msg(1, dcs(d), content(b'text')))
    # a message that is shorter than its length: segment, then the connection closes
    Conn(b, 40014, handshake=False).send(msg(1, new_serial(3))[:6])
    # reserved warning / keep alive periods
    cb.send(msg(0x16, ka_period(0xbb)))
    cb.send(msg(1, warn_period(0xff)))
    # message with a length of 0 and one with unknown type
    cb.send(bytes([0x16, 0, 0, 0]))
    cb.send(bytes([0x00, 0, 0, 0]))
    cb.send(bytes([0xff, 0, 0, 1, 0x0b]))
    write_pcap(os.path.join(outdir, 'gsm_cbsp-coverage.pcap'), f)
    write_pcap(os.path.join(outdir, 'gsm_cbsp-coverage-malformed.pcap'), b)
    print(len(f), len(b))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
