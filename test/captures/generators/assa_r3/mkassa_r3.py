#!/usr/bin/env python3
# Generates test/captures/assa_r3_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ASSA R3 dissector
(epan/dissectors/packet-assa_r3.c).

Every packet is built from scratch with struct; no captured traffic is
used. A host (192.0.2.10) talks R3 to a lock controller (192.0.2.20) on
TCP ports 2571 and 8023, the dissector's default ports.

Usage: mkassa_r3.py <output directory>

Writes:
  assa_r3-coverage.pcap            every command, manufacturing command,
                                   response type, upstream command,
                                   upstream field, manufacturing field and
                                   configuration item, PDUs split over
                                   segments and several PDUs in a segment,
                                   and the reproducers of the offset fixes
  assa_r3-coverage-malformed.pcap  paths that end in an exception or an
                                   error expert info
"""

import os
import struct
import sys

HOST = (192, 0, 2, 10)
LOCK = (192, 0, 2, 20)

# --------------------------------------------------------------------------
# pcap writer (Ethernet / IPv4 / TCP)

def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\0'
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, sport, dport, seq, ack, flags, payload=b'', src=HOST, dst=LOCK):
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', ip_checksum(pseudo + hdr + payload)) + hdr[18:]
        l4 = hdr + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                         0x4000, 64, 6, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        if src == HOST:
            eth = b'\x02\x00\x00\x00\x00\x14' + b'\x02\x00\x00\x00\x00\x0a' + b'\x08\x00'
        else:
            eth = b'\x02\x00\x00\x00\x00\x0a' + b'\x02\x00\x00\x00\x00\x14' + b'\x08\x00'
        self.frames.append(eth + ip + l4)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class TcpStream:
    """A TCP connection from the host to the lock, with correct sequence
    numbers."""
    def __init__(self, cap, cport, port=2571):
        self.cap, self.cport, self.port = cap, cport, port
        self.cseq, self.sseq = 1000 + cport, 5000 + cport
        cap.tcp(cport, port, self.cseq, 0, 0x02)
        cap.tcp(port, cport, self.sseq, self.cseq + 1, 0x12, src=LOCK, dst=HOST)
        self.cseq += 1
        self.sseq += 1
        cap.tcp(cport, port, self.cseq, self.sseq, 0x10)

    def host(self, *datas):
        """Send each argument as one TCP segment from the host."""
        for data in datas:
            self.cap.tcp(self.cport, self.port, self.cseq, self.sseq, 0x18, data)
            self.cseq += len(data)

    def lock(self, *datas):
        for data in datas:
            self.cap.tcp(self.port, self.cport, self.sseq, self.cseq, 0x18, data,
                         src=LOCK, dst=HOST)
            self.sseq += len(data)

    def close(self):
        self.cap.tcp(self.cport, self.port, self.cseq, self.sseq, 0x11)
        self.cseq += 1
        self.cap.tcp(self.port, self.cport, self.sseq, self.cseq, 0x11, src=LOCK, dst=HOST)
        self.sseq += 1
        self.cap.tcp(self.cport, self.port, self.cseq, self.sseq, 0x10)


def split(data, *cuts):
    out, last = [], 0
    for c in cuts:
        out.append(data[last:c])
        last = c
    return out + [data[last:]]


# --------------------------------------------------------------------------
# R3 encoding

def u8(v):  return struct.pack('<B', v)
def u16(v): return struct.pack('<H', v)
def u24(v): return struct.pack('<I', v)[:3]
def u32(v): return struct.pack('<I', v)


def crc16_r3(data):
    """crc16_x25_ccitt_seed(buf, len, 0): poly 0x1021, seed 0, not reflected."""
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xffff
    return crc


def pdu(cmds, pktno=1, addr=1, enc=0, bad_crc=False, bad_xor=False):
    """sigil, address, packet number, length, encryption, commands, CRC, XOR"""
    plen = len(cmds) + 7
    assert plen <= 255, plen
    hdr = bytes([0x01, addr, pktno & 0xff, plen, enc])
    crc = crc16_r3(hdr[1:] + cmds)
    if bad_crc:
        crc ^= 0x1234
    x = plen ^ 0xff
    if bad_xor:
        x ^= 0x55
    return hdr + cmds + struct.pack('<HB', crc, x)


def pdu_crc_low(cmds, wanted, addr=1):
    """A PDU whose CRC low octet is in 'wanted', found by varying the packet
    number. The manufacturing peek/poke and force options commands read to
    the end of the PDU, so they also decode the CRC and XOR octets."""
    for n in range(256):
        p = pdu(cmds, pktno=n, addr=addr)
        if p[-3] in wanted:
            return p
    raise ValueError('no packet number gives a CRC low octet in %r' % (wanted,))


def cmd(code, data=b''):
    return u8(len(data) + 2) + u8(code) + data


def mfgcmd(code, data=b''):
    """CMD_MFGCOMMAND followed by the manufacturing command"""
    return cmd(29) + cmd(code, data)


def resp(rtype, to_cmd):
    return bytes([4, 0, rtype, to_cmd])


def hasdata(upcmd, data):
    return u8(len(data) + 4) + bytes([0, 2, upcmd]) + data


def field(ftype, data):
    return u8(len(data) + 2) + u8(ftype) + data


def mfgfield(fld, data):
    return u8(len(data) + 2) + u8(fld) + data


SERIAL = b'IT512H0001SA03AA'        # ITS, 2005, week 12, Sx, seq 0001, Sargent, Ethernet, keypad+eProx, batteries, 82276
SERIAL2 = b'ZZ#99Q1234X?zzQ?'       # every part unknown

# configMap from the dissector: the type of each configuration item
# (1 bool, 2 u8, 3 u16, 4 u32, 5 string)
CONFIGMAP = [5, 5, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 3, 3, 2, 2, 2, 3, 3, 3, 3, 3,
             3, 3, 3, 3, 3, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 3, 3, 3, 2, 3, 2, 1, 3,
             3, 3, 2, 3, 2, 1, 3, 3, 3, 2, 3, 2, 1, 1, 1, 1, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 2, 2, 2,
             2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 5, 2, 4,
             3, 3, 3, 3, 2, 2, 2, 2, 2, 5, 5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 5, 5, 2, 2, 1,
             1, 2, 2, 2, 1, 1, 2]
assert len(CONFIGMAP) == 157


def config_value(item, ctype):
    if ctype == 1:
        return u8(item & 1)
    if ctype == 2:
        return u8(item)
    if ctype == 3:
        return u16(0x100 + item)
    if ctype == 4:
        return u32(0x01020300 + item)
    return b'cfg%d' % item


def setconfig_items():
    """[length] [item] [value] for every configuration item and two
    unknown ones"""
    items = []
    for item, ctype in enumerate(CONFIGMAP):
        v = config_value(item, ctype)
        items.append(u8(len(v) + 2) + u8(item) + v)
    items.append(b'\x04\x9d\xaa\xbb')   # 157, past the table
    items.append(b'\x03\xf0\x01')       # 240
    return items


def queryconfig_items():
    """[length] [item] [type] [value] for every configuration item, plus
    CONFIGTYPE_NONE and an unknown type"""
    items = []
    for item, ctype in enumerate(CONFIGMAP):
        v = config_value(item, ctype)
        items.append(u8(len(v) + 3) + u8(item) + u8(ctype) + v)
    items.append(b'\x06\x9d\x00\xde\xad\xbe')   # CONFIGTYPE_NONE, unknown item
    items.append(b'\x05\x01\x07\x11\x22')       # unknown config type
    return items


def pack_items(items, limit):
    """Group items into lists whose total length is at most limit."""
    groups, cur = [], b''
    for it in items:
        if len(cur) + len(it) > limit:
            groups.append(cur)
            cur = b''
        cur += it
    if cur:
        groups.append(cur)
    return groups


def eventlog_record(n, event):
    return u16(n) + bytes([24, 7, 19, 13, 45, 30]) + u16(1000 + n) + u8(event)


def declined_record(n, ctype, prefix=True):
    rec = bytes([24, 7, 19, 13, 45, 31]) + u16(0x1234) + u8(ctype) + \
        b'1234567890123456789' + b'ABCDEFGHIJKLMNOPQRS' + b'\x00\x00'
    return (u16(n) + rec) if prefix else rec


# --------------------------------------------------------------------------
# Main capture

def host_commands(cap):
    """Every host to lock command, each answered by the lock."""
    s = TcpStream(cap, 40001)
    n = [0]

    def send(c, answer=0):
        n[0] += 1
        s.host(pdu(c, pktno=n[0]))
        s.lock(pdu(resp(answer, c[1]), pktno=n[0]))

    send(cmd(1))                                    # HANDSHAKE
    send(cmd(3))                                    # QUERYSERIALNUMBER
    send(cmd(4))                                    # QUERYVERSION
    send(cmd(5, bytes([24, 7, 19, 5, 13, 45, 30]))) # SETDATETIME
    send(cmd(6))                                    # QUERYDATETIME
    for g in pack_items(setconfig_items(), 240):    # SETCONFIG, every item
        send(cmd(7, g))
    send(cmd(8, bytes(range(0, 157, 7))))           # GETCONFIG
    # MANAGEUSER: every parameter type and an unknown one
    mu = (field(0, b'\x01') + field(1, u16(42)) + field(2, b'\x01') + field(3, b'\x03') +
          field(4, b'\x00') + field(5, b'\x02') + field(6, b'12345678') + field(7, b'\x01') +
          field(8, b'\x01\x02\x03\x04\x05') + field(9, b'\x02') + field(10, u32(0x80000001)) +
          field(11, bytes([12, 31, 25])) + field(12, b'\x05') + field(13, b'\x07') +
          field(14, b'\xaa\xbb') + field(0xff, b''))
    send(cmd(9, mu))
    send(cmd(10, b'\x00'))                          # DELETEUSERS all
    send(cmd(10, b'\x01'))                          # DELETEUSERS cached
    send(cmd(11, bytes([3, 12, 24, 8, 0, 12, 26, 17, 30])))   # DEFINEEXCEPTION
    send(cmd(12, b'\x05' + bytes([0xa5, 0x01, 0x80, 0xff, 0x00, 0x0f, 0xf0, 0x5a])))  # DEFINEEXCEPTIONGROUP
    send(cmd(13, b'\x02' + b''.join(u32((0x55555555 << m) & 0x7fffffff) for m in range(12))))  # DEFINECALENDAR
    send(cmd(14, bytes([4, 8, 0, 17, 30, 0x3e, 2, 0x12])))   # DEFINETIMEZONE, access always
    send(cmd(14, bytes([5, 0, 0, 23, 59, 0x41, 0, 0x03])))   # DEFINETIMEZONE
    send(cmd(15, u16(0x1234) + b'\x02'))            # RMTAUTHRETRY
    send(cmd(16, bytes([5, 0, 1, 2, 3, 30, 76])))   # FILTERS, recording
    send(cmd(16, bytes([0, 1])))                    # FILTERS, reporting, none
    # ALARMCONFIGURE: disabled, enabled, error state, unknown alarm id
    send(cmd(17, bytes([3, 1, 0, 3, 4, 1, 3, 8, 2, 3, 0x42, 1, 4, 9, 1, 0])))
    send(cmd(17))                                   # ALARMCONFIGURE, empty list
    send(cmd(18, bytes([24, 1, 1, 0, 0, 24, 12, 31, 23, 59]) + u16(0xffff)))  # EVENTLOGDUMP
    send(cmd(19, bytes([24, 1, 1, 0, 0, 24, 12, 31, 23, 59])))   # DECLINEDLOGDUMP
    send(cmd(20, bytes([24, 2, 1, 0, 0, 24, 11, 30, 22, 58])))   # ALARMLOGDUMP

    # DOWNLOADFIRMWARE: every action, with good CRCs, and one bad CRC
    def dlfw(record, action, extra, bad=False):
        body = u16(0) + u16(record) + u8(action) + extra
        body = u16(len(body) + 2) + body[2:]
        c = crc16_r3(body)
        if bad:
            c ^= 0xffff
        return cmd(21, body + u16(c))
    send(dlfw(0, 0, bytes([30, 1])))
    send(dlfw(1, 1, u32(0x00010000) + b'\x10' + bytes(range(16))))
    send(dlfw(2, 1, u32(0x00010010) + b'\x04' + b'\xde\xad\xbe\xef', bad=True))
    send(dlfw(3, 2, b''))
    send(dlfw(4, 3, b''))
    send(dlfw(5, 4, b''))
    send(cmd(23, b'\x03'))                          # POWERTABLESELECTION
    send(cmd(24, u16(0x8f81)))                      # CLEARNVRAM
    send(cmd(25, b'\x01' + u16(500) + b'AT+X'))     # DPAC
    send(cmd(26))                                   # SELFTEST
    send(cmd(28, u16(77) + b'\x10'))                # LOGWRITE
    send(cmd(30))                                   # NVRAMBACKUP
    send(cmd(31))                                   # EXTENDEDRESPONSE
    # several commands in one PDU
    n[0] += 1
    s.host(pdu(cmd(1) + cmd(4) + cmd(6) + cmd(3), pktno=n[0], enc=1))
    s.lock(pdu(resp(0, 1) + resp(0, 4) + resp(0, 6) + resp(0, 3), pktno=n[0], enc=1))
    # an empty PDU
    s.host(pdu(b'', pktno=0))
    # RESET then KILLSESSION
    send(cmd(27))
    send(cmd(2))
    s.close()


def responses(cap):
    """Every single octet response type and an unknown one."""
    s = TcpStream(cap, 40002)
    s.host(pdu(cmd(1)))
    for rt in range(52):
        if rt == 2:
            continue
        s.lock(pdu(resp(rt, rt % 32), pktno=rt))
    s.lock(pdu(resp(0xc8, 1), pktno=0xc8))
    s.close()


def upstream_fields_all():
    """Every upstream field type (and unknown ones) as lists of fields."""
    f = [
        field(1, SERIAL),
        field(2, u16(0x0102)),
        field(3, b'\x02'),
        field(4, b'\x01'),
        field(5, b'8989'),
        field(6, u16(77)),
        field(7, b'\x1e'),
        field(8, u16(5)),
        field(9, b'R3 1.23b'),
        field(10, bytes([24, 7, 19, 13, 45, 30]) + u16(5) + b'\x01'),
        field(11, bytes([24, 7, 19, 5, 13, 45, 30, 1])),
        field(12, u16(1000)),
        field(13, u16(20)),
        field(14, declined_record(0, 0x0a, prefix=False)),
        field(15, b'\x03'),
        field(16, b'\x01'),
        field(17, b'\x00'),
        field(18, b'\x01'),
        field(19, b'\x02'),
        field(20, b'\x04'),
        field(21, bytes([12, 31, 25])),
        field(22, b'\x09'),
        field(23, u32(0x80000003)),
        field(24, b'\x02'),
        field(25, b'1234\x00'),
        field(26, b'\x81\x82\x83'),
        field(27, u16(200)),
        field(28, bytes([24, 7, 19, 13, 45, 32, 4]) + u16(12)),
        field(29, b'AUX 0.9'),
        field(0, b'\x00\x01'),          # UPSTREAMFIELD_NOTUSED
        field(30, b'\x55'),             # past the table
        field(0xfe, b''),
    ]
    return f


def upstream(cap):
    """Every upstream command (lock to host), with every upstream field."""
    s = TcpStream(cap, 40003)
    n = [0]

    def up(upcmd, data):
        n[0] += 1
        s.host(pdu(cmd(3), pktno=n[0]))
        s.lock(pdu(hasdata(upcmd, data), pktno=n[0]))

    up(0, b'\x01\x02')                              # RESERVED (warning)
    up(1, b'\x00Debug: hello from the lock')        # DEBUGMSG
    up(2, field(9, b'R3 2.00') + field(29, b'AUX 1'))   # QUERYVERSION
    up(3, field(11, bytes([24, 7, 19, 5, 13, 45, 30, 0])))   # QUERYDATETIME
    up(4, field(1, SERIAL))                         # QUERYSERIALNUMBER
    up(4, field(1, SERIAL2))                        # unknown serial number parts
    up(5, eventlog_record(9, 1))                    # DUMPEVENTLOG
    up(5, eventlog_record(10, 0xfe))                # unknown event
    up(6, u16(0x0040) + b'\x08' + bytes(range(8)))  # DUMPNVRAM
    up(7, field(2, u16(3)) + field(3, b'\x01') + field(4, b'\x01') + field(5, b'4321') +
          field(6, u16(9)) + field(7, b'\x0a'))     # RMTAUTHREQUEST
    up(8, field(8, u16(5)) + field(15, b'\x01') + field(16, b'\x00') + field(17, b'\x01') +
          field(18, b'\x01') + field(19, b'\x00') + field(20, b'\x02') +
          field(21, bytes([1, 2, 30])) + field(22, b'\x00') + field(23, u32(1)) +
          field(24, b'\x01') + field(25, b'12\x00') + field(26, b'\x00'))   # RETRIEVEUSER
    for g in pack_items(queryconfig_items(), 230):  # QUERYCONFIG, every item
        up(9, g)
    up(10, field(10, bytes([24, 7, 19, 13, 46, 0]) + u16(6) + b'\x02'))   # RMTEVENTLOGRECORD
    up(11, b'\x00\x00\x07\x05OK\r\n')               # DPAC
    for g in pack_items(upstream_fields_all(), 230):   # NOTIFY, every field
        up(12, g)
    up(14, field(12, u16(9000)))                    # EVENTLOGWARNING
    up(15, u16(0x0100) + b'\x00\x04\xff\x00\xff\x00')   # DUMPNVRAMRLE
    up(16, field(14, declined_record(0, 0x11, prefix=False)))   # RMTDECLINEDRECORD
    up(17, field(13, u16(450)))                     # DECLINEDWARNING
    up(18, declined_record(3, 0x1a))                # DUMPDECLINEDLOG
    up(19, field(28, bytes([24, 7, 19, 13, 47, 1, 2]) + u16(3)))  # RMTALARMRECORD
    up(20, field(27, u16(190)))                     # ALARMWARNING
    up(21, u16(4) + bytes([24, 7, 19, 13, 48, 2, 4]) + u16(0))   # DUMPALARMLOG
    up(22, field(1, SERIAL))                        # CONNECTSCHEDULER
    up(23, field(1, SERIAL))                        # CONNECTCOMMUSER
    up(24, field(1, SERIAL))                        # CONNECTALARM
    up(25, u16(17) + u32(0x00ff00ff) + u16(0x1234)) # DUMPDEBUGLOG
    up(26, b'\x00')                                 # past the table (warning)
    up(0xff, b'')
    s.close()


def mfg_fields():
    """The upstream manufacturing fields (UPSTREAMCOMMAND_MFG)."""
    out = []
    ports = b''.join(bytes([0x10 + p, 0x20 + p, 0x30 + p]) for p in range(10))  # A..K (no I)
    out.append(mfgfield(0, ports))
    out.append(mfgfield(1, bytes([0, 50, 100, 150, 200, 250, 255, 128])))
    out.append(mfgfield(1, bytes(range(10, 19))))   # too many ADC values (warning)
    out.append(mfgfield(2, b'\x07' + u16(0x1234) + b'\x05'))
    # checkpoint log: every reset type
    cpl = b'\x07' + bytes([0xff, 0x01, 0x1c, 0x02, 0x00, 0x03, 0x1e, 0x04, 0x18, 0x05,
                           0x14, 0x06, 0x10, 0x07, 0x1f, 0xfe])
    out.append(mfgfield(3, cpl))
    out.append(mfgfield(4, bytes([0x55, 0xaa, 0x0f, 0xf0, 0x33, 0xcc, 0x81, 0x18, 0x7e, 0xe7,
                                  0x5a, 0xa5, 0x3c, 0xc3, 0x99, 0x66, 0x01, 0x80, 0xff])))
    out.append(mfgfield(5, b''.join(u8(t) + u32(0x10000 * t + 1) for t in range(6))))
    out.append(mfgfield(6, u16(0x4321) + b'\x02' +
                        b''.join(u8(t) + u16(0x1000 + t) + u16(100) + u8(1) + u16(t) + u32(3)
                                 for t in range(3))))
    # peek/poke results: every read type, then a write type ends the list (warning)
    out.append(mfgfield(7, b'\x00' + u16(0x100) + b'\x11' +
                        b'\x01' + u16(0x102) + u16(0x2222) +
                        b'\x02' + u16(0x104) + u24(0x333333) +
                        b'\x03' + u16(0x108) + u32(0x44444444) +
                        b'\x04' + u16(0x110) + b'\x05hello'))
    out.append(mfgfield(7, b'\x05' + u16(0x200) + b'\x01'))
    out.append(mfgfield(8, u24(0x2aaaa5)))
    out.append(mfgfield(9, b''.join(bytes([4, c]) + u16(100 * (c + 1)) for c in range(9))))
    regs = bytes(range(18)) + b'\xa0\x50'
    out.append(mfgfield(10, regs))
    out.append(mfgfield(11, u32(0xdeadbeef) + u32(0x00001234)))
    out.append(mfgfield(12, b''.join(bytes([3, c, 0]) for c in range(8))))      # no errors
    out.append(mfgfield(12, bytes([3, 0, 0, 3, 5, 1, 0, 9, 9])))               # error, then a 0 length
    out.append(mfgfield(13, b'\x05\x03\x00' + b''.join(bytes([s, s ^ 1, s]) for s in range(14)) +
                        b'\x02\x01\xfe'))
    out.append(mfgfield(14, b'\x0a'))
    out.append(mfgfield(15, b'7'))
    out.append(mfgfield(16, b'%B1234567890^DOE/JOHN^?'))
    out.append(mfgfield(17, b'0123456789abcdef'))
    out.append(mfgfield(18, b'\x00'))               # unknown field (warning)
    out.append(mfgfield(0xff, b''))
    return out


def mfg(cap):
    """Every manufacturing command (port 8023) and the lock's upstream
    manufacturing fields."""
    s = TcpStream(cap, 40004, port=8023)
    n = [0]

    def send(c):
        n[0] += 1
        s.host(pdu(c, pktno=n[0]))
        s.lock(pdu(resp(0, 29), pktno=n[0]))

    send(mfgcmd(0, SERIAL))                         # SETSERIALNUMBER
    send(mfgcmd(0, SERIAL2))
    s.host(pdu(mfgcmd(1, bytes(range(16)))))        # SETCRYPTKEY (key runs to the end)
    send(mfgcmd(2, b'\x01'))                        # DUMPNVRAM
    for code in (3, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25,
                 26, 27, 28, 29, 31, 32, 33, 34):
        send(mfgcmd(code))
    send(mfgcmd(4, b'\x01'))                        # REMOTEUNLOCK
    send(mfgcmd(30, b'\x02'))                       # TESTPRESERVE
    # PEEKPOKE: every operation. The CRC and XOR octets are decoded as a
    # last entry too, so the CRC low octet must be a READU8..READU32.
    pp = (b'\x00' + u16(0x100) + b'\x01' + u16(0x102) + b'\x02' + u16(0x104) +
          b'\x03' + u16(0x108) + b'\x04' + u16(0x110) + b'\x08' +
          b'\x05' + u16(0x120) + b'\x55' + b'\x06' + u16(0x122) + u16(0x6666) +
          b'\x07' + u16(0x124) + u24(0x777777) + b'\x08' + u16(0x128) + u32(0x88888888) +
          b'\x09' + u16(0x130) + b'\x03abc')
    s.host(pdu_crc_low(mfgcmd(19, pp), (0, 1, 2, 3)))
    s.host(pdu_crc_low(mfgcmd(19, b'\x0a' + u16(0x140)), (0, 1, 2, 3)))   # unknown operation (warning)
    # FORCEOPTIONS: 8, 16, 24 and 32 bit states; the CRC low octet must be 0
    # (end of list) or 3 (an 8 bit state taken from the XOR octet)
    fo = (bytes([3, 0, 1]) + bytes([4, 1]) + u16(0x0202) + bytes([5, 2]) + u24(0x030303) +
          bytes([6, 3]) + u32(0x04040404) + bytes([3, 0x40, 1]))
    s.host(pdu_crc_low(mfgcmd(12, fo), (0,)))
    s.host(pdu_crc_low(mfgcmd(12, bytes([3, 5, 0])), (3,)))
    s.host(pdu(mfgcmd(35)))                         # unknown mfg command (warning)
    s.host(pdu(cmd(29) + cmd(0xfe)))
    # upstream manufacturing fields
    for i, f in enumerate(mfg_fields()):
        s.lock(pdu(hasdata(13, f), pktno=0x80 + i))
    s.close()


def odd_pdus(cap):
    """TCP reassembly, several PDUs in a segment, the ~~~ds string, the
    reproducers of the fixed offsets, unknown commands."""
    s = TcpStream(cap, 40005)
    # a PDU over three segments, the first one cut inside the 4 octet header
    big = pdu(cmd(13, b'\x07' + b''.join(u32(0x7fffffff >> m) for m in range(12))), pktno=1)
    s.host(*split(big, 2, 30))
    # three PDUs in one segment, the last one cut short and finished in the next
    a = pdu(cmd(1), pktno=2)
    b = pdu(cmd(4), pktno=3)
    c = pdu(cmd(5, bytes([24, 7, 19, 5, 13, 45, 30])), pktno=4)
    s.host(a + b + c[:6], c[6:])
    s.lock(pdu(resp(0, 1), pktno=2) + pdu(hasdata(2, field(9, b'R3 2.00')), pktno=3) +
           pdu(resp(0, 5), pktno=4))
    # the "~~~ds" string (length octet 'd': 101 octet PDU)
    s.lock(b'~~~ds' + b'\r\n' + b' ' * 94)
    # unknown command values (warning)
    s.host(pdu(cmd(32)))
    s.host(pdu(cmd(0xff, b'\x01')))
    # DOWNLOADFIRMWARETIMEOUT, an internal command (warning)
    s.host(pdu(cmd(22, b'\x01\x02')))
    # DOWNLOADFIRMWARE with an unknown action (warning)
    s.host(pdu(cmd(21, u16(7) + u16(9) + b'\x09' + u16(0))))
    # Reproducers of "ASSA R3: Fix the offsets of several fields and the CRC text"
    # M41T81 register 0x13: RS taken from the last register octet (0x50 -> RS 5)
    s.lock(pdu(hasdata(13, mfgfield(10, bytes(range(18)) + b'\xa0\x50')), pktno=0x41))
    # checkpoint log: entries start after the entry pointer
    s.lock(pdu(hasdata(13, mfgfield(3, b'\x07\xff\x01')), pktno=0x42))
    # bad XOR octet: the XOR item is on the last octet
    s.host(pdu(cmd(3), pktno=0x43, bad_xor=True))
    # bad CRC: "incorrect, should be <calculated>" after the packet's CRC
    s.host(pdu(cmd(3), pktno=0x44, bad_crc=True))
    # declined record field: credential types from octet 8 (0x1a: types 2 and 3)
    s.lock(pdu(hasdata(12, field(14, declined_record(0, 0x1a, prefix=False))), pktno=0x45))
    s.close()


# --------------------------------------------------------------------------
# Malformed capture: exceptions and error expert infos

def malformed(cap):
    s = TcpStream(cap, 41001)
    bad = []
    # upstream fields with the wrong length (error expert infos)
    bad.append(hasdata(12, b'\x01\x02'))                     # field length < 2
    bad.append(hasdata(12, field(10, b'\x00' * 8)))          # event log record
    bad.append(hasdata(12, field(11, b'\x00' * 7)))          # date/time
    bad.append(hasdata(12, field(14, b'\x00' * 48)))         # declined record
    bad.append(hasdata(12, field(21, b'\x00' * 2)))          # expire on
    bad.append(hasdata(12, field(23, b'\x00' * 3)))          # timezone
    bad.append(hasdata(12, field(28, b'\x00' * 8)))          # alarm record
    bad.append(hasdata(12, field(1, b'IT5')))                # serial number too short (exception)
    bad.append(hasdata(5, b'\x00' * 12))                     # event log dump, 12 octets
    bad.append(hasdata(9, b'\x00\x01'))                      # query config, item length 0
    bad.append(hasdata(13, mfgfield(0, b'\x00' * 4)))        # IO pins not modulo 3
    bad.append(hasdata(13, mfgfield(10, b'\x00' * 19)))      # M41T81 not 20 octets
    bad.append(hasdata(13, mfgfield(12, b'\x00' * 4)))       # checksum results not modulo 3
    bad.append(hasdata(13, mfgfield(9, b'\x04\x00\x01\x00\x00\x00')))   # capabilities, 0 length
    bad.append(hasdata(13, mfgfield(5, b'\x00\x01\x02')))    # task flags not modulo 5 (exception)
    bad.append(hasdata(13, mfgfield(3, b'\x07\x01')))        # checkpoint log, odd entry (exception)
    bad.append(hasdata(13, mfgfield(7, b'\x04' + u16(1) + b'\x20abc')))  # peek string past the end
    bad.append(hasdata(13, mfgfield(4, b'\x00' * 5)))        # CPU registers too short
    bad.append(hasdata(6, u16(1) + b'\x20\x00'))             # NVRAM dump past the end
    bad.append(b'\x10\x00\x02\x0c\x00')                      # response length past the PDU
    for i, b in enumerate(bad):
        s.lock(pdu(b, pktno=i))
    host_bad = [
        cmd(7, b'\x00\x05'),                                 # setconfig, item length 0
        cmd(9, b'\x01\x00'),                                 # manage user, length < 2
        cmd(9, field(0, b'\x01\x02') + field(1, b'\x01') + field(11, b'\x01') + field(10, b'\x01')),
        cmd(17, b'\x00\x01\x00'),                            # alarm, length 0
        cmd(5, b'\x18\x07'),                                 # set date/time too short
        cmd(13, b'\x01\x00'),                                # define calendar too short
        cmd(21, u16(9) + u16(1) + b'\x01' + u32(0) + b'\x40'),   # firmware data past the end
        cmd(16, b'\x09\x00\x01'),                            # filter list past the end
        mfgcmd(12, bytes([7, 1, 0, 0, 0, 0, 0])),            # force options, bad length
        mfgcmd(0, b'IT5'),                                   # serial number too short
        b'\x00\x01',                                         # command length 0
        cmd(29) + cmd(19, b'\x09' + u16(0) + b'\x40'),       # poke string past the end
    ]
    for i, c in enumerate(host_bad):
        s.host(pdu(c, pktno=0x40 + i))
    # length octet below 3: the command loop runs past the end
    s.host(b'\x01\x01\x01\x02\x00\x00')
    # commands longer than the PDU
    s.host(pdu(b'\x09\x01'))
    s.close()


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Pcap()
    host_commands(cap)
    responses(cap)
    upstream(cap)
    mfg(cap)
    odd_pdus(cap)
    cap.write(os.path.join(out, 'assa_r3-coverage.pcap'))
    bad = Pcap()
    malformed(bad)
    bad.write(os.path.join(out, 'assa_r3-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
