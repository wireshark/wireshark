#!/usr/bin/env python3
# Generates test/captures/cola_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the SICK CoLa dissector
(packet-cola.c, CoLa A and CoLa B).

CoLa runs over TCP (port 2111/2112 on SICK laser scanners). CoLa B
(binary) frames are a 0x02020202 magic number, a 32 bit length (which
includes the 4 octet command), the command ("sRN ", "sWN ", "sMN ",
"sEN ", "sRA ", "sWA ", "sAN ", "sEA ", "sSN ", "sFA ", "sRI\\0",
"sRA\\0"), a name followed by a space and binary parameters, and an XOR
checksum. CoLa A (ASCII) frames are STX, the command, a name and space
separated hexadecimal parameters, and ETX. Both are found by heuristics
on TCP that are enabled by default. Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkcola.py <output directory>

Writes:
  cola-coverage.pcap            every command, every named read, write,
                                method, event and answer the dissector
                                decodes (binary and ASCII), binary and
                                ASCII scan data with every optional
                                block, output states, PDUs split over
                                segments and several in one segment, and
                                the reproducers of the fixed bugs
  cola-coverage-malformed.pcap  bad checksums, lengths below 4, missing
                                names, ASCII scan data cut short or with
                                bad numbers at every parameter, binary
                                answers cut short
"""

import os
import struct
import sys

# ------------------------------------------------------------ link layer


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def ether_ip(src, dst, proto, l4):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, 64, proto,
                     0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return b'\x02\x00' + ip4(dst) + b'\x02\x00' + ip4(src) + b'\x08\x00' + \
        ip + l4


class Tcp:
    """One TCP connection with a handshake and correct sequence numbers."""

    def __init__(self, frames, cli, srv, cport, sport, handshake=True):
        self.frames = frames
        self.ep = {0: (cli, cport), 1: (srv, sport)}
        self.seq = {0: 1000, 1: 5000}
        if handshake:
            self._seg(0, 0x02, b'')
            self.seq[0] += 1
            self._seg(1, 0x12, b'')
            self.seq[1] += 1
            self._seg(0, 0x10, b'')

    def _seg(self, d, flags, payload):
        (src, sp), (dst, dp) = self.ep[d], self.ep[1 - d]
        ack = self.seq[1 - d] if flags != 0x02 else 0
        opt = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        t = struct.pack('>HHIIBBHHH', sp, dp, self.seq[d], ack,
                        (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + \
            opt + payload
        ph = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
        self.frames.append(ether_ip(src, dst, 6, t))

    def send(self, d, payload):
        self._seg(d, 0x18, payload)
        self.seq[d] += len(payload)

    def close(self):
        self._seg(0, 0x11, b'')
        self.seq[0] += 1
        self._seg(1, 0x11, b'')
        self.seq[1] += 1
        self._seg(0, 0x10, b'')


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 100,
                                (i % 100) * 10000, len(fr), len(fr)))
            f.write(fr)


# ------------------------------------------------------------------ CoLa

def cola_b(body, length=None, checksum=None):
    """body = 4 octet command + data; the length includes the command."""
    x = 0
    for b in body:
        x ^= b
    if checksum is not None:
        x = checksum
    return struct.pack('>II', 0x02020202,
                       len(body) if length is None else length) + body + \
        bytes([x])


def cola_a(text):
    return b'\x02' + (text.encode() if isinstance(text, str) else text) + \
        b'\x03'


def u8(v):
    return struct.pack('>B', v)


def u16(v):
    return struct.pack('>H', v)


def u32(v):
    return struct.pack('>I', v & 0xffffffff)


def i32(v):
    return struct.pack('>i', v)


def f32(v):
    return struct.pack('>f', v)


def ts(year, mon, day, hour, minute, sec, usec):
    return struct.pack('>HBBBBBI', year, mon, day, hour, minute, sec, usec)


def scancfg():
    # scan frequency 25 Hz (2500), 1 scanner, 0.25 deg, -45 .. 225 deg
    return u32(2500) + u16(1) + u32(2500) + i32(-450000) + i32(2250000)


def outputrange():
    return u16(1) + u32(2500) + i32(-450000) + i32(2250000)


def binary_scan_data(full):
    d = u16(1)                                   # version
    d += u16(1) + u32(0x0089a27f) + u16(0)       # device number, serial, status
    d += u16(7) + u16(8) + u32(123456) + u32(123999) + u16(0x0003) + u16(0x0005)
    if full:
        # the layer angle is read as 4 hexadecimal characters: "0010" = 16;
        # the "10" are also the first octets of the scan frequency
        d += b'00'
        d += b'10' + b'\x00\x00' + u32(2500)     # scan freq, measurement freq
        d += u16(1) + u32(1000) + u16(20)        # encoder amount, pos, speed
        d += u16(2)                              # 16 bit channels
        for name, vals in ((b'DIST1', (100, 200, 300)), (b'DIST2', (101,))):
            d += name + f32(1.0) + f32(0.0) + i32(-450000) + u16(2500) + \
                u16(len(vals)) + b''.join(u16(v) for v in vals)
        d += u16(1)                              # 8 bit channels
        d += b'RSSI1' + f32(1.0) + f32(0.0) + i32(-450000) + u16(2500) + \
            u16(3) + bytes([10, 20, 30])
        d += u16(1) + f32(1.5) + f32(2.5) + f32(0.5) + f32(0.0) + f32(0.0) + \
            f32(90.0) + u8(1) + u8(1)            # position
        d += u16(1) + u16(5) + b'LMS1x'          # device name
        d += u16(1) + u16(7) + b'comment'        # comment
        d += u16(1) + ts(2024, 5, 6, 7, 8, 9, 250000)    # time
        d += u16(1) + b'INCR' + u32(1000) + u32(2000) + u32(450000)  # event
    else:
        d += u16(0)                              # layer angle (not hex)
        d += u32(1500) + u32(1500)
        d += u16(0)                              # no encoder
        d += u16(0) + u16(0)                     # no channels
        d += u16(0) + u16(0) + u16(0) + u16(0) + u16(0)
    return d


def output_state(time_present):
    d = u16(0) + u32(42)                         # status version, counter
    d += u8(1) + u32(5)                          # output 1
    d += u8(0) + u32(6)                          # ext output 1
    if time_present:
        d += u8(1) + ts(2024, 1, 2, 3, 4, 5, 6)
    else:
        # the flag is read as 16 bits but takes one octet
        d += u8(0) + u8(0)
    return d


def stlms():
    # status, temperature flag, time "12:34:56", date "01/02/2024", LEDs
    d = u16(7) + u8(0)
    d += u16(8) + u16(12) + b'\x00' + u16(34) + b'\x00' + u16(56)
    d += u16(10) + u16(1) + b'\x00' + u16(2) + b'\x00' + u32(2024)
    d += u16(1) + u16(0) + u16(1) + bytes(6)
    return d


ASCII_SCAN_FULL = [
    '1', '1', '89A27F', '0', '0',                # version, device, status
    '7', '8', '1E240', '1E45F', '0', '3', '0', '5',  # status info
    'FFF6',                                      # layer angle -10
    '9C4', '9C4',                                # frequencies
    '1', '3E8', '14',                            # encoder amount, pos, speed
    '1',                                         # 16 bit channels
    'DIST1', '3F800000', '00000000', 'FFF92230', '9C4', '3', '64', 'C8', '12C',
    '1',                                         # 8 bit channels
    'RSSI1', '3F800000', '00000000', 'FFF92230', '9C4', '2', 'A', '14',
    '0', '0', '0', '0', '0',                     # position .. event (unparsed)
]


def ascii_scan(tokens):
    return ' '.join(tokens)


# --------------------------------------------------------------- captures

CLI, DEV = '192.0.2.1', '192.0.2.2'


def main_frames():
    fr = []
    tb = Tcp(fr, CLI, DEV, 51000, 2111)          # CoLa B
    frames = {}

    def q(body):
        tb.send(0, cola_b(body))

    def a(body):
        tb.send(1, cola_b(body))

    # reads, the reproducer cola_small_fixes.py frame 1 (name without the
    # checksum), and an answer with a name only
    frames['b_first'] = len(fr) + 1
    q(b'sRN LMPscancfg')
    a(b'sRA LMPscancfg ' + scancfg())
    q(b'sRN LCMcfg')
    a(b'sRA LCMcfg ' + u8(2) + u16(10) + u16(20) + u16(30))
    q(b'sRN CMContLvlM')
    a(b'sRA CMContLvlM ' + u8(1))
    q(b'sRN LMPoutputRange')
    a(b'sRA LMPoutputRange ' + outputrange())
    q(b'sRN STlms')
    a(b'sRA STlms ' + stlms())
    # (TSCTCmaxoffset and TSCTCdelay add a float field with length 1,
    # packet-cola.c:1927 and 1935, an error; they are in the malformed
    # capture; here only the reads)
    q(b'sRN TSCTCmaxoffset')
    q(b'sRN TSCTCdelay')
    for name, data in (('DeviceTime', u8(9)), ('CLFogFilterEn', u8(1)),
                       ('LICSpTh', u8(5)), ('LICencsp', u32(1234)),
                       ('SYextmon', u8(1) + u32(5000)),
                       ('LIDoutputstate', output_state(True)),
                       ('UnknownVar', b'\x01\x02'), ('NoParams', None)):
        q(b'sRN ' + name.encode())
        a(b'sRA ' + name.encode() + (b' ' + data if data is not None else b''))
    q(b'sRN LMDscandata')
    frames['b_scan_full'] = len(fr) + 1
    a(b'sRA LMDscandata ' + binary_scan_data(True))
    q(b'sRN LMDscandata')
    a(b'sRA LMDscandata ' + binary_scan_data(False))

    # writes with every named binary parameter set, and their answer
    writes = [
        ('MMAlignmentMode', u8(1)), ('LMPautostartmeas', u8(1)),
        ('CLApplication', u16(1)),
        ('SetActiveApplications', u8(2) + b'FEVL' + u8(1) + b'RANG' + u8(0)),
        ('LCMcfg', u8(1) + u32(100) + u32(200) + u32(300)),
        ('LMDscandatacfg', u16(1) + u8(1) + u8(1) + u8(0) + u16(1) + u8(0) +
         u8(1) + u8(1) + u8(1) + u16(1)),
        ('LMPoutputRange', u16(1) + u32(2500) + i32(-450000) + i32(2250000)),
        ('TSCRole', u8(1)), ('TSCTCInterface', u8(0)),
        ('TSCTCSrvAddr', ip4('192.0.2.123')), ('TSCTCtimezone', u8(13)),
        ('TSCTCupdatetime', u32(3600)), ('LFPparticle', u8(1) + u16(500)),
        ('LFPmeanfilter', u8(1) + u16(5) + u8(0)), ('LFPnto1filter', u8(1)),
        ('FREchoFilter', u8(2)), ('MSsuppmode', u8(1)),
        ('CLFogFilterEn', u8(1)), ('MCSenseLevel', u8(3)),
        ('CLNFDigFilterEn', u8(1)), ('CLHWFilterSectEn', u32(0x1f)),
        ('LICsrc', u8(1)), ('LICencset', u8(2)), ('LICencres', u32(1000)),
        ('LICFixVel', u32(2000)), ('DO6Fnc', u8(3)), ('DO3Fnc', u8(7)),
        ('DO1Fnc', u8(4)), ('DO1Logic', u32(1)), ('DO2Fnc', u8(5)),
        ('DO2Logic', u32(0)), ('SYMode', u8(1)), ('SYPhase', u16(180)),
        ('DO3And4Fnc', u8(1)), ('DI3DebTim', u16(10)),
        ('UnknownWrite', u8(0x55)),
    ]
    frames['b_writes'] = len(fr) + 1
    for name, data in writes:
        q(b'sWN ' + name.encode() + b' ' + data)
        a(b'sWA ' + name.encode())

    # methods and their answers
    methods = [
        # the binary SetAccessMode request shows uninitialised stack memory
        # as the password (packet-cola.c:1153), so it is in the malformed
        # capture; here only the request without parameters
        ('SetAccessMode', None, u8(1)),
        ('mLMPsetscancfg', scancfg(), u8(0) + scancfg()),
        ('mCLsetscancfglist', u8(1), u8(0)),
        ('SetPassword', u8(3) + u32(0x12345678), u8(1)),
        ('CheckPassword', u8(3) + u32(0x12345678), u8(1)),
        ('mDOSetOutput', u8(1) + u8(1), u8(1)),
        ('LMCstandby', None, u8(0)), ('LMCstartmeas', None, u8(0)),
        ('LMCstopmeas', None, u8(0)), ('mEEwriteall', None, u8(1)),
        ('Run', None, u8(1)), ('UnknownMethod', u8(1), u8(2)),
    ]
    frames['b_methods'] = len(fr) + 1
    for name, data, ans in methods:
        q(b'sMN ' + name.encode() + (b' ' + data if data is not None else b''))
        a(b'sAN ' + name.encode() + b' ' + ans)
    a(b'sAN NoParams')
    # the reproducers of the date/time fixes: the set time with
    # 0xFFFFFFFF and 5000000 microseconds, and the answer status
    frames['b_settime'] = len(fr) + 1
    q(b'sMN LSPsetdatetime ' + ts(2024, 1, 2, 3, 4, 5, 0))
    q(b'sMN LSPsetdatetime ' + ts(2024, 1, 2, 3, 4, 5, 0xFFFFFFFF))
    q(b'sMN LSPsetdatetime ' + ts(2024, 1, 2, 3, 4, 5, 5000000))
    a(b'sAN LSPsetdatetime ' + u8(1))

    # events, event answers, notifications
    frames['b_events'] = len(fr) + 1
    q(b'sEN LMDscandata ' + u8(1))
    a(b'sEA LMDscandata ' + u8(1))
    a(b'sSN LMDscandata ' + binary_scan_data(True))
    q(b'sEN LIDoutputstate ' + u8(1))
    a(b'sEA LIDoutputstate ' + u8(1))
    a(b'sSN LIDoutputstate ' + output_state(False))
    q(b'sEN NoParams')
    a(b'sEA NoParams')
    a(b'sSN NoParams')
    a(b'sSN Unknown ' + u8(1))
    # errors and SOPAS specific commands
    frames['b_errors'] = len(fr) + 1
    a(b'sFA ' + u8(5))
    a(b'sFA\x00' + u8(6))
    q(b'sRI\x00' + b'\x01\x02\x03')
    a(b'sRA\x00' + b'\x04\x05\x06')
    # a write answer longer than 255 octets (reproducer cola_small_fixes.py
    # frame 2: the checksum was wrong before the fix)
    frames['b_long'] = len(fr) + 1
    a(b'sWA ' + bytes(0x41 + (i % 26) for i in range(300)))
    # three PDUs in one segment, and one PDU over three segments
    frames['b_multi'] = len(fr) + 1
    tb.send(0, cola_b(b'sRN DeviceTime') + cola_b(b'sRN TSCTCdelay') +
            cola_b(b'sRN LICSpTh'))
    m = cola_b(b'sRA LMDscandata ' + binary_scan_data(True))
    tb.send(1, m[:6])
    tb.send(1, m[6:50])
    tb.send(1, m[50:])
    # an unknown command (the one warning, "Unknown command")
    frames['b_unknown'] = len(fr) + 1
    q(b'sXX ' + b'abc')
    tb.close()

    # -- CoLa A (ASCII)
    ta = Tcp(fr, CLI, DEV, 51001, 2112)
    frames['a_first'] = len(fr) + 1

    def qa(text):
        ta.send(0, cola_a(text))

    def aa(text):
        ta.send(1, cola_a(text))

    qa('sRN LMPscancfg')
    aa('sRA LMPscancfg 9C4 1 9C4 FFF92230 225510')
    qa('sWN LMPautostartmeas 1')
    aa('sWA LMPautostartmeas')
    qa('sMN SetAccessMode 03 F4724744')
    aa('sAN SetAccessMode 1')
    qa('sMN SetAccessMode Q F4724744')
    aa('sAN SetAccessMode Q')
    qa('sMN LMCstartmeas')
    aa('sAN LMCstartmeas 0')
    aa('sAN LMCstartmeas Q')
    qa('sMN Run')
    aa('sAN Run 1')
    qa('sMN mLMPsetscancfg +2500 +1 +2500 -450000 +2250000')
    aa('sAN mLMPsetscancfg 0 9C4 1 9C4 FFF92230 225510')
    qa('sEN LMDscandata 1')
    aa('sEA LMDscandata 1')
    frames['a_scan'] = len(fr) + 1
    aa('sSN LMDscandata ' + ascii_scan(ASCII_SCAN_FULL))
    qa('sRN LMDscandata')
    aa('sRA LMDscandata ' + ascii_scan(ASCII_SCAN_FULL))
    # the reproducer cola_small_fixes.py frame 5 (no channels)
    frames['a_scan_repro'] = len(fr) + 1
    aa('sRA LMDscandata 1 1 89A27F 0 0 1 2 3 4 0 0 0 0 0 0 0 0 0 0 0 0')
    # ASCII output state and STlms are read as binary octets
    aa('sRA LIDoutputstate 0000000100000002000000030 ')
    aa('sRA STlms 00000000000000000000000000000000000000000000000000')
    aa('sSN LIDoutputstate 0000000100000002000000030 ')
    frames['a_errors'] = len(fr) + 1
    aa('sFA 5')
    aa('sFA Q')
    aa(b'sFA\x00' + b'6')
    qa('sRI 12 34')
    qa('sEN NoParams')
    aa('sRA NoParams')
    aa('sAN NoParams')
    aa('sEA NoParams')
    aa('sSN NoParams')
    # a segment that is neither CoLa A nor CoLa B
    ta.send(0, b'hello, world\r\n')
    ta.close()

    # -- reproducer cola_settime_assert.py (its own connection)
    tr = Tcp(fr, CLI, DEV, 51002, 2112, handshake=False)
    frames['repro_settime'] = len(fr) + 1
    tr.send(0, cola_b(b'sAN LSPsetdatetime ' + ts(2024, 1, 2, 3, 4, 5, 0)))
    return fr, frames


def malformed_frames():
    fr = []
    t = Tcp(fr, CLI, DEV, 52000, 2111)
    t.send(1, cola_b(b'sRA LMPscancfg ' + scancfg(), checksum=0))  # bad sum
    t.send(1, cola_b(b'sRA', length=3))                 # length below 4
    t.send(1, cola_b(b'sWN NoDelimiter'))               # write without name
    # binary TSCTCmaxoffset and TSCTCdelay answers: a float field added
    # with length 1 (packet-cola.c:1927 and 1935)
    t.send(1, cola_b(b'sRA TSCTCmaxoffset ' + u8(3)))
    t.send(1, cola_b(b'sRA TSCTCdelay ' + u8(4)))
    # binary SetAccessMode: the password is taken from uninitialised stack
    # memory (dword_to_hex() returns the end of the string), see README
    t.send(0, cola_b(b'sMN SetAccessMode ' + u8(3) + u32(0xf4724744)))
    # binary answers cut short
    for name, data in (('LMPscancfg', scancfg()), ('LCMcfg', u8(1)),
                       ('LMPoutputRange', outputrange()),
                       ('STlms', stlms()), ('LIDoutputstate', output_state(True)),
                       ('LMDscandata', binary_scan_data(True)),
                       ('SYextmon', u8(1))):
        t.send(1, cola_b(b'sRA ' + name.encode() + b' ' + data[:len(data) // 2]))
    # a length beyond the capture
    t.send(1, struct.pack('>II', 0x02020202, 0xfffffff0) + b'sRA x')
    t.close()
    ta = Tcp(fr, CLI, DEV, 52001, 2112)
    ta.send(0, cola_a('sWN NoDelimiter'))
    ta.send(0, cola_a('sMN SetAccessMode 03'))
    # ASCII scan data cut short after every parameter, and with a bad
    # number in every position
    for k in range(len(ASCII_SCAN_FULL) - 5):
        ta.send(1, cola_a('sRA LMDscandata ' + ascii_scan(ASCII_SCAN_FULL[:k])))
        bad = list(ASCII_SCAN_FULL)
        bad[k] = 'ZZ'
        ta.send(1, cola_a('sRA LMDscandata ' + ascii_scan(bad)))
    # STX without ETX (the heuristic rejects it)
    ta.send(1, b'\x02sRA LMPscancfg 9C4')
    ta.close()
    return fr


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    fr, frames = main_frames()
    write_pcap(os.path.join(outdir, 'cola-coverage.pcap'), fr)
    write_pcap(os.path.join(outdir, 'cola-coverage-malformed.pcap'),
               malformed_frames())
    for k, v in sorted(frames.items(), key=lambda x: x[1]):
        print(k, v)


if __name__ == '__main__':
    main()
