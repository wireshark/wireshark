#!/usr/bin/env python3
# Generates test/captures/cipmotion_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CIP Motion dissector
(epan/dissectors/packet-cipmotion.c).

CIP Motion is carried in CIP class 1 I/O over EtherNet/IP (UDP 2222).
ENIP recognizes an I/O connection as CIP Motion when the Forward Open
that set it up (explicit messaging, TCP 44818) has the Motion Device
Axis Object (class 0x42) in its connection path; the connection point
(2 or 3) selects the format revision and whether a run/idle header is
present. Explicit Get/Set_Attribute_List requests to class 0x42 use the
CIP Motion attribute table.

Every packet is built from scratch with struct; no captured traffic is
used. Addresses are from the documentation range 192.0.2.0/24 and the
MAC addresses are locally administered.

Usage: mkcipmotion.py <output directory>

Writes:
  cipmotion-coverage.pcap            Forward Opens for motion connections
                                     (connection points 2 and 3, with a
                                     configuration block), explicit
                                     attribute access to class 0x42, and
                                     controller-to-device and
                                     device-to-controller I/O with every
                                     header, block, data set bit and
                                     service, and the reproducers of the
                                     cyclic/event block size fix
  cipmotion-coverage-malformed.pcap  format revision mismatches and blocks
                                     or attribute lists longer than the
                                     packet
"""

import os
import struct
import sys

# ---------------------------------------------------------------- framing

CLI_MAC = bytes.fromhex('020000000a01')   # controller (originator)
SRV_MAC = bytes.fromhex('020000000a02')   # drive (target)
CLI_IP = (192, 0, 2, 10)
SRV_IP = (192, 0, 2, 20)
ENIP_PORT = 44818
IO_PORT = 2222


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(proto, payload, src, dst, ident=1):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident & 0xffff, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:] + payload


def eth(src_mac, dst_mac, payload):
    return dst_mac + src_mac + b'\x08\x00' + payload


class TcpStream:
    def __init__(self, cport, cseq=1000, sseq=5000):
        self.cport = cport
        self.seq = {True: cseq, False: sseq}

    def frame(self, from_client, payload, flags=0x18):
        if from_client:
            src, dst, sport, dport = CLI_IP, SRV_IP, self.cport, ENIP_PORT
            smac, dmac = CLI_MAC, SRV_MAC
        else:
            src, dst, sport, dport = SRV_IP, CLI_IP, ENIP_PORT, self.cport
            smac, dmac = SRV_MAC, CLI_MAC
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        self.seq[from_client] = seq + len(payload)
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
        pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        c = csum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        return eth(smac, dmac, ipv4(6, tcp + payload, src, dst, ident=seq))


def udp_frame(src, dst, sport, dport, payload, smac, dmac, ident=1):
    hdr = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, 8 + len(payload))
    c = csum(pseudo + hdr + payload) or 0xffff
    hdr = hdr[:6] + struct.pack('!H', c)
    return eth(smac, dmac, ipv4(17, hdr + payload, src, dst, ident))


SESSION = 0x12345678


def enip_srrd(cip, context):
    cpf = struct.pack('<IHH', 0, 0, 2)
    cpf += struct.pack('<HH', 0x0000, 0)
    cpf += struct.pack('<HH', 0x00B2, len(cip)) + cip
    return struct.pack('<HHIIQI', 0x006F, len(cpf), SESSION, 0, context, 0) + cpf


def enip_io(connid, seq32, data):
    cpf = struct.pack('<H', 2)
    cpf += struct.pack('<HHII', 0x8002, 8, connid, seq32)
    cpf += struct.pack('<HH', 0x00B1, len(data)) + data
    return cpf


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            sec = 1700000000 + i // 100
            usec = (i % 100) * 10000
            f.write(struct.pack('<IIII', sec, usec, len(fr), len(fr)) + fr)


# ---------------------------------------------------------------- CIP

def u8(v):
    return struct.pack('<B', v)


def u16(v):
    return struct.pack('<H', v)


def u32(v):
    return struct.pack('<I', v)


def u64(v):
    return struct.pack('<Q', v)


def i32(v):
    return struct.pack('<i', v)


def f32(v):
    return struct.pack('<f', v)


def f64(v):
    return struct.pack('<d', v)


def seg(ltype, value):
    if value < 0x100:
        return bytes([0x20 | ltype, value])
    return bytes([0x21 | ltype, 0]) + u16(value)


def cls(v):
    return seg(0x00, v)


def inst(v):
    return seg(0x04, v)


def cpt(v):
    return seg(0x0C, v)


def att(v):
    return seg(0x10, v)


def ekey(vendor=1, devtype=37, prod=34, compat=0x83, minor=5):
    return bytes([0x34, 4]) + u16(vendor) + u16(devtype) + u16(prod) + bytes([compat, minor])


def simple_data(data):
    assert len(data) % 2 == 0
    return bytes([0x80, len(data) // 2]) + data


def req(service, path, data=b''):
    return bytes([service, len(path) // 2]) + path + data


def rsp(service, data=b'', status=0):
    return bytes([service | 0x80, 0, status, 0]) + data


def fwd_open(o2t, t2o, serial, conn_path, rpi=1000, vendor=0x1234, orig_serial=0x89ABCDEF):
    d = bytes([0x0A, 0x0E]) + u32(o2t) + u32(t2o) + u16(serial) + u16(vendor) + u32(orig_serial)
    d += bytes([1, 0, 0, 0])
    d += u32(rpi) + u16(0x4864) + u32(rpi) + u16(0x4864)
    d += bytes([0x01, len(conn_path) // 2]) + conn_path
    return req(0x54, cls(6) + inst(1), d)


def fwd_open_rsp(o2t, t2o, serial, vendor=0x1234, orig_serial=0x89ABCDEF, api=1000):
    d = u32(o2t) + u32(t2o) + u16(serial) + u16(vendor) + u32(orig_serial) + u32(api) + u32(api)
    d += bytes([0, 0])
    return rsp(0x54, d)


def fwd_close(serial, conn_path, vendor=0x1234, orig_serial=0x89ABCDEF):
    d = bytes([0x0A, 0x0E]) + u16(serial) + u16(vendor) + u32(orig_serial)
    d += bytes([len(conn_path) // 2, 0]) + conn_path
    return req(0x4E, cls(6) + inst(1), d)


def fwd_close_rsp(serial, vendor=0x1234, orig_serial=0x89ABCDEF):
    return rsp(0x4E, u16(serial) + u16(vendor) + u32(orig_serial) + bytes([0, 0]))


# ---------------------------------------------------------------- CIP Motion

FMT_FIXED_C2D, FMT_FIXED_D2C, FMT_C2D, FMT_D2C = 2, 3, 6, 7

# Motion attributes: id -> (class attribute, encoded value)
CLASS_ATTRS = {
    14: u8(0x0F),            # Node Control: every bit
    15: u8(0x0F),            # Node Status: every bit
    21: u8(20),              # Controller Update Delay High Limit
    22: u8(10),              # Controller Update Delay Low Limit
    29: u32(1000),           # Sync Threshold
    31: u8(0x0F),            # Time Data Set: every bit
    34: u32(0x00001234),     # Drive Power Structure Class ID
    35: u32(2000),           # Step Threshold
    36: u8(0x07),            # Connection Configuration Bits: every bit
}
INST_ATTRS = {
    40: u8(1),               # Control Mode
    41: u8(2),               # Control Method
    42: u8(0x14),            # Feedback Mode: dual feedback, LINT
    44: f32(2.0),            # Feedback Unit Ratio
    60: u32(0x7000FFFF),     # Event Checking Control: every bit, 7 acks
    61: u32(0xF000FFFF),     # Event Checking Status: every bit, extended
    89: u8(0x0F),            # Control Status
    90: u8(0xC7),            # Actual Data Set
    91: u8(0xCF),            # Command Data Set
    92: u8(0x06),            # Command Control: interpolate, DINT
    94: u8(0x1F),            # Status Data Set
    431: i32(-1000),         # Position Trim
    451: f32(1.5),           # Velocity Trim
    470: f32(10.0),          # Velocity Threshold
    471: f32(0.5),           # Velocity Lock Tolerance
    472: f32(0.25),          # Velocity Standstill Window
    481: f32(3.0),           # Acceleration Trim
    491: f32(4.0),           # Torque Trim
    590: u8(1),              # Proving Configuration
    591: f32(5.0),           # Torque Prove Current
    592: f32(6.0),           # Brake Test Torque
    608: f32(7.0),           # Zero Speed
    609: f32(8.0),           # Zero Speed Time
    620: f32(600.0),         # DC Bus Voltage
    624: u8(2),              # Bus Regulator Action
    636: f32(9.0),           # Inverter Capacity
    651: u32(0x01FFFFFF),    # Axis Status: every bit
    701: f32(110.0),         # Converter Thermal Overload User Limit
    705: f32(320.0),         # Bus Undervoltage User Limit
    740: u32(0x00FFFFFF),    # Axis Status 2: every bit
    1329: u16(8),            # Rotary Motor Poles
    1330: f32(0.001),        # Rotary Motor Inertia
    1332: f32(3000.0),       # Rotary Motor Max Speed
}


def pad4(b):
    return b + b'\0' * (-len(b) % 4)


def c2d_header(update_id, inst_count, time_set=0, rev=2, node_ctrl=0x07, last_update=0,
               ts=0, toff=0):
    h = bytes([FMT_C2D, rev, update_id, node_ctrl, inst_count, 0, last_update, time_set])
    if time_set & 1:
        h += u64(ts)
    if time_set & 2:
        h += u64(toff)
    return h


def d2c_header(update_id, inst_count, time_set=0, rev=2, node_sts=0x0F, fltalarms=0,
               last_update=0, ts=0, toff=0, lost=0, late=0, rx=0, tx=0):
    h = bytes([FMT_D2C, rev, update_id, node_sts, inst_count, fltalarms, last_update, time_set])
    if time_set & 1:
        h += u64(ts)
    if time_set & 2:
        h += u64(toff)
    if time_set & 4:
        h += bytes([lost, late, 0, 0])
    if time_set & 8:
        h += u64(rx) + u64(tx)
    return h


def instance(number, cyclic=b'', rw=b'', event=b'', service=b''):
    """Instance data header and its blocks. Every block must already be
    a multiple of four octets: the header gives the sizes in words."""
    for b in (cyclic, rw, event, service):
        assert len(b) % 4 == 0, (number, len(b))
    total = 8 + len(cyclic) + len(rw) + len(event) + len(service)
    hdr = bytes([number, 0, total // 4, (len(cyclic) + len(rw)) // 4,
                 len(cyclic) // 4, len(rw) // 4, len(event) // 4, len(service) // 4])
    return hdr + cyclic + rw + event + service


def cmd_block(cmd_set, lreal=True, intrp=2, act_set=0x07, sts_set=0x1F, mode=1, fb=0x02,
              axis_ctrl=1, ctrl_sts=0x0F, data=None, size=None):
    """Cyclic Command Data Block: header and the command values the bits
    select, unless data is given. size pads or truncates the block."""
    cc = intrp | (0x00 if lreal else 0x04)
    b = bytes([mode, fb, axis_ctrl, ctrl_sts, cmd_set, act_set, sts_set, cc])
    if data is None:
        data = b''
        if cmd_set & 0x01:
            data += f64(1234.0) if lreal else i32(123456)
        if cmd_set & 0x02:
            data += f32(100.0)
        if cmd_set & 0x04:
            data += f32(-50.0)
        if cmd_set & 0x08:
            data += f32(12.0)
    b += data
    if size is not None:
        b = (b + b'\0' * size)[:size]
    return b


def status_values(sts_set):
    d = b''
    if sts_set & 0x01:
        d += bytes([1, 0x21, 3, 2]) + u64(1111111111)
    if sts_set & 0x02:
        d += bytes([2, 0x22, 4, 1]) + u64(2222222222)
    if sts_set & 0x04:
        d += u32(0x01FFFFFF) + u32(0xA5A5A5A5)
    if sts_set & 0x08:
        d += u32(0x0000000F) + u32(0x5A5A5A5A)
    if sts_set & 0x10:
        d += u32(0x00000003) + u32(0x12345678) + bytes([4, 0, 0, 0])
    return d


def act_block(act_set, sts_set=0, pos64=False, mode=1, fb_mode=2, axis_resp=1, resp_stat=0,
              axis_state=4, data=None, size=None):
    """Cyclic Actual Data Block."""
    fb = fb_mode | (0x10 if pos64 else 0x00)
    b = bytes([mode, fb, axis_resp, resp_stat, 0, act_set, sts_set, axis_state])
    if data is None:
        data = b''
        if act_set & 0x01:
            data += u64(0x0000000100000002) if pos64 else i32(-123456)
        if act_set & 0x02:
            data += f32(99.0)
        if act_set & 0x04:
            data += f32(-2.0)
        data += status_values(sts_set)
    b += data
    if size is not None:
        b = (b + b'\0' * size)[:size]
    return b


def write_block(wblk, rblk, data=b''):
    return pad4(bytes([wblk, 0, rblk, 0]) + data)


def read_block(wblk, wsts, rblk, rsts, data=b''):
    return pad4(bytes([wblk, wsts, rblk, rsts]) + data)


def cntr_event(acks, bits=0xFFFF, extended=False, count=None, size=None):
    """Controller event block: checking control and acks (id, status)."""
    n = len(acks) if count is None else count
    ctrl = bits | (n & 7) << 28 | (0x80000000 if extended else 0)
    b = u32(ctrl) + b''.join(bytes([i, s]) for i, s in acks)
    b = pad4(b)
    if size is not None:
        b = (b + b'\0' * size)[:size]
    return b


def devce_event(nots, bits=0xFFFF, extended=False, count=None, size=None):
    """Device event block: checking status and notifications (id, status,
    type, reserved, position, time stamp)."""
    n = len(nots) if count is None else count
    sts = bits | (n & 7) << 28 | (0x80000000 if extended else 0)
    b = u32(sts)
    for eid, est, etype, pos, ts in nots:
        b += bytes([eid, est, etype, 0]) + i32(pos) + u64(ts)
    if size is not None:
        b = (b + b'\0' * size)[:size]
    return b


def cntr_svc(tid, code, data=b''):
    return pad4(bytes([tid, code, 0, 0]) + data)


def devce_svc(tid, code, data=b'', status=0, ext=0):
    return pad4(bytes([tid, code, status, ext]) + data)


def axis_entry(attr_id, value=b'', dim=0, elem=None, start=0, count=None, err=None):
    """Attribute entry of Get/Set Axis Attribute List (response/request):
    id, dimension, element size, [start index, data elements], data."""
    if err is not None:
        return u16(attr_id) + bytes([0xFF, err])
    if elem is None:
        elem = len(value) if dim == 0 else len(value) // (count or 1)
    e = u16(attr_id) + bytes([dim, elem])
    if dim == 1:
        e += u16(start) + u16(count)
    return e + pad4(value)


def get_req_entry(attr_id, dim=0, elem=4, start=0, count=1):
    e = u16(attr_id) + bytes([dim, elem])
    if dim == 1:
        e += u16(start) + u16(count)
    return e


def axis_list(entries):
    return u16(len(entries)) + u16(0) + b''.join(entries)


# ---------------------------------------------------------------- capture

class Capture:
    def __init__(self):
        self.frames = []
        self.labels = []
        self.ctx = 0x100
        self.stream = TcpStream(50000, 1000, 5000)
        self.seq = {}

    def add(self, frame, label):
        self.frames.append(frame)
        self.labels.append(label)

    def pair(self, request, response, label):
        self.ctx += 1
        self.add(self.stream.frame(True, enip_srrd(request, self.ctx)), label + ' (request)')
        if response is not None:
            self.add(self.stream.frame(False, enip_srrd(response, self.ctx)), label + ' (response)')

    def io(self, from_client, connid, payload, label, prefix=b''):
        """Class 1 I/O: CIP sequence count, [run/idle], CIP Motion data."""
        n = self.seq.get(connid, 0) + 1
        self.seq[connid] = n
        data = u16(n) + prefix + payload
        if from_client:
            s, d, sm, dm = CLI_IP, SRV_IP, CLI_MAC, SRV_MAC
        else:
            s, d, sm, dm = SRV_IP, CLI_IP, SRV_MAC, CLI_MAC
        self.add(udp_frame(s, d, IO_PORT, IO_PORT, enip_io(connid, n, data), sm, dm,
                           ident=len(self.frames)), label)


# Connections
CP2_OT, CP2_TO, CP2_SERIAL = 0x80000601, 0x00010601, 0x0601   # connection point 2
CP3_OT, CP3_TO, CP3_SERIAL = 0x80000602, 0x00010602, 0x0602   # connection point 3
NOCP_OT, NOCP_TO, NOCP_SERIAL = 0x80000603, 0x00010603, 0x0603  # no connection point
UNKNOWN_OT = 0x80000699                                        # no Forward Open (Decode As)

CONFIG_BLOCK = bytes([1, 0x07, 0, 0]) + u32(0x00001234)
CP2_PATH = ekey() + cls(0x42) + inst(1) + cpt(2) + simple_data(CONFIG_BLOCK)
CP3_PATH = ekey() + cls(0x42) + inst(1) + cpt(3) + simple_data(CONFIG_BLOCK)
RUN_IDLE = u32(1)


def open_connections(c):
    c.pair(fwd_open(CP2_OT, CP2_TO, CP2_SERIAL, CP2_PATH), fwd_open_rsp(CP2_OT, CP2_TO, CP2_SERIAL),
           'Forward Open motion axis, connection point 2, configuration block')
    c.pair(fwd_open(CP3_OT, CP3_TO, CP3_SERIAL, CP3_PATH), fwd_open_rsp(CP3_OT, CP3_TO, CP3_SERIAL),
           'Forward Open motion axis, connection point 3, configuration block')


def c2d(c, payload, label):
    c.io(True, CP2_OT, payload, 'C2D ' + label)


def d2c(c, payload, label):
    c.io(False, CP2_TO, payload, 'D2C ' + label)


def build_main():
    c = Capture()
    open_connections(c)

    # ------------------------------------------------ explicit messaging
    class_ids = sorted(CLASS_ATTRS)
    inst_ids = sorted(INST_ATTRS)
    c.pair(req(0x03, cls(0x42) + inst(0), u16(len(class_ids)) + b''.join(u16(a) for a in class_ids)),
           rsp(0x03, u16(len(class_ids)) + b''.join(u16(a) + u16(0) + CLASS_ATTRS[a] for a in class_ids)),
           'Get_Attribute_List, motion class attributes')
    c.pair(req(0x03, cls(0x42) + inst(1), u16(len(inst_ids)) + b''.join(u16(a) for a in inst_ids)),
           rsp(0x03, u16(len(inst_ids)) + b''.join(u16(a) + u16(0) + INST_ATTRS[a] for a in inst_ids)),
           'Get_Attribute_List, motion instance attributes')
    sal = [431, 451, 651, 740, 92]
    c.pair(req(0x04, cls(0x42) + inst(1), u16(len(sal)) + b''.join(u16(a) + INST_ATTRS[a] for a in sal)),
           rsp(0x04, u16(len(sal)) + b''.join(u16(a) + u16(0) for a in sal)),
           'Set_Attribute_List, motion instance attributes')
    c.pair(req(0x0E, cls(0x42) + inst(1) + att(60)), rsp(0x0E, INST_ATTRS[60]),
           'Get_Attribute_Single, Event Checking Control')

    # ------------------------------------------------ connection headers
    # Controller-to-device, no time data, one instance, LREAL position
    c2d(c, c2d_header(1, 1) + instance(1, cmd_block(0x0F, lreal=True)),
        'LREAL position, velocity, acceleration, torque')
    d2c(c, d2c_header(1, 1) + instance(1, act_block(0x07, 0x1F)),
        '32 bit actual position, velocity, acceleration, every status data set')
    # Time stamp and time offset (controller), every time data set bit (device)
    c2d(c, c2d_header(2, 1, time_set=0x03, ts=1700000000123456789, toff=-5 & 0xFFFFFFFFFFFFFFFF,
                      node_ctrl=0x0F, last_update=1)
        + instance(1, cmd_block(0xCF, lreal=False, intrp=1)),
        'time stamp and offset, DINT position, unwind and displacement bits')
    d2c(c, d2c_header(2, 1, time_set=0x0F, ts=1700000000123456000, toff=42, lost=3, late=2,
                      rx=1700000000100000000, tx=1700000000110000000, node_sts=0x08, fltalarms=0x03,
                      last_update=2)
        + instance(1, act_block(0xC7, 0x1F, pos64=True)),
        'every time data set bit, 64 bit actual position')
    # Time stamp only / offset only / diagnostics only
    c2d(c, c2d_header(3, 1, time_set=0x01, ts=1) + instance(1, cmd_block(0x02)), 'time stamp only, velocity')
    c2d(c, c2d_header(4, 1, time_set=0x02, toff=2) + instance(1, cmd_block(0x04)), 'time offset only, acceleration')
    c2d(c, c2d_header(5, 1, node_ctrl=0) + instance(1, cmd_block(0x08, intrp=0)), 'torque only, immediate')
    d2c(c, d2c_header(3, 1, time_set=0x04, lost=1, late=1) + instance(1, act_block(0x02)), 'update diagnostics, velocity only')
    d2c(c, d2c_header(4, 1, time_set=0x08, rx=5, tx=6) + instance(1, act_block(0x04)), 'time diagnostics, acceleration only')
    d2c(c, d2c_header(5, 1, time_set=0x01, ts=7) + instance(1, act_block(0x00, 0x01)), 'time stamp, axis fault only')
    d2c(c, d2c_header(6, 1, time_set=0x02, toff=8) + instance(1, act_block(0x00, 0x02)), 'time offset, axis alarm only')
    d2c(c, d2c_header(7, 1) + instance(1, act_block(0x00, 0x04)), 'axis status only')
    d2c(c, d2c_header(8, 1) + instance(1, act_block(0x00, 0x08)), 'axis I/O status only')
    d2c(c, d2c_header(9, 1) + instance(1, act_block(0x00, 0x10)), 'axis safety only')
    d2c(c, d2c_header(10, 1) + instance(1, act_block(0x01, 0x00, pos64=True)), '64 bit position only')
    # No bits at all, and no blocks at all
    c2d(c, c2d_header(6, 1) + instance(1, cmd_block(0x00, act_set=0, sts_set=0)), 'no command data set bits')
    d2c(c, d2c_header(11, 1) + instance(1, act_block(0x00, 0x00)), 'no actual or status data set bits')
    c2d(c, c2d_header(7, 0), 'no instances')
    d2c(c, d2c_header(12, 0), 'no instances')
    c2d(c, c2d_header(8, 1) + instance(1), 'instance with no blocks')
    # Every axis control / response value
    for k, v in enumerate([0, 2, 3, 4, 5, 6, 7, 8, 9, 127]):
        c2d(c, c2d_header(20 + k, 1) + instance(1, cmd_block(0x01, mode=k % 5, axis_ctrl=v, ctrl_sts=k & 0x0F,
                                                          fb=(k % 5))),
            'axis control %d' % v)
        d2c(c, d2c_header(20 + k, 1) + instance(1, act_block(0x01, 0x04, mode=k % 5, fb_mode=k % 5,
                                                          axis_resp=v, resp_stat=k, axis_state=k)),
            'axis response %d' % v)

    # ------------------------------------------------ cyclic read/write blocks
    c2d(c, c2d_header(40, 1) + instance(1, cmd_block(0x03, lreal=False), write_block(1, 2)),
        'cyclic write block without data')
    c2d(c, c2d_header(41, 1) + instance(1, cmd_block(0x03, lreal=False), write_block(3, 4, bytes(range(12)))),
        'cyclic write block with data')
    d2c(c, d2c_header(40, 1) + instance(1, act_block(0x03), read_block(1, 0, 2, 0)),
        'cyclic read block without data')
    d2c(c, d2c_header(41, 1) + instance(1, act_block(0x03), read_block(3, 1, 4, 2, bytes(range(16)))),
        'cyclic read block with data')
    # Read/write block without a cyclic block
    c2d(c, c2d_header(42, 1) + instance(2, rw=write_block(5, 6, b'\xAA' * 4)), 'only a cyclic write block')
    d2c(c, d2c_header(42, 1) + instance(2, rw=read_block(5, 0, 6, 0, b'\xBB' * 4)), 'only a cyclic read block')

    # ------------------------------------------------ event blocks
    for n in range(8):
        c2d(c, c2d_header(50 + n, 1) + instance(1, cmd_block(0x01), event=cntr_event(
            [(k + 1, k % 3) for k in range(n)], bits=(0xFFFF if n % 2 else 0x5555 << (n % 2)))),
            'event block with %d acknowledgements' % n)
    for n in range(8):
        nots = [(k + 1, k % 2, k % 12, -1000 * k, 1700000000000000000 + k) for k in range(n)]
        d2c(c, d2c_header(50 + n, 1) + instance(1, act_block(0x01), event=devce_event(
            nots, bits=(0xFFFF if n % 2 else 0xAAAA))),
            'event block with %d notifications' % n)
    # Every event type
    nots = [(k, 0, k, k, k) for k in range(12)]
    d2c(c, d2c_header(58, 2) + instance(1, event=devce_event(nots[:7])) + instance(2, event=devce_event(nots[7:])),
        'event types 0-11 in two instances')

    # ------------------------------------------------ service blocks
    # Get Axis Attribute List: class attributes (instance 0) and instance
    # attributes, scalar and array requests, an unknown attribute
    c2d(c, c2d_header(60, 1) + instance(0, service=cntr_svc(1, 0x4B, axis_list(
        [get_req_entry(a, elem=len(CLASS_ATTRS[a])) for a in class_ids]))),
        'Get Axis Attribute List request, class attributes')
    d2c(c, d2c_header(60, 1) + instance(0, service=devce_svc(1, 0x4B, axis_list(
        [axis_entry(a, CLASS_ATTRS[a]) for a in class_ids]))),
        'Get Axis Attribute List response, class attributes')
    c2d(c, c2d_header(61, 1) + instance(1, service=cntr_svc(2, 0x4B, axis_list(
        [get_req_entry(a, elem=len(INST_ATTRS[a])) for a in inst_ids]
        + [get_req_entry(431, dim=1, elem=4, start=2, count=3), get_req_entry(9999)]))),
        'Get Axis Attribute List request, instance attributes, array, unknown')
    d2c(c, d2c_header(61, 1) + instance(1, service=devce_svc(2, 0x4B, axis_list(
        [axis_entry(a, INST_ATTRS[a]) for a in inst_ids]
        + [axis_entry(431, i32(1) + i32(2) + i32(3), dim=1, elem=4, start=2, count=3),
           axis_entry(9999, b'\x01\x02\x03'), axis_entry(1329, u16(8) + b'\xEE\xEE'),
           axis_entry(9998, err=0x14), axis_entry(431, dim=2, value=b'\x00' * 8, elem=8)]))),
        'Get Axis Attribute List response, instance attributes, array, unknown, error, dimension 2')
    # Set Axis Attribute List
    c2d(c, c2d_header(62, 1) + instance(1, service=cntr_svc(3, 0x4C, axis_list(
        [axis_entry(a, INST_ATTRS[a]) for a in inst_ids]
        + [axis_entry(431, i32(4) + i32(5), dim=1, elem=4, start=0, count=2),
           axis_entry(9999, b'\x01\x02\x03\x04\x05'), axis_entry(624, u8(1) + b'\xEE\xEE\xEE')]))),
        'Set Axis Attribute List request, instance attributes, array, unknown, longer than the attribute')
    d2c(c, d2c_header(62, 1) + instance(1, service=devce_svc(3, 0x4C, axis_list(
        [u16(a) + bytes([0, 0]) for a in inst_ids] + [u16(9999) + bytes([0x14, 0])]))),
        'Set Axis Attribute List response')
    c2d(c, c2d_header(63, 1) + instance(0, service=cntr_svc(4, 0x4C, axis_list(
        [axis_entry(a, CLASS_ATTRS[a]) for a in class_ids]))),
        'Set Axis Attribute List request, class attributes')
    d2c(c, d2c_header(63, 1) + instance(0, service=devce_svc(4, 0x4C, axis_list(
        [u16(a) + bytes([0, 0]) for a in class_ids]))),
        'Set Axis Attribute List response, class attributes')
    # Group Sync
    c2d(c, c2d_header(64, 1) + instance(1, service=cntr_svc(5, 0x1C, u64(0x0011223344556677))),
        'Group Sync request')
    for k, st in enumerate([0, 1, 2, 3, 9]):
        d2c(c, d2c_header(64 + k, 1) + instance(1, service=devce_svc(5, 0x1C, bytes([st, 0, 0, 0]))),
            'Group Sync response, status %d' % st)
    # Set Cyclic Write / Read List
    cyc = [430, 431, 451, 9999]
    c2d(c, c2d_header(65, 1) + instance(1, service=cntr_svc(6, 0x4D, u16(len(cyc)) + u16(0)
                                                            + b''.join(u16(a) for a in cyc))),
        'Set Cyclic Write List request')
    d2c(c, d2c_header(70, 1) + instance(1, service=devce_svc(6, 0x4D, u16(len(cyc)) + u16(7)
                                                             + b''.join(u16(a) + bytes([k, 0]) for k, a in enumerate(cyc)))),
        'Set Cyclic Write List response')
    c2d(c, c2d_header(66, 1) + instance(1, service=cntr_svc(7, 0x4E, u16(len(cyc)) + u16(0)
                                                            + b''.join(u16(a) for a in cyc))),
        'Set Cyclic Read List request')
    d2c(c, d2c_header(71, 1) + instance(1, service=devce_svc(7, 0x4E, u16(len(cyc)) + u16(8)
                                                             + b''.join(u16(a) + bytes([0, 0]) for a in cyc))),
        'Set Cyclic Read List response')
    # Set_Attribute_List (generic CIP service with the motion table)
    sal_req = u16(len(sal)) + b''.join(u16(a) + INST_ATTRS[a] for a in sal)
    c2d(c, c2d_header(67, 1) + instance(1, service=cntr_svc(8, 0x04, sal_req)),
        'Set_Attribute_List request')
    d2c(c, d2c_header(72, 1) + instance(1, service=devce_svc(8, 0x04, u16(len(sal)) + b''.join(u16(a) + u16(0) for a in sal))),
        'Set_Attribute_List response')
    c2d(c, c2d_header(68, 1) + instance(1, service=cntr_svc(9, 0x04, u16(2) + u16(431) + i32(7) + u16(9999) + b'\x01\x02\x03\x04')),
        'Set_Attribute_List request with an unknown attribute (rest shown as data)')
    c2d(c, c2d_header(69, 2) + instance(1, service=cntr_svc(10, 0x04, u16(1) + u16(40) + u8(1))) + instance(2, cmd_block(0x01)),
        'Set_Attribute_List request followed by another instance')
    # Every other service code (generic data), with and without data
    for k, code in enumerate([0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x0E, 0x77]):
        c2d(c, c2d_header(80 + k, 1) + instance(1, service=cntr_svc(11 + k, code, bytes([k] * 4))),
            'service 0x%02X request with data' % code)
        d2c(c, d2c_header(80 + k, 1) + instance(1, service=devce_svc(11 + k, code, bytes([k] * 8), status=k, ext=k)),
            'service 0x%02X response with data' % code)
    for code in (0x4B, 0x4C, 0x1C, 0x4D, 0x4E, 0x04):
        c2d(c, c2d_header(90, 1) + instance(1, service=cntr_svc(30, code)), 'service 0x%02X request without data' % code)
        d2c(c, d2c_header(90, 1) + instance(1, service=devce_svc(30, code, status=0x08)),
            'service 0x%02X error response without data' % code)

    # ------------------------------------------------ everything together
    c2d(c, c2d_header(100, 3, time_set=0x03, ts=11, toff=12)
        + instance(1, cmd_block(0x0F, lreal=True), write_block(1, 1, b'\x01' * 8),
                   cntr_event([(1, 0), (2, 1), (3, 2)]),
                   cntr_svc(40, 0x4B, axis_list([get_req_entry(651), get_req_entry(740)])))
        + instance(2, cmd_block(0x0F, lreal=False), write_block(2, 2), cntr_event([]),
                   cntr_svc(41, 0x1C, u64(1)))
        + instance(3, cmd_block(0x03, lreal=False), b'', cntr_event([(9, 0)]),
                   cntr_svc(42, 0x4C, axis_list([axis_entry(451, f32(2.5))]))),
        'three instances with every block type')
    d2c(c, d2c_header(100, 3, time_set=0x0F)
        + instance(1, act_block(0x07, 0x1F), read_block(1, 0, 1, 0, b'\x02' * 8),
                   devce_event([(1, 0, 4, 100, 200)]),
                   devce_svc(40, 0x4B, axis_list([axis_entry(651, INST_ATTRS[651]), axis_entry(740, INST_ATTRS[740])])))
        + instance(2, act_block(0x07, 0x1F, pos64=True), read_block(2, 0, 2, 0), devce_event([]),
                   devce_svc(41, 0x1C, bytes([0, 0, 0, 0])))
        + instance(3, act_block(0x03, 0x05), b'', devce_event([(2, 1, 5, -1, 3)]),
                   devce_svc(42, 0x4C, axis_list([u16(451) + bytes([0, 0])]))),
        'three instances with every block type')
    # Data after the last instance
    c2d(c, c2d_header(101, 1) + instance(1, cmd_block(0x01)) + b'\xDE\xAD\xBE\xEF', 'data after the last instance')
    d2c(c, d2c_header(101, 1) + instance(1, act_block(0x01)) + b'\xDE\xAD\xBE\xEF', 'data after the last instance')

    # ------------------------------------------------ other connection formats
    c2d(c, bytes([FMT_FIXED_C2D, 2, 1, 0]) + b'\x11' * 16, 'fixed controller-to-device format (not dissected)')
    d2c(c, bytes([FMT_FIXED_D2C, 2, 1, 0]) + b'\x22' * 16, 'fixed device-to-controller format (not dissected)')
    c2d(c, bytes([0x09, 2, 1, 0]) + b'\x33' * 8, 'unknown connection format')

    # ------------------------------------------------ connection point 3: run/idle header
    c.io(True, CP3_OT, c2d_header(1, 1, rev=3) + instance(1, cmd_block(0x0F), write_block(1, 1),
                                                         cntr_event([(1, 0)]), cntr_svc(1, 0x1C, u64(5))),
         'C2D connection point 3 (run/idle header, format revision 3)', prefix=RUN_IDLE)
    c.io(False, CP3_TO, d2c_header(1, 1, rev=3, time_set=0x0F) + instance(1, act_block(0x07, 0x1F), read_block(1, 0, 1, 0),
                                                                          devce_event([(1, 0, 0, 1, 2)]), devce_svc(1, 0x1C, u32(0))),
         'D2C connection point 3 (run/idle header, format revision 3)', prefix=RUN_IDLE)
    c.io(True, CP3_OT, c2d_header(2, 1, rev=3) + instance(1, cmd_block(0x01)),
         'C2D connection point 3, idle', prefix=u32(0))

    # ------------------------------------------------ reproducers: block sizes and data set bits
    # "CIP Motion: Do not read past a cyclic or event block". Each
    # cyclic block is followed by a cyclic write/read block, which must
    # start right after the declared block size.
    R = 'reproducer: '
    # Command data set bits that need more than the block holds
    c2d(c, c2d_header(110, 1) + instance(1, cmd_block(0x01, lreal=True, size=12), write_block(0x71, 0x72)),
        R + 'LREAL position does not fit in a 12 octet command block')
    c2d(c, c2d_header(111, 1) + instance(1, cmd_block(0x01, lreal=False, size=8), write_block(0x71, 0x72)),
        R + 'command block of 8 octets with position bit set (no room)')
    c2d(c, c2d_header(112, 1) + instance(1, cmd_block(0x03, lreal=False, size=12), write_block(0x71, 0x72)),
        R + 'velocity does not fit in the command block')
    c2d(c, c2d_header(113, 1) + instance(1, cmd_block(0x07, lreal=False, size=16), write_block(0x71, 0x72)),
        R + 'acceleration does not fit in the command block')
    c2d(c, c2d_header(114, 1) + instance(1, cmd_block(0x0F, lreal=True, size=28 - 4), write_block(0x71, 0x72)),
        R + 'torque does not fit in the command block')
    # Block larger than its bits: padding after the values
    c2d(c, c2d_header(115, 1) + instance(1, cmd_block(0x02, size=32), write_block(0x71, 0x72, b'\x5A' * 4)),
        R + 'command block larger than its data set bits (padding)')
    d2c(c, d2c_header(115, 1) + instance(1, act_block(0x02, 0x04, size=40), read_block(0x71, 0, 0x72, 0, b'\x5A' * 4)),
        R + 'actual block larger than its data set bits (padding)')
    # Cyclic block smaller than its 8 octet header
    c2d(c, c2d_header(116, 1) + instance(1, b'\x01\x02\x03\x04', write_block(0x71, 0x72)),
        R + 'command block of 4 octets')
    d2c(c, d2c_header(116, 1) + instance(1, b'\x01\x02\x03\x04', read_block(0x71, 0, 0x72, 0)),
        R + 'actual block of 4 octets')
    # Actual and status data set bits that need more than the block holds
    d2c(c, d2c_header(117, 1) + instance(1, act_block(0x01, 0x1F, size=8), read_block(0x71, 0, 0x72, 0)),
        R + 'actual block of 8 octets with position and status bits set (no room)')
    d2c(c, d2c_header(118, 1) + instance(1, act_block(0x01, 0x1F, pos64=True, size=12), read_block(0x71, 0, 0x72, 0)),
        R + '64 bit position does not fit in the actual block (status skipped)')
    d2c(c, d2c_header(119, 1) + instance(1, act_block(0x03, 0x1F, size=12), read_block(0x71, 0, 0x72, 0)),
        R + 'actual velocity does not fit')
    d2c(c, d2c_header(120, 1) + instance(1, act_block(0x07, 0x1F, size=16), read_block(0x71, 0, 0x72, 0)),
        R + 'actual acceleration does not fit')
    d2c(c, d2c_header(121, 1) + instance(1, act_block(0x00, 0x01, size=8), read_block(0x71, 0, 0x72, 0)),
        R + 'status block of 8 octets with the fault bit set (no room)')
    d2c(c, d2c_header(122, 1) + instance(1, act_block(0x00, 0x01, size=16), read_block(0x71, 0, 0x72, 0)),
        R + 'axis fault does not fit')
    d2c(c, d2c_header(123, 1) + instance(1, act_block(0x00, 0x03, size=28), read_block(0x71, 0, 0x72, 0)),
        R + 'axis alarm does not fit')
    d2c(c, d2c_header(124, 1) + instance(1, act_block(0x00, 0x04, size=12), read_block(0x71, 0, 0x72, 0)),
        R + 'axis status does not fit')
    d2c(c, d2c_header(125, 1) + instance(1, act_block(0x00, 0x08, size=12), read_block(0x71, 0, 0x72, 0)),
        R + 'axis I/O status does not fit')
    d2c(c, d2c_header(126, 1) + instance(1, act_block(0x00, 0x10, size=16), read_block(0x71, 0, 0x72, 0)),
        R + 'axis safety does not fit')
    # Event count with the extended format bit 31 set: 2 acks, not 10
    c2d(c, c2d_header(127, 1) + instance(1, event=cntr_event([(1, 0), (2, 0)], extended=True),
                                         service=cntr_svc(0x71, 0x1C, u64(0x7171))),
        R + 'event block with the extended format bit and 2 acknowledgements')
    d2c(c, d2c_header(127, 1) + instance(1, event=devce_event([(1, 0, 4, 1, 2)], extended=True),
                                         service=devce_svc(0x71, 0x1C, u32(0))),
        R + 'event block with the extended format bit and 1 notification')
    # More acknowledgements / notifications than the block holds
    c2d(c, c2d_header(128, 1) + instance(1, event=cntr_event([(1, 0), (2, 0)], count=7),
                                         service=cntr_svc(0x72, 0x1C, u64(0x7272))),
        R + 'event block of 8 octets that announces 7 acknowledgements')
    d2c(c, d2c_header(128, 1) + instance(1, event=devce_event([(1, 0, 4, 1, 2)], count=3),
                                         service=devce_svc(0x72, 0x1C, u32(0))),
        R + 'event block of 20 octets that announces 3 notifications')

    # ------------------------------------------------ Decode As
    # I/O on a connection without a Forward Open: CIP I/O by default,
    # CIP Motion - Rev 3 with -d cip.io,cipm3
    c.io(True, UNKNOWN_OT, c2d_header(1, 1, rev=3) + instance(1, cmd_block(0x01)),
         'I/O without a Forward Open (Decode As cipm3)', prefix=RUN_IDLE)

    c.pair(fwd_close(CP2_SERIAL, cls(0x42) + inst(1) + cpt(2)), fwd_close_rsp(CP2_SERIAL),
           'Forward Close, connection point 2')
    c.pair(fwd_close(CP3_SERIAL, cls(0x42) + inst(1) + cpt(3)), fwd_close_rsp(CP3_SERIAL),
           'Forward Close, connection point 3')
    return c


def build_malformed():
    c = Capture()
    open_connections(c)
    c.pair(fwd_open(NOCP_OT, NOCP_TO, NOCP_SERIAL, ekey() + cls(0x42) + inst(1)),
           fwd_open_rsp(NOCP_OT, NOCP_TO, NOCP_SERIAL), 'Forward Open motion axis without a connection point')
    # Format revision does not match the connection point (warning)
    c2d(c, c2d_header(1, 1, rev=3) + instance(1, cmd_block(0x01)), 'format revision 3 on connection point 2')
    d2c(c, d2c_header(1, 1, rev=1) + instance(1, act_block(0x01)), 'format revision 1 on connection point 2')
    c.io(True, NOCP_OT, c2d_header(1, 1) + instance(1, cmd_block(0x01)),
         'C2D on a motion connection without a connection point', prefix=RUN_IDLE)
    # Truncated headers and blocks
    c2d(c, bytes([FMT_C2D, 2, 1]), 'connection header cut short')
    c2d(c, c2d_header(2, 1, time_set=0x03)[:12], 'time stamp cut short')
    d2c(c, d2c_header(2, 1, time_set=0x0F)[:30], 'time diagnostics cut short')
    c2d(c, c2d_header(3, 2) + instance(1, cmd_block(0x01)), 'two instances announced, one present')
    c2d(c, c2d_header(4, 1) + instance(1, cmd_block(0x0F))[:20], 'command block longer than the packet')
    d2c(c, d2c_header(3, 1) + instance(1, act_block(0x07, 0x1F))[:40], 'actual block longer than the packet')
    c2d(c, c2d_header(5, 1) + instance(1, rw=write_block(1, 1, b'\x01' * 8))[:14], 'write block longer than the packet')
    d2c(c, d2c_header(4, 1) + instance(1, rw=read_block(1, 0, 1, 0, b'\x01' * 8))[:14], 'read block longer than the packet')
    c2d(c, c2d_header(6, 1) + instance(1, event=cntr_event([(1, 0), (2, 0)]))[:12], 'event block longer than the packet')
    d2c(c, d2c_header(5, 1) + instance(1, event=devce_event([(1, 0, 4, 1, 2)]))[:20], 'event block longer than the packet')
    # Service blocks with counts larger than the data
    c2d(c, c2d_header(7, 1) + instance(1, service=cntr_svc(1, 0x4B, u16(50) + u16(0) + get_req_entry(40))),
        'Get Axis Attribute List request, count larger than the data')
    d2c(c, d2c_header(7, 1) + instance(1, service=devce_svc(1, 0x4B, u16(50) + u16(0) + axis_entry(40, u8(1)))),
        'Get Axis Attribute List response, count larger than the data')
    c2d(c, c2d_header(8, 1) + instance(1, service=cntr_svc(2, 0x4C, u16(50) + u16(0) + axis_entry(40, u8(1)))),
        'Set Axis Attribute List request, count larger than the data')
    d2c(c, d2c_header(8, 1) + instance(1, service=devce_svc(2, 0x4C, u16(50) + u16(0) + u16(40) + u16(0))),
        'Set Axis Attribute List response, count larger than the data')
    c2d(c, c2d_header(9, 1) + instance(1, service=cntr_svc(3, 0x4C, axis_list([axis_entry(431, b'', dim=1, elem=4, count=1000)]))),
        'Set Axis Attribute List request, array larger than the data')
    d2c(c, d2c_header(9, 1) + instance(1, service=devce_svc(3, 0x4B, axis_list([axis_entry(431, b'', dim=1, elem=4, count=1000)]))),
        'Get Axis Attribute List response, array larger than the data')
    c2d(c, c2d_header(10, 1) + instance(1, service=cntr_svc(4, 0x4D, u16(50) + u16(0) + u16(431))),
        'Set Cyclic Write List request, count larger than the data')
    d2c(c, d2c_header(10, 1) + instance(1, service=devce_svc(4, 0x4E, u16(50) + u16(0) + u16(431) + u16(0))),
        'Set Cyclic Read List response, count larger than the data')
    c2d(c, c2d_header(11, 1) + instance(1, service=cntr_svc(5, 0x04, u16(3) + u16(431) + i32(1))),
        'Set_Attribute_List request, count larger than the data')
    d2c(c, d2c_header(11, 1) + instance(1, service=devce_svc(5, 0x04, u16(3) + u16(431) + u16(0))),
        'Set_Attribute_List response, count larger than the data')
    c2d(c, c2d_header(12, 1) + instance(1, service=cntr_svc(6, 0x04, u16(1) + u16(651))),
        'Set_Attribute_List request, Axis Status longer than the block')
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    for name, builder in (('cipmotion-coverage.pcap', build_main),
                          ('cipmotion-coverage-malformed.pcap', build_malformed)):
        c = builder()
        write_pcap(os.path.join(out, name), c.frames)
        with open(os.path.join(out, name.replace('.pcap', '.frames.txt')), 'w') as f:
            for i, label in enumerate(c.labels):
                f.write('%d\t%s\n' % (i + 1, label))
        print(name, len(c.frames), 'frames')


if __name__ == '__main__':
    main()
