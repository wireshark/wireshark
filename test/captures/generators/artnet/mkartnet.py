#!/usr/bin/env python3
# Generates test/captures/artnet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build synthetic Art-Net coverage captures (packet-artnet.c).

Usage: mkartnet.py <outdir>

Every packet is built here with struct; nothing comes from a real
network. Writes artnet-coverage.pcap (valid packets) and
artnet-coverage-malformed.pcap (truncated / inconsistent packets).
"""
import os
import struct
import sys


ARTNET_PORT = 6454
ID = b'Art-Net\0'
PROTVER = struct.pack('>H', 14)


def ip_csum(hdr):
    s = sum(struct.unpack('!10H', hdr))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def frame(payload, src=1, dst=255, sport=ARTNET_PORT, dport=ARTNET_PORT):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, src]), bytes([10, 0, 0, dst]))
    ip = ip[:10] + struct.pack('!H', ip_csum(ip)) + ip[12:]
    dmac = b'\xff' * 6 if dst == 255 else bytes([2, 0, 0, 0, 0, dst])
    return dmac + bytes([2, 0, 0, 0, 0, src]) + b'\x08\x00' + ip + udp


def art(opcode, body, protver=True):
    """Art-Net packet: ID, little endian opcode, ProtVer (except poll replies)."""
    return ID + struct.pack('<H', opcode) + (PROTVER if protver else b'') + body


def pad(s, n):
    s = s.encode() if isinstance(s, str) else s
    return s[:n] + b'\0' * (n - len(s[:n]))


def rdm(cc, pid, pd=b'', rt_or_port=None, dst=(0x7a70, 0x00000001),
        src=(0x0001, 0x12345678), tn=1, mc_or_flags=0, subdev=0):
    """RDM message without the 0xCC start code, with a valid checksum."""
    if rt_or_port is None:
        rt_or_port = 0 if cc & 1 else 1
    m = (bytes([0x01, 24 + len(pd)]) + struct.pack('>HI', *dst)
         + struct.pack('>HI', *src) + bytes([tn, rt_or_port, mc_or_flags])
         + struct.pack('>H', subdev) + bytes([cc]) + struct.pack('>HB', pid, len(pd))
         + pd)
    return m + struct.pack('>H', (0xcc + sum(m)) & 0xffff)


# ---------------------------------------------------------------- Art-Net ops

def poll(flags=0x06, prio=0x10, target=None, esta=None):
    b = bytes([flags, prio])
    if target is not None:
        b += struct.pack('>HH', *target)
    if esta is not None:
        b += struct.pack('>HH', *esta)
    return art(0x2000, b)


def poll_reply(ip=(10, 0, 0, 2), net=0x01, sub=0x02, report='#0001 [0042] Power On Tests successful',
               bind_ip=(0, 0, 0, 0), bind_index=0, status3=0x00, bgq=None, filler=10,
               swin=(0, 1, 2, 3), swout=(4, 5, 6, 7), short='Node', long_='Synthetic Art-Net node',
               porttypes=(0xc0, 0x80, 0x40, 0x05), status1=0xd2, status2=0x0f):
    b = bytes(ip) + struct.pack('<H', ARTNET_PORT) + struct.pack('>H', 0x0102)
    b += bytes([net, sub]) + struct.pack('>H', 0x2bc0) + bytes([0x00, status1])
    b += struct.pack('<H', 0x7a70)
    b += pad(short, 18) + pad(long_, 64) + pad(report, 64)
    b += struct.pack('>H', 4) + bytes(porttypes)
    b += bytes([0x80, 0x44, 0x20, 0x00])        # GoodInput
    b += bytes([0x80, 0x42, 0x02, 0x00])        # GoodOutputA
    b += bytes(swin) + bytes(swout)
    b += bytes([100, 0x0f, 0x0f]) + b'\0\0\0' + bytes([0x00])  # sACN prio, macro, remote, spare, style
    b += bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])           # MAC
    b += bytes(bind_ip) + bytes([bind_index, status2])
    b += bytes([0xc0, 0x80, 0x40, 0x00])        # GoodOutputB
    b += bytes([status3])
    b += struct.pack('>HI', 0x7a70, 0x00000002)  # default responder UID
    b += struct.pack('>HH', 0x1234, 44)          # user, refresh rate
    if status3 & 0x02:
        b += bytes([bgq if bgq is not None else 0x01])
    b += b'\0' * filler
    return art(0x2100, b, protver=False)


def dmx_pkt(seq, phys, universe, data):
    return art(0x5000, bytes([seq, phys]) + struct.pack('<H', universe)
               + struct.pack('>H', len(data)) + data)


def nzs(seq, sc, sub, net, data, length=None):
    if length is None:
        length = len(data)
    return art(0x5100, bytes([seq, sc, sub, net]) + struct.pack('>H', length) + data)


def vlc(lang, payload, flags=0xe0, total_len=None, extra=b''):
    body = struct.pack('>HB', 0x414c, 0x45) + bytes([flags])
    body += struct.pack('>HHH', 0x1234, 0x0001, len(payload))
    body += struct.pack('>H', sum(payload) & 0xffff) + b'\0' + bytes([0x40])
    body += struct.pack('>HHHH', 0x0100, 0x0002, lang, 0x000a) + payload + extra
    return nzs(1, 0x91, 0x00, 0x00, body, total_len if total_len is not None else len(body))


def address(net, sub, cmd, bind=1, swin=(0x00, 0x01, 0x82, 0x7f), swout=(0x04, 0x05, 0x86, 0x7f)):
    b = bytes([net, bind]) + pad('NewShort', 18) + pad('New long name', 64)
    b += bytes(swin) + bytes(swout) + bytes([sub, 150, cmd])
    return art(0x6000, b)


def art_input(bind=1, ports=4, inp=(0x00, 0x01, 0x00, 0x01)):
    return art(0x7000, bytes([0, bind]) + struct.pack('>H', ports) + bytes(inp))


def tod_request(net, cmd, addrs):
    return art(0x8000, b'\0\0' + b'\0' * 7 + bytes([net, cmd, len(addrs)]) + bytes(addrs))


def tod_data(port, bind, net, cmdres, addr, uids, total=None, block=0):
    b = bytes([0x01, port]) + b'\0' * 6 + bytes([bind, net, cmdres, addr])
    b += struct.pack('>HBB', total if total is not None else len(uids), block, len(uids))
    for m, d in uids:
        b += struct.pack('>HI', m, d)
    return art(0x8100, b)


def tod_control(net, cmd, addr):
    return art(0x8200, b'\0\0' + b'\0' * 7 + bytes([net, cmd, addr]))


def art_rdm(rdm_msg, rdmver=1, net=0, cmd=0, addr=0, sc=False, fifo=(5, 10)):
    if rdmver == 0:
        b = b'\0\0' + b'\0' * 8
    else:
        b = bytes([rdmver, 0]) + b'\0' * 5 + bytes([fifo[0], fifo[1], net])
    b += bytes([cmd, addr]) + (b'\xcc' if sc else b'') + rdm_msg
    return art(0x8300, b)


def rdm_sub(cc, pid=0x00f0, subdev=1, count=2, data=b''):
    b = bytes([1, 0]) + struct.pack('>HI', 0x7a70, 0x00000005) + b'\0' + bytes([cc])
    b += struct.pack('>HHH', pid, subdev, count) + b'\0' * 4 + data
    return art(0x8400, b)


def firmware_master(ftype, block, length, data):
    return art(0xf200, b'\0\0' + bytes([ftype, block]) + struct.pack('>I', length)
               + b'\0' * 20 + pad(data, 1024))


def file_tn_master(ftype, block, length, name, data):
    return art(0xf400, b'\0\0' + bytes([ftype, block]) + struct.pack('>I', length)
               + pad(name, 14) + struct.pack('>H', sum(data) & 0xffff) + b'\0' * 4 + pad(data, 512))


def ip_prog(cmd, ip=(10, 0, 0, 9), sm=(255, 0, 0, 0), port=ARTNET_PORT, gw=(10, 0, 0, 254)):
    return art(0xf800, b'\0\0' + bytes([cmd, 0]) + bytes(ip) + bytes(sm)
               + struct.pack('>H', port) + bytes(gw) + b'\0' * 4)


def ip_prog_reply(status, ip=(10, 0, 0, 9), sm=(255, 0, 0, 0), gw=(10, 0, 0, 254)):
    return art(0xf900, b'\0' * 4 + bytes(ip) + bytes(sm) + struct.pack('>H', ARTNET_PORT)
               + bytes([status, 0]) + bytes(gw) + b'\0\0')


def diag(prio, port, text):
    t = text.encode() + b'\0'
    return art(0x2300, bytes([0, prio, port, 0]) + struct.pack('>H', len(t)) + t)


def command(esta, text):
    t = text.encode() + b'\0'
    return art(0x2400, struct.pack('>HH', esta, len(t)) + t)


def data_request(req, esta=0x7a70, oem=0x2bc0):
    return art(0x2700, struct.pack('>HHH', esta, oem, req) + b'\0' * 22)


def data_reply(req, payload=b'', esta=0x7a70, oem=0x2bc0):
    return art(0x2800, struct.pack('>HHHH', esta, oem, req, len(payload)) + payload)


def time_code(frames, sec, mins, hours, ttype, stream=0):
    return art(0x9700, bytes([0, stream, frames, sec, mins, hours, ttype]))


def trigger(oem, key, subkey, data=b''):
    return art(0x9900, b'\0\0' + struct.pack('>H', oem) + bytes([key, subkey]) + pad(data, 512))


def directory(cmd, fileno):
    return art(0x9a00, b'\0\0' + bytes([cmd]) + struct.pack('>H', fileno))


def directory_reply(flags, fileno, name, desc, length, data):
    return art(0x9b00, b'\0\0' + bytes([flags]) + struct.pack('>H', fileno) + pad(name, 16)
               + pad(desc, 64) + struct.pack('>Q', length) + pad(data, 64))


def video_setup(control, height, first, last, font, data):
    return art(0xa010, b'\0' * 4 + bytes([control, height, first, last]) + pad(font, 64) + data)


def video_palette(r, g, b):
    return art(0xa020, b'\0\0' + bytes(r) + bytes(g) + bytes(b))


def video_data(x, y, lx, ly, data):
    return art(0xa040, b'\0\0' + bytes([x, y, lx, ly]) + data)


# Clean RDM parameter data per (PID, command class), found by search_rdm.py
# (every candidate decodes with no expert info and no exception).
# BEGIN RDM_MESSAGES
RDM_MESSAGES = [  # (cc, pid, parameter data, port id / response type, kwargs)
    (0x10, 0x0001, bytes.fromhex('010101010101010101010101'), 1, {}),
    (0x11, 0x0002, bytes.fromhex('0101010101010101'), 0, {}),
    (0x11, 0x0003, bytes.fromhex('0101010101010101'), 0, {}),
    (0x21, 0x0010, bytes.fromhex('010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x21, 0x0011, bytes.fromhex('010101'), 0, {}),
    (0x21, 0x0015, bytes.fromhex('010101010101'), 0, {}),
    (0x20, 0x0016, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0016, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0016, bytes.fromhex('01'), 1, {}),
    (0x31, 0x0016, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0017, bytes.fromhex('01010101010101010101010101010101010101'), 0, {}),
    (0x20, 0x0020, bytes.fromhex('01'), 1, {}),
    (0x20, 0x0030, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0030, bytes.fromhex('010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x20, 0x0031, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0031, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0033, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0033, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0034, bytes.fromhex('010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x30, 0x0034, bytes.fromhex('010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 1, {}),
    (0x21, 0x0050, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x20, 0x0051, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0051, bytes.fromhex('01010101010101010101010101010101010101'), 0, {}),
    (0x20, 0x0052, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0052, bytes.fromhex('01010101'), 0, {}),
    (0x20, 0x0053, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0053, bytes.fromhex('01'), 0, {}),
    (0x20, 0x0054, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0054, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0055, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x21, 0x0056, bytes.fromhex('01'), 0, {}),
    (0x20, 0x0057, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0057, bytes.fromhex('01'), 0, {}),
    (0x20, 0x0058, bytes.fromhex('0101010101010101'), 1, {}),
    (0x21, 0x0058, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x30, 0x0058, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 1, {}),
    (0x20, 0x0059, bytes.fromhex('010101010101'), 1, {}),
    (0x21, 0x0059, bytes.fromhex('000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100'), 0, {}),
    (0x30, 0x0059, bytes.fromhex('000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102030001020300010203000102'), 1, {}),
    (0x20, 0x005a, bytes.fromhex('010101010101'), 1, {}),
    (0x21, 0x005a, bytes.fromhex('010101010101010101'), 0, {}),
    (0x21, 0x0060, bytes.fromhex('01010101010101010101010101010101010101'), 0, {}),
    (0x21, 0x0070, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x21, 0x0080, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0081, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0082, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0082, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0090, bytes.fromhex('01'), 0, {}),
    (0x21, 0x00a0, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x21, 0x00b0, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x00b0, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x00c0, bytes.fromhex('01'), 0, {}),
    (0x21, 0x00c1, bytes.fromhex('01010101'), 0, {}),
    (0x21, 0x00c2, bytes.fromhex('01'), 0, {}),
    (0x21, 0x00d0, bytes.fromhex('01'), 0, {}),
    (0x21, 0x00d1, bytes.fromhex('01'), 0, {}),
    (0x21, 0x00d2, bytes.fromhex('01'), 0, {}),
    (0x21, 0x00d3, bytes.fromhex('01'), 0, {}),
    (0x20, 0x00d4, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x00d4, bytes.fromhex('0101010101010101010101010101010101010101010101'), 0, {}),
    (0x21, 0x00e0, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x00e0, bytes.fromhex('01'), 1, {}),
    (0x20, 0x00e1, bytes.fromhex('01'), 1, {}),
    (0x21, 0x00e1, bytes.fromhex('0101'), 0, {}),
    (0x20, 0x00e2, bytes.fromhex('01'), 1, {}),
    (0x21, 0x00e2, bytes.fromhex('0101010101'), 0, {}),
    (0x21, 0x00f0, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x00f0, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0120, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x20, 0x0121, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0121, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0122, bytes.fromhex('010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x21, 0x0140, bytes.fromhex('01010101'), 0, {}),
    (0x30, 0x0140, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0141, bytes.fromhex('01010101010101'), 0, {}),
    (0x30, 0x0141, bytes.fromhex('01010101010101'), 1, {}),
    (0x21, 0x0142, bytes.fromhex('01010101010101'), 0, {}),
    (0x30, 0x0142, bytes.fromhex('01010101010101'), 1, {}),
    (0x20, 0x0200, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0200, bytes.fromhex('010101010101010101010101'), 0, {}),
    (0x20, 0x0201, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0201, bytes.fromhex('010101010101010101'), 0, {}),
    (0x30, 0x0201, bytes.fromhex('01'), 1, {}),
    (0x31, 0x0201, bytes.fromhex('010101010101010101'), 0, {}),
    (0x20, 0x0202, bytes.fromhex('01'), 1, {}),
    (0x20, 0x0210, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0210, bytes.fromhex('01'), 0, {}),
    (0x20, 0x0211, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0211, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0340, bytes.fromhex('0101010101010101010101'), 0, {}),
    (0x21, 0x0341, bytes.fromhex('0101010101'), 0, {}),
    (0x30, 0x0341, bytes.fromhex('0101010101'), 1, {}),
    (0x21, 0x0342, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x0342, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0343, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x0343, bytes.fromhex('01'), 1, {}),
    (0x20, 0x0344, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0344, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0345, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x0345, bytes.fromhex('01'), 1, {}),
    (0x20, 0x0346, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0346, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0347, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x0347, bytes.fromhex('01'), 1, {}),
    (0x20, 0x0348, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0348, bytes.fromhex('01010101'), 0, {}),
    (0x21, 0x0400, bytes.fromhex('01010101'), 0, {}),
    (0x30, 0x0400, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0401, bytes.fromhex('01010101'), 0, {}),
    (0x30, 0x0401, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0402, bytes.fromhex('01010101'), 0, {}),
    (0x30, 0x0402, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0403, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0403, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0404, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0404, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0405, bytes.fromhex('01010101'), 0, {}),
    (0x30, 0x0405, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0440, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0440, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0500, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0500, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0501, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0501, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0600, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0600, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0601, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0601, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0602, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0602, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0603, bytes.fromhex('01010101010101'), 0, {}),
    (0x30, 0x0603, bytes.fromhex('01010101010101'), 1, {}),
    (0x21, 0x0640, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x0640, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0641, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x0641, bytes.fromhex('010101'), 1, {}),
    (0x20, 0x0642, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0642, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0650, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0651, bytes.fromhex('000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100'), 0, {}),
    (0x30, 0x0652, bytes.fromhex('01'), 1, {}),
    (0x30, 0x0653, bytes.fromhex('01'), 1, {}),
    (0x20, 0x0654, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0654, bytes.fromhex('01'), 0, {}),
    (0x21, 0x0656, bytes.fromhex('01010101'), 0, {}),
    (0x30, 0x0656, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0700, bytes.fromhex('010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x20, 0x0701, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0701, bytes.fromhex('010101'), 0, {}),
    (0x20, 0x0702, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0702, bytes.fromhex('01010101010101010101'), 0, {}),
    (0x20, 0x0703, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0703, bytes.fromhex('0101010101'), 0, {}),
    (0x30, 0x0703, bytes.fromhex('0101010101'), 1, {}),
    (0x20, 0x0704, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0704, bytes.fromhex('0101010101'), 0, {}),
    (0x30, 0x0704, bytes.fromhex('0101010101'), 1, {}),
    (0x20, 0x0705, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0705, bytes.fromhex('01010101010101010101'), 0, {}),
    (0x20, 0x0706, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x0706, bytes.fromhex('010101010101010101'), 0, {}),
    (0x30, 0x0706, bytes.fromhex('010101010101010101'), 1, {}),
    (0x30, 0x0707, bytes.fromhex('01010101'), 1, {}),
    (0x30, 0x0708, bytes.fromhex('01010101'), 1, {}),
    (0x30, 0x0709, bytes.fromhex('01010101'), 1, {}),
    (0x21, 0x070a, bytes.fromhex('0101010101010101'), 0, {}),
    (0x30, 0x070a, bytes.fromhex('0101010101010101'), 1, {}),
    (0x20, 0x070b, bytes.fromhex('01'), 1, {}),
    (0x21, 0x070b, bytes.fromhex('0101010101'), 0, {}),
    (0x30, 0x070b, bytes.fromhex('0101010101'), 1, {}),
    (0x21, 0x070c, bytes.fromhex('01'), 0, {}),
    (0x30, 0x070c, bytes.fromhex('01'), 1, {}),
    (0x21, 0x070d, bytes.fromhex('01'), 0, {}),
    (0x30, 0x070d, bytes.fromhex('01'), 1, {}),
    (0x20, 0x0800, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0801, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0801, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0803, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x0803, bytes.fromhex('01'), 1, {}),
    (0x21, 0x0900, bytes.fromhex('010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x21, 0x0901, bytes.fromhex('01010101'), 0, {}),
    (0x20, 0x0902, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0902, bytes.fromhex('010101'), 0, {}),
    (0x30, 0x0902, bytes.fromhex('010101'), 1, {}),
    (0x31, 0x0902, bytes.fromhex('0101'), 0, {}),
    (0x20, 0x0903, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0903, bytes.fromhex('01010101'), 0, {}),
    (0x30, 0x0903, bytes.fromhex('01010101'), 1, {}),
    (0x31, 0x0903, bytes.fromhex('0101'), 0, {}),
    (0x20, 0x0904, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0904, bytes.fromhex('010101'), 0, {}),
    (0x30, 0x0904, bytes.fromhex('010101'), 1, {}),
    (0x31, 0x0904, bytes.fromhex('0101'), 0, {}),
    (0x20, 0x0905, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0905, bytes.fromhex('01'), 0, {}),
    (0x30, 0x0905, bytes.fromhex('01'), 1, {}),
    (0x31, 0x0905, bytes.fromhex('0101'), 0, {}),
    (0x20, 0x0906, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0906, bytes.fromhex('010101'), 0, {}),
    (0x30, 0x0906, bytes.fromhex('010101'), 1, {}),
    (0x20, 0x0907, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0907, bytes.fromhex('0101010101'), 0, {}),
    (0x30, 0x0907, bytes.fromhex('010101'), 1, {}),
    (0x31, 0x0907, bytes.fromhex('0101'), 0, {}),
    (0x20, 0x0908, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0908, bytes.fromhex('010101'), 0, {}),
    (0x30, 0x0908, bytes.fromhex('010101'), 1, {}),
    (0x31, 0x0908, bytes.fromhex('0101'), 0, {}),
    (0x20, 0x0909, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x0909, bytes.fromhex('01010101'), 0, {}),
    (0x30, 0x0909, bytes.fromhex('010101'), 1, {}),
    (0x31, 0x0909, bytes.fromhex('0101'), 0, {}),
    (0x20, 0x090a, bytes.fromhex('01'), 1, {}),
    (0x21, 0x090a, bytes.fromhex('01'), 0, {}),
    (0x20, 0x090b, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x090b, bytes.fromhex('010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x20, 0x090c, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x090c, bytes.fromhex('010101010101'), 0, {}),
    (0x20, 0x090d, bytes.fromhex('0101010101010101'), 1, {}),
    (0x21, 0x090d, bytes.fromhex('01010101010101010101010101010101'), 0, {}),
    (0x21, 0x090e, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x090e, bytes.fromhex('01'), 1, {}),
    (0x20, 0x090f, bytes.fromhex('01'), 1, {}),
    (0x21, 0x090f, bytes.fromhex('01'), 0, {}),
    (0x21, 0x1000, bytes.fromhex('01'), 0, {}),
    (0x30, 0x1000, bytes.fromhex('01'), 1, {}),
    (0x30, 0x1001, bytes.fromhex('01'), 1, {}),
    (0x21, 0x1010, bytes.fromhex('01'), 0, {}),
    (0x30, 0x1010, bytes.fromhex('01'), 1, {}),
    (0x21, 0x1020, bytes.fromhex('01'), 0, {}),
    (0x30, 0x1020, bytes.fromhex('01'), 1, {}),
    (0x20, 0x1021, bytes.fromhex('01'), 1, {}),
    (0x21, 0x1021, bytes.fromhex('01'), 0, {}),
    (0x21, 0x1022, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x30, 0x1030, bytes.fromhex('0101010101010101'), 1, {}),
    (0x21, 0x1031, bytes.fromhex('010101'), 0, {}),
    (0x30, 0x1031, bytes.fromhex('010101'), 1, {}),
    (0x21, 0x1040, bytes.fromhex('01'), 0, {}),
    (0x30, 0x1040, bytes.fromhex('01'), 1, {}),
    (0x21, 0x1041, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x20, 0x1042, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x1042, bytes.fromhex('010101010101010101'), 0, {}),
    (0x30, 0x1042, bytes.fromhex('010101010101010101'), 1, {}),
    (0x21, 0x1043, bytes.fromhex('01'), 0, {}),
    (0x30, 0x1043, bytes.fromhex('01'), 1, {}),
    (0x21, 0x1044, bytes.fromhex('01'), 0, {}),
    (0x30, 0x1044, bytes.fromhex('01'), 1, {}),
    (0x21, 0x1050, bytes.fromhex('0101'), 0, {}),
    (0x30, 0x1050, bytes.fromhex('0101'), 1, {}),
    (0x21, 0x1051, bytes.fromhex('01'), 0, {}),
    (0x20, 0x1200, bytes.fromhex('010101010101'), 1, {}),
    (0x21, 0x1200, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x31, 0x1200, bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101010101010101'), 0, {}),
    (0x20, 0x1201, bytes.fromhex('01'), 1, {}),
    (0x21, 0x1201, bytes.fromhex('010101010101010101'), 0, {}),
    (0x31, 0x1201, bytes.fromhex('010101010101010101'), 0, {}),
    (0x20, 0x1202, bytes.fromhex('010101'), 1, {}),
    (0x21, 0x1202, bytes.fromhex('000102030001020300010203000102'), 0, {}),
    (0x30, 0x1202, bytes.fromhex('010101'), 1, {}),
    (0x31, 0x1202, bytes.fromhex('000102030001020300010203000102'), 0, {}),
    (0x30, 0x1203, bytes.fromhex('01'), 1, {}),
    (0x31, 0x1203, bytes.fromhex('0101010101'), 0, {}),
    (0x20, 0x1205, bytes.fromhex('010101'), 1, {}),
]
# END RDM_MESSAGES

# ------------------------------------------------------------------ captures

def main_capture():
    P = []  # list of (payload, src, dst)

    def add(p, src=1, dst=255, **kw):
        P.append((p, src, dst, kw))

    # 1: discovery -- ArtPoll in every length the dissector handles
    add(poll(0x06, 0x10, (0, 32767), (0x7a70, 0x2bc0)))          # full Rev. 4
    add(poll(0x3e, 0x80, (1, 10)))                              # no EstaMan/OEM
    add(poll(0x00, 0x40))                                       # pre Rev. DE
    add(poll(0x02, 0xe0, (0, 0), (0, 0)))
    add(poll(0x02, 0x33, (0, 0), (0, 0)))                       # unknown priority
    add(poll(0x02, 0x10, (0, 0), (0, 0)) + b'\x99')             # excess byte
    # ArtPollReply variants
    add(poll_reply(), 2, 1)
    add(poll_reply(report='#ffff 7 x', bind_ip=(10, 0, 0, 2), bind_index=1,
                   status3=0x02, bgq=0x03, filler=0), 2, 1)
    add(poll_reply(report='', bind_ip=(10, 0, 0, 3), bind_index=2, status3=0xff,
                   bgq=0x80, net=0x7f, sub=0x0f, swin=(0x0f, 0x0e, 0x0d, 0x0c),
                   porttypes=(0x01, 0x02, 0x03, 0x04), status1=0x00, status2=0xf0), 3, 1)
    add(poll_reply(report='#0001 [0042] ' + 'A' * 60, filler=0, status3=0x40), 4, 1)  # 64 octets, no NUL
    add(poll_reply(report='#00ff 123 Ready', bind_ip=(10, 0, 0, 5), bind_index=4, status3=0x80), 5, 1)
    add(poll_reply(report='#0002 [9] Ok', status3=0xc0), 6, 1)
    add(art(0x2200, b'', protver=False), 2, 1)                    # ArtPollFpReply
    add(art(0x2200, b'\x01\x02', protver=False), 2, 1)            # ArtPollFpReply, excess bytes
    # 15: diagnostics, commands, data
    add(diag(0x10, 1, 'Low priority diagnostic'), 2, 1)
    add(diag(0xe0, 0, 'Critical: DMX input lost'), 2, 1)
    add(diag(0xff, 4, ''), 2, 1)
    add(command(0xffff, 'SwoutText=Playback&SwinText=Record&'))
    add(command(0x7a70, ''))
    for req in (0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x8000, 0x1234):
        add(data_request(req))
    add(data_reply(0x0001, b'https://example.com/product'), 2, 1)
    add(data_reply(0x0005, b''), 2, 1)
    add(data_reply(0x8001, b'\x01\x02\x03\x04'), 2, 1)
    # ArtDmx: full universe, short frame, frame shorter than its length field
    full = bytes((i * 7) & 0xff for i in range(512))
    full = full[:10] + b'\xff\xfe\x00\x80' + full[14:]
    add(dmx_pkt(1, 0, 0x0001, full))
    add(dmx_pkt(2, 1, 0x7fff, bytes(range(0, 250, 10)) + b'\xff'))
    add(dmx_pkt(0, 3, 0x0010, b'\x00' * 2))
    add(dmx_pkt(3, 0, 0x0001, bytes([255] * 37)))
    # ArtNzs: non zero start codes with DMX data, VLC
    add(nzs(1, 0x17, 0x01, 0x00, b'Text start code data'))
    add(nzs(2, 0xdd, 0x12, 0x01, bytes(range(64))))
    add(nzs(3, 0x91, 0x00, 0x00, bytes(range(40))))               # 0x91 without VLC magic
    add(nzs(4, 0x91, 0x00, 0x00, b'\x41\x4c\x00' + bytes(10)))    # wrong sub code
    add(nzs(5, 0x55, 0x00, 0x00, b'\x01\x02', 2))                 # less than 3 octets: early return
    add(nzs(6, 0x17, 0x00, 0x00, b'ab', 2) + b'\x00')             # 3 octets, length 2: excess byte
    add(nzs(7, 0x17, 0x00, 0x00, b'abcdef', 3))                   # length shorter than data
    add(vlc(0x0000, b'https://example.com/beacon'))
    add(vlc(0x0001, b'Synthetic beacon text', flags=0x40))
    add(vlc(0x0002, b'\x12\x34', flags=0x20))
    add(vlc(0x0002, b'', flags=0x00))                              # LocId without payload
    add(vlc(0x0007, b'\x00\x11\x22\x33'))                          # other language code
    # ArtSync
    add(art(0x5200, b'\0\0'))
    add(art(0x5200, b'\0\0\0\0'))                                  # excess bytes
    # 52: ArtAddress
    add(address(0x00, 0x00, 0x00))
    add(address(0x7f, 0x7f, 0x01))
    add(address(0x85, 0x83, 0x02, swin=(0x7f, 0x00, 0x8f, 0x81)))
    for cmd in (0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x10, 0x21,
                0x32, 0x53, 0x61, 0x72, 0x93, 0xa2, 0xb3, 0xc0, 0xd1, 0xe2, 0x0d):
        add(address(0x01, 0x81, cmd))
    # ArtInput
    add(art_input(1, 4, (0x00, 0x01, 0x00, 0x01)))
    add(art_input(2, 1, (0x01, 0x01, 0x01, 0x01)))
    # 81: RDM - ArtTodRequest, ArtTodData, ArtTodControl
    add(tod_request(0x00, 0x00, [0x00, 0x01, 0x02, 0x10]))
    add(tod_request(0x01, 0x01, []))
    add(tod_request(0x00, 0x07, [0xff]))                           # unknown command
    add(tod_data(1, 1, 0x00, 0x00, 0x01,
                 [(0x7a70, 1), (0x7a70, 2), (0x4c5a, 0x80000003)]), 2, 1)
    add(tod_data(2, 2, 0x7f, 0x01, 0xff, [], total=0), 2, 1)
    add(tod_data(1, 1, 0x01, 0xff, 0x10, [(0x0001, 0x00000001)] * 20, total=300, block=1), 2, 1)
    for cmd in (0x00, 0x01, 0x02, 0x03, 0x04, 0x09):
        add(tod_control(0x01, cmd, 0x02))
    # ArtRdm: every Art-Net form, RDM payloads (see rdm_pids.py)
    add(art_rdm(rdm(0x20, 0x0060), rdmver=0))                      # Art-Net 2 layout
    add(art_rdm(rdm(0x20, 0x0060), rdmver=1, net=0x01, addr=0x02, sc=True))  # with start code
    add(art_rdm(rdm(0x21, 0x0060, struct.pack('>HHHIHBBHHB', 0x0100, 0x0101, 0x0508, 0x01020304,
                                              17, 1, 2, 1, 0, 1)), rdmver=2, cmd=0x00), 2, 1)
    add(art_rdm(rdm(0x20, 0x0060), rdmver=1, cmd=0xff))
    for i, (cc, pid, pd, rt, kw) in enumerate(RDM_MESSAGES):
        resp = cc & 1
        add(art_rdm(rdm(cc, pid, pd, rt_or_port=rt, tn=i & 0xff, **kw), rdmver=1),
            2 if resp else 1, 1 if resp else 2)
    # RDM header variants: empty parameter data, every response type,
    # manufacturer specific PIDs (ETC and a manufacturer without a dissector)
    for cc in (0x10, 0x11, 0x20, 0x21, 0x30, 0x31):
        add(art_rdm(rdm(cc, 0x0082, b'', mc_or_flags=3 if cc & 1 else 0x03, subdev=0xffff if cc == 0x30 else 0)))
    add(art_rdm(rdm(0x21, 0x0082, b'\x00\x0a', rt_or_port=0x01)), 2, 1)        # ACK_TIMER
    add(art_rdm(rdm(0x31, 0x0082, b'\x00\x0a', rt_or_port=0x01)), 2, 1)
    add(art_rdm(rdm(0x21, 0x0082, b'\x00\x05', rt_or_port=0x02)), 2, 1)        # NACK_REASON
    add(art_rdm(rdm(0x31, 0x00f0, b'\x00\x06', rt_or_port=0x02)), 2, 1)
    add(art_rdm(rdm(0x21, 0x0050, b'\x00\x60\x00\x82\x00\xf0', rt_or_port=0x03)), 2, 1)  # ACK_OVERFLOW, known PID
    add(art_rdm(rdm(0x21, 0x00f0, b'\x00\x01', rt_or_port=0x03)), 2, 1)        # ACK_OVERFLOW, raw
    add(art_rdm(rdm(0x31, 0x00f0, b'\x00\x01', rt_or_port=0x03)), 2, 1)
    add(art_rdm(rdm(0x21, 0x0082, b'\x00\x10', rt_or_port=0x04)), 2, 1)  # ACK_TIMER_HI_RES
    add(art_rdm(rdm(0x31, 0x0082, b'\x00\x10', rt_or_port=0x04)), 2, 1)
    add(art_rdm(rdm(0x20, 0x8101, b'', dst=(0x6574, 0x00000010))))               # ETC GET
    add(art_rdm(rdm(0x21, 0x8101, b'\x01', src=(0x6574, 0x00000010))), 2, 1)    # ETC GET_RESPONSE
    add(art_rdm(rdm(0x30, 0x8104, b'\x02', dst=(0x6574, 0x00000010))))
    add(art_rdm(rdm(0x21, 0x8001, b'\x01\x02\x03', src=(0x1234, 0x00000010))), 2, 1)  # no manufacturer dissector
    add(art_rdm(rdm(0x20, 0x00f0, b'', dst=(0xffff, 0xffffffff))))               # broadcast
    add(art_rdm(rdm(0x20, 0x00f0, b'', src=(0x8001, 0x00000001))))               # dynamic UID
    add(art_rdm(rdm(0x20, 0x00f0, b'') + b'\x00\x00'))                          # trailing octets
    # ArtRdmSub
    for cc in (0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 0x40):
        data = struct.pack('>HH', 1, 512) if cc in (0x21, 0x30) else b''
        add(rdm_sub(cc, data=data), 2 if cc & 1 else 1, 1 if cc & 1 else 2)
    # Media server opcodes (no body defined), with and without trailing data
    for op in (0x9000, 0x9100, 0x9200, 0x9300):
        add(art(op, b''))
        add(art(op, b'\x01\x02\x03'))
    # ArtTimeCode, ArtTimeSync, ArtTrigger
    add(time_code(24, 59, 59, 23, 0))
    add(time_code(10, 0, 30, 1, 1, stream=1))
    add(time_code(29, 1, 2, 3, 2))
    add(time_code(29, 1, 2, 3, 3))
    add(time_code(1, 1, 1, 1, 7))
    add(art(0x9800, b''))
    add(art(0x9800, b'\x00\x01'))
    for key, sub in ((0, 0x41), (1, 0x05), (2, 0x01), (3, 0x02), (4, 0)):
        add(trigger(0xffff, key, sub))
    add(trigger(0x2bc0, 0x10, 0x20, b'OEM specific trigger payload'))
    # ArtDirectory, ArtDirectoryReply
    add(directory(0x00, 0x0000))
    add(directory(0x01, 0x0003))
    add(directory_reply(0x00, 0x0000, 'show.bin', 'Show file', 123456, b'\x01\x02'), 2, 1)
    add(directory_reply(0x01, 0x0001, 'fw.alf', 'Firmware', 0xffffffffffff, b''), 2, 1)
    # ArtVideoSetup, ArtVideoPalette, ArtVideoData
    add(video_setup(0x00, 8, 0x20, 4, 'Courier', bytes(range(32))))
    add(video_setup(0x01, 0, 0, 0, '', b''))
    add(video_palette(range(17), range(17, 34), range(34, 51)))
    add(video_data(1, 2, 4, 2, bytes(range(16))))
    add(video_data(0, 0, 0, 0, b''))
    # ArtMacMaster, ArtMacSlave (no body defined)
    add(art(0xf000, b''))
    add(art(0xf100, b'\x00\x00'))
    # ArtFirmwareMaster, ArtFirmwareReply
    for ftype in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06):
        add(firmware_master(ftype, ftype, 2048 + ftype, bytes(range(256)) * 4))
    for ftype in (0x00, 0x01, 0xff):
        add(art(0xf300, b'\0\0' + bytes([ftype]) + b'\0' * 21), 2, 1)
    # ArtFileTnMaster, ArtFileFnMaster, ArtFileFnReply
    add(file_tn_master(0x00, 0, 1024, 'show.dat', b'File data block 0'))
    add(file_tn_master(0x01, 1, 1024, 'show.dat', b'File data block 1'))
    add(file_tn_master(0x02, 2, 1024, 'show.dat', b'Last block'))
    add(art(0xf500, b''))
    add(art(0xf600, b''), 2, 1)
    # ArtIpProg, ArtIpProgReply
    add(ip_prog(0x00))
    add(ip_prog(0x80 | 0x40 | 0x10 | 0x08 | 0x04 | 0x02 | 0x01))
    add(ip_prog(0x88))
    add(ip_prog_reply(0x40), 2, 1)
    add(ip_prog_reply(0x00, ip=(2, 0, 0, 2)), 2, 1)
    # Unknown opcodes, with and without data; zero length opcodes
    add(art(0x1234, b'\x01\x02\x03\x04'))
    add(art(0xabcd, b''))
    add(art(0x2500, b''))
    # Not Art-Net: the heuristic rejects these
    add(b'Art-Ne', 7, 255)
    add(b'Art-Net\x01\x00\x20\x00\x0e', 7, 255)
    return P


def malformed_capture():
    P = []

    def add(p, src=1, dst=255):
        P.append((p, src, dst, {}))

    # ArtPollReply expert infos (group Malformed, severity Warning)
    add(poll_reply(report='Node status is fine', status3=0x40), 4, 1)        # invalid node report format
    add(poll_reply(bind_ip=(10, 0, 0, 5), bind_index=0, status3=0x80), 5, 1)  # bind IP without index
    add(poll_reply(bind_ip=(0, 0, 0, 0), bind_index=3, status3=0xc0), 6, 1)   # bind index without IP
    # Opcode cut short
    add(ID + b'\x00')
    add(ID + struct.pack('<H', 0xabcd))
    add(ID + struct.pack('<H', 0x2000) + b'\x00')
    add(poll()[:13])
    add(poll_reply()[:100], 2, 1)
    add(poll_reply()[:180], 2, 1)
    add(poll_reply(report='#0001 [1] ok', filler=0)[:-5], 2, 1)
    add(poll_reply(status3=0x02, filler=0)[:-1], 2, 1)
    add(dmx_pkt(1, 0, 1, bytes(10))[:16])
    add(dmx_pkt(1, 0, 1, bytes(100))[:60])
    add(nzs(1, 0x17, 0, 0, b'abc', 300))
    add(vlc(0x0000, b'http://x', total_len=300)[:-4])
    add(vlc(0x0001, b'')[:-6])
    add(address(0, 0, 0)[:50])
    add(art_input()[:-2])
    add(tod_request(0, 0, [1, 2, 3])[:-2])
    add(tod_data(1, 1, 0, 0, 0, [(1, 1), (2, 2)])[:-4], 2, 1)
    add(tod_control(0, 0, 0)[:-1])
    add(art_rdm(b'', rdmver=1)[:-1])
    add(art_rdm(rdm(0x20, 0x0060)[:10], rdmver=1))
    add(art_rdm(rdm(0x21, 0x0060, b'\x01\x00')[:-2] + b'\x00\x00', rdmver=1), 2, 1)  # bad checksum
    add(rdm_sub(0x10)[:-3])
    add(art(0xa010, b'\0' * 4 + bytes([0, 16, 0, 255]) + pad('x', 64) + bytes(20)))
    add(art(0xa020, bytes(20)))
    add(art(0xa040, b'\0\0' + bytes([0, 0, 255, 255]) + bytes(10)))
    add(firmware_master(0, 0, 0, b'')[:200])
    add(art(0xf300, b'\0\0'))
    add(file_tn_master(0, 0, 0, '', b'')[:100])
    add(ip_prog(0)[:20])
    add(ip_prog_reply(0)[:20], 2, 1)
    add(diag(0x10, 0, 'x')[:-1] + b'')
    add(art(0x2300, bytes([0, 0x10, 0, 0]) + struct.pack('>H', 200) + b'short'))
    add(art(0x2400, struct.pack('>HH', 0xffff, 100) + b'short'))
    add(art(0x2700, b'\0' * 10))
    add(art(0x2800, struct.pack('>HHHH', 0, 0, 1, 50) + b'short'), 2, 1)
    add(art(0x9700, b'\0\0\0'))
    add(art(0x9900, b'\0\0\xff\xff\x00\x00' + bytes(100)))
    add(art(0x9a00, b'\0\0'))
    add(art(0x9b00, b'\0' * 30), 2, 1)
    add(art(0x5200, b''))
    add(art(0x8100, b'\x01'), 2, 1)
    add(art_rdm(rdm(0x21, 0x0082, b'\x01\x02', rt_or_port=0x07)), 2, 1)  # unknown RDM response type
    add(art_rdm(rdm(0x20, 0x0060, b'\x01\x02\x03')))                     # PDL mismatch
    return P


def write_pcap(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (p, src, dst, kw) in enumerate(pkts):
            fr = frame(p, src, dst, **kw)
            f.write(struct.pack('<IIII', 1767225600 + i // 50, (i % 50) * 20000, len(fr), len(fr)) + fr)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'artnet-coverage.pcap'), main_capture())
    write_pcap(os.path.join(out, 'artnet-coverage-malformed.pcap'), malformed_capture())
