#!/usr/bin/env python3
# Generates test/captures/btl2cap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for the Bluetooth L2CAP dissector
(epan/dissectors/packet-btl2cap.c). Every packet is built with struct;
nothing comes from a real network.

Usage: mkbtl2cap.py <outdir>
  btl2cap-coverage.pcapng            main capture (frame ranges in README)
  btl2cap-coverage-malformed.pcap  truncated and inconsistent PDUs (pcap,
                                     so without interface IDs)
  btl2cap-coverage-malformed-exp.pcapng  two Exported PDUs with bad lengths

The captures are pcapng with two link types: Bluetooth HCI H4 with
direction (201) for BR/EDR and LE ACL data, and Bluetooth LE Link Layer
with pseudo-header (256), which is the only way L2CAP sees an LE link
(no direction in Info) and an LE link layer retransmission.
"""
import os
import struct
import sys

SENT, RECV = 0, 1
LT_H4 = 201
LT_LE_LL = 256
LT_EXP_PDU = 252

H_BR = 0x0001          # BR/EDR ACL connection handle
H_LE = 0x0040          # LE ACL connection handle
BD_ADDR = bytes.fromhex('665544332211')      # 11:22:33:44:55:66, little endian
LE_ADDR = bytes.fromhex('cc5544332211')      # 11:22:33:44:55:cc

SIG, CONNLESS, AMP, ATT, LESIG, SMP, BRSMP = 1, 2, 3, 4, 5, 6, 7

PSM_SDP = 0x0001
PSM_HID_CTRL = 0x0011
PSM_HIDDYN = 0x1011     # remote HID record (SDP), used by the ERTM channel
PSM_LOCAL = 0x1015      # our own HID record (SDP), remote connects to us
PSM_LEHID = 0x0081      # remote record whose PSM is also used as an LE PSM


# ---------------------------------------------------------------- pcapng

class Pcapng:
    def __init__(self):
        self.blocks = []
        self.ifaces = {}
        self.ts = 1700000000 * 1000000
        self.count = 0
        self._block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

    def _block(self, btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = len(body) + 12
        self.blocks.append(struct.pack('<II', btype, total) + body + struct.pack('<I', total))

    def iface(self, linktype):
        if linktype not in self.ifaces:
            self.ifaces[linktype] = len(self.ifaces)
            self._block(1, struct.pack('<HHI', linktype, 0, 262144))
        return self.ifaces[linktype]

    def add(self, data, linktype=LT_H4, caplen=None):
        i = self.iface(linktype)
        self.ts += 1000
        if caplen is None:
            caplen = len(data)
        self._block(6, struct.pack('<IIIII', i, self.ts >> 32, self.ts & 0xffffffff,
                                   caplen, len(data)) + data[:caplen])
        self.count += 1
        return self.count

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(b''.join(self.blocks))


# ---------------------------------------------------------------- HCI / L2CAP

def crc16(data):
    """CRC-16 (poly 0x8005 reflected), initial value 0: the L2CAP FCS."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def exp_pdu(name, payload):
    n = name.encode()
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def h4(direction, ptype, payload):
    return struct.pack('>I', direction) + bytes([ptype]) + payload


def conn_complete(handle=H_BR, bd_addr=BD_ADDR):
    ev = struct.pack('<BH6sBB', 0, handle, bd_addr, 1, 0)
    return h4(RECV, 0x04, bytes([0x03, len(ev)]) + ev)


def le_conn_complete(handle=H_LE, peer=BD_ADDR):
    ev = struct.pack('<BBHBB6sHHHB', 0x01, 0, handle, 0, 0, peer, 24, 0, 400, 0)
    return h4(RECV, 0x04, bytes([0x3E, len(ev)]) + ev)


def acl(direction, l2, handle=H_BR):
    a = struct.pack('<HH', (handle & 0x0fff) | 0x2000, len(l2)) + l2
    return h4(direction, 0x02, a)


def l2(cid, payload, length=None):
    if length is None:
        length = len(payload)
    return struct.pack('<HH', length, cid) + payload


def l2_fcs(cid, body, bad_fcs=False):
    """Control field + payload followed by an FCS over the whole PDU."""
    hdr = struct.pack('<HH', len(body) + 2, cid)
    fcs = crc16(hdr + body) ^ (0x5555 if bad_fcs else 0)
    return hdr + body + struct.pack('<H', fcs)


def sig(code, ident, data, length=None):
    if length is None:
        length = len(data)
    return struct.pack('<BBH', code, ident, length) + data


def opt(otype, data, olen=None):
    if olen is None:
        olen = len(data)
    return bytes([otype, olen]) + data


def opt_mtu(mtu):
    return opt(0x01, struct.pack('<H', mtu))


def opt_rfc(mode, txwin=8, maxtx=3, rtx=2000, mon=12000, mps=1000):
    return opt(0x04, struct.pack('<BBBHHH', mode, txwin, maxtx, rtx, mon, mps))


def opt_fcs(v):
    return opt(0x05, bytes([v]))


def opt_ews(w):
    return opt(0x07, struct.pack('<H', w))


# control fields
def ctl_std_i(txseq, sar=0, reqseq=0, r=0):
    return struct.pack('<H', (sar << 14) | (reqseq << 8) | (r << 7) | (txseq << 1))


def ctl_std_s(s, reqseq=0, r=0):
    return struct.pack('<H', (reqseq << 8) | (r << 7) | (s << 2) | 1)


def ctl_enh_i(txseq, sar=0, reqseq=0, f=0):
    return struct.pack('<H', (sar << 14) | (reqseq << 8) | (f << 7) | (txseq << 1))


def ctl_enh_s(s, reqseq=0, p=0, f=0):
    return struct.pack('<H', (reqseq << 8) | (f << 7) | (p << 4) | (s << 2) | 1)


def ctl_ext_i(txseq, sar=0, reqseq=0, f=0):
    return struct.pack('<I', (txseq << 18) | (sar << 16) | (reqseq << 2) | (f << 1))


def ctl_ext_s(s, reqseq=0, p=0, f=0):
    return struct.pack('<I', (p << 18) | (s << 16) | (reqseq << 2) | (f << 1) | 1)


class Chan:
    """A connection-oriented channel: local CID (ours), remote CID."""

    def __init__(self, cap, local, remote, handle=H_BR):
        self.cap, self.local, self.remote, self.handle = cap, local, remote, handle

    def cid(self, direction):
        return self.remote if direction == SENT else self.local

    def b(self, direction, payload):
        return self.cap.add(acl(direction, l2(self.cid(direction), payload), self.handle))

    def f(self, direction, body, bad_fcs=False):
        return self.cap.add(acl(direction, l2_fcs(self.cid(direction), body, bad_fcs), self.handle))

    def raw(self, direction, pdu):
        return self.cap.add(acl(direction, pdu, self.handle))


class Sig:
    def __init__(self, cap, handle=H_BR, cid=SIG):
        self.cap, self.handle, self.cid = cap, handle, cid
        self.ident = 0

    def next_ident(self):
        self.ident = (self.ident % 255) + 1
        return self.ident

    def send(self, direction, *cmds):
        return self.cap.add(acl(direction, l2(self.cid, b''.join(cmds)), self.handle))

    # BR/EDR channel set-up: (direction of the request) Connection Request
    # and Response, then optional Configure Requests that set the mode of
    # each direction.
    def connect(self, psm, local, remote, outgoing=True, code=0x02, ctrl=None):
        i = self.next_ident()
        extra = b'' if ctrl is None else bytes([ctrl])
        if outgoing:
            self.send(SENT, sig(code, i, struct.pack('<HH', psm, local) + extra))
            self.send(RECV, sig(code + 1, i, struct.pack('<HHHH', remote, local, 0, 0)))
        else:
            self.send(RECV, sig(code, i, struct.pack('<HH', psm, remote) + extra))
            self.send(SENT, sig(code + 1, i, struct.pack('<HHHH', local, remote, 0, 0)))
        return Chan(self.cap, local, remote, self.handle)

    def configure(self, ch, out_opts=None, in_opts=None):
        """out_opts: options of a received Configure Request (sets how we
        send); in_opts: options of a sent Configure Request (sets how the
        remote side sends). None = no request."""
        if out_opts is not None:
            i = self.next_ident()
            self.send(RECV, sig(0x04, i, struct.pack('<HH', ch.local, 0) + out_opts))
            self.send(SENT, sig(0x05, i, struct.pack('<HHH', ch.remote, 0, 0)))
        if in_opts is not None:
            i = self.next_ident()
            self.send(SENT, sig(0x04, i, struct.pack('<HH', ch.remote, 0) + in_opts))
            self.send(RECV, sig(0x05, i, struct.pack('<HHH', ch.local, 0, 0)))

    def disconnect(self, ch, outgoing=True):
        i = self.next_ident()
        if outgoing:
            self.send(SENT, sig(0x06, i, struct.pack('<HH', ch.remote, ch.local)))
            self.send(RECV, sig(0x07, i, struct.pack('<HH', ch.remote, ch.local)))
        else:
            self.send(RECV, sig(0x06, i, struct.pack('<HH', ch.local, ch.remote)))
            self.send(SENT, sig(0x07, i, struct.pack('<HH', ch.local, ch.remote)))


# ---------------------------------------------------------------- SDP

def de_u16(v):
    return b'\x09' + struct.pack('>H', v)


def de_u32(v):
    return b'\x0a' + struct.pack('>I', v)


def de_uuid16(v):
    return b'\x19' + struct.pack('>H', v)


def de_seq(*items):
    body = b''.join(items)
    return b'\x35' + bytes([len(body)]) + body


def sdp_record(handle, uuid, psm):
    return de_seq(
        de_u16(0x0000), de_u32(handle),
        de_u16(0x0001), de_seq(de_uuid16(uuid)),
        de_u16(0x0004), de_seq(de_seq(de_uuid16(0x0100), de_u16(psm))),
    )


def sdp_ssa(tid, records):
    req_params = (de_seq(de_uuid16(0x0100)) + struct.pack('>H', 0x0200) +
                  de_seq(de_u32(0x0000FFFF)) + b'\x00')
    req = struct.pack('>BHH', 0x06, tid, len(req_params)) + req_params
    lists = de_seq(*records)
    rsp_params = struct.pack('>H', len(lists)) + lists + b'\x00'
    rsp = struct.pack('>BHH', 0x07, tid, len(rsp_params)) + rsp_params
    return req, rsp


# ---------------------------------------------------------------- payloads

def hid_data(report):
    return b'\xa1' + report           # HID DATA, input report


ATT_READ_REQ = b'\x0a\x03\x00'        # ATT Read Request, handle 0x0003
ATT_READ_RSP = b'\x0b\x42\x43'        # ATT Read Response


# ---------------------------------------------------------------- BTLE LL

def crc24(data, init):
    """Bluetooth LE link layer CRC (poly 0x00065B), bits sent LSB first."""
    crc = init
    for byte in data:
        for i in range(8):
            bit = (byte >> i) & 1
            fb = ((crc >> 23) & 1) ^ bit
            crc = (crc << 1) & 0xffffff
            if fb:
                crc ^= 0x00065B
    out = 0
    for i in range(24):                 # transmitted MSB of the register first
        out |= ((crc >> (23 - i)) & 1) << i
    return struct.pack('<I', out)[:3]


ADV_AA = 0x8E89BED6
LE_AA = 0x50654A1B
LE_CRC_INIT = 0x555555


def le_ll(aa, pdu, crc_init, rf_channel, direction=None):
    """LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR: pseudo-header, then the
    link layer packet with a valid CRC."""
    flags = 0x0001 | 0x0002 | 0x0010         # dewhitened, signal power and ref AA valid
    flags |= 0x0400 | 0x0800                 # CRC checked and valid
    if direction == 'c2p':
        flags |= 2 << 7                      # data, central to peripheral
    elif direction == 'p2c':
        flags |= 3 << 7                      # data, peripheral to central
    phdr = struct.pack('<BbbBIH', rf_channel, -40, -90, 0, aa, flags)
    pkt = struct.pack('<I', aa) + pdu
    return phdr + pkt + crc24(pdu, crc_init)


def le_connect_ind():
    """CONNECT_IND from the central (11:22:33:44:55:cc) to the peripheral
    (11:22:33:44:55:66), giving the access address and CRC init."""
    lldata = (struct.pack('<I', LE_AA) + struct.pack('<I', LE_CRC_INIT)[:3] +
              struct.pack('<BHHHH', 2, 6, 24, 0, 400) + b'\xff\xff\xff\xff\x1f' + bytes([0x25]))
    payload = LE_ADDR + BD_ADDR + lldata
    hdr = struct.pack('<BB', 0x05 | 0x40 | 0x80, len(payload))     # CONNECT_IND, TxAdd, RxAdd random
    return hdr + payload


def le_data(llid, sn, nesn, payload):
    return struct.pack('<BB', llid | (nesn << 2) | (sn << 3), len(payload)) + payload


# ---------------------------------------------------------------- main capture

def main_capture():
    c = Pcapng()
    m = {}
    m['conn'] = c.add(conn_complete())                       # BR/EDR handle 1
    c.add(le_conn_complete())                                 # LE handle 0x40
    s = Sig(c)
    le = Sig(c, H_LE, LESIG)

    # --- Information, Echo, Command Reject
    m['info'] = s.send(SENT, sig(0x0A, 1, struct.pack('<H', 1)),
                       sig(0x0A, 2, struct.pack('<H', 2)),
                       sig(0x0A, 3, struct.pack('<H', 3)),
                       sig(0x0A, 4, struct.pack('<H', 9)))
    s.send(RECV, sig(0x0B, 1, struct.pack('<HHH', 1, 0, 672)))
    s.send(RECV, sig(0x0B, 2, struct.pack('<HHI', 2, 0, 0x3FF)))
    s.send(RECV, sig(0x0B, 3, struct.pack('<HHII', 3, 0, 0xBE, 0x80000000)))
    s.send(RECV, sig(0x0B, 4, struct.pack('<HH', 9, 0) + b'\x01\x02\x03'))
    s.send(RECV, sig(0x0B, 5, struct.pack('<HH', 2, 1)))     # Not Supported, no data
    s.send(RECV, sig(0x0B, 6, struct.pack('<HHI', 2, 0, 0x0A5)))
    m['echo'] = s.send(SENT, sig(0x08, 7, b'ping'))
    s.send(RECV, sig(0x09, 7, b'pong'))
    m['rej'] = s.send(RECV, sig(0x01, 8, struct.pack('<H', 0)),
                      sig(0x01, 9, struct.pack('<HH', 1, 48)),
                      sig(0x01, 10, struct.pack('<HHH', 2, 0x0050, 0x0051)),
                      sig(0x01, 11, struct.pack('<H', 7)))
    s.ident = 20

    # --- SDP channel, announces two remote HID records on dynamic PSMs
    m['sdp'] = c.count + 1
    sdp = s.connect(PSM_SDP, 0x0040, 0x0041)
    s.configure(sdp, out_opts=opt_mtu(672), in_opts=opt_mtu(672))
    req, rsp = sdp_ssa(1, [sdp_record(0x10001, 0x1124, PSM_HIDDYN),
                           sdp_record(0x10002, 0x1124, PSM_LEHID)])
    sdp.b(SENT, req)
    m['sdp_rsp'] = sdp.b(RECV, rsp)
    # The remote device reads our HID record (PSM 0x1015)
    req, rsp = sdp_ssa(2, [sdp_record(0x10003, 0x1124, PSM_LOCAL)])
    sdp.b(RECV, req)
    sdp.b(SENT, rsp)

    # --- ERTM channel on the remote HID PSM: all configuration options
    m['ertm'] = c.count + 1
    ertm = s.connect(PSM_HIDDYN, 0x0042, 0x0043)
    qos = opt(0x03, struct.pack('<BBIIIII', 0, 2, 1000, 2000, 3000, 4000, 5000))
    efs = opt(0x06, struct.pack('<BBHIII', 1, 1, 672, 10000, 20000, 30000))
    m['config_all'] = c.count + 1
    s.configure(ertm,
                out_opts=(opt_mtu(1000) + opt(0x02, struct.pack('<H', 0xFFFF)) + qos +
                          opt_rfc(3) + opt_fcs(1) + efs + opt_ews(32) +
                          opt(0x0B, b'\x00\x01') + opt(0x0C, b'')),
                in_opts=opt_rfc(3) + opt_fcs(1))
    # A Configure Response with options and a continuation Configure Request
    i = s.next_ident()
    m['config_rsp_opts'] = s.send(SENT, sig(0x04, i, struct.pack('<HH', ertm.remote, 1) + opt_rfc(3)))
    s.send(RECV, sig(0x05, i, struct.pack('<HHH', ertm.local, 1, 4) + opt_mtu(672) + opt_rfc(3)))
    m['ertm_unseg'] = ertm.f(SENT, ctl_enh_i(0) + hid_data(b'\x05\x02\x03'))
    m['ertm_start'] = ertm.f(SENT, ctl_enh_i(1, sar=1) + struct.pack('<H', 12) + hid_data(b'\x10\x11\x12'))
    m['ertm_cont'] = ertm.f(SENT, ctl_enh_i(2, sar=3) + b'\x13\x14\x15\x16')
    m['ertm_end'] = ertm.f(SENT, ctl_enh_i(3, sar=2) + b'\x17\x18\x19\x1a')
    m['ertm_rr'] = ertm.f(RECV, ctl_enh_s(0, reqseq=4))
    ertm.f(RECV, ctl_enh_s(1, reqseq=4, p=1))                # REJ
    ertm.f(RECV, ctl_enh_s(2, reqseq=4, f=1))                # RNR
    ertm.f(RECV, ctl_enh_s(3, reqseq=4))                     # SREJ
    ertm.f(RECV, ctl_enh_i(0, reqseq=4) + hid_data(b'\x20'))
    # reproducer btl2cap_sdu_alloc.py: SDU length larger than what arrived,
    # grown by each continuation
    m['ertm_alloc'] = ertm.f(SENT, ctl_enh_i(4, sar=1) + struct.pack('<H', 300) + hid_data(b'A' * 49))
    for k in range(4):
        ertm.f(SENT, ctl_enh_i(5 + k, sar=3) + bytes([0x30 + k]) * 50)
    m['ertm_alloc_end'] = ertm.f(SENT, ctl_enh_i(9, sar=2) + b'Z' * 50)

    # --- Retransmission mode (we send) and Flow Control mode (remote sends)
    #     on HID Control (a fixed PSM): standard control field
    m['rtx'] = c.count + 1
    rtx = s.connect(PSM_HID_CTRL, 0x0044, 0x0045)
    s.configure(rtx, out_opts=opt_rfc(1), in_opts=opt_rfc(2))
    m['rtx_i'] = rtx.f(SENT, ctl_std_i(0, r=1) + hid_data(b'\x05'))
    rtx.f(SENT, ctl_std_i(1, sar=1) + struct.pack('<H', 5) + hid_data(b'\x06'))
    rtx.f(SENT, ctl_std_i(2, sar=2) + b'\x07\x08\x09')
    rtx.f(RECV, ctl_std_s(0, reqseq=3))
    rtx.f(RECV, ctl_std_s(1, reqseq=3, r=1))
    rtx.f(RECV, ctl_std_i(0, reqseq=3) + hid_data(b'\x0a'))

    # --- Streaming mode with Extended Window Size 0: extended (4-octet)
    #     control field (reproducer btl2cap_ext_control_len.py)
    m['ext'] = c.count + 1
    ext = s.connect(0x1001, 0x0046, 0x0047)
    s.configure(ext, out_opts=opt_rfc(4, 0, 0, 0, 0, 1000) + opt_ews(0),
                in_opts=opt_rfc(4, 0, 0, 0, 0, 1000) + opt_ews(0))
    m['ext_unseg'] = ext.f(SENT, ctl_ext_i(0) + b'HELLOWORLD')
    m['ext_start'] = ext.f(SENT, ctl_ext_i(1, sar=1) + struct.pack('<H', 15) + b'HELLO')
    ext.f(SENT, ctl_ext_i(2, sar=3) + b'-WIDE')
    m['ext_end'] = ext.f(SENT, ctl_ext_i(3, sar=2) + b'-WORLD'[1:])
    m['ext_s'] = ext.f(RECV, ctl_ext_s(0, reqseq=4))
    ext.f(RECV, ctl_ext_s(1, reqseq=4, p=1, f=1))
    ext.f(RECV, ctl_ext_i(0, reqseq=4) + b'ACK')

    # --- Streaming mode with a non-zero Extended Window Size: enhanced
    #     control field
    m['strm'] = c.count + 1
    strm = s.connect(0x1003, 0x0048, 0x0049)
    s.configure(strm, out_opts=opt_rfc(4, 0, 0, 0, 0, 1000) + opt_ews(10))
    m['strm_i'] = strm.f(SENT, ctl_enh_i(0) + b'stream')
    strm.f(SENT, ctl_enh_i(1, sar=1) + struct.pack('<H', 8) + b'stre')
    m['strm_end'] = strm.f(SENT, ctl_enh_i(2, sar=2) + b'am!!')

    # --- Basic mode, dynamic PSM without SDP record; an MTU option with a
    #     length of 4 followed by an FCS option (reproducer
    #     btl2cap_sig_cmd_bounds.py frame 2); disconnected by us, then data
    #     after the disconnection
    m['basic'] = c.count + 1
    basic = s.connect(0x1005, 0x004A, 0x004B)
    m['opt_len4'] = c.count + 1
    s.configure(basic, out_opts=opt(0x01, struct.pack('<HH', 672, 0xBEEF)) + opt_fcs(0),
                in_opts=b'')
    m['basic_data'] = basic.b(SENT, b'basic mode payload')
    basic.b(RECV, b'basic mode reply')
    m['basic_disc'] = c.count + 1
    s.disconnect(basic)
    m['after_disc'] = basic.b(SENT, b'late')

    # --- The remote device connects to our HID record PSM; it disconnects
    m['local'] = c.count + 1
    loc = s.connect(PSM_LOCAL, 0x004C, 0x0070, outgoing=False)
    m['local_data'] = loc.b(RECV, hid_data(b'\x41\x42'))
    loc.b(SENT, hid_data(b'\x43'))
    m['local_disc'] = c.count + 1
    s.disconnect(loc, outgoing=False)

    # --- SDP data and disconnection (known PSM, outgoing)
    sdp.b(SENT, sdp_ssa(3, [])[0])
    m['sdp_disc'] = c.count + 1
    s.disconnect(sdp)

    # --- ERTM channel disconnected by the remote device (service name
    #     from the SDP record)
    m['ertm_disc'] = c.count + 1
    s.disconnect(ertm, outgoing=False)

    # --- AMP: Create Channel, Move Channel
    m['create'] = c.count + 1
    amp = s.connect(0x1007, 0x004E, 0x004F, code=0x0C, ctrl=1)
    amp.b(SENT, b'on AMP')
    i = s.next_ident()
    m['move'] = s.send(SENT, sig(0x0E, i, struct.pack('<HB', amp.local, 0)))
    s.send(RECV, sig(0x0F, i, struct.pack('<HH', amp.local, 1)))
    s.send(RECV, sig(0x0F, i, struct.pack('<HH', amp.local, 0)))
    s.send(SENT, sig(0x10, i + 1, struct.pack('<HH', amp.local, 0)))
    s.send(RECV, sig(0x11, i + 1, struct.pack('<H', amp.local)))
    s.send(SENT, sig(0x0E, i + 2, struct.pack('<HB', amp.local, 1)),
           sig(0x0E, i + 3, struct.pack('<HB', amp.local, 7)))
    s.send(RECV, sig(0x0F, i + 2, struct.pack('<HH', amp.local, 9)),
           sig(0x10, i + 3, struct.pack('<HH', amp.local, 1)),
           sig(0x10, i + 4, struct.pack('<HH', amp.local, 5)))
    s.ident = i + 4

    # --- A Connection Request left unanswered, then abandoned with a
    #     Disconnection Request (no remote CID known)
    i = s.next_ident()
    m['abandon'] = s.send(SENT, sig(0x02, i, struct.pack('<HH', 0x100B, 0x0058)))
    i = s.next_ident()
    m['abandon_disc'] = s.send(SENT, sig(0x06, i, struct.pack('<HH', 0x0000, 0x0058)))

    # --- Connection Responses: pending, refused, unknown result
    i = s.next_ident()
    m['refused'] = s.send(SENT, sig(0x02, i, struct.pack('<HH', 0x0009, 0x0050)))
    s.send(RECV, sig(0x03, i, struct.pack('<HHHH', 0x0000, 0x0050, 1, 2)))
    s.send(RECV, sig(0x03, i, struct.pack('<HHHH', 0x0000, 0x0050, 3, 0)))
    s.send(RECV, sig(0x03, i, struct.pack('<HHHH', 0x0000, 0x0050, 0x77, 0)))
    s.send(RECV, sig(0x0D, i, struct.pack('<HHHH', 0x0000, 0x0050, 5, 0)))

    # --- L2CAP Credit Based Connection on BR/EDR: two channels on the
    #     remote HID PSM, LE-frames with SDU reassembly
    i = s.next_ident()
    m['ecred'] = s.send(SENT, sig(0x17, i, struct.pack('<HHHH', PSM_HIDDYN, 100, 64, 5) +
                                  struct.pack('<HH', 0x0060, 0x0061)))
    s.send(RECV, sig(0x18, i, struct.pack('<HHHH', 100, 64, 5, 0) + struct.pack('<HH', 0x0080, 0x0081)))
    e1 = Chan(c, 0x0060, 0x0080)
    e2 = Chan(c, 0x0061, 0x0081)
    m['ecred_sdu'] = e1.b(SENT, struct.pack('<H', 3) + hid_data(b'\x51\x52'))
    m['ecred_first'] = e2.b(RECV, struct.pack('<H', 9) + hid_data(b'\x61\x62'))
    e2.b(RECV, b'\x63\x64\x65')
    m['ecred_last'] = e2.b(RECV, b'\x66\x67\x68')
    m['ecred_disc'] = c.count + 1
    s.disconnect(e1)
    # The remote device opens an L2CAP Credit Based channel to us
    i = s.next_ident()
    m['ecred_in'] = s.send(RECV, sig(0x17, i, struct.pack('<HHHH', 0x1009, 100, 64, 5) +
                                     struct.pack('<H', 0x0090)))
    s.send(SENT, sig(0x18, i, struct.pack('<HHHH', 100, 64, 5, 0) + struct.pack('<H', 0x0062)))
    Chan(c, 0x0062, 0x0090).b(RECV, struct.pack('<H', 2) + b'in')


    # --- Connectionless channel: fixed PSM, remote and local HID record
    #     PSMs, unknown PSM
    m['connless'] = c.add(acl(SENT, l2(CONNLESS, struct.pack('<H', PSM_HID_CTRL) + hid_data(b'\x71'))))
    c.add(acl(SENT, l2(CONNLESS, struct.pack('<H', PSM_HIDDYN) + hid_data(b'\x72'))))
    c.add(acl(RECV, l2(CONNLESS, struct.pack('<H', PSM_LOCAL) + hid_data(b'\x73'))))
    c.add(acl(RECV, l2(CONNLESS, struct.pack('<H', 0x1101) + b'connectionless')))

    # --- Fixed channels: AMP Manager I-frame (FCS over header and control
    #     only, as packet-btl2cap.c checks it) and S-frame, BR/EDR SMP,
    #     reserved fixed CID, a dynamic CID without a connection
    amp_cmd = struct.pack('<BBHHH', 0x02, 1, 4, 670, 0)      # AMP Discover Request
    hdr = struct.pack('<HH', 2 + len(amp_cmd) + 2, AMP) + ctl_std_i(0)
    m['amp_i'] = c.add(acl(SENT, hdr + amp_cmd + struct.pack('<H', crc16(hdr))))
    m['amp_s'] = c.add(acl(RECV, l2_fcs(AMP, ctl_std_s(0, reqseq=1))))
    m['brsmp'] = c.add(acl(SENT, l2(BRSMP, b'\x0b\x01')))   # SMP Security Request
    m['reserved'] = c.add(acl(SENT, l2(0x0020, b'reserved fixed')))
    m['unknown_cid'] = c.add(acl(SENT, l2(0x0099, b'no connection')))

    # --- Exported PDUs (no ACL data, no direction): Echo Request and a
    #     connectionless frame
    m['exp'] = c.add(exp_pdu('btl2cap', l2(SIG, sig(0x08, 0x30, b'exp'))), LT_EXP_PDU)
    c.add(exp_pdu('btl2cap', l2(CONNLESS, struct.pack('<H', 0x1101) + b'exported')), LT_EXP_PDU)

    # --- LE signalling
    m['le_param'] = le.send(RECV, sig(0x12, 1, struct.pack('<HHHH', 24, 40, 0, 400)))
    le.send(SENT, sig(0x13, 1, struct.pack('<H', 0)))
    m['le_param_bad'] = le.send(RECV, sig(0x12, 2, struct.pack('<HHHH', 6, 8, 499, 10)))
    le.send(SENT, sig(0x13, 2, struct.pack('<H', 1)))
    le.send(SENT, sig(0x13, 3, struct.pack('<H', 5)))
    m['le_rej'] = le.send(RECV, sig(0x01, 4, struct.pack('<H', 0)))
    m['le_unknown'] = le.send(RECV, sig(0x1C, 5, b'\x01\x02'))
    # LE Credit Based Connection on an LE PSM that the SDP record also
    # names (same peer address), and on the EATT PSM
    m['lecred'] = le.send(SENT, sig(0x14, 6, struct.pack('<HHHHH', PSM_LEHID, 0x0040, 100, 23, 4)))
    le.send(RECV, sig(0x15, 6, struct.pack('<HHHHH', 0x0050, 100, 23, 4, 0)))
    lec = Chan(c, 0x0040, 0x0050, H_LE)
    m['le_sdu'] = lec.b(SENT, struct.pack('<H', 4) + hid_data(b'\x81\x82\x83'))
    m['le_first'] = lec.b(RECV, struct.pack('<H', 7) + hid_data(b'\x91\x92'))
    lec.b(RECV, b'\x93\x94')
    m['le_last'] = lec.b(RECV, b'\x95\x96')
    m['le_credit'] = le.send(RECV, sig(0x16, 7, struct.pack('<HH', 0x0050, 10)))
    le.send(RECV, sig(0x14, 8, struct.pack('<HHHHH', 0x0027, 0x0051, 64, 64, 2)))
    le.send(SENT, sig(0x15, 8, struct.pack('<HHHHH', 0x0041, 64, 64, 2, 0)))
    eatt = Chan(c, 0x0041, 0x0051, H_LE)
    m['eatt'] = eatt.b(RECV, struct.pack('<H', 3) + ATT_READ_REQ)
    eatt.b(SENT, struct.pack('<H', 3) + ATT_READ_RSP)
    le.send(SENT, sig(0x14, 9, struct.pack('<HHHHH', 0x0080, 0x0042, 64, 64, 2)))
    le.send(RECV, sig(0x15, 9, struct.pack('<HHHHH', 0x0000, 0, 0, 0, 2)))
    # reproducer btl2cap_sig_cmd_bounds.py frame 1: two L2CAP Credit Based
    # Connection Requests in one signalling PDU
    m['ecred2'] = le.send(SENT, sig(0x17, 10, struct.pack('<HHHH', 0x0081, 100, 100, 5) +
                                    struct.pack('<HH', 0x0043, 0x0044)),
                          sig(0x17, 11, struct.pack('<HHHH', 0x0027, 100, 100, 5) +
                              struct.pack('<HH', 0x0045, 0x0046)))
    le.send(RECV, sig(0x18, 10, struct.pack('<HHHH', 100, 100, 5, 0) + struct.pack('<HH', 0x0052, 0x0053)),
            sig(0x18, 11, struct.pack('<HHHH', 100, 100, 5, 0) + struct.pack('<HH', 0x0054, 0x0055)))
    ec = Chan(c, 0x0046, 0x0055, H_LE)
    m['ecred2_data'] = ec.b(SENT, struct.pack('<H', 3) + ATT_READ_REQ)
    ec.b(RECV, struct.pack('<H', 3) + ATT_READ_RSP)
    m['att'] = c.add(acl(SENT, l2(ATT, ATT_READ_REQ), H_LE))
    c.add(acl(RECV, l2(ATT, ATT_READ_RSP), H_LE))
    m['smp'] = c.add(acl(RECV, l2(SMP, b'\x0b\x01'), H_LE))
    m['le_disc'] = le.send(SENT, sig(0x06, 12, struct.pack('<HH', 0x0050, 0x0040)))
    le.send(RECV, sig(0x07, 12, struct.pack('<HH', 0x0050, 0x0040)))

    # --- Bluetooth LE link layer: CONNECT_IND, L2CAP signalling and an LE
    #     Credit Based channel seen at the link layer, with a link layer
    #     retransmission of an LE-frame
    m['ll'] = c.add(le_ll(ADV_AA, le_connect_ind(), 0x555555, 0), LT_LE_LL)
    sn = {'c2p': 0, 'p2c': 0}
    nesn = {'c2p': 0, 'p2c': 0}

    def ll(direction, llid, payload, retransmit=False):
        if retransmit:
            sn[direction] ^= 1
        pkt = le_data(llid, sn[direction], nesn[direction], payload)
        other = 'p2c' if direction == 'c2p' else 'c2p'
        sn[direction] ^= 1
        nesn[other] ^= 1
        return c.add(le_ll(LE_AA, pkt, LE_CRC_INIT, 5, direction), LT_LE_LL)

    ll('c2p', 2, l2(LESIG, sig(0x14, 1, struct.pack('<HHHHH', 0x0080, 0x0040, 100, 23, 4))))
    ll('p2c', 2, l2(LESIG, sig(0x15, 1, struct.pack('<HHHHH', 0x0060, 100, 23, 4, 0))))
    m['ll_sdu'] = ll('c2p', 2, l2(0x0060, struct.pack('<H', 6) + b'abcd'))
    m['ll_retx'] = ll('c2p', 2, l2(0x0060, struct.pack('<H', 6) + b'abcd'), retransmit=True)
    ll('c2p', 2, l2(0x0060, b'ef'))
    return c, m


# ---------------------------------------------------------------- malformed

class Pcap(Pcapng):
    """pcap (H4 with direction only): no interface ID in the records."""

    def __init__(self):
        self.frames = []
        self.ts = 1700000000 * 1000000
        self.count = 0

    def add(self, data, linktype=LT_H4, caplen=None):
        assert linktype == LT_H4
        self.ts += 1000
        if caplen is None:
            caplen = len(data)
        self.frames.append(struct.pack('<IIII', self.ts // 1000000, self.ts % 1000000,
                                       caplen, len(data)) + data[:caplen])
        self.count += 1
        return self.count

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, LT_H4))
            f.write(b''.join(self.frames))


def malformed_capture():
    c = Pcap()
    c.add(conn_complete())
    c.add(le_conn_complete())
    s = Sig(c)
    le = Sig(c, H_LE, LESIG)
    ertm = s.connect(0x1001, 0x0040, 0x0041)
    s.configure(ertm, out_opts=opt_rfc(3), in_opts=opt_rfc(3))
    # Valid commands, so that a capture without interface IDs (pcap) runs
    # every state-tracking function: Configure Response with options, L2CAP
    # Credit Based Connection, Disconnection
    s.send(RECV, sig(0x05, 0x60, struct.pack('<HHH', 0x0040, 0, 0) + opt_mtu(672)))
    s.send(SENT, sig(0x17, 0x61, struct.pack('<HHHH', 0x1003, 100, 100, 5) + struct.pack('<H', 0x0050)))
    s.send(RECV, sig(0x18, 0x61, struct.pack('<HHHH', 100, 100, 5, 0) + struct.pack('<H', 0x0060)))
    Chan(c, 0x0050, 0x0060).b(SENT, struct.pack('<H', 2) + b'ok')
    t = s.connect(0x1005, 0x0052, 0x0062)
    s.disconnect(t)
    # SAR=Start with a length that leaves no room for the SDU length (throws)
    ertm.raw(SENT, struct.pack('<HH', 6, 0x0041) + ctl_enh_i(0, sar=1) + b'\x10\x00\x00\x00')
    # SAR=Start with an SDU length shorter than the payload (warning)
    ertm.f(SENT, ctl_enh_i(1, sar=1) + struct.pack('<H', 2) + b'abcdef')
    # Unsegmented I-frame without room for the FCS (throws)
    ertm.raw(SENT, struct.pack('<HH', 4, 0x0041) + ctl_enh_i(2) + b'\x00\x00')
    # Bad FCS on an I-frame and on an S-frame
    ertm.f(SENT, ctl_enh_i(3) + b'bad fcs', bad_fcs=True)
    ertm.f(RECV, ctl_enh_s(0), bad_fcs=True)
    # Continuation without a start, a start then an end that overflows,
    # an end that leaves the SDU short
    ertm.f(RECV, ctl_enh_i(0, sar=3) + b'orphan')
    ertm.f(SENT, ctl_enh_i(4, sar=1) + struct.pack('<H', 6) + b'abc')
    ertm.f(SENT, ctl_enh_i(5, sar=2) + b'defghij')
    ertm.f(SENT, ctl_enh_i(6, sar=1) + struct.pack('<H', 10) + b'abc')
    ertm.f(SENT, ctl_enh_i(7, sar=2) + b'de')
    # AMP Manager I-frame without room for the FCS
    c.add(acl(SENT, l2(AMP, ctl_std_i(0) + b'\x00\x00')))
    # Truncated signalling commands
    for code, data in ((0x01, b'\x01\x00'), (0x01, b'\x02\x00\x40'), (0x02, b'\x01'),
                       (0x03, b'\x40\x00'), (0x04, b'\x40\x00\x00\x00\x01\x02\x00'),
                       (0x0A, b''), (0x0B, b'\x02\x00\x00\x00\x01'),
                       (0x0B, b'\x03\x00\x00\x00\x01\x00\x00\x00'), (0x0E, b'\x40'),
                       (0x12, b'\x06\x00\x08\x00'), (0x14, b'\x80\x00\x40\x00'),
                       (0x15, b'\x40\x00'), (0x16, b'\x40\x00'), (0x17, b'\x81\x00\x64\x00'),
                       (0x18, b'\x64\x00'), (0x08, b'')):
        s.send(SENT, sig(code, 0x70, data))
    # Information Response with type 1 and only one octet of MTU
    s.send(RECV, sig(0x0B, 0x71, struct.pack('<HH', 1, 0) + b'\x01'))
    # Unknown command code without data
    s.send(RECV, sig(0x1F, 0x72, b''))
    # L2CAP Credit Based Connection Request with an odd SCID list length
    s.send(SENT, sig(0x17, 0x73, struct.pack('<HHHH', 0x1011, 100, 100, 5) + b'\x60'))
    # Configure Request with an option running past the PDU
    s.send(RECV, sig(0x04, 0x74, struct.pack('<HH', 0x0040, 0) + b'\x04\x09\x03'))
    # Connection Parameter Update Request with a zero maximum interval
    le.send(RECV, sig(0x12, 1, struct.pack('<HHHH', 6, 0, 0, 10)))
    # LE Credit Based channel on LE PSM 0 (no PSM): SDU length below the
    # payload (warning), a first frame shorter than the SDU length field,
    # and a basic-mode channel on PSM 0
    le.send(SENT, sig(0x14, 2, struct.pack('<HHHHH', 0x0000, 0x0040, 100, 23, 4)))
    le.send(RECV, sig(0x15, 2, struct.pack('<HHHHH', 0x0050, 100, 23, 4, 0)))
    lec = Chan(c, 0x0040, 0x0050, H_LE)
    lec.b(SENT, struct.pack('<H', 1) + b'abc')
    lec.b(SENT, b'\x01')
    lec.b(SENT, struct.pack('<H', 3) + b'xyz')
    z = s.connect(0x0000, 0x0042, 0x0043)
    z.b(SENT, b'psm zero')
    s.configure(z, out_opts=opt_rfc(3))
    z.f(SENT, ctl_enh_i(0) + b'psm zero ertm')
    z.f(SENT, ctl_enh_i(1, sar=1) + struct.pack('<H', 6) + b'abc')
    z.f(SENT, ctl_enh_i(2, sar=2) + b'def')
    # reproducer btl2cap_config_state_2pass.py: reconfiguring the mode of
    # a channel after data has flowed on it (output differs with -2)
    cs = s.connect(0x1003, 0x0044, 0x0045)
    s.configure(cs, out_opts=opt_rfc(3))
    cs.f(SENT, ctl_enh_i(0) + b'HELLOWORLD')
    s.configure(cs, out_opts=b'')
    # Truncated frame (captured length shorter than the ACL length)
    c.add(acl(SENT, l2(SIG, sig(0x0A, 0x75, struct.pack('<H', 2)))), caplen=15)
    return c


def malformed_exp_capture():
    """Exported PDUs straight to btl2cap: Bluetooth HCI ACL would hold
    back a frame whose L2CAP length is longer than the ACL data."""
    c = Pcapng()
    # L2CAP length longer than the frame
    c.add(exp_pdu('btl2cap', struct.pack('<HH', 40, SIG) + sig(0x08, 1, b'short')), LT_EXP_PDU)
    # Connectionless with a length shorter than the PSM
    c.add(exp_pdu('btl2cap', l2(CONNLESS, b'\x01\x00', length=1)), LT_EXP_PDU)
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    c, m = main_capture()
    c.write(os.path.join(out, 'btl2cap-coverage.pcapng'))
    malformed_capture().write(os.path.join(out, 'btl2cap-coverage-malformed.pcap'))
    malformed_exp_capture().write(os.path.join(out, 'btl2cap-coverage-malformed-exp.pcapng'))
    for k, v in m.items():
        print('%-16s %d' % (k, v))


if __name__ == '__main__':
    main()
