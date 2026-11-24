#!/usr/bin/env python3
# Generates test/captures/mausb_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the MAUSB dissector
(packet-mausb.c, Media Agnostic USB). MAUSB is reached by default through
802.2 LLC/SNAP with the Wi-Fi Alliance OUI (50:6f:9a) and PID 0x1500. The
TCP and UDP paths have no default port (Decode As).

Usage: mkmausb.py <output directory> [-v]
Writes
  mausb-coverage.pcapng            main capture (LLC/SNAP, default prefs)
  mausb-coverage-decodeas.pcapng   TCP port 8000 (-d tcp.port==8000,mausb)
                                   and UDP port 8001 (-d udp.port==8001,mausb)
  mausb-coverage-malformed.pcapng  paths only malformed input reaches
"""
import struct
import sys

LT_ETH = 1
LT_EXPPDU = 252


def pcapng(path, frames, extra_lt=()):
    """frames: list of (interface, bytes). Interface 0 is Ethernet, 1 is
    Exported PDU, 2.. the link types in extra_lt. 10 ms per frame."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (LT_ETH, LT_EXPPDU) + tuple(extra_lt):
        out += block(1, struct.pack('<HHI', lt, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def mac(addr):
    return bytes([2, 0]) + ip4(addr)


IDENT = [0]


def ipv4(proto, payload, src, dst):
    IDENT[0] += 1
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IDENT[0] & 0xffff,
                      0x4000, 64, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + hdr + payload


def udp(payload, src, sport, dst, dport):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return (0, ipv4(17, u, src, dst))


class TCP:
    """A TCP connection; c2s()/s2c() return frames carrying data."""

    def __init__(self, cli, cport, srv, sport):
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.cseq, self.sseq = 1000, 5000

    def seg(self, payload, to_server, flags=0x18, seq=None):
        if to_server:
            src, sp, dst, dp = self.cli, self.cport, self.srv, self.sport
            s, a = self.cseq, self.sseq
        else:
            src, sp, dst, dp = self.srv, self.sport, self.cli, self.cport
            s, a = self.sseq, self.cseq
        if seq is not None:
            s = seq
        opts = b''
        if flags & 0x02:
            opts = b'\x02\x04\x05\xb4'
            if not flags & 0x10:
                a = 0
        t = struct.pack('!HHIIBBHHH', sp, dp, s & 0xffffffff, a & 0xffffffff,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return (0, ipv4(6, t, src, dst))

    def handshake(self):
        f = [self.seg(b'', True, 0x02)]
        self.cseq += 1
        f.append(self.seg(b'', False, 0x12))
        self.sseq += 1
        f.append(self.seg(b'', True, 0x10))
        return f

    def c2s(self, payload):
        f = self.seg(payload, True)
        self.cseq += len(payload)
        return f

    def s2c(self, payload):
        f = self.seg(payload, False)
        self.sseq += len(payload)
        return f


def exported_pdu(proto_name, payload):
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad
    tags += struct.pack('!HH', 0, 0)
    return (1, tags + payload)


def u16(v): return struct.pack('<H', v)
def u32(v): return struct.pack('<I', v)
def u64(v): return struct.pack('<Q', v)
def b16(v): return struct.pack('>H', v)
def b32(v): return struct.pack('>I', v)
# ---- end of prelude ----

# ------------------------------------------------------------ MAUSB

HOST = 0x10
RETRY = 0x20
TSTAMP = 0x40
RSVD = 0x80

# management packet types
(CapReq, CapResp, USBDevHandleReq, USBDevHandleResp, EPHandleReq, EPHandleResp,
 EPActivateReq, EPActivateResp, EPInactivateReq, EPInactivateResp, EPResetReq,
 EPResetResp, ClearTransfersReq, ClearTransfersResp, EPHandleDeleteReq,
 EPHandleDeleteResp) = range(0x00, 0x10)
(DevResetReq, DevResetResp, ModifyEP0Req, ModifyEP0Resp, SetUSBDevAddrReq,
 SetUSBDevAddrResp, UpdateDevReq, UpdateDevResp, USBDevDisconnectReq,
 USBDevDisconnectResp, USBSuspendReq, USBSuspendResp, USBResumeReq, USBResumeResp,
 RemoteWakeReq, RemoteWakeResp) = range(0x10, 0x20)
(PingReq, PingResp, DevDisconnectReq, DevDisconnectResp, DevInitDisconnectReq,
 DevInitDisconnectResp, SynchReq, SynchResp, CancelTransferReq, CancelTransferResp,
 EPOpenStreamReq, EPOpenStreamResp, EPCloseStreamReq, EPCloseStreamResp,
 USBDevResetReq, USBDevResetResp) = range(0x20, 0x30)
(DevNotificationReq, DevNotificationResp, EPSetKeepAliveReq, EPSetKeepAliveResp,
 GetPortBWReq, GetPortBWResp, SleepReq, SleepResp, WakeReq, WakeResp) = range(0x30, 0x3A)
VendorSpecificReq, VendorSpecificResp = 0x3E, 0x3F
TransferSetupReq, TransferSetupResp, TransferTearDownConf = 0x40, 0x41, 0x42
TransferReq, TransferResp, TransferAck, IsochTransferReq, IsochTransferResp = range(0x80, 0x85)

CTRL, ISO, BULK, INTR = 0, 1, 2, 3


def common(ptype, total, flags, handle, dev, ssid, status, version=0):
    return (bytes([version | flags, ptype]) + u16(total) + u16(handle)
            + bytes([dev, ssid, status]))


def mgmt(ptype, spec=b'', token=1, flags=HOST, handle=0x0001, status=0, dev=1, ssid=0,
         pad=0, length=None, version=0):
    """Management packet: 9 octet common header, 10 bit dialog token,
    14 bit padding (octets 9-11), then the type specific data."""
    t = struct.pack('<H', (token & 0x3ff) | ((pad & 0x3fff) << 2)) + bytes([(pad >> 14) & 0xff])
    n = 12 + len(spec) if length is None else length
    return common(ptype, n, flags, handle, dev, ssid, status, version) + t + spec


def ephandle(d=1, ep=1, dev=3, bus=1):
    return u16((d & 1) | ((ep & 0xf) << 1) | ((dev & 0x7f) << 5) | ((bus & 0xf) << 12))


def data(ptype, rest=b'', flags=0, handle=None, eps=1, arq=0, neg=0, eot=0, ttype=BULK,
         trsvd=0, stream=0, seq=0, req=0, credit=0, dev=1, ssid=0, status=0, length=None,
         ihdr=None, ptime=None, version=0):
    """Data packet: 20 octet header. For isochronous packets the 16 bit
    field after the T-flags is the number of headers (12 bits) and the
    I-flags (4 bits), and the last DWORD is the presentation time and the
    number of segments."""
    if handle is None:
        handle = ephandle()
    tf = (eps & 3) | (arq << 2) | (neg << 3) | (eot << 4) | (ttype << 5) | (trsvd << 7)
    if ihdr is not None:
        stream = ihdr
    if ptime is not None:
        credit = ptime
    n = 20 + len(rest) if length is None else length
    h = common(ptype, n, flags, int.from_bytes(handle, 'little'), dev, ssid, status, version)
    return h + bytes([tf]) + u16(stream) + seq.to_bytes(3, 'little') + bytes([req]) + u32(credit) + rest


def llc(mausb, src='192.0.2.1', dst='192.0.2.2'):
    """802.3 + LLC/SNAP with the Wi-Fi Alliance OUI and PID 0x1500."""
    pl = b'\xaa\xaa\x03\x50\x6f\x9a' + b16(0x1500) + mausb
    return (0, mac(dst) + mac(src) + b16(len(pl)) + pl)


# ---- type specific parts

def capdesc(ctype, n=4, fill=0x11):
    return bytes([n, ctype]) + bytes([fill + i for i in range(n - 2)])


def capresp(descs, num_ep=8, num_dev=2, streams=4, devtype=0, treq=16, mreq=7, rsvd=0,
            count=None, dlen=None):
    body = b''.join(descs)
    return (u16(num_ep) + bytes([num_dev, streams | (devtype << 5),
                                 len(descs) if count is None else count])
            + (len(body) if dlen is None else dlen).to_bytes(3, 'little')
            + u16(treq) + u16(mreq | (rsvd << 12)) + body)


def usb_ep_desc(addr, attrs, maxp, interval):
    return bytes([7, 5, addr, attrs]) + u16(maxp) + bytes([interval])


def ss_comp():
    return bytes([6, 0x30, 15, 0, 0, 0])


def ssp_iso_comp():
    return bytes([8, 0x31, 0, 0]) + u32(1024)


def ephandlereq(descs_n, size, count=None):
    """EPHandleReq: 5 bit number, 6 bit descriptor size (bits 5-10) in the
    first two octets, padded to a DWORD, then the endpoint descriptors."""
    eps = []
    for i in range(descs_n):
        if size == 8:
            d = usb_ep_desc(0x81 + i, 3, 64, 4) + b'\0'
        elif size == 16:
            d = usb_ep_desc(0x02 + i, 2, 512, 0) + ss_comp() + b'\0\0\0'
        else:
            d = usb_ep_desc(0x83, 1, 1024, 1) + ss_comp() + ssp_iso_comp() + b'\0\0\0'
        eps.append(d)
    n = descs_n if count is None else count
    return u16(n | (size << 5)) + b'\0\0' + b''.join(eps)


def ephandleresp(handles):
    out = u32(len(handles))
    for i, h in enumerate(handles):
        out += h + bytes([i & 0x0f]) + b'\0' + u16(1 + i) + b'\0\0' + u32(4096 << i) \
            + u16(100 + i) + u16(200 + i)
    return out


def clear_req(blocks):
    out = bytes([len(blocks)]) + b'\0\0\0'
    for i, h in enumerate(blocks):
        out += h + u16(i) + bytes([10 + i]) + b'\0\0\0'
    return out


def clear_resp(blocks):
    out = bytes([len(blocks)]) + b'\0\0\0'
    for i, h in enumerate(blocks):
        out += h + u16(i) + u32(i & 3) + bytes([20 + i]) + (1000 + i).to_bytes(3, 'little') + u32(4096 * i)
    return out


def delete_handles(handles):
    return bytes([len(handles)]) + b'\0\0\0' + b''.join(handles)


def cancel_req(h):
    return h + u16(0) + bytes([7]) + b'\0\0\0'


def cancel_resp(h, status):
    return h + u16(0) + bytes([7]) + bytes([status, 0, 0]) + b'\0' * 8


SETUP_GET_DEV = bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00])
DEVICE_DESC = bytes([0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40]) + u16(0x1d6b) + u16(0x0002) \
    + u16(0x0100) + bytes([1, 2, 3, 1])
A = '192.0.2.1'
B = '192.0.2.2'


def main_frames():
    f = []

    def add(p, src=A, dst=B):
        f.append(llc(p, src, dst))

    # Management: requests from the host, responses from the device
    add(mgmt(CapReq, b'\x01\x02\x03\x04', token=1))
    add(mgmt(CapResp, capresp([capdesc(0, 4), capdesc(1, 6), capdesc(2, 8), capdesc(3, 5),
                               capdesc(4, 18), capdesc(5, 3), capdesc(9, 2), capdesc(7, 10)]),
             token=1, flags=0))
    add(mgmt(CapResp, capresp([], num_ep=1, num_dev=1, streams=0, devtype=1), token=2, flags=0))
    for dt in (2, 3, 7):
        add(mgmt(CapResp, capresp([capdesc(0, 4)], devtype=dt, rsvd=3), token=3, flags=0))
    add(mgmt(USBDevHandleReq, b'\x00\x01\x02\x03\x04\x05\x06\x07', token=4))
    add(mgmt(USBDevHandleResp, b'\x00\x00\x00\x00\x01\x00\x00\x00', token=4, flags=0, handle=0x0002))
    h1, h2, h3 = ephandle(1, 1), ephandle(0, 2, 3, 1), ephandle(1, 15, 127, 15)
    add(mgmt(EPHandleReq, ephandlereq(2, 8), token=5))
    add(mgmt(EPHandleReq, ephandlereq(3, 16), token=6))
    add(mgmt(EPHandleReq, ephandlereq(1, 8), token=7))
    add(mgmt(EPHandleResp, ephandleresp([h1, h2, h3]), token=5, flags=0))
    add(mgmt(EPHandleResp, ephandleresp([]), token=6, flags=0))
    for t in (EPActivateReq, EPInactivateReq, EPResetReq):
        add(mgmt(t, h1 + b'\0\0', token=8))
        add(mgmt(t + 1, h1 + b'\0\0', token=8, flags=0))
    add(mgmt(ClearTransfersReq, clear_req([h1, h2, h3]), token=9))
    add(mgmt(ClearTransfersReq, clear_req([]), token=9))
    add(mgmt(ClearTransfersResp, clear_resp([h1, h2]), token=9, flags=0))
    add(mgmt(ClearTransfersResp, clear_resp([]), token=9, flags=0))
    add(mgmt(EPHandleDeleteReq, delete_handles([h1, h2, h3]), token=10))
    add(mgmt(EPHandleDeleteResp, delete_handles([h1, h2]), token=10, flags=0))
    add(mgmt(EPHandleDeleteReq, delete_handles([]), token=10))
    # generic type specific data
    for t in (ModifyEP0Req, ModifyEP0Resp, SetUSBDevAddrReq, SetUSBDevAddrResp, UpdateDevReq,
              SynchReq, EPOpenStreamReq, EPOpenStreamResp, EPCloseStreamReq, EPCloseStreamResp,
              USBDevResetReq, USBDevResetResp, VendorSpecificReq, VendorSpecificResp):
        add(mgmt(t, b'\xde\xad\xbe\xef\x00\x01\x02\x03', token=11, flags=HOST if t % 2 == 0 else 0))
    # types without additional data
    for t in (DevResetReq, DevResetResp, UpdateDevResp, USBDevDisconnectReq, USBDevDisconnectResp,
              SleepReq, SleepResp, WakeReq, WakeResp, PingReq, PingResp, DevDisconnectReq,
              DevDisconnectResp, DevInitDisconnectReq, DevInitDisconnectResp, SynchResp):
        add(mgmt(t, token=12, flags=HOST if t % 2 == 0 else 0))
    # types with no case in the dissector at all (suspend/resume/notify/keepalive/...)
    # are in the malformed capture ("Undefined management packet type")
    add(mgmt(CancelTransferReq, cancel_req(h1), token=13))
    for st in range(6):
        add(mgmt(CancelTransferResp, cancel_resp(h1, st), token=13, flags=0))
    # status values and flags on a Ping
    for i, st in enumerate([0] + list(range(128, 157))):
        add(mgmt(PingResp, token=100 + i, flags=0, status=st, ssid=i & 3, dev=i + 1))
    add(mgmt(PingReq, token=1023, flags=HOST | RETRY, dev=255, ssid=255))
    add(mgmt(PingReq, token=2, flags=HOST | TSTAMP | RSVD, pad=0x3fff))
    add(mgmt(PingReq, token=2, version=1))        # unknown version
    # Control packets (neither management nor data: only the header)
    add(hdr_ctrl(TransferSetupReq, h1))
    add(hdr_ctrl(TransferSetupResp, h1, flags=0))
    add(hdr_ctrl(TransferTearDownConf, h1))
    # Data packets: control transfer with setup data (seq 0, from host)
    ep0 = ephandle(0, 0, 3, 1)
    ep0in = ephandle(1, 0, 3, 1)
    add(data(TransferReq, SETUP_GET_DEV, flags=HOST, handle=ep0, ttype=CTRL, seq=0, req=1,
             credit=18, eot=1))
    add(data(TransferResp, DEVICE_DESC, flags=0, handle=ep0in, ttype=CTRL, seq=0, req=1,
             eps=2, eot=1), src=B, dst=A)
    add(data(TransferAck, b'', flags=0, handle=ep0in, ttype=CTRL, seq=1, req=1, credit=64), src=B, dst=A)
    # set address (no data stage), status stage response
    add(data(TransferReq, bytes([0x00, 0x05, 0x04, 0x00, 0, 0, 0, 0]), flags=HOST, handle=ep0,
             ttype=CTRL, seq=0, req=2))
    add(data(TransferResp, b'', flags=0, handle=ep0in, ttype=CTRL, seq=0, req=2, eot=1, eps=3), src=B, dst=A)
    # control OUT with data stage in later packets (seq != 0)
    add(data(TransferReq, b'\x01\x02\x03\x04', flags=HOST, handle=ep0, ttype=CTRL, seq=1, req=3, arq=1))
    # bulk OUT and IN
    bo, bi = ephandle(0, 2, 3, 1), ephandle(1, 1, 3, 1)
    add(data(TransferReq, b'bulk out data' * 4, flags=HOST, handle=bo, ttype=BULK, seq=0, req=4,
             stream=7, credit=52, eot=1, arq=1))
    add(data(TransferResp, b'', flags=0, handle=bo, ttype=BULK, seq=0, req=4, stream=7, status=0, eot=1),
        src=B, dst=A)
    add(data(TransferReq, b'', flags=HOST, handle=bi, ttype=BULK, seq=0, req=5, credit=512, neg=1))
    add(data(TransferResp, b'bulk in data', flags=0, handle=bi, ttype=BULK, seq=0, req=5, eot=1, status=141),
        src=B, dst=A)
    add(data(TransferResp, b'x' * 20, flags=RETRY, handle=bi, ttype=BULK, seq=1, req=5, status=136, trsvd=1),
        src=B, dst=A)
    # interrupt IN
    ii = ephandle(1, 3, 3, 1)
    add(data(TransferReq, b'', flags=HOST, handle=ii, ttype=INTR, seq=0, req=6, credit=8))
    add(data(TransferResp, b'\x00\x01\x02\x03\x04\x05\x06\x07', flags=0, handle=ii, ttype=INTR,
             seq=0, req=6, eot=1), src=B, dst=A)
    # isochronous: number of headers / I-flags, presentation time, optional
    # timestamp and media time/transmission delay
    io = ephandle(0, 4, 3, 1)
    iflags = [0x0, 0x1, 0x2, 0x4, 0x8, 0xf]
    for i, fl in enumerate(iflags):
        add(data(IsochTransferReq, b'\xaa' * 32, flags=HOST, handle=io, ttype=ISO, seq=i, req=10 + i,
                 ihdr=(i + 1) | (fl << 12), ptime=(i << 3 | (i & 7)) | (i << 20)))
    add(data(IsochTransferReq, u32(0x00ABCDEF) + b'\xbb' * 16, flags=HOST | TSTAMP, handle=io,
             ttype=ISO, seq=7, req=20, ihdr=2 | (0x0 << 12), ptime=0x12345678))
    add(data(IsochTransferReq, u32(0x01020304) + u32(0x00000fff) + b'\xcc' * 16, flags=HOST | TSTAMP,
             handle=io, ttype=ISO, seq=8, req=21, ihdr=3 | (0x8 << 12), ptime=0x00300001))
    add(data(IsochTransferReq, u32(0x01020304) + b'\xcc' * 16, flags=HOST, handle=io,
             ttype=ISO, seq=9, req=22, ihdr=3 | (0x8 << 12), ptime=0x00300001))
    add(data(IsochTransferResp, b'\xdd' * 32, flags=0, handle=ephandle(1, 4, 3, 1), ttype=ISO, seq=7,
             req=20, eps=1, ihdr=4, ptime=0x00400000), src=B, dst=A)
    add(data(IsochTransferResp, b'', flags=0, handle=ephandle(1, 4, 3, 1), ttype=ISO, seq=8,
             req=21, eps=0, ihdr=4, ptime=0x00400000), src=B, dst=A)
    add(data(TransferAck, b'', flags=0, handle=ephandle(1, 4, 3, 1), ttype=ISO, seq=8, req=21), src=B, dst=A)
    return f


def hdr_ctrl(ptype, handle, flags=HOST):
    return common(ptype, 20, flags, int.from_bytes(handle, 'little'), 1, 0, 0) + b'\0' * 11


def tcp_frames():
    """TCP (Decode As mausb): several MAUSB packets in one segment, a
    packet over two segments, a packet whose header is split."""
    f = []
    c = TCP(A, 40000, B, 8000)
    f += c.handshake()
    ping = mgmt(PingReq, token=1)
    pong = mgmt(PingResp, token=1, flags=0)
    f.append(c.c2s(ping))
    f.append(c.s2c(pong))
    f.append(c.c2s(ping + mgmt(PingReq, token=2) + mgmt(CapReq, b'\0\0\0\0', token=3)))
    big = data(TransferReq, b'tcp bulk' * 30, flags=HOST, handle=ephandle(0, 2, 3, 1), ttype=BULK,
               seq=0, req=1, credit=240)
    f.append(c.c2s(big[:100]))
    f.append(c.c2s(big[100:]))
    f.append(c.s2c(pong[:3]))
    f.append(c.s2c(pong[3:] + mgmt(PingResp, token=2, flags=0)[:6]))
    f.append(c.s2c(mgmt(PingResp, token=2, flags=0)[6:]))
    return f


def udp_frames():
    """UDP (Decode As mausb)."""
    f = []
    f.append(udp(mgmt(PingReq, token=5), A, 40001, B, 8001))
    f.append(udp(data(TransferReq, b'udp bulk', flags=HOST, handle=ephandle(0, 2, 3, 1), ttype=BULK,
                      seq=0, req=2, credit=8), A, 40001, B, 8001))
    f.append(udp(mgmt(PingResp, token=5, flags=0), B, 8001, A, 40001))
    return f


def malformed_frames():
    f = []

    def add(p, src=A, dst=B):
        f.append(llc(p, src, dst))

    def mf(p):
        add(p)

    # length field does not match the packet
    mf(mgmt(PingReq, token=1, length=40))
    mf(mgmt(PingReq, token=1, length=12) + b'\0\0\0\0')
    mf(data(TransferReq, b'abcd', ttype=BULK, length=5, handle=ephandle(0, 2, 3, 1), flags=HOST))
    # data after a management packet without type specific data
    mf(mgmt(PingReq, b'\x01\x02\x03\x04', token=2))
    mf(mgmt(PingResp, b'\x01\x02\x03\x04', token=2, flags=0))
    # undefined management packet types
    for t in (USBSuspendReq, USBSuspendResp, USBResumeReq, USBResumeResp, RemoteWakeReq, RemoteWakeResp,
              DevNotificationReq, DevNotificationResp, EPSetKeepAliveReq, EPSetKeepAliveResp,
              GetPortBWReq, GetPortBWResp, 0x3A, 0x3B, 0x3C, 0x3D):
        mf(mgmt(t, b'\0\0\0\0', token=3))
    # CapResp: descriptor length longer than the packet, wrong length,
    # descriptor with a length that does not match its type, count wrong
    mf(mgmt(CapResp, capresp([capdesc(0, 4)], dlen=400), flags=0))
    mf(mgmt(CapResp, capresp([capdesc(0, 4), capdesc(1, 6)], dlen=4), flags=0))
    mf(mgmt(CapResp, capresp([capdesc(0, 4), capdesc(1, 6)], dlen=20), flags=0))
    mf(mgmt(CapResp, capresp([capdesc(0, 4)], count=3), flags=0))
    mf(mgmt(CapResp, capresp([capdesc(0, 4), capdesc(2, 8)], count=1), flags=0))
    mf(mgmt(CapResp, capresp([bytes([1, 0])]), flags=0))
    mf(mgmt(CapResp, capresp([bytes([0, 0])]), flags=0))
    mf(mgmt(CapResp, capresp([bytes([250, 0]) + b'\0' * 10]), flags=0))
    mf(mgmt(CapResp, capresp([capdesc(0, 4)])[:8], flags=0))
    mf(mgmt(CapResp, capresp([]) + b'\0\0\0\0', flags=0))
    # EPHandleReq: descriptor size field does not match the layout; 24 octet
    # descriptors (loop_offset += dissect_usb_unknown_descriptor adds an
    # absolute offset to the loop offset: see README)
    mf(mgmt(EPHandleReq, u16(1 | (12 << 5)) + b'\0\0' + usb_ep_desc(0x81, 3, 64, 4) + b'\0' * 5))
    mf(mgmt(EPHandleReq, u16(2 | (8 << 5)) + b'\0\0' + usb_ep_desc(0x81, 3, 64, 4) + b'\0'))
    mf(mgmt(EPHandleReq, u16(1 | (24 << 5)) + b'\0\0' + usb_ep_desc(0x83, 1, 1024, 1) + ss_comp()
            + ssp_iso_comp() + b'\0\0\0'))
    mf(mgmt(EPHandleReq, u16(1 | (24 << 5)) + b'\0\0' + usb_ep_desc(0x83, 1, 1024, 1) + ss_comp()
            + ssp_iso_comp() + b'\0' * 100))
    mf(mgmt(EPHandleReq, u16(1 | (16 << 5)) + b'\0\0' + b'\0' * 4))
    mf(mgmt(EPHandleReq, u16(31 | (8 << 5)) + b'\0\0' + usb_ep_desc(0x81, 3, 64, 4) + b'\0'))
    # EPHandleResp / EPHandleDelete / ClearTransfers with a count above the data
    mf(mgmt(EPHandleResp, u32(5) + ephandleresp([ephandle()])[4:], flags=0))
    mf(mgmt(EPHandleDeleteReq, bytes([9]) + b'\0\0\0' + ephandle()))
    mf(mgmt(ClearTransfersReq, bytes([4]) + b'\0\0\0' + ephandle() + b'\0' * 6))
    mf(mgmt(ClearTransfersResp, bytes([31]) + b'\0\0\0' + ephandle() + b'\0' * 14, flags=0))
    # type specific data longer than the packet / truncated structures
    mf(mgmt(CancelTransferReq, ephandle() + b'\0\0'))
    mf(mgmt(CancelTransferResp, ephandle() + b'\0\0\x07\x02\0\0', flags=0))
    mf(mgmt(CapReq, b'', length=12) [:11])
    # truncated data packets and a data packet with a short USB part
    mf(data(TransferReq, b'', ttype=BULK, handle=ephandle(0, 2, 3, 1), flags=HOST)[:14])
    mf(data(TransferReq, b'', ttype=CTRL, handle=ephandle(0, 0, 3, 1), flags=HOST, seq=0)[:20] + b'\x80\x06')
    mf(data(IsochTransferReq, b'', ttype=ISO, handle=ephandle(0, 4, 3, 1), flags=HOST | TSTAMP, ihdr=1))
    mf(data(IsochTransferReq, b'', ttype=ISO, handle=ephandle(0, 4, 3, 1), flags=HOST, ihdr=1 | (8 << 12)))
    # shorter than the common header
    mf(b'\x10\x20\x0c\x00\x01')
    mf(b'\x10\x00\x04\x00')
    # PDU with length zero and a length shorter than the header
    mf(hdr_ctrl(TransferSetupReq, ephandle())[:9])
    # more than 255 descriptors of 255 octets: over 32767 octets of
    # descriptors (16 bit offsets in the dissector); sent over TCP
    return f


def big_capresp():
    """255 capability descriptors of 255 octets in one CapResp: 65025
    octets of descriptors, offsets above 32767."""
    d = [bytes([255, i % 6]) + bytes([i & 0xff]) * 253 for i in range(255)]
    return mgmt(CapResp, capresp(d), flags=0)


def big_frames():
    c = TCP(A, 40002, B, 8000)
    f = c.handshake()
    p = big_capresp()
    f.append(c.s2c(p))
    # same over UDP (decode as mausb)
    f.append(udp(p, B, 8001, A, 40001))
    # CapResp whose descriptor length field is 0xffffff (wraps in the
    # dissector's length arithmetic) over UDP
    f.append(udp(mgmt(CapResp, capresp([capdesc(0, 4)], dlen=0xffffff), flags=0), B, 8001, A, 40001))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mf = main_frames()
    pcapng(out + '/mausb-coverage.pcapng', mf)
    # TCP/UDP need Decode As (no default port): separate capture
    df = tcp_frames() + udp_frames()
    pcapng(out + '/mausb-coverage-decodeas.pcapng', df)
    xf = malformed_frames() + big_frames()
    pcapng(out + '/mausb-coverage-malformed.pcapng', xf)
    if '-v' in sys.argv:
        print('main', len(mf), 'decodeas', len(df), 'malformed', len(xf))


main()
