#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic USB capture helpers (pcapng with several link types).

Every packet is built with struct; nothing is captured from a real bus.
Link types: Linux usbmon 64 byte (220) and 48 byte (189), USBPcap (249),
FreeBSD usbpf (186), macOS (266) and USB/IP over TCP (Ethernet).
"""
import struct

LT_ETH, LT_USB_LINUX, LT_USB_FREEBSD, LT_USB_LINUX_MM, LT_USBPCAP, LT_USB_DARWIN = 1, 189, 186, 220, 249, 266

ISO, INT, CTRL, BULK = 0, 1, 2, 3


class Pcapng:
    """Minimal pcapng writer. Timestamps are microseconds since an arbitrary
    base and advance by `step` per packet unless given."""

    def __init__(self, base=1700000000):
        self.b = bytearray()
        self.nif = 0
        self.t = base * 1000000
        self.step = 1000
        self.count = 0
        self._block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

    def _block(self, typ, body):
        body += b'\0' * (-len(body) % 4)
        n = len(body) + 12
        self.b += struct.pack('<II', typ, n) + body + struct.pack('<I', n)

    def idb(self, lt, snap=262144):
        self._block(1, struct.pack('<HHI', lt, 0, snap))
        self.nif += 1
        return self.nif - 1

    def pkt(self, ifid, data, dt=None):
        self.t += self.step if dt is None else dt
        self._block(6, struct.pack('<IIIII', ifid, self.t >> 32, self.t & 0xffffffff,
                                   len(data), len(data)) + data)
        self.count += 1

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(self.b)


def setup(bm, req, value=0, index=0, length=0):
    return struct.pack('<BBHHH', bm, req, value, index, length)


# ---------------------------------------------------------------- Linux

def linux(typ, xfer, ep, dev, bus=1, uid=1, setup_b=None, data=b'', urb_len=None,
          status=0, hdr64=True, interval=0, start_frame=0, xfer_flags=0, descs=None,
          iso_err=0, setup_flag=None, data_flag=None, ts=1700000000, usec=0, ndesc=None,
          iso_data=b''):
    """One usbmon record. typ is b'S' / b'C' / b'E'. For isochronous URBs
    `descs` is a list of (status, offset, length) and the data follows the
    descriptors."""
    if setup_b is not None:
        sf = 0
        sl = setup_b
    elif xfer == ISO:
        sf = ord('-')
        sl = struct.pack('<II', iso_err, len(descs or []) if ndesc is None else ndesc)
    else:
        sf = ord('-')
        sl = b'\0' * 8
    if setup_flag is not None:
        sf = setup_flag
    payload = data
    if xfer == ISO and descs is not None:
        payload = b''.join(struct.pack('<iIII', s, o, l, 0) for s, o, l in descs) + iso_data
    if data_flag is None:
        data_flag = 0 if payload else ord('<')
    if urb_len is None:
        urb_len = len(payload)
    h = struct.pack('<QBBBBHBBqiiII', uid, typ[0], xfer, ep, dev, bus, sf, data_flag,
                    ts, usec, status, urb_len, len(payload)) + sl
    assert len(h) == 48
    if hdr64:
        h += struct.pack('<iiII', interval, start_frame, xfer_flags,
                         len(descs or []) if xfer == ISO and ndesc is None else (ndesc or 0))
    return h + payload


# ---------------------------------------------------------------- USBPcap

def usbpcap(info, bus, dev, ep, xfer, irp=1, stage=None, data=b'', status=0,
            function=0, datalen=None, iso=None, iso_data=b''):
    """info bit 0 set means completion. stage is the control stage (control
    transfers only). iso is (start_frame, errors, [(offset, length, status)])."""
    body = b''
    if stage is not None:
        body += bytes([stage])
    if iso is not None:
        sf, err, pk = iso
        body += struct.pack('<III', sf, len(pk), err)
        body += b''.join(struct.pack('<III', o, l, s) for o, l, s in pk)
        body += iso_data
    else:
        body += data
    if datalen is None:
        datalen = len(data) + len(iso_data)
    h = struct.pack('<HQIHBHHBBI', 27 + (1 if stage is not None else 0), irp, status, function,
                    info, bus, dev, ep, xfer, datalen)
    return h + body


# ---------------------------------------------------------------- FreeBSD

FB_FLAG_READ, FB_FLAG_DATA = 1, 2
FB_SUBMIT, FB_COMPLETE = 0, 1
FB_CTRL, FB_ISO, FB_BULK, FB_INT = 0, 1, 2, 3
FB_ST_CONTROL_HDR = 0x100


def freebsd(utype, xfer, ep, dev, frames, bus=4, speed=2, xferstatus=0x1, xferflags=0,
            interval=0, error=0, packet_size=64, packet_count=0, mode=0):
    """frames is a list of (flags, data, length) with length None meaning
    len(data); the payload is padded to 4 octets."""
    h = bytearray(128)
    struct.pack_into('<II', h, 0, 128, bus)
    h[8] = dev
    h[9] = mode
    h[10] = utype
    h[11] = xfer
    struct.pack_into('<IIIIIII', h, 12, xferflags, xferstatus, error, interval,
                     len(frames), packet_size, packet_count)
    h[40] = ep
    h[44] = speed
    out = bytes(h)
    for fl, d, ln in frames:
        out += struct.pack('<II', len(d) if ln is None else ln, fl)
        if fl & FB_FLAG_DATA:
            out += d + b'\0' * (-len(d) % 4)
    return out


# ---------------------------------------------------------------- Darwin

def darwin(req_type, xfer_idx, ep, dev, iolen=0, status=0, num_iso=0, ioid=1, location=0x05100000,
           speed=2, data=b'', header_len=32, extra=b''):
    """xfer_idx: 0 control, 1 iso, 2 bulk, 3 interrupt."""
    h = struct.pack('<HBBIIIQIBBBB', 0x0100, header_len, req_type, iolen, status, num_iso, ioid,
                    location, speed, dev, ep, xfer_idx) + extra
    return h.ljust(header_len, b'\0') + data


def darwin_frame(hdr_len, frame_len, status, frame_no, ts=None, data=b''):
    h = struct.pack('<IIIQ', hdr_len, frame_len, status, frame_no)
    if ts is not None:
        h += struct.pack('<Q', ts)
    h = h.ljust(hdr_len, b'\0')
    out = h + data
    return out + b'\0' * (-len(out) % 4)


# ---------------------------------------------------------------- USB/IP over TCP

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Tcp:
    """One TCP connection, Ethernet framing, two directions."""

    def __init__(self, cli='192.0.2.1', srv='192.0.2.2', cport=40000, sport=3240):
        self.cli, self.srv, self.cport, self.sport = cli, srv, cport, sport
        self.seq = {True: 1000, False: 5000}

    def seg(self, from_client, payload, flags=0x18):
        src, dst = (self.cli, self.srv) if from_client else (self.srv, self.cli)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        sa = bytes(map(int, src.split('.')))
        da = bytes(map(int, dst.split('.')))
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)
        ph = sa + da + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', _csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0, sa, da)
        ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
        eth = (b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' if from_client
               else b'\x02\0\0\0\0\x01' + b'\x02\0\0\0\0\x02') + b'\x08\x00'
        self.seq[from_client] = (seq + len(payload) + (1 if flags & 3 else 0)) & 0xffffffff
        return eth + ip + tcp + payload


def usbip_submit(seq, devid, direction, ep, data=b'', length=None, flags=0, start_frame=0,
                 npk=0xffffffff, interval=0, setup_b=b'\0' * 8, iso=b''):
    """OP_CMD_SUBMIT. Data follows for an OUT transfer; the ISO descriptors
    (16 octets each) follow the data."""
    if length is None:
        length = len(data)
    h = struct.pack('!IIIIIIIIII', 1, seq, devid, direction, ep, flags, length, start_frame,
                    npk, interval) + setup_b
    return h + (data if direction == 0 else b'') + iso


def usbip_ret(seq, status=0, data=b'', actual=None, start_frame=0, npk=0xffffffff, errcount=0, iso=b''):
    if actual is None:
        actual = len(data)
    h = struct.pack('!IIIIIIIIII', 3, seq, 0, 0, 0, status, actual, start_frame, npk, errcount) + b'\0' * 8
    return h + data + iso


def usbip_unlink(seq, devid, direction, ep, unlink_seq):
    return struct.pack('!IIIIII', 2, seq, devid, direction, ep, unlink_seq) + b'\0' * 24


def usbip_ret_unlink(seq, status=0):
    return struct.pack('!IIIIII', 4, seq, 0, 0, 0, status & 0xffffffff) + b'\0' * 24


# ---------------------------------------------------------------- descriptors

def dev_desc(cls=0, sub=0, proto=0, mps=64, vid=0x1234, pid=0x5678, bcd=0x0200, dev_bcd=0x0100,
             imanu=1, iprod=2, iser=3, ncfg=1, length=18):
    return struct.pack('<BBHBBBBHHHBBBB', length, 1, bcd, cls, sub, proto, mps, vid, pid, dev_bcd,
                       imanu, iprod, iser, ncfg)


def cfg_desc(body, nif=1, val=1, attr=0xe0, power=50, icfg=0):
    return struct.pack('<BBHBBBBB', 9, 2, 9 + len(body), nif, val, icfg, attr, power) + body


def if_desc(num, alt, neps, cls, sub, proto, istr=0, length=9):
    return struct.pack('<BBBBBBBBB', length, 4, num, alt, neps, cls, sub, proto, istr)


def ep_desc(addr, attr, mps, interval=0, extra=b'', length=None):
    d = struct.pack('<BBBBHB', 7 + len(extra) if length is None else length, 5, addr, attr, mps, interval) + extra
    return d


def ep_companion(burst=0, attr=0, bpi=0, length=6):
    return struct.pack('<BBBBH', length, 0x30, burst, attr, bpi)[:length] if length <= 6 else \
        struct.pack('<BBBBH', length, 0x30, burst, attr, bpi) + b'\0' * (length - 6)


def iad_desc(first, count, cls, sub, proto, ifn=0):
    return struct.pack('<BBBBBBBB', 8, 11, first, count, cls, sub, proto, ifn)


def string_desc(s):
    e = s.encode('utf-16-le')
    return bytes([2 + len(e), 3]) + e


def langid_desc(*ids):
    return bytes([2 + 2 * len(ids), 3]) + b''.join(struct.pack('<H', i) for i in ids)


def bos_desc(caps):
    body = b''.join(caps)
    return struct.pack('<BBHB', 5, 0x0f, 5 + len(body), len(caps)) + body


def cap(typ, body):
    return bytes([3 + len(body), 0x10, typ]) + body


# ---------------------------------------------------------------- scenario helper

class Bus:
    """Writes USB transactions to a Pcapng in one link type. All methods take
    the device address; the bus number is fixed at construction."""

    def __init__(self, w, kind, ifid, bus=1):
        self.w, self.kind, self.ifid, self.bus = w, kind, ifid, bus
        self.uid = 0x1000
        self.out = []

    def emit(self, rec, dt=None):
        self.w.pkt(self.ifid, rec, dt)

    # control transfer: setup is 8 bytes. resp is the data of the completion
    # (IN) or None; out_data is the data stage of an OUT transfer.
    def control(self, dev, setup_b, resp=b'', out_data=b'', status=0, dt=None, reqonly=False):
        self.uid += 1
        uid = self.uid
        bm = setup_b[0]
        wlen = struct.unpack('<H', setup_b[6:8])[0]
        d_in = bool(bm & 0x80)
        ep = 0x80 if d_in else 0
        k = self.kind
        if k in ('mm', 'l48'):
            h64 = (k == 'mm')
            self.emit(linux(b'S', CTRL, ep, dev, self.bus, uid, setup_b, out_data, wlen if d_in else len(out_data), hdr64=h64), dt)
            if not reqonly:
                self.emit(linux(b'C', CTRL, ep, dev, self.bus, uid, None, resp, len(resp), status, hdr64=h64), dt)
        elif k == 'pcap':
            self.emit(usbpcap(0, self.bus, dev, 0x80 if d_in else 0, CTRL, uid, 0, setup_b + out_data), dt)
            if reqonly:
                return
            if d_in:
                self.emit(usbpcap(1, self.bus, dev, 0x80, CTRL, uid, 1, resp), dt)
            self.emit(usbpcap(1, self.bus, dev, 0 if not d_in else 0, CTRL, uid, 2, b''), dt)
        elif k == 'bsd':
            fr = [(FB_FLAG_DATA, setup_b, None)]
            if out_data:
                fr.append((FB_FLAG_DATA, out_data, None))
            self.emit(freebsd(FB_SUBMIT, FB_CTRL, 0, dev, fr, xferstatus=FB_ST_CONTROL_HDR | 1), dt)
            if not reqonly:
                self.emit(freebsd(FB_COMPLETE, FB_CTRL, 0, dev, [(FB_FLAG_DATA, resp, None)] if resp else [(0, b'', 0)]), dt)
        elif k == 'mac':
            self.emit(darwin(0, 0, 0, dev, wlen, data=setup_b + out_data), dt)
            if not reqonly:
                self.emit(darwin(1, 0, 0, dev, len(resp), data=resp), dt)
        else:
            raise ValueError(k)

    def xfer(self, dev, ep, xfer, data=b'', submit_len=None, status=0, dt=None, req_data=b''):
        """bulk or interrupt: a submit and a completion. For an IN endpoint
        (bit 7 of ep) data is the completion payload, else it is the submit
        payload."""
        self.uid += 1
        uid = self.uid
        d_in = bool(ep & 0x80)
        k = self.kind
        if k in ('mm', 'l48'):
            h64 = (k == 'mm')
            if d_in:
                self.emit(linux(b'S', xfer, ep, dev, self.bus, uid, None, b'', submit_len or 64, hdr64=h64), dt)
                self.emit(linux(b'C', xfer, ep, dev, self.bus, uid, None, data, len(data), status, hdr64=h64), dt)
            else:
                self.emit(linux(b'S', xfer, ep, dev, self.bus, uid, None, data, len(data), hdr64=h64), dt)
                self.emit(linux(b'C', xfer, ep, dev, self.bus, uid, None, b'', len(data), status, hdr64=h64), dt)
        elif k == 'pcap':
            if d_in:
                self.emit(usbpcap(0, self.bus, dev, ep, xfer, uid, None, b'', datalen=submit_len or 64), dt)
                self.emit(usbpcap(1, self.bus, dev, ep, xfer, uid, None, data), dt)
            else:
                self.emit(usbpcap(0, self.bus, dev, ep, xfer, uid, None, data), dt)
                self.emit(usbpcap(1, self.bus, dev, ep, xfer, uid, None, b'', datalen=0), dt)
        elif k == 'bsd':
            t = FB_BULK if xfer == BULK else FB_INT
            if d_in:
                self.emit(freebsd(FB_SUBMIT, t, ep, dev, [(FB_FLAG_READ, b'', submit_len or 64)]), dt)
                self.emit(freebsd(FB_COMPLETE, t, ep, dev, [(FB_FLAG_READ | FB_FLAG_DATA, data, None)]), dt)
            else:
                self.emit(freebsd(FB_SUBMIT, t, ep, dev, [(FB_FLAG_DATA, data, None)]), dt)
                self.emit(freebsd(FB_COMPLETE, t, ep, dev, [(0, b'', len(data))]), dt)
        elif k == 'mac':
            t = 2 if xfer == BULK else 3
            if d_in:
                self.emit(darwin(0, t, ep, dev, submit_len or 64), dt)
                self.emit(darwin(1, t, ep, dev, len(data), data=data), dt)
            else:
                self.emit(darwin(0, t, ep, dev, len(data), data=data), dt)
                self.emit(darwin(1, t, ep, dev, len(data)), dt)
        else:
            raise ValueError(k)

    # ---- standard requests
    def get_desc(self, dev, typ, index, data, wlen=None, lang=0, bm=0x80):
        if wlen is None:
            wlen = len(data)
        self.control(dev, setup(bm, 6, (typ << 8) | index, lang, wlen), data)

    def enumerate(self, dev, desc, cfg, strings=()):
        """GET_DESCRIPTOR device (8 octets, then full), configuration (9
        octets then full), strings."""
        self.get_desc(dev, 1, 0, desc[:8], 8)
        self.get_desc(dev, 1, 0, desc, 18)
        self.get_desc(dev, 2, 0, cfg[:9], 9)
        self.get_desc(dev, 2, 0, cfg, len(cfg))
        for i, s in enumerate(strings):
            self.get_desc(dev, 3, i, s, 255, lang=0x0409 if i else 0)
        self.control(dev, setup(0x00, 9, 1))
