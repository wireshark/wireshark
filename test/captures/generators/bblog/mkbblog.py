#!/usr/bin/env python3
# Generates test/captures/bblog_coverage.pcapng.gz, bblog_exported_pdu.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BBLog dissector (packet-bblog.c).

Netflix Black Box Logging (FreeBSD TCP BBLog) is stored in pcapng: custom
blocks (type 0x00000BAD) with PEN 10949 (Netflix) carry an event (with the
TCP info as a custom binary option) or a skip count, and Enhanced Packet
Blocks carry the TCP info as a Netflix custom binary option (code 2989).
The layouts are those read by wiretap/pcapng-netflix-custom.c. Every block
is built from scratch with struct; no captured traffic is used.

Usage: mkbblog.py <output directory>

Writes:
  bblog-coverage.pcapng            the main capture (frame ranges in README.md)
  bblog-coverage-malformed.pcapng  event blocks without or with a short TCP
                                   info option, and in a no-copy custom block,
                                   and a Netflix custom block without a type
  bblog_exported_pdu.pcap          an Exported PDU naming "bblog" (the same
                                   bytes as bblog_epdu_null_block.pcap)
"""

import os
import struct
import sys

PEN_NFLX = 10949
BT_SHB = 0x0A0D0D0A
BT_IDB = 0x00000001
BT_EPB = 0x00000006
BT_CB_COPY = 0x00000BAD
BT_CB_NO_COPY = 0x40000BAD

OPT_COMMENT = 1
OPT_EPB_FLAGS = 2
OPT_CUSTOM_BIN_COPY = 2989

NFLX_BLOCK_TYPE_EVENT = 1
NFLX_BLOCK_TYPE_SKIP = 2

NFLX_OPT_TYPE_VERSION = 1
NFLX_OPT_TYPE_TCPINFO = 2
NFLX_OPT_TYPE_DUMPINFO = 4
NFLX_OPT_TYPE_DUMPTIME = 5
NFLX_OPT_TYPE_STACKNAME = 6

TF_REQ_SCALE = 0x20
TF_RCVD_SCALE = 0x40

TCP_LOG_TIMER = 3
TCP_LOG_PRU = 70

# Time offset in the dump info; event block time stamps are this plus the
# event's own tv_sec/tv_usec.
OFFSET_SEC = 1700000000
OFFSET_USEC = 0


def pad4(b):
    return b + b'\0' * (-len(b) % 4)


def option(code, value):
    return struct.pack('<HH', code, len(value)) + pad4(value)


def opt_end():
    return struct.pack('<HH', 0, 0)


def nflx_option(nflx_type, data):
    return option(OPT_CUSTOM_BIN_COPY,
                  struct.pack('<II', PEN_NFLX, nflx_type) + data)


def block(btype, body):
    body = pad4(body)
    total = 12 + len(body)
    return struct.pack('<II', btype, total) + body + struct.pack('<I', total)


def shb(options=b''):
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    if options:
        body += options + opt_end()
    return block(BT_SHB, body)


def idb(linktype=1):
    return block(BT_IDB, struct.pack('<HHI', linktype, 0, 65535))


def epb(data, ts_usec, options=b''):
    body = struct.pack('<IIIII', 0, ts_usec >> 32, ts_usec & 0xffffffff,
                       len(data), len(data)) + pad4(data)
    if options:
        body += options + opt_end()
    return block(BT_EPB, body)


def custom_block(nflx_type, fixed=b'', options=b'', btype=BT_CB_COPY):
    body = struct.pack('<II', PEN_NFLX, nflx_type) + fixed
    if options:
        body += options + opt_end()
    return block(btype, body)


def skip_block(skipped, comment=None):
    opts = option(OPT_COMMENT, comment.encode()) if comment else b''
    return custom_block(NFLX_BLOCK_TYPE_SKIP, struct.pack('<I', skipped), opts)


def tcpinfo(sec=1, usec=0, ticks=1000, sn=1, stackid=0, eventid=1,
            eventflags=0, errno=0, rxbuf=(0, 0, 0), txbuf=(0, 0, 0),
            state=4, starttime=500, iss=1000000, flags=0, snd_una=1000001,
            snd_max=1000001, snd_cwnd=14600, snd_nxt=1000001,
            snd_recover=1000001, snd_wnd=65535, snd_ssthresh=1073725440,
            srtt=320, rttvar=160, rcv_up=2000001, rcv_adv=2065536, flags2=0,
            rcv_nxt=2000001, rcv_wnd=65535, dupacks=0, segqlen=0,
            numholes=0, flex1=0, flex2=0, fbyte_in=0, fbyte_out=0,
            snd_scale=0, rcv_scale=0, pad=(0, 0, 0), stackinfo=None,
            tlb_len=0, extra=b''):
    """struct nflx_tcpinfo without the trailing padding: 268 bytes."""
    d = struct.pack('<QQIIBBHi', sec, usec, ticks, sn, stackid, eventid,
                    eventflags, errno)
    d += struct.pack('<6I', *rxbuf, *txbuf)
    d += struct.pack('<iIII', state, starttime, iss, flags)
    d += struct.pack('<11I', snd_una, snd_max, snd_cwnd, snd_nxt, snd_recover,
                     snd_wnd, snd_ssthresh, srtt, rttvar, rcv_up, rcv_adv)
    d += struct.pack('<IIIIii', flags2, rcv_nxt, rcv_wnd, dupacks, segqlen,
                     numholes)
    d += struct.pack('<IIII', flex1, flex2, fbyte_in, fbyte_out)
    d += struct.pack('<B3B', (snd_scale & 0xf) | ((rcv_scale & 0xf) << 4), *pad)
    if stackinfo is None:
        stackinfo = bytes(104)
    assert len(stackinfo) == 104
    d += stackinfo
    d += struct.pack('<I', tlb_len)
    assert len(d) == 268
    return d + extra


def bbr_stackinfo(n):
    return (struct.pack('<4Q', 10000000 + n, 20000000 + n, 30000 + n, 40000000 + n)
            + struct.pack('<14I', *range(n, n + 14))
            + struct.pack('<3H', 256, 512, 7)
            + struct.pack('<6B', 1, 2, 0, 1, 0, 8)
            + struct.pack('<I', n))


def event_block(seq, **kw):
    kw.setdefault('sn', seq)
    kw.setdefault('sec', seq)
    kw.setdefault('usec', (seq * 1000) % 1000000)
    kw.setdefault('ticks', 1000 + seq * 10)
    comment = kw.pop('comment', None)
    opts = nflx_option(NFLX_OPT_TYPE_TCPINFO, tcpinfo(**kw))
    if comment:
        opts = option(OPT_COMMENT, comment.encode()) + opts
    return custom_block(NFLX_BLOCK_TYPE_EVENT, options=opts)


# All 32 t_flags bits and the 10 t_flags2 bits, rotated over the events so
# every bit is shown set somewhere.
T_FLAGS2_BITS = [1 << i for i in range(10)]


def dumpinfo():
    d = struct.pack('<IIQHH', 1, 0, 0, 443, 49152)
    d += struct.pack('<4I', 0x6433A8C0, 0, 0, 0)    # 192.168.51.100 (LE)
    d += struct.pack('<4I', 0x0A33A8C0, 0, 0, 0)    # 192.168.51.10
    d += struct.pack('<I', 0)
    d += struct.pack('<QQ', OFFSET_SEC, OFFSET_USEC)
    d += b'synthetic-bblog-id'.ljust(64, b'\0')
    d += b'coverage'.ljust(32, b'\0')
    d += b'test'.ljust(32, b'\0')
    d += struct.pack('<B7x', 2)
    assert len(d) == 208
    return d


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


CLIENT = bytes([192, 168, 51, 100])
SERVER = bytes([192, 168, 51, 10])
MAC_C = bytes.fromhex('020000000064')
MAC_S = bytes.fromhex('02000000000a')


def udp_frame(src, dst, sport, dport, data):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    seg = hdr[:6] + struct.pack('>H', c) + data
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), 1, 0x4000, 64, 17,
                     0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    eth = (MAC_S + MAC_C) if src == CLIENT else (MAC_C + MAC_S)
    return eth + b'\x08\x00' + ip + seg


def flags_opt(direction):
    return option(OPT_EPB_FLAGS, struct.pack('<I', direction))


def main_capture():
    out = []
    shb_opts = (option(OPT_COMMENT, b'Synthetic BBLog coverage capture')
                + nflx_option(NFLX_OPT_TYPE_VERSION, struct.pack('<I', 1))
                + nflx_option(NFLX_OPT_TYPE_DUMPINFO, dumpinfo())
                + nflx_option(NFLX_OPT_TYPE_DUMPTIME, struct.pack('<q', OFFSET_SEC + 3600))
                + nflx_option(NFLX_OPT_TYPE_STACKNAME, b'\x01rack\0'))
    out.append(shb(shb_opts))
    out.append(idb(1))

    frames = []
    # Frame 1: skip block
    frames.append(skip_block(5))
    seq = 1
    # Frames 2-70: every named event identifier except TIMER and PRU
    # (1..71 without 3 and 70), with event flags 0..31 and every t_flags
    # and t_flags2 bit rotating through them.
    tf_bit = 0
    for ev in range(1, 72):
        if ev in (TCP_LOG_TIMER, TCP_LOG_PRU):
            continue
        seq += 1
        ef = (ev - 1) % 32
        kw = dict(eventid=ev, eventflags=ef, stackid=ev % 3,
                  errno=[0, 35, 54, 60, 65][ev % 5],
                  state=ev % 11,
                  flags=(1 << (tf_bit % 32)) | (1 << ((tf_bit + 16) % 32)),
                  flags2=T_FLAGS2_BITS[ev % 10],
                  flex1=ev * 0x101, flex2=ev * 0x202,
                  snd_scale=ev % 15, rcv_scale=(ev + 7) % 15,
                  pad=(ev & 1, 2, 3), tlb_len=ev * 10,
                  dupacks=ev % 4, segqlen=ev % 3, numholes=ev % 2,
                  fbyte_in=ev, fbyte_out=ev + 1)
        tf_bit += 1
        if ef & 1:
            kw['rxbuf'] = (100 + ev, 200 + ev, 300 + ev)
        if ef & 2:
            kw['txbuf'] = (400 + ev, 500 + ev, 600 + ev)
        if ef & 0x10:
            kw['stackinfo'] = bbr_stackinfo(ev)
        if ev == 1:
            kw['comment'] = 'event with a comment'
        if ev == 2:
            # TCP info longer than struct nflx_tcpinfo
            kw['extra'] = bytes(12)
        frames.append(event_block(seq, **kw))
    # Frames 71-100: TIMER events, every timer type (and an unknown one)
    # with every timer operation (and an unknown one).
    for ttype in (0, 1, 2, 3, 4, 9):
        for tev in (0, 1, 2, 3, 7):
            seq += 1
            frames.append(event_block(seq, eventid=TCP_LOG_TIMER,
                                      flex1=(tev << 8) | ttype,
                                      flex2=200 + ttype * 10 + tev))
    # Frames 101-127: PRU events, every request (0..25) and an unknown one
    for pru in list(range(26)) + [0x7f]:
        seq += 1
        frames.append(event_block(seq, eventid=TCP_LOG_PRU,
                                  flex1=0xab00 | pru, eventflags=0x3,
                                  rxbuf=(1, 2, 3), txbuf=(4, 5, 6)))
    # Frames 128-129: unknown event identifiers
    for ev in (0, 200):
        seq += 1
        frames.append(event_block(seq, eventid=ev, flex1=0x11223344,
                                  flex2=0x55667788))
    # Frame 130: skip block with a comment and a large count
    frames.append(skip_block(4000000000, 'skipped events'))

    # Frames 131-140: Enhanced Packet Blocks carrying the TCP info as a
    # Netflix custom option, in both directions, without and with an
    # unknown direction. The packets are IPv4/UDP datagrams to the discard
    # port: the window scaling the option sets only matters when TCP
    # creates a conversation, and a TCP conversation's completeness is
    # shown differently in the first and second pass, so TCP would break
    # the identical one-pass/two-pass output.
    ws = TF_REQ_SCALE | TF_RCVD_SCALE
    t0 = (OFFSET_SEC + 200) * 1000000

    def seg(n, outbound, opts):
        data = b'bblog-%02d' % n
        if outbound:
            f = udp_frame(CLIENT, SERVER, 50000 + n, 9, data)
        else:
            f = udp_frame(SERVER, CLIENT, 50000 + n, 9, data)
        return epb(f, t0 + n * 1000, opts)

    def ti(**kw):
        return nflx_option(NFLX_OPT_TYPE_TCPINFO, tcpinfo(**kw))
    # 131 inbound, WS sent and received: src scale = snd_scale (7),
    # dst scale = rcv_scale (6)
    frames.append(seg(1, False, flags_opt(1) + ti(eventid=1, flags=ws,
                                                   snd_scale=7, rcv_scale=6)))
    # 132 outbound, WS sent and received: src = rcv_scale (6), dst = snd_scale (7)
    frames.append(seg(2, True, flags_opt(2) + ti(eventid=2, flags=ws,
                                                  snd_scale=7, rcv_scale=6)))
    # 133 direction flag present but unknown (0): scaling unknown; every
    # event flag, buffers and stack info
    frames.append(seg(3, True, flags_opt(0) + ti(eventid=2, flags=ws,
                                                  snd_scale=7, rcv_scale=6,
                                                  eventflags=0x1f,
                                                  rxbuf=(7, 8, 9),
                                                  txbuf=(10, 11, 12),
                                                  stackinfo=bbr_stackinfo(1),
                                                  tlb_len=18)))
    # 134 no flags option: P2P_DIR_UNKNOWN; TCP info longer than
    # struct nflx_tcpinfo (clamped)
    frames.append(seg(4, False, ti(eventid=1, flags=ws, snd_scale=7,
                                   rcv_scale=6, extra=bytes(16))))
    # 135 established without window scaling: scaling not used (-2)
    frames.append(seg(5, True, flags_opt(2) + ti(eventid=2, state=4, flags=0)))
    # 136 SYN-SENT, WS requested but not received: scaling unknown (-1)
    frames.append(seg(6, True, flags_opt(2) + ti(eventid=2, state=2,
                                                  flags=TF_REQ_SCALE)))
    # 137 short TCP info (16 bytes): ignored by the dissector
    frames.append(seg(7, False, flags_opt(1)
                      + nflx_option(NFLX_OPT_TYPE_TCPINFO, struct.pack('<QQ', 1, 2))))
    # 138 a Netflix option of another type (version) and a comment
    frames.append(seg(8, True, option(OPT_COMMENT, b'version option')
                      + flags_opt(2)
                      + nflx_option(NFLX_OPT_TYPE_VERSION, struct.pack('<I', 1))))
    # 139 inbound, every t_flags and t_flags2 bit, every event flag,
    # negative errno, queue length and holes
    frames.append(seg(9, False, flags_opt(1) + ti(eventid=1, state=8,
                                                   flags=0xffffffff, flags2=0x3ff,
                                                   eventflags=0x1f, errno=-1,
                                                   rxbuf=(1, 2, 3), txbuf=(4, 5, 6),
                                                   snd_scale=14, rcv_scale=2,
                                                   pad=(1, 2, 3), segqlen=-1,
                                                   numholes=-2)))
    # 140 no options
    frames.append(seg(10, True, b''))
    out.extend(frames)
    return b''.join(out), len(frames)


def malformed_capture():
    out = [shb(), idb(1)]
    # 1: event block without a TCP info option: no data at all
    out.append(custom_block(NFLX_BLOCK_TYPE_EVENT,
                            options=option(OPT_COMMENT, b'no tcpinfo')))
    # 2: event block with a 100-byte TCP info: ends before flex1
    out.append(custom_block(NFLX_BLOCK_TYPE_EVENT,
                            options=nflx_option(NFLX_OPT_TYPE_TCPINFO,
                                                tcpinfo(eventid=1)[:100])))
    # 3: event block with a 200-byte TCP info: ends before the payload length
    out.append(custom_block(NFLX_BLOCK_TYPE_EVENT,
                            options=nflx_option(NFLX_OPT_TYPE_TCPINFO,
                                                tcpinfo(eventid=1, eventflags=0x13)[:200])))
    # 4: event in a no-copy custom block: the TCP info is not appended
    out.append(custom_block(NFLX_BLOCK_TYPE_EVENT,
                            options=nflx_option(NFLX_OPT_TYPE_TCPINFO,
                                                tcpinfo(eventid=1)),
                            btype=BT_CB_NO_COPY))
    # 5: skip block in a no-copy custom block (decodes)
    out.append(custom_block(NFLX_BLOCK_TYPE_SKIP, struct.pack('<I', 9),
                            btype=BT_CB_NO_COPY))
    # 6: Netflix custom block too short for the Netflix block type: wiretap
    # keeps it as a record without mandatory data
    out.append(block(BT_CB_COPY, struct.pack('<I', PEN_NFLX)))
    return b''.join(out), 6


def epdu_capture():
    """Exported PDU naming "bblog" on an ordinary packet record (linktype 252).
    The same bytes as bblog_epdu_null_block.pcap."""
    def tag(t, v):
        v = bytes(v)
        p = (-len(v)) % 4
        return struct.pack('>HH', t, len(v) + p) + v + b'\0' * p
    epdu = tag(12, b'bblog') + struct.pack('>HH', 0, 0) + bytes(300)
    hdr = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252)
    return hdr + struct.pack('<IIII', 0, 0, len(epdu), len(epdu)) + epdu


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    data, n = main_capture()
    with open(os.path.join(outdir, 'bblog-coverage.pcapng'), 'wb') as f:
        f.write(data)
    print('bblog-coverage.pcapng: %d frames' % n)
    data, n = malformed_capture()
    with open(os.path.join(outdir, 'bblog-coverage-malformed.pcapng'), 'wb') as f:
        f.write(data)
    print('bblog-coverage-malformed.pcapng: %d frames' % n)
    with open(os.path.join(outdir, 'bblog_exported_pdu.pcap'), 'wb') as f:
        f.write(epdu_capture())


if __name__ == '__main__':
    main()
