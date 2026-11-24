#!/usr/bin/env python3
# Generates test/captures/gryphon_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic Gryphon coverage captures.

Usage: mkgryphon.py <outdir>

Writes gryphon-coverage.pcap (valid traffic on TCP port 7000) and
gryphon-coverage-malformed.pcap (paths only malformed input reaches).
Everything is built with struct; nothing is captured from a network.
"""
import os
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
from gconsts import (  # noqa: E402,SD_*, CMD_*, GLIN*, GDLY*
    ACTIVATE_FILTER, BIT_FIELD_CHECK, CMD_BCAST_OFF, CMD_BCAST_ON, CMD_BLM_GET_DATA,
    CMD_BLM_GET_MODE, CMD_BLM_GET_STATS, CMD_BLM_SET_MODE, CMD_CARD_ADD_FILTER,
    CMD_CARD_GET_DEFAULT_FILTER, CMD_CARD_GET_EVNAMES, CMD_CARD_GET_FILTER,
    CMD_CARD_GET_FILTER_HANDLES, CMD_CARD_GET_FILTER_MODE, CMD_CARD_GET_SPEED,
    CMD_CARD_GET_SPEEDS, CMD_CARD_IOCTL, CMD_CARD_MODIFY_FILTER, CMD_CARD_SET_DEFAULT_FILTER,
    CMD_CARD_SET_FILTER, CMD_CARD_SET_FILTER_MODE, CMD_CARD_SET_SPEED, CMD_CARD_TX,
    CMD_CARD_TX_LOOP_OFF, CMD_CARD_TX_LOOP_ON, CMD_CLIENT_GET_ID, CMD_CLIENT_SET_ID,
    CMD_CLIENT_SHUTDOWN, CMD_CNVT_DESTROY_SESSION, CMD_CNVT_GET_NODE_SIGNALS, CMD_CNVT_GET_UNITS,
    CMD_CNVT_GET_VALUES, CMD_CNVT_RESTORE_SESSION, CMD_CNVT_SAVE_SESSION, CMD_CNVT_SET_VALUES,
    CMD_EMULATE_NODES, CMD_EVENT_DISABLE, CMD_EVENT_ENABLE, CMD_FLIGHT_GET_CONFIG,
    CMD_FLIGHT_START_MON, CMD_FLIGHT_STOP_MON, CMD_GET_CONFIG, CMD_GET_ENCODING_INFO,
    CMD_GET_FRAME_INFO, CMD_GET_FRAMES, CMD_GET_LDF_INFO, CMD_GET_NODE_NAMES,
    CMD_GET_NODE_SIGNALS, CMD_GET_RXDROP, CMD_GET_SCHEDULES, CMD_GET_SIGNAL_DETAIL,
    CMD_GET_SIGNAL_INFO, CMD_GET_STAT, CMD_GET_TIME, CMD_INIT, CMD_IOPWR_CLRBIT,
    CMD_IOPWR_CLRLATCH, CMD_IOPWR_GETINP, CMD_IOPWR_GETLATCH, CMD_IOPWR_GETOUT,
    CMD_IOPWR_GETPOWER, CMD_IOPWR_SETBIT, CMD_IOPWR_SETOUT, CMD_LDF_DELETE, CMD_LDF_DESC,
    CMD_LDF_LIST, CMD_LDF_PARSE, CMD_LDF_UPLOAD, CMD_MSGRESP_ADD, CMD_MSGRESP_GET,
    CMD_MSGRESP_GET_HANDLES, CMD_MSGRESP_MODIFY, CMD_PGM_DELETE, CMD_PGM_DESC, CMD_PGM_FILES,
    CMD_PGM_LIST, CMD_PGM_OPTIONS, CMD_PGM_START, CMD_PGM_START2, CMD_PGM_STATUS, CMD_PGM_STOP,
    CMD_PGM_UPLOAD, CMD_RESET_RXDROP, CMD_RESTORE_SESSION, CMD_SAVE_SESSION, CMD_SCHED_KILL_TX,
    CMD_SCHED_MSG_REPLACE, CMD_SCHED_TX, CMD_SEND_ID, CMD_SEND_ID_DATA, CMD_SERVER_REG,
    CMD_SERVER_SET_OPT, CMD_SERVER_SET_SORT, CMD_SET_TIME, CMD_START_SCHEDULE, CMD_STOP_SCHEDULE,
    CMD_STORE_DATA, CMD_USDT_ACTIVATE_STMIN_OVERRIDE, CMD_USDT_GET_BSMAX_FC,
    CMD_USDT_GET_STMIN_FC, CMD_USDT_GET_STMIN_OVERRIDE, CMD_USDT_IOCTL, CMD_USDT_REGISTER,
    CMD_USDT_REGISTER_NON_LEGACY, CMD_USDT_SET_BSMAX_FC, CMD_USDT_SET_FUNCTIONAL,
    CMD_USDT_SET_STMIN_FC, CMD_USDT_SET_STMIN_MULT, CMD_USDT_SET_STMIN_OVERRIDE,
    CMD_UTIL_GET_INIT_STRATEGY, CMD_UTIL_SET_INIT_STRATEGY, DEACTIVATE_FILTER,
    DEFAULT_FILTER_BLOCK, DEFAULT_FILTER_PASS, DELETE_FILTER, DIG_TRANSITION, DONT_WAIT_FOR_RESP,
    FILTER_ACTIVE_FLAG, FILTER_DATA_TYPE_DATA, FILTER_DATA_TYPE_EXTRA_DATA,
    FILTER_DATA_TYPE_HEADER, FILTER_DATA_TYPE_HEADER_FRAME, FILTER_EVENT_TYPE_DATA,
    FILTER_EVENT_TYPE_HEADER, FILTER_OFF_PASS_ALL, FILTER_ON, FILTER_PASS_FLAG,
    FR_DEACT_AFTER_PER, FR_DEACT_ON_EVENT, FR_PERIOD_MSGS, FR_RESP_AFTER_PERIOD, G82527, GCAN,
    GCANGETBTRS, GCANSETBTRS, GDGLIN08, GDLYGETHITIME, GDLYGETHIVALUE, GDLYGETLOTIME,
    GDLYGETLOVALUE, GDLYSETHITIME, GDLYSETHIVALUE, GDLYSETLOTIME, GDLYSETLOVALUE, GINIT, GLIN,
    GLINACTSCHED, GLINADDSCHED, GLINCLEARALLSLAVETABLE, GLINCLEARONESHOT, GLINCLEARSLAVETABLE,
    GLINDEACTSCHED, GLINDELSCHED, GLINGETBITRATE, GLINGETMASTEREVENTENABLE, GLINGETNSLAVETABLE,
    GLINGETNUMSCHEDS, GLINGETONESHOT, GLINGETSCHED, GLINGETSCHEDNAMES, GLINGETSCHEDSIZE,
    GLINGETSLAVETABLE, GLINGETSLAVETABLEPIDS, GLINSETBITRATE, GLINSETFLAGS,
    GLINSETMASTEREVENTENABLE, GLINSETONESHOT, GLINSETSLAVETABLE, PGM_ASCII, PGM_BIN, PGM_CONV,
    PGM_DATA, PGM_PGM, PGM_TYPE, RESP_UNSUPPORTED, SD_CARD, SD_CLIENT, SD_SERVER, SD_USDT,
    SVALUE_GT, SVALUE_LT, UVALUE_LE, VALUE_EQ, VALUE_NE, WAIT_FOR_PREV_RESP,
)

CLIENT = SD_CLIENT


def pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, d in enumerate(frames):
            f.write(struct.pack('<IIII', 1600000000 + i // 5, (i % 5) * 200000,
                                len(d), len(d)))
            f.write(d)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


class Stream:
    """One TCP connection client:40000 -> server:7000."""
    CIP, SIP = '192.0.2.1', '192.0.2.2'

    def __init__(self, cport=40000, sport=7000):
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.frames = []
        self.ipid = 1

    def _frame(self, c2s, payload, flags):
        if c2s:
            sp, dp, seq, ack, s, d = (self.cport, self.sport, self.cseq,
                                      self.sseq, self.CIP, self.SIP)
            mac = b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01'
        else:
            sp, dp, seq, ack, s, d = (self.sport, self.cport, self.sseq,
                                      self.cseq, self.SIP, self.CIP)
            mac = b'\x02\0\0\0\0\x01' + b'\x02\0\0\0\0\x02'
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 2 else b''
        if flags == 0x02:
            ack = 0
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, ((20 + len(opts)) // 4) << 4,
                          flags, 65535, 0, 0) + opts + payload
        ph = socket.inet_aton(s) + socket.inet_aton(d) + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), self.ipid, 0,
                         64, 6, 0, socket.inet_aton(s), socket.inet_aton(d))
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.frames.append(mac + b'\x08\x00' + ip + tcp)
        adv = len(payload) + (1 if flags & 3 else 0)
        if c2s:
            self.cseq += adv
        else:
            self.sseq += adv

    def handshake(self):
        self._frame(True, b'', 0x02)
        self._frame(False, b'', 0x12)
        self._frame(True, b'', 0x10)

    def send(self, c2s, payload):
        self._frame(c2s, payload, 0x18)

    def ack(self, c2s):
        self._frame(c2s, b'', 0x10)


# ---------------------------------------------------------------- helpers
def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)


def msg(src, srcch, dst, dstch, ft, body, flags=0):
    hdr = bytes([src, srcch, dst, dstch]) + struct.pack('!H', len(body)) + bytes([ft | flags, 0])
    return pad4(hdr + body)


def fs(n, text):
    """Fixed-size NUL padded string."""
    b = text.encode() if isinstance(text, str) else text
    return b[:n].ljust(n, b'\0')


def z(text):
    return text.encode() + b'\0'


def txt(t):
    """TEXT body: NUL terminated, length a multiple of 4 (see README)."""
    b = t.encode() + b'\0'
    return b + b'\0' * ((-len(b)) % 4)


def u8(*a):
    return bytes(a)


def be16(x):
    return struct.pack('!H', x)


def be32(x):
    return struct.pack('!I', x)


def le16(x):
    return struct.pack('<H', x)


def le32(x):
    return struct.pack('<I', x)


def bef(x):
    return struct.pack('!f', x)


def svc(cmd):
    """Service (destination) of a command constant."""
    return cmd >> 8 if cmd > 0x3f else SD_CARD


class Conv:
    """Builds command/response PDUs with a rolling context byte."""

    def __init__(self):
        self.ctx = 0

    def next(self):
        self.ctx = (self.ctx % 250) + 1
        return self.ctx

    def cmd(self, cmd, data=b'', ctx=None, dstch=1, srcch=5, dst=None):
        if ctx is None:
            ctx = self.next()
        if dst is None:
            dst = svc(cmd)
        body = bytes([cmd & 0xff, ctx, 0, 0]) + data
        return msg(CLIENT, srcch, dst, dstch, 1, body)

    def rsp(self, cmd, data=b'', ctx=None, status=0, src=None, srcch=1):
        ctx = self.ctx if ctx is None else ctx
        if src is None:
            src = svc(cmd)
        body = bytes([cmd & 0xff, ctx, 0, 0]) + be32(status) + data
        return msg(src, srcch, CLIENT, 5, 2, body)


def data_msg(hdr=b'', data=b'', extra=b'', mode=0x80, prio=0, err=0, ts=123456,
             ctx=0, hdrbits=None):
    h = bytes([len(hdr), (len(hdr) * 8) if hdrbits is None else hdrbits]) \
        + be16(len(data)) + bytes([len(extra), mode, prio, err]) \
        + be32(ts) + bytes([ctx, 0, 0, 0])
    body = h + hdr + data + extra
    return body + b'\0' * ((-len(body)) % 4)


def filter_block(ftype, op, value=b'', mask=None, start=0):
    """A filter block as filter_block() reads it."""
    length = len(value)
    b = be16(start) + be16(length) + u8(ftype, op) + b'\0\0'
    if op == BIT_FIELD_CHECK:
        b += value + (mask if mask is not None else b'\xff' * length)
        b += b'\0' * ((length * 2) % 4)
    else:
        b += value
        b += b'\0' * (3 - ((length + 3) % 4))
    return b


def addfilt(flags, blocks):
    return u8(flags, len(blocks)) + b'\0' * 6 + b''.join(blocks)


def encoding_block(kind, **kw):
    t = fs(12, kind)
    if kind[0] == 'l':
        return t + be16(kw.get('v', 1)) + z(kw.get('s', 'ok'))
    if kind[0] == 'p':
        return t + be16(0) + be16(255) + z('1') + z('0') + z('rpm')
    if kind[0] in 'ba':
        return t + be16(kw.get('v', 3))
    return t


def sched_msg(sleep, count, period, flags, chan, data):
    return be32(sleep) + be32(count) + be32(period) + be16(flags) + u8(chan, 0) + data


MARKS = []


def build_main():
    st = Stream()
    marks = MARKS
    st.handshake()
    c = Conv()
    out = st.send

    def xchg(cmd, cdata=b'', rdata=b'', status=0, dstch=1, rsrc=None, **kw):
        """Request in a frame of its own, then the response."""
        ctx = c.next()
        out(True, c.cmd(cmd, cdata, ctx=ctx, dstch=dstch, **kw))
        out(False, c.rsp(cmd, rdata, ctx=ctx, status=status, src=rsrc))

    # ---- general commands
    marks.append(('general commands', len(st.frames) + 1))
    xchg(CMD_INIT, u8(0, 0, 0, 0))
    xchg(CMD_INIT, u8(1, 0, 0, 0))
    xchg(CMD_GET_STAT, b'', b'\0' * 12)
    xchg(CMD_GET_CONFIG, b'',
         fs(20, 'Gryphon S4') + fs(8, '1.02') + fs(20, 'S4-0001') + u8(2, 2) + fs(10, 'ext')
         + b'\0' * 4
         + fs(20, 'CAN driver') + fs(8, '2.1') + fs(16, 'sec') + be32(0x0000000b)
         + be16(8) + be16(0) + fs(20, 'HW0001') + be16(GCAN * 256 + G82527) + u8(1, 2)
         + be16(8) + be16(0)
         + fs(20, 'LIN driver') + fs(8, '3.0') + fs(16, 'sec2') + be32(0)
         + be16(8) + be16(1) + fs(20, 'HW0002') + be16(GLIN * 256 + GDGLIN08) + u8(2, 3)
         + be16(0) + be16(0), status=0)
    xchg(CMD_EVENT_ENABLE, u8(0))
    xchg(CMD_EVENT_ENABLE, u8(7))
    xchg(CMD_EVENT_DISABLE, u8(0))
    xchg(CMD_EVENT_DISABLE, u8(7))
    xchg(CMD_GET_TIME, b'', struct.pack('!Q', 160000012345678))
    xchg(CMD_SET_TIME, struct.pack('!Q', 160000012345678))
    xchg(CMD_GET_RXDROP, b'', be32(5))
    xchg(CMD_RESET_RXDROP)
    xchg(CMD_BCAST_ON)
    xchg(CMD_BCAST_OFF)
    xchg(0x0c, b'\x01\x02\x03\x04', b'\xaa\xbb\xcc')   # unknown low command
    # error status in a response
    xchg(CMD_INIT, u8(0, 0, 0, 0), b'', status=RESP_UNSUPPORTED)

    # ---- card commands
    marks.append(('card commands', len(st.frames) + 1))
    xchg(CMD_CARD_SET_SPEED, u8(3, 0, 0, 0))
    xchg(CMD_CARD_GET_SPEED, b'', u8(3, 0, 0, 0))
    xchg(CMD_CARD_SET_FILTER, be32(1) + u8(0, 0, 0, 0))                    # pass all
    xchg(CMD_CARD_SET_FILTER, be32(0) + u8(1, 0, 0, 2) + b'\x11' * 6 + b'\0\0')
    xchg(CMD_CARD_GET_FILTER, u8(2, 0, 0, 0), addfilt(3, [filter_block(0, VALUE_EQ, b'\x12')]))
    xchg(CMD_CARD_TX, data_msg(hdr=b'\x00\x00\x01\x23', data=b'\x01\x02\x03\x04\x05', mode=0x80))
    xchg(CMD_CARD_TX, data_msg(hdr=b'\x07', data=b'', extra=b'\xee', mode=0x21, prio=3, err=1))
    xchg(CMD_CARD_TX_LOOP_ON)
    xchg(CMD_CARD_TX_LOOP_OFF)
    # add filter: every operator and value length
    blocks = [filter_block(FILTER_DATA_TYPE_HEADER_FRAME, BIT_FIELD_CHECK, b'\x01'),
              filter_block(FILTER_DATA_TYPE_HEADER, BIT_FIELD_CHECK, b'\x01\x02', b'\xff\x00'),
              filter_block(FILTER_DATA_TYPE_DATA, BIT_FIELD_CHECK, b'\x01\x02\x03', b'\xff\xff\x00'),
              filter_block(FILTER_DATA_TYPE_EXTRA_DATA, SVALUE_GT, b'\x05'),
              filter_block(FILTER_EVENT_TYPE_HEADER, UVALUE_LE, b'\x00\x05'),
              filter_block(FILTER_EVENT_TYPE_DATA, VALUE_NE, b'\x00\x00\x00\x05'),
              filter_block(FILTER_DATA_TYPE_DATA, DIG_TRANSITION, b'\x00\x00\x05'),
              filter_block(FILTER_DATA_TYPE_DATA, VALUE_EQ, b'\x00\x00\x00\x00\x05', start=2)]
    xchg(CMD_CARD_ADD_FILTER, addfilt(FILTER_PASS_FLAG | FILTER_ACTIVE_FLAG, blocks), u8(4, 0, 0, 0))
    xchg(CMD_CARD_ADD_FILTER, addfilt(0, [filter_block(0, SVALUE_LT, b'\x80')]), u8(5, 0, 0, 0))
    xchg(CMD_CARD_MODIFY_FILTER, u8(0, ACTIVATE_FILTER, 0, 0))
    xchg(CMD_CARD_MODIFY_FILTER, u8(4, DELETE_FILTER, 0, 0))
    xchg(CMD_CARD_GET_FILTER_HANDLES, b'', u8(3, 1, 2, 3, 0, 0, 0)[:4] + b'')    # 3 handles + 0 pad
    xchg(CMD_CARD_GET_FILTER_HANDLES, b'', u8(2, 7, 8, 0))                       # 2 handles + 1 pad
    xchg(CMD_CARD_SET_DEFAULT_FILTER, u8(DEFAULT_FILTER_PASS, 0, 0, 0))
    xchg(CMD_CARD_GET_DEFAULT_FILTER, b'', u8(DEFAULT_FILTER_BLOCK, 0, 0, 0))
    xchg(CMD_CARD_SET_FILTER_MODE, u8(FILTER_ON, 0, 0, 0))
    xchg(CMD_CARD_GET_FILTER_MODE, b'', u8(FILTER_OFF_PASS_ALL, 0, 0, 0))
    xchg(CMD_CARD_GET_EVNAMES, b'', u8(1) + fs(19, 'Bus off') + u8(2) + fs(19, 'Error passive'))
    xchg(CMD_CARD_GET_SPEEDS, b'', be32(GCANSETBTRS) + be32(GCANGETBTRS) + u8(4, 2)
         + b'\x01\x02\x03\x04' + b'\x05\x06\x07\x08')

    # ---- server / client
    marks.append(('server / client', len(st.frames) + 1))
    xchg(CMD_SERVER_REG, fs(16, 'user') + fs(32, 'secret'), u8(7, 3, 0, 0))
    xchg(CMD_SERVER_SET_SORT, u8(1))
    xchg(CMD_SERVER_SET_OPT, u8(1))
    xchg(CMD_CLIENT_GET_ID, b'', u8(9, 0, 0, 0))
    xchg(CMD_CLIENT_SET_ID, u8(9, 0, 0, 0))
    xchg(CMD_CLIENT_SHUTDOWN)

    # ---- bus load monitor
    marks.append(('bus load monitor', len(st.frames) + 1))
    blm = be32(200000) + be16(1234) + be16(2345) + be16(3456) + be16(4567)
    xchg(CMD_BLM_SET_MODE, be32(1) + be32(1500))
    xchg(CMD_BLM_SET_MODE, be32(2) + be32(100))
    xchg(CMD_BLM_SET_MODE, be32(0) + be32(0))
    xchg(CMD_BLM_GET_MODE, b'', be32(1) + be32(2500))
    xchg(CMD_BLM_GET_DATA, b'', blm)
    xchg(CMD_BLM_GET_STATS, b'', blm + be32(1) + be32(2) + be32(3) + be32(4) + be32(5) + be32(6))

    # ---- LIN description files
    marks.append(('LIN description files', len(st.frames) + 1))
    xchg(CMD_LDF_LIST, u8(0), u8(2, 0) + be16(0)
         + fs(32, 'one.ldf') + fs(80, 'First') + fs(32, 'two.ldf') + fs(80, 'Second'))
    xchg(CMD_LDF_DELETE, fs(32, 'one.ldf'))
    xchg(CMD_LDF_DESC, be32(100) + fs(32, 'new.ldf') + fs(80, 'New file'), u8(1, 0, 0))
    xchg(CMD_LDF_UPLOAD, be16(1) + b'LIN_description_file;\n', b'')
    xchg(CMD_LDF_PARSE, fs(32, 'new.ldf'))
    xchg(CMD_GET_LDF_INFO, b'', fs(16, '2.1') + fs(16, '2.0') + be32(19200))
    xchg(CMD_GET_NODE_NAMES, b'', be16(3) + z('master') + z('slave1') + z('slave2'))
    xchg(CMD_GET_NODE_NAMES, b'', be16(0) + z('master'))
    xchg(CMD_EMULATE_NODES, u8(2) + u8(1) + z('slave1') + u8(2) + z('slave2'))
    xchg(CMD_GET_FRAMES, z('slave1'), be16(2) + u8(0x10) + z('frame_a') + u8(0x11) + z('frame_b'))
    xchg(CMD_GET_FRAME_INFO, z('frame_a') + u8(0x10), u8(1) + z('pub') + u8(2) + z('sig_a') + z('sig_b'))
    xchg(CMD_GET_FRAME_INFO, u8(0), u8(1) + z('pub') + u8(0))
    xchg(CMD_GET_SIGNAL_INFO, z('sig_a'), u8(0, 8) + z('enc_a'))
    xchg(CMD_GET_SIGNAL_DETAIL, z('sig_a'), u8(0, 8) + be16(5)
         + encoding_block('logical') + encoding_block('physical') + encoding_block('bcd')
         + encoding_block('ascii') + encoding_block('other'))
    xchg(CMD_GET_ENCODING_INFO, z('enc_a'), be16(2) + encoding_block('logical') + encoding_block('bcd'))
    xchg(CMD_GET_SCHEDULES, b'', be16(2) + z('sched1') + z('sched2'))
    xchg(CMD_START_SCHEDULE, z('sched1'))
    xchg(CMD_STOP_SCHEDULE)
    xchg(CMD_STORE_DATA, b'\x01\x02\x03\x04')
    xchg(CMD_SEND_ID, b'\x10\0\0\0')
    xchg(CMD_SEND_ID_DATA, b'\x10\x01\x02\x03')
    xchg(CMD_SAVE_SESSION, b'session-data')
    xchg(CMD_RESTORE_SESSION, b'session-data', fs(32, 'session-name'))
    xchg(CMD_GET_NODE_SIGNALS, z('slave1'), be16(2) + z('sig_a') + z('sig_b'))

    # ---- signal conversion
    marks.append(('signal conversion', len(st.frames) + 1))
    xchg(CMD_CNVT_GET_VALUES, u8(2) + z('sig_a') + z('sig_b'),
         u8(3) + u8(0x01) + bef(1.5) + u8(0x02) + be32(7) + u8(0x04) + z('text')
         + u8(0x07) + bef(2.5) + be32(8) + z('all'))
    xchg(CMD_CNVT_GET_UNITS, u8(2) + z('sig_a') + z('sig_b'), u8(2) + z('rpm') + z('km/h'))
    xchg(CMD_CNVT_SET_VALUES, u8(2) + z('sig_a') + bef(1.25) + z('sig_b') + bef(-3.5))
    xchg(CMD_CNVT_DESTROY_SESSION, b'\x01\x02\x03\x04')
    xchg(CMD_CNVT_SAVE_SESSION, b'cnvt-session')
    xchg(CMD_CNVT_RESTORE_SESSION, b'cnvt-session', fs(32, 'cnvt-name'))
    xchg(CMD_CNVT_GET_NODE_SIGNALS, z('slave1'), be16(1) + z('sig_a'))

    # ---- flight recorder (no decoder: generic data)
    marks.append(('flight recorder (no decoder: generic data)', len(st.frames) + 1))
    xchg(CMD_FLIGHT_GET_CONFIG, b'', b'\x01\x02\x03\x04')
    xchg(CMD_FLIGHT_START_MON, b'\x01\x02\x03\x04')
    xchg(CMD_FLIGHT_STOP_MON)

    # ---- message responses
    marks.append(('message responses', len(st.frames) + 1))
    flt = [filter_block(FILTER_DATA_TYPE_HEADER, VALUE_EQ, b'\x07')]
    inner_data = msg(CLIENT, 5, SD_CARD, 1, 3, data_msg(hdr=b'\x08', data=b'\x01\x02'),
                     flags=DONT_WAIT_FOR_RESP)
    inner_cmd = msg(CLIENT, 5, SD_CARD, 1, 1, u8(CMD_INIT, 9, 0, 0) + u8(0, 0, 0, 0),
                    flags=WAIT_FOR_PREV_RESP)
    inner_cmd2 = msg(CLIENT, 5, SD_CARD, 1, 1, u8(CMD_CARD_SET_SPEED & 0xff, 9, 0, 0) + u8(1, 0, 0, 0))

    def addresp(flags, action, aval, blocks, resps):
        return (u8(flags, len(blocks), len(resps), 0, action, 0) + be16(aval)
                + b''.join(blocks) + b''.join(resps))
    xchg(CMD_MSGRESP_ADD, addresp(1, FR_RESP_AFTER_PERIOD, 150, flt, [inner_data]), u8(2, 0, 0, 0))
    xchg(CMD_MSGRESP_ADD, addresp(0, FR_PERIOD_MSGS | FR_DEACT_ON_EVENT, 10, flt,
                                  [inner_cmd, inner_cmd2]), u8(3, 0, 0, 0))
    xchg(CMD_MSGRESP_ADD, addresp(1, FR_DEACT_AFTER_PER, 0, flt, [inner_data]), u8(4, 0, 0, 0))
    xchg(CMD_MSGRESP_GET, u8(2, 0, 0, 0), addresp(1, 0, 20, flt, [inner_data]))
    xchg(CMD_MSGRESP_MODIFY, u8(2, ACTIVATE_FILTER, 0, 0))
    xchg(CMD_MSGRESP_MODIFY, u8(0, DEACTIVATE_FILTER, 0, 0), dstch=4)
    xchg(CMD_MSGRESP_MODIFY, u8(0, DELETE_FILTER, 0, 0), dstch=0)
    xchg(CMD_MSGRESP_GET_HANDLES, b'', u8(2, 2, 3, 0))
    xchg(CMD_MSGRESP_GET_HANDLES, b'', u8(3, 2, 3, 4, 0, 0, 0)[:4])
    # a MISC frame that nests whole messages, including a nested MISC
    nested_misc = msg(CLIENT, 5, SD_CARD, 1, 5, inner_cmd2)
    out(True, msg(SD_CARD, 1, CLIENT, 5, 5, inner_data + inner_cmd2 + nested_misc))

    # ---- program loader
    marks.append(('program loader', len(st.frames) + 1))
    xchg(CMD_PGM_DESC, be32(2048) + fs(32, 'prog.bin') + fs(80, 'A test program'), u8(1, 0, 0, 0))
    xchg(CMD_PGM_DELETE, fs(32, 'prog.bin'))
    xchg(CMD_PGM_LIST, u8(0, 0, 0, 0), u8(2, 0) + be16(0)
         + fs(32, 'prog.bin') + fs(80, 'one') + fs(32, 'other.bin') + fs(80, 'two'))
    xchg(CMD_PGM_START, fs(32, 'prog.bin') + z('arg1 arg2') + b'\0' * 0, u8(4, 0, 0, 0))
    xchg(CMD_PGM_START, fs(32, 'prog.bin'), u8(4, 0, 0, 0))
    xchg(CMD_PGM_START, fs(32, 'prog.bin') + z('x') , u8(4, 0, 0, 0))
    xchg(CMD_PGM_START2, b'\x01\x02\x03\x04', u8(5, 0, 0, 0), rsrc=SD_CLIENT, dst=SD_CLIENT)
    xchg(CMD_PGM_STOP, b'\x04\0\0\0', u8(4, 0, 0, 0))
    xchg(CMD_PGM_STATUS, fs(32, 'prog.bin'), u8(2, 4, 5, 0))
    xchg(CMD_PGM_STATUS, fs(32, 'prog.bin'), u8(0, 0, 0, 0))
    xchg(CMD_PGM_OPTIONS, u8(1, 0, 0, 0) + u8(PGM_CONV, 1, PGM_BIN, 0)
         + u8(PGM_CONV, 1, PGM_ASCII, 0) + u8(PGM_TYPE, 2) + be16(PGM_PGM) + u8(PGM_TYPE, 4)
         + be32(PGM_DATA) + b'\0\0' + u8(9, 3, 1, 2, 3) + b'\0\0\0', u8(1, 4, 0, 0))
    xchg(CMD_PGM_FILES, u8(0) + b'file1\0file2\0', u8(1) + b'file3\0')
    xchg(CMD_PGM_FILES, u8(1) + b'file4\0', u8(0) + b'\0')

    # ---- scheduler
    marks.append(('scheduler', len(st.frames) + 1))
    m1 = data_msg(hdr=b'\x01\x23', data=b'\xaa\xbb\xcc')
    m2 = data_msg(hdr=b'\x04', data=b'')
    xchg(CMD_SCHED_TX, be32(5) + be32(1)
         + sched_msg(100, 1, 10, 0x8000, 0, m1) + sched_msg(0, 2, 20, 0x0001, 3, m2) + b'',
         be32(0x80000001), dstch=7)
    xchg(CMD_SCHED_TX, be32(0xFFFFFFFF) + be32(0)
         + sched_msg(100, 1, 10, 0x8001, 2, m1), be32(0x80000002), dstch=7)
    xchg(CMD_SCHED_KILL_TX, be32(0x80000001))
    xchg(CMD_SCHED_MSG_REPLACE, be32(0x80000002) + u8(0, 0, 0, 0) + data_msg(hdr=b'\x02', data=b'\x11'))
    xchg(CMD_SCHED_MSG_REPLACE, be32(0x00000003) + u8(1, 0, 0, 0) + data_msg(hdr=b'\x02', data=b'\x11'))

    # ---- USDT
    marks.append(('USDT', len(st.frames) + 1))
    xchg(CMD_USDT_IOCTL, b'\x01\x02\x03\x04')
    xchg(CMD_USDT_REGISTER, u8(0, 0, 0, 0))                          # flags 0: reserved
    ids2 = be32(0x7e0) + be32(0x7e8)
    xchg(CMD_USDT_REGISTER, u8(3, 0x07, 0x07, 2) + be32(0x100) + be32(0x200)
         + be32(2) + be32(0x7e0) + be32(0x7e8) + be32(0x7e9)
         + be32(1) + be32(0x7f0) + be32(0x7f8) + be32(0x7f9))        # ext ids, two blocks
    xchg(CMD_USDT_REGISTER, u8(1, 0, 0, 0) + be32(0) + be32(0) + be32(0) + be32(0)
         + be32(0) + be32(0) + be32(0) + be32(0))                   # ids 0, empty blocks
    xchg(CMD_USDT_REGISTER, u8(1, 0, 0, 1) + be32(0x600) + be32(2) + be32(0x7e0) + be32(0x7e8)
         + be32(0x7e9) + b'\0' * 16)                                # trailing empty block
    xchg(CMD_USDT_SET_FUNCTIONAL, u8(1, 0, 0, 0) + be32(1) + be32(0x7df) + be32(0x7e8) + be32(0x7e9))
    xchg(CMD_USDT_SET_STMIN_MULT, bef(1.5))
    xchg(CMD_USDT_SET_STMIN_FC, u8(5))
    xchg(CMD_USDT_GET_STMIN_FC, b'', u8(5))
    xchg(CMD_USDT_SET_BSMAX_FC, u8(8))
    xchg(CMD_USDT_GET_BSMAX_FC, b'', u8(8))

    def blk(nids, req, resp, uudt, e1=0, e2=0, e3=0):
        return be32(nids) + be32(req) + be32(resp) + be32(uudt) + u8(e1, e2, e3, 0)
    zero = be32(0) + b'\0' * 16
    reg = lambda blocks: u8(1, 0x1f, 0x1f, 0) + b''.join(blocks) + zero
    E, H = 0x20000000, 0x80000000     # extended address bit, 29-bit header bit
    xchg(CMD_USDT_REGISTER_NON_LEGACY, reg([
        blk(1, 0x7e0, 0x7e8, 0x7e9),
        blk(1 | E, 0x7e0 | E, 0x7e8 | E, 0x7e9 | E, 1, 2, 3),
        blk(1, 0x7e0 | H, 0x7e8 | H, 0x7e9 | H),
        blk(1 | H | E, 0x7e0 | H | E, 0x7e8 | H | E, 0x7e9 | H | E, 4, 5, 6),
        blk(3, 0x7e0, 0x7e8, 0x7e9),
        blk(3 | E, 0x7e0 | E, 0x7e8 | E, 0x7e9 | E, 1, 2, 3),
        blk(3, 0x7e0 | H, 0x7e8 | H, 0x7e9 | H),
        blk(4 | H | E, 0x7e0 | H | E, 0x7e8 | H | E, 0x7e9 | H | E, 4, 5, 6)]))
    xchg(CMD_USDT_SET_STMIN_OVERRIDE, u8(3))
    xchg(CMD_USDT_GET_STMIN_OVERRIDE, b'', u8(3, 1))
    xchg(CMD_USDT_ACTIVATE_STMIN_OVERRIDE, u8(1))

    # ---- I/O and power
    marks.append(('I/O and power', len(st.frames) + 1))
    xchg(CMD_IOPWR_GETINP, b'', u8(0))
    xchg(CMD_IOPWR_GETINP, b'', u8(0x0f))
    xchg(CMD_IOPWR_GETLATCH, b'', u8(0x05))
    xchg(CMD_IOPWR_CLRLATCH, u8(0x03), u8(0))
    xchg(CMD_IOPWR_CLRLATCH, u8(0), u8(0x01))
    xchg(CMD_IOPWR_GETOUT, b'', u8(0))
    xchg(CMD_IOPWR_GETOUT, b'', u8(3))
    xchg(CMD_IOPWR_SETOUT, u8(0))
    xchg(CMD_IOPWR_SETOUT, u8(3))
    xchg(CMD_IOPWR_SETBIT, u8(1))
    xchg(CMD_IOPWR_CLRBIT, u8(2))
    xchg(CMD_IOPWR_GETPOWER, b'', u8(1))

    # ---- utility
    marks.append(('utility', len(st.frames) + 1))
    xchg(CMD_UTIL_SET_INIT_STRATEGY, be32(10) + u8(4, 8, 0, 12))
    xchg(CMD_UTIL_GET_INIT_STRATEGY, b'', be32(20) + u8(0, 4))

    # ---- ioctls
    marks.append(('ioctls', len(st.frames) + 1))
    def ioctl(code, cdata=b'', rdata=None, status=0):
        ctx = c.next()
        out(True, c.cmd(CMD_CARD_IOCTL, be32(code) + cdata, ctx=ctx))
        out(False, c.rsp(CMD_CARD_IOCTL, cdata if rdata is None else rdata, ctx=ctx,
                         status=status))

    sched_msgs = (le32(100) + u8(2, 0x05) + b'\x10\x11' + b'\xaa\xbb\xcc\xdd\xee'
                  + le32(250) + u8(1, 0x32) + b'\x20' + b'\x01\x02')
    ioctl(GINIT, b'\0\0\0\0')
    ioctl(GLINDEACTSCHED, b'', b'')
    ioctl(GLINDEACTSCHED, b'\0\0\0\0', b'\0\0\0\0')
    ioctl(GLINACTSCHED, fs(32, 'sched1'))
    ioctl(GLINGETNUMSCHEDS, le16(3))
    ioctl(GLINGETSCHEDNAMES, fs(32, 'sched1') + fs(32, 'sched2'))
    ioctl(GLINGETSCHED, le32(60) + fs(32, 'sched1') + le32(125) + u8(2, 0x35) + b'\x10\x11'
          + b'\xaa\xbb\xcc\xdd\xee')
    ioctl(GLINGETSCHEDSIZE, le32(60) + fs(32, 'sched1'))
    ioctl(GLINDELSCHED, fs(32, ''))
    ioctl(GLINDELSCHED, fs(32, 'sched1'))
    ioctl(GLINADDSCHED, le32(4 + 32 + len(sched_msgs)) + fs(32, 'sched1') + sched_msgs)
    # nbytes smaller than the block that follows
    ioctl(GLINADDSCHED, le32(4 + 32 + 4) + fs(32, 'short') + le32(100) + u8(1, 0x02) + b'\x10\x11'
          + b'\0\0\0\0')
    ioctl(GLINSETFLAGS, u8(1, 4, 0, 0x80, 0x40, 0x11))
    ioctl(GLINSETBITRATE, le32(19200))
    ioctl(GLINGETNSLAVETABLE, u8(4))
    ioctl(GLINGETSLAVETABLEPIDS, u8(3, 0x10, 0x11, 0x12))
    ioctl(GLINGETSLAVETABLE, u8(0x10, 3, 1, 1, 0) + b'\x01\x02\x03' + u8(0x77))
    ioctl(GLINGETSLAVETABLE, u8(0x10, 0, 0, 0, 1))
    ioctl(GLINSETSLAVETABLE, u8(0x10, 3, 1, 1) + b'\x01\x02\x03' + u8(0x77))
    ioctl(GLINSETSLAVETABLE, u8(0x10, 0, 0, 0))
    ioctl(GLINCLEARSLAVETABLE, u8(0x10))
    ioctl(GLINCLEARALLSLAVETABLE, b'\0\0\0\0')
    ioctl(GLINGETMASTEREVENTENABLE, u8(1))
    ioctl(GLINSETMASTEREVENTENABLE, u8(0))
    ioctl(GLINGETONESHOT, u8(0x10, 3, 1) + b'\x01\x02\x03' + b'\x55')
    ioctl(GLINSETONESHOT, u8(0x10, 0, 0))
    ioctl(GLINCLEARONESHOT, b'\0\0\0\0')
    ioctl(GLINGETBITRATE, le32(19200))                        # no decoder: raw ioctl data
    ioctl(GDLYGETHIVALUE, le16(1) + le16(500))
    ioctl(GDLYSETHIVALUE, le16(1) + le16(500))
    ioctl(GDLYGETLOVALUE, le16(2) + le16(100))
    ioctl(GDLYSETLOVALUE, le16(2) + le16(100))
    ioctl(GDLYGETHITIME, le16(1) + le16(50))
    ioctl(GDLYSETHITIME, le16(1) + le16(50))
    ioctl(GDLYGETLOTIME, le16(2) + le16(60))
    ioctl(GDLYSETLOTIME, le16(2) + le16(60))
    ioctl(GCANGETBTRS, b'\0\0\0\0')
    # an ioctl response whose request is not in the capture (no context)
    out(False, c.rsp(CMD_CARD_IOCTL, b'', ctx=250))
    # a response without a request, and one with data but no request
    out(False, c.rsp(CMD_GET_TIME, struct.pack('!Q', 1), ctx=251))

    # ---- data, events, text, signals
    marks.append(('data, events, text, signals', len(st.frames) + 1))
    out(False, msg(SD_CARD, 1, CLIENT, 5, 3, data_msg(hdr=b'\x00\x00\x01\x23', data=b'\x01\x02\x03', ctx=4,
                                                    mode=0x01 | 0x02 | 0x04 | 0x08 | 0x10)))
    out(False, msg(SD_CARD, 1, CLIENT, 5, 3, data_msg(hdr=b'', data=b'', mode=0xff)))
    out(False, msg(SD_CARD, 1, CLIENT, 5, 4, u8(1, 4, 0, 0) + be32(100000) + b'\x01\x02\x03\x04\x05'))
    out(False, msg(SD_CARD, 1, CLIENT, 5, 4, u8(2, 4, 0, 0) + be32(100001)))
    out(False, msg(SD_CARD, 1, CLIENT, 5, 6, txt('Hello Gryphon!')))
    out(False, msg(SD_CARD, 1, CLIENT, 5, 6, txt('Hi')))
    out(False, msg(SD_CARD, 1, CLIENT, 5, 7, b''))                  # SIG: no body decoding
    # a frame whose source is a plain client id (non-special) and dest special
    out(True, msg(0x20, 3, SD_SERVER, 4, 6, txt('script tex')))
    out(True, msg(SD_SERVER, 4, 0x20, 3, 6, txt('to script 1')))
    out(True, msg(SD_CLIENT, 4, SD_SERVER, 2, 6, txt('client to sr')))

    # ---- TCP reassembly
    marks.append(('TCP reassembly', len(st.frames) + 1))
    # one PDU split into two segments (split in the body)
    pdu = c.cmd(CMD_CARD_SET_SPEED, u8(4, 0, 0, 0), ctx=c.next())
    out(True, pdu[:10])
    out(True, pdu[10:])
    out(False, c.rsp(CMD_CARD_SET_SPEED, b'', ctx=c.ctx))
    # PDU split inside the 8 byte header
    pdu = c.cmd(CMD_INIT, u8(0, 0, 0, 0), ctx=c.next())
    out(True, pdu[:5])
    out(True, pdu[5:])
    out(False, c.rsp(CMD_INIT, b'', ctx=c.ctx))
    # several PDUs in one segment, the last one split over the next
    a = c.cmd(CMD_GET_TIME, ctx=c.next())
    b = c.cmd(CMD_GET_RXDROP, ctx=c.next())
    d = c.cmd(CMD_CARD_GET_SPEED, ctx=c.next())
    out(True, a + b + d[:7])
    out(True, d[7:])
    out(False, c.rsp(CMD_GET_TIME, struct.pack('!Q', 99), ctx=c.ctx - 2)
        + c.rsp(CMD_GET_RXDROP, be32(1), ctx=c.ctx - 1)
        + c.rsp(CMD_CARD_GET_SPEED, u8(2, 0, 0, 0), ctx=c.ctx))
    # a large PDU split over three segments
    pdu = c.cmd(CMD_SCHED_MSG_REPLACE, be32(0x80000009) + u8(0, 0, 0, 0)
                + data_msg(hdr=b'\x02', data=bytes(range(180))), ctx=c.next())
    out(True, pdu[:60])
    out(True, pdu[60:130])
    out(True, pdu[130:])
    out(False, c.rsp(CMD_SCHED_MSG_REPLACE, be32(0x80000009), ctx=c.ctx))
    st.ack(True)

    # ---- reproducers of the bugs fixed on the branch
    marks.append(('reproducers of the bugs fixed on the branch', len(st.frames) + 1))
    # (1) USDT register with an empty (nids == 0) block: used to loop forever
    body = u8(CMD_USDT_REGISTER_NON_LEGACY & 0xff, 77, 0, 0) + u8(1, 0, 0, 0) + zero
    out(True, msg(CLIENT, 5, SD_USDT, 1, 1, body))
    # (2) dissection depth leak: many PDUs in one segment whose bodies are too
    #     short for their decoder.  Each throws; the depth must not grow.
    #     Kept to a few PDUs that decode: the real reproducer goes into the
    #     malformed capture.
    # (3) the usdt register legacy path with trailing data; ioctl small cases
    return st.frames


def build_malformed():
    st = Stream(cport=40001)
    st.handshake()
    c = Conv()
    out = st.send
    # (a) the repeating-PDU depth leak reproducer (p3_gryphon_depth_leak): 300
    #     CMD_SET_TIME PDUs with a body that is too short, in one segment
    short = msg(CLIENT, 5, SD_CARD, 1, 1, u8(CMD_SET_TIME, 1, 0, 0) + b'\0\0\0\0')
    out(True, short * 300)
    # (b) USDT register: the last non-empty block runs past the PDU
    body = u8(CMD_USDT_REGISTER_NON_LEGACY & 0xff, 78, 0, 0) + u8(1, 0, 0, 0) \
        + be32(1) + be32(0x7e0) + be32(0x7e8) + be32(0x7e9) + u8(0, 0, 0, 0)
    out(True, msg(CLIENT, 5, SD_USDT, 1, 1, body))
    # (b2) PGM_UPLOAD: the padding is computed from the remaining length
    #      including the PDU padding, so every upload runs past the PDU
    out(True, c.cmd(CMD_PGM_UPLOAD, be16(0) + u8(1) + b'\x01\x02\x03\x04\x05', ctx=c.next()))
    out(True, c.cmd(CMD_PGM_UPLOAD, be16(1) + u8(1) + b'\x01\x02\x03\x04', ctx=c.next()))
    # (b3) TEXT frames whose length is not a multiple of 4: same problem
    out(False, msg(SD_CARD, 1, CLIENT, 5, 6, b'Hello Gryphon\0'))
    out(True, msg(CLIENT, 5, SD_SERVER, 4, 6, b'to script\0'))
    # (c) invalid frame type: expert info
    out(True, msg(CLIENT, 5, SD_CARD, 1, 0x1f, b'\x01\x02\x03\x04'))
    out(True, msg(CLIENT, 5, SD_CARD, 1, 0x00, b'\x01\x02\x03\x04'))
    # (d) truncated bodies for many decoders (each throws a bounds error)
    cmds = [CMD_GET_CONFIG, CMD_CARD_SET_FILTER, CMD_CARD_ADD_FILTER, CMD_CARD_TX,
            CMD_SERVER_REG, CMD_BLM_SET_MODE, CMD_LDF_DESC, CMD_MSGRESP_ADD,
            CMD_PGM_DESC, CMD_PGM_OPTIONS, CMD_SCHED_TX, CMD_USDT_REGISTER,
            CMD_UTIL_SET_INIT_STRATEGY, CMD_CNVT_SET_VALUES, CMD_CARD_IOCTL]
    for cm in cmds:
        out(True, c.cmd(cm, b'\x01', ctx=c.next()))
        out(False, c.rsp(cm, b'\x01', ctx=c.ctx))
    # (e) response decoders with truncated data
    for cm in [CMD_GET_CONFIG, CMD_CARD_GET_SPEEDS, CMD_BLM_GET_STATS, CMD_LDF_LIST,
               CMD_PGM_LIST, CMD_GET_NODE_NAMES, CMD_CNVT_GET_VALUES, CMD_MSGRESP_GET]:
        out(False, c.rsp(cm, b'\x05\x01', ctx=c.next()))
    # (f) ioctl with nbytes < 36 (explicit ReportedBoundsError)
    out(True, c.cmd(CMD_CARD_IOCTL, be32(GLINADDSCHED) + le32(8) + b'\0' * 8, ctx=c.next()))
    # (g) a counted loop with a zero count (GET_NODE_NAMES) and a short string loop
    out(False, c.rsp(CMD_GET_NODE_NAMES, be16(0), ctx=c.next()))
    out(False, c.rsp(CMD_CNVT_GET_UNITS, u8(255) + z('a'), ctx=c.next()))
    # (i) events and data too short
    out(False, msg(SD_CARD, 1, CLIENT, 5, 4, u8(1, 4)))
    out(False, msg(SD_CARD, 1, CLIENT, 5, 3, u8(4, 0)))
    # (j) data frame whose declared lengths exceed the PDU
    out(False, msg(SD_CARD, 1, CLIENT, 5, 3, u8(8, 64) + be16(500) + u8(0, 0x80, 0, 0) + b'\0' * 8))
    # (k) response / command shorter than their fixed header
    out(False, msg(SD_CARD, 1, CLIENT, 5, 2, u8(1, 2)))
    out(True, msg(CLIENT, 5, SD_CARD, 1, 1, u8(1, 2)))
    # (l) a PDU whose length field is larger than the segment, never completed
    out(True, msg(CLIENT, 5, SD_CARD, 1, 1, b'\0' * 200)[:60])
    return st.frames


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(outdir, exist_ok=True)
    pcap(os.path.join(outdir, 'gryphon-coverage.pcap'), build_main())
    for name, first in MARKS:
        print('first frame %4d: %s' % (first, name))
    pcap(os.path.join(outdir, 'gryphon-coverage-malformed.pcap'), build_malformed())


if __name__ == '__main__':
    main()
