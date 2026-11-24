#!/usr/bin/env python3
# Generates test/captures/btavdtp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic captures for packet-btavdtp.c coverage (AVDTP, A2DP,
# VDP, aptX, LDAC, SCMS-T). Usage: mkbtavdtp.py <outdir>
# Writes btavdtp-coverage.pcapng (main) and
# btavdtp-coverage-malformed.pcapng. Every packet is built here with
# struct; nothing is captured from a real network.
#
# Bluetooth HCI H4 with direction (link type 201): each HCI connection
# handle gets a Connection Complete event and L2CAP Connection
# Request/Response on PSM 0x19 so L2CAP tracks the channels. The main
# capture follows the rules that keep one pass and -2 the same: no media
# before the OPEN accept, no RECONFIGURE of a stream that carries media,
# one SET_CONFIGURATION per stream (each stream has its own handle).
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

LT_H4_PHDR = 201
LT_EXP_PDU = 252
SENT, RECV = 0, 1


class Pcapng:
    def __init__(self):
        self.blocks = []
        self.ifaces = {}
        self.ts = 1700000000 * 1000000
        self._block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        self.count = 0

    def _block(self, btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = len(body) + 12
        self.blocks.append(struct.pack('<II', btype, total) + body + struct.pack('<I', total))

    def iface(self, linktype):
        if linktype not in self.ifaces:
            self.ifaces[linktype] = len(self.ifaces)
            self._block(1, struct.pack('<HHI', linktype, 0, 262144))
        return self.ifaces[linktype]

    def add(self, linktype, data, step=20000):
        i = self.iface(linktype)
        self.ts += step
        self._block(6, struct.pack('<IIIII', i, self.ts >> 32, self.ts & 0xffffffff,
                                   len(data), len(data)) + data)
        self.count += 1
        return self.count

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(b''.join(self.blocks))


# ---------------------------------------------------------------- HCI/L2CAP
def h4(direction, ptype, body):
    return struct.pack('>I', direction) + bytes([ptype]) + body


def acl(direction, handle, cid, payload):
    l2 = struct.pack('<HH', len(payload), cid) + payload
    return h4(direction, 2, struct.pack('<HH', (handle & 0x0fff) | 0x2000, len(l2)) + l2)


def conn_complete(handle, bdaddr):
    ev = struct.pack('<BH', 0, handle) + bdaddr[::-1] + b'\x01\x00'
    return h4(RECV, 4, bytes([0x03, len(ev)]) + ev)


def disconn_complete(handle):
    ev = struct.pack('<BHB', 0, handle, 0x13)
    return h4(RECV, 4, bytes([0x05, len(ev)]) + ev)


def l2_connect(handle, psm, scid, dcid, ident):
    req = struct.pack('<BBHHH', 0x02, ident, 4, psm, scid)
    rsp = struct.pack('<BBHHHHH', 0x03, ident, 8, dcid, scid, 0, 0)
    return [acl(SENT, handle, 1, req), acl(RECV, handle, 1, rsp)]


def l2_disconnect(handle, scid, dcid, ident):
    req = struct.pack('<BBHHH', 0x06, ident, 4, dcid, scid)
    rsp = struct.pack('<BBHHH', 0x07, ident, 4, dcid, scid)
    return [acl(SENT, handle, 1, req), acl(RECV, handle, 1, rsp)]


# ---------------------------------------------------------------- AVDTP
CMD, GREJ, ACC, REJ = 0, 1, 2, 3
DISCOVER, GET_CAP, SET_CONF, GET_CONF, RECONF, OPEN, START, CLOSE, SUSPEND, \
    ABORT, SECURITY, GET_ALL_CAP, DELAY = range(1, 14)


def sig(trans, msg, sigid, payload=b'', ptype=0, nosp=None):
    hdr = bytes([(trans & 0xf) << 4 | ptype << 2 | msg])
    if ptype == 1:
        hdr += bytes([nosp])
    return hdr + bytes([sigid]) + payload


def seid(n):
    return bytes([n << 2])


def sep(n, media, sink, in_use=False):
    return bytes([n << 2 | (2 if in_use else 0), media << 4 | (8 if sink else 0)])


def cat(c, body=b''):
    return bytes([c, len(body)]) + body


def codec(media, ctype, body):
    return cat(7, bytes([media << 4, ctype]) + body)


TRANSPORT = cat(1)
SBC_CFG = codec(0, 0, bytes([0x21, 0x15, 2, 53]))      # 44.1k JS, 16 blk, 8 sb, loudness
SBC_ALL = codec(0, 0, bytes([0xff, 0xff, 2, 250]))
SBC_NONE = codec(0, 0, bytes([0, 0, 2, 2]))
SBC_BADPOOL = codec(0, 0, bytes([0x21, 0x15, 1, 251]))
SBC_ZERO = codec(0, 0, bytes([0, 0, 0, 0]))
MPEG12 = codec(0, 1, bytes([0xff, 0x7f, 0xff, 0xff]))
AAC = codec(0, 2, bytes([0xf0, 0xff, 0xfc, 0x8f, 0xff, 0xff]))
ATRAC = codec(0, 4, bytes([0x3c, 0x00, 0x30, 0x07, 0xff, 0xff, 0x00]))
APTX = codec(0, 0xff, struct.pack('<IH', 0x4f, 1) + bytes([0x22]))
APTX_ALL = codec(0, 0xff, struct.pack('<IH', 0x4f, 1) + bytes([0xff]))
APTX_NONE = codec(0, 0xff, struct.pack('<IH', 0x4f, 1) + bytes([0x00]))
APTX_FREQ = codec(0, 0xff, struct.pack('<IH', 0xd7, 1) + bytes([0x80]))   # Qualcomm aptX, no channel
APTX_CHAN = codec(0, 0xff, struct.pack('<IH', 0x4f, 1) + bytes([0x08]))   # no frequency
APTX_NOCHAN = codec(0, 0xff, struct.pack('<IH', 0x4f, 1) + bytes([0x40]))  # no channel mode
APTX_48M = codec(0, 0xff, struct.pack('<IH', 0x4f, 1) + bytes([0x18]))
APTX_16J = codec(0, 0xff, struct.pack('<IH', 0x4f, 1) + bytes([0x81]))
APTX_HD = codec(0, 0xff, struct.pack('<IH', 0xd7, 0x24) + bytes([0x22]) + b'\0\0\0\0')
APTX_HD_ALL = codec(0, 0xff, struct.pack('<IH', 0x4f, 0x24) + bytes([0xff]) + b'\0\0\0\0')
APT_OTHER = codec(0, 0xff, struct.pack('<IH', 0x4f, 0x05) + b'\x12\x34')
LDAC = codec(0, 0xff, struct.pack('<IH', 0x12d, 0xaa) + bytes([0x20, 0x01]))
LDAC_ALL = codec(0, 0xff, struct.pack('<IH', 0x12d, 0xaa) + bytes([0x3f, 0x07]))
LDAC_NONE = codec(0, 0xff, struct.pack('<IH', 0x12d, 0xaa) + bytes([0x00, 0x00]))
SONY_OTHER = codec(0, 0xff, struct.pack('<IH', 0x12d, 0x01) + b'\x56')
OPUS = codec(0, 0xff, struct.pack('<IH', 0xe0, 1) + bytes([0x82]))
OPUS_ALL = codec(0, 0xff, struct.pack('<IH', 0xe0, 1) + bytes([0xff]))
OPUS_NONE = codec(0, 0xff, struct.pack('<IH', 0xe0, 1) + bytes([0x00]))
OPUS_NOFREQ = codec(0, 0xff, struct.pack('<IH', 0xe0, 1) + bytes([0x01]))
GOOGLE_OTHER = codec(0, 0xff, struct.pack('<IH', 0xe0, 2) + b'\x78\x9a')
VENDOR_OTHER = codec(0, 0xff, struct.pack('<IH', 0x0a, 0x1234) + b'\xbc')
AUDIO_UNKNOWN = codec(0, 0x03, b'\x01\x02')
H263 = codec(1, 1, bytes([0xe0]))
H263_P3 = codec(1, 3, bytes([0x80]))
H263_P8 = codec(1, 4, bytes([0x40]))
MPEG4 = codec(1, 2, bytes([0xf0]))
VIDEO_VENDOR = codec(1, 0xff, struct.pack('<IH', 0x0a, 0x0001) + b'\x01')
VIDEO_UNKNOWN = codec(1, 0x09, b'\x01')
OTHER_MEDIA = codec(2, 0x00, b'\x01\x02')
SCMS_T = cat(4, b'\x02\x00')
DTCP_DATA = cat(4, b'\x01\x00\xaa\xbb')
RECOVERY = cat(3, bytes([1, 0x10, 0x10]))
RECOVERY_0 = cat(3, bytes([1, 0x00, 0x00]))
RECOVERY_BIG = cat(3, bytes([2, 0x18, 0x20]))
REPORTING = cat(2)
HEADER_COMP = cat(5, bytes([0xe0]))
MUX3 = cat(6, bytes([0x80, 0x08, 0x10, 0x10, 0x18, 0x18, 0x20]))
MUX1 = cat(6, bytes([0x00]))
MUX2 = cat(6, bytes([0x80, 0x08, 0x10, 0x10, 0x18]))
DELAY_REP = cat(8)
UNKNOWN_CAT = cat(0x20, b'\x01\x02')
TRANSPORT_LOSC = cat(1, b'\xee')                         # warning: unexpected losc data


def avrcp_vd(ctype, pdu_id, packet_type, params):
    return bytes([ctype, 0x48, 0x00]) + b'\x00\x19\x58' + bytes([pdu_id, packet_type]) + \
        struct.pack('>H', len(params)) + params


def avctp(cr, payload, trans=0):
    return bytes([(trans << 4) | (cr << 1)]) + struct.pack('>H', 0x110E) + payload


def rtp(seq, ts, payload, pt=96, ssrc=0x11223344):
    return struct.pack('>BBHII', 0x80, pt, seq, ts, ssrc) + payload


def sbc_frame(cfg, bitpool):
    freq, blocks, mode, subbands = cfg >> 6, (cfg >> 4) & 3, (cfg >> 2) & 3, cfg & 1
    nsb, nblk = 4 * (subbands + 1), 4 * (blocks + 1)
    ch = 1 if mode == 0 else 2
    length = (4 * nsb * ch) // 8
    if ch == 1 or mode == 1:
        val = nblk * ch * bitpool
    else:
        val = (nsb if mode == 3 else 0) + nblk * bitpool
    length += (val + 7) // 8
    return bytes([0x9c, cfg, bitpool, 0x5a]) + bytes((i * 37) & 0xff for i in range(length))


def sbc_payload(frames):
    return bytes([len(frames)]) + b''.join(frames)


# aptX: raw 4 octet samples; LDAC: frame header + syncword frames
def ldac_frame(fsid, cci, length):
    flen = length - 1
    return bytes([0xaa, fsid << 5 | cci << 3 | (flen >> 6), (flen & 0x3f) << 2]) + bytes(length)


def mp2t_packet(pid=0x100, cc=0):
    return bytes([0x47, 0x40 | (pid >> 8), pid & 0xff, 0x10 | cc]) + bytes(range(184))


# MPEG-1 Layer III 32 kbit/s 32 kHz frame: 144 octets
def mp3_frame():
    return bytes([0xff, 0xfb, 0x18, 0xc4]) + bytes(140)


def h263_payload():
    # RFC 2190 mode A header + picture start code
    return bytes([0x00, 0x00, 0x00, 0x00]) + bytes([0x00, 0x00, 0x80, 0x02, 0x08]) + bytes(8)


def mp4v_payload():
    return bytes([0x00, 0x00, 0x01, 0xb0, 0x01, 0x00, 0x00, 0x01, 0xb6, 0x10, 0x20, 0x30])


class Session:
    """One HCI connection with an AVDTP signaling channel."""
    def __init__(self, cap, handle, ctrl=(0x40, 0x50)):
        self.cap, self.h = cap, handle
        self.ctrl = ctrl
        self.media = None
        self.trans = 0
        self.ident = 1
        bdaddr = bytes([0x00, 0x1b, 0xdc, 0x00, 0x10, handle])
        self.add(conn_complete(handle, bdaddr))
        self.connect('ctrl', ctrl)

    def add(self, pkt, step=20000):
        return self.cap.add(LT_H4_PHDR, pkt, step)

    def connect(self, what, cids):
        for p in l2_connect(self.h, 0x19, cids[0], cids[1], self.ident):
            self.add(p)
        self.ident += 1
        if what == 'media':
            self.media = cids

    def disconnect(self, cids):
        for p in l2_disconnect(self.h, cids[0], cids[1], self.ident):
            self.add(p)
        self.ident += 1

    def cmd(self, sigid, payload=b'', **kw):
        self.trans = (self.trans + 1) & 0xf
        return self.add(acl(SENT, self.h, self.ctrl[1], sig(self.trans, CMD, sigid, payload, **kw)))

    def rsp(self, msg, sigid, payload=b'', **kw):
        return self.add(acl(RECV, self.h, self.ctrl[0], sig(self.trans, msg, sigid, payload, **kw)))

    def raw(self, direction, data, cids=None):
        cids = cids or self.ctrl
        return self.add(acl(direction, self.h, cids[1] if direction == SENT else cids[0], data))

    def media_pkt(self, data, step=20000):
        return self.add(acl(SENT, self.h, self.media[1], data), step)

    def stream(self, seps, acp, caps, media=(), start=True, int_seid=7):
        """DISCOVER, SET_CONFIGURATION, OPEN, media channel, START, media."""
        self.cmd(DISCOVER)
        self.rsp(ACC, DISCOVER, b''.join(seps))
        self.cmd(SET_CONF, seid(acp) + seid(int_seid) + caps)
        self.rsp(ACC, SET_CONF)
        self.cmd(OPEN, seid(acp))
        self.rsp(ACC, OPEN)
        self.connect('media', (self.ctrl[0] + 1, self.ctrl[1] + 1))
        if start:
            self.cmd(START, seid(acp))
            self.rsp(ACC, START)
        first = None
        for m in media:
            n = self.media_pkt(m)
            first = first or n
        return first


def build_main(path):
    cap = Pcapng()
    F = {}

    # ---- Video first: VDP registers its RTP conversation with port 0 but
    # RTP looks it up by the stream number, so a later video stream would
    # find an earlier A2DP conversation and be decoded as SBC
    v = [sep(1, 1, True)]
    F['h263'] = Session(cap, 14).stream(v, 1, TRANSPORT + H263, [rtp(1, 0, h263_payload(), pt=97)])
    F['mpeg4_scms'] = Session(cap, 15).stream(v, 1, TRANSPORT + SCMS_T + MPEG4,
            [rtp(1, 0, b'\x01' + mp4v_payload(), pt=98)])
    F['video_nostart'] = Session(cap, 17).stream(v, 1, TRANSPORT + H263,
            [rtp(1, 0, h263_payload(), pt=97)], start=False)

    # ---- Handle 1: SBC stream and the whole signaling procedure
    s = Session(cap, 1)
    s.cmd(DISCOVER)
    F['discover_rej'] = s.rsp(REJ, DISCOVER, b'\x31')
    s.cmd(DISCOVER)
    F['discover'] = s.rsp(ACC, DISCOVER, sep(1, 0, True) + sep(2, 1, True) + sep(3, 0, True, True) + sep(4, 0, False))
    F['getcap'] = s.cmd(GET_CAP, seid(1))
    F['getcap_acc'] = s.rsp(ACC, GET_CAP, TRANSPORT + REPORTING + RECOVERY + SCMS_T + HEADER_COMP + MUX3 + SBC_ALL + DELAY_REP + UNKNOWN_CAT)
    s.cmd(GET_CAP, seid(2))
    s.rsp(REJ, GET_CAP, b'\x12')
    s.cmd(GET_ALL_CAP, seid(1))
    F['getallcap_acc'] = s.rsp(ACC, GET_ALL_CAP, TRANSPORT + RECOVERY_0 + DTCP_DATA + MUX1 + SBC_NONE + DELAY_REP)
    s.cmd(GET_ALL_CAP, seid(3))
    F['losc'] = s.rsp(ACC, GET_ALL_CAP, TRANSPORT_LOSC + RECOVERY_BIG + MUX2 + SBC_BADPOOL + SBC_ZERO)
    F['setconf_rej'] = s.cmd(SET_CONF, seid(4) + seid(1) + TRANSPORT + SBC_CFG)
    s.rsp(REJ, SET_CONF, b'\x07\x29')
    F['setconf'] = s.cmd(SET_CONF, seid(1) + seid(5) + TRANSPORT + SBC_CFG + DELAY_REP)
    s.rsp(ACC, SET_CONF)
    s.cmd(GET_CONF, seid(1))
    F['getconf_acc'] = s.rsp(ACC, GET_CONF, TRANSPORT + SBC_CFG + DELAY_REP)
    s.cmd(GET_CONF, seid(9))
    s.rsp(REJ, GET_CONF, b'\x12')
    s.cmd(OPEN, seid(4))
    s.rsp(REJ, OPEN, b'\x31')
    F['open'] = s.cmd(OPEN, seid(1))
    F['open_acc'] = s.rsp(ACC, OPEN)
    s.connect('media', (0x41, 0x51))
    F['delay'] = s.cmd(DELAY, seid(1) + struct.pack('>H', 1505))
    s.rsp(ACC, DELAY)
    s.cmd(DELAY, seid(1) + struct.pack('>H', 20))
    s.rsp(REJ, DELAY, b'\x31')
    s.cmd(START, seid(1) + seid(3))
    s.rsp(REJ, START, seid(3) + b'\x31')
    F['start'] = s.cmd(START, seid(1))
    F['start_acc'] = s.rsp(ACC, START)
    F['sbc'] = s.media_pkt(rtp(1, 0, sbc_payload([sbc_frame(0xbd, 53), sbc_frame(0xbd, 53)])))
    s.media_pkt(rtp(2, 256, sbc_payload([sbc_frame(0x00, 2)])))                 # 16k mono 4 blk 4 sb
    s.media_pkt(rtp(3, 512, sbc_payload([sbc_frame(0x46, 20), sbc_frame(0xda, 30)])))  # 32k dual / 48k stereo
    s.cmd(SUSPEND, seid(1) + seid(3))
    s.rsp(REJ, SUSPEND, seid(3) + b'\x31')
    s.cmd(SUSPEND, seid(1))
    s.rsp(ACC, SUSPEND)
    s.cmd(SECURITY, seid(1) + b'\x01\x02\x03')
    F['security_acc'] = s.rsp(ACC, SECURITY, b'\x04\x05')
    s.cmd(SECURITY, seid(1) + b'\x01')
    s.rsp(REJ, SECURITY, b'\x31')
    # Second START: the stream number goes up
    s.cmd(START, seid(1))
    s.rsp(ACC, START)
    # AVRCP on the same connection: the playback position is used by the
    # next media packet (keyed by interface and adapter)
    for p in l2_connect(1, 0x17, 0x43, 0x53, 9):
        s.add(p)
    F['avrcp_interim'] = s.raw(RECV, avctp(1, avrcp_vd(0x0f, 0x31, 0, bytes([5]) + struct.pack('>I', 1000))), (0x43, 0x53))
    F['sbc2'] = s.media_pkt(rtp(4, 768, sbc_payload([sbc_frame(0xbd, 53)])))
    F['avrcp_changed'] = s.raw(RECV, avctp(1, avrcp_vd(0x0d, 0x31, 0, bytes([5]) + struct.pack('>I', 5000))), (0x43, 0x53))
    F['sbc3'] = s.media_pkt(rtp(5, 1024, sbc_payload([sbc_frame(0xbd, 53)])))
    s.media_pkt(rtp(6, 1280, sbc_payload([sbc_frame(0xbd, 53)])))
    # Third channel on PSM 0x19: neither signaling nor media
    s.connect('other', (0x42, 0x52))
    F['unknown_channel'] = s.raw(SENT, b'\x01\x02\x03\x04', (0x42, 0x52))
    # Signaling packet types, general reject, unknown signals, data after a message
    F['sig_start'] = s.rsp(ACC, GET_CAP, TRANSPORT + SBC_CFG, ptype=1, nosp=1)
    F['sig_cont'] = s.raw(RECV, bytes([s.trans << 4 | 2 << 2 | ACC]) + b'\xaa\xbb')
    F['sig_end'] = s.raw(RECV, bytes([s.trans << 4 | 3 << 2 | ACC]) + b'\xcc')
    F['grej'] = s.cmd(0x0e)
    s.rsp(GREJ, 0x0e, b'')
    F['unknown_sig'] = s.cmd(0x3f, b'\x01\x02')
    s.cmd(DISCOVER, b'\x99')
    # ABORT reject, CLOSE reject, CLOSE accept ends this channel set
    s.cmd(ABORT, seid(1))
    s.rsp(REJ, ABORT, b'\x31')
    s.cmd(CLOSE, seid(1))
    s.rsp(REJ, CLOSE, b'\x31')
    s.cmd(CLOSE, seid(1))
    F['close_acc'] = s.rsp(ACC, CLOSE)
    # New channel set after the close: the next signaling packet starts it
    s.cmd(DISCOVER)
    s.rsp(ACC, DISCOVER, sep(1, 0, True))
    F['after_close_media'] = s.media_pkt(rtp(6, 1280, sbc_payload([sbc_frame(0xbd, 53)])))
    s.cmd(ABORT, seid(1))
    F['abort_acc'] = s.rsp(ACC, ABORT)
    s.cmd(DISCOVER)
    s.rsp(ACC, DISCOVER, sep(1, 0, True))
    s.disconnect((0x41, 0x51))
    s.disconnect((0x40, 0x50))
    s.add(disconn_complete(1))

    # ---- Handle 2: RECONFIGURE (no media on this stream)
    s = Session(cap, 2)
    s.cmd(DISCOVER)
    s.rsp(ACC, DISCOVER, sep(1, 0, True))
    s.cmd(SET_CONF, seid(1) + seid(2) + TRANSPORT + SBC_CFG)
    s.rsp(ACC, SET_CONF)
    F['reconf'] = s.cmd(RECONF, seid(1) + MPEG12)
    s.rsp(ACC, RECONF)
    s.cmd(RECONF, seid(1) + SBC_CFG)
    s.rsp(REJ, RECONF, b'\x07\x29')
    s.cmd(RECONF, seid(1) + RECOVERY)
    s.rsp(ACC, RECONF)

    # ---- Handle 3: capabilities of every codec (no state)
    s = Session(cap, 3)
    s.cmd(DISCOVER)
    s.rsp(ACC, DISCOVER, sep(1, 0, True) + sep(2, 1, True) + sep(3, 2, True))
    F['caps_first'] = None
    for caps in (MPEG12, AAC, ATRAC, APTX_ALL, APTX_NONE, APTX_FREQ, APTX_CHAN, APTX_HD_ALL,
                 APT_OTHER, LDAC_ALL, LDAC_NONE, SONY_OTHER, OPUS_ALL, OPUS_NONE, OPUS_NOFREQ,
                 GOOGLE_OTHER, VENDOR_OTHER, AUDIO_UNKNOWN, H263, H263_P3, H263_P8, MPEG4,
                 VIDEO_VENDOR, VIDEO_UNKNOWN, OTHER_MEDIA):
        s.cmd(GET_CAP, seid(1))
        n = s.rsp(ACC, GET_CAP, TRANSPORT + caps)
        F['caps_first'] = F['caps_first'] or n

    # ---- One stream per handle and codec
    def a(n):
        return [sep(1, 0, True)]

    v = [sep(1, 1, True)]
    F['sbc_scms'] = Session(cap, 4).stream(a(1), 1, TRANSPORT + SCMS_T + SBC_CFG,
            [rtp(1, 0, b'\x01' + sbc_payload([sbc_frame(0xbd, 53)])),
             rtp(2, 128, b'\x02' + sbc_payload([sbc_frame(0xbd, 53)]))])
    F['mpeg12'] = Session(cap, 5).stream(a(1), 1, TRANSPORT + MPEG12, [rtp(1, 0, mp2t_packet())])
    F['aac'] = Session(cap, 6).stream(a(1), 1, TRANSPORT + AAC, [rtp(1, 0, mp3_frame())])
    F['atrac'] = Session(cap, 7).stream(a(1), 1, TRANSPORT + ATRAC, [rtp(1, 0, bytes(16))])
    s = Session(cap, 8)
    F['aptx'] = s.stream(a(1), 1, TRANSPORT + APTX, [bytes(range(64))])
    s.media_pkt(bytes(range(64)), 2000)
    s.media_pkt(bytes(range(32)), 1500)
    s = Session(cap, 9)
    F['aptx_hd_scms'] = s.stream(a(1), 1, TRANSPORT + SCMS_T + APTX_HD, [rtp(1, 0, b'\x00' + bytes(48))])
    s.media_pkt(rtp(2, 12, b'\x03' + bytes(48)))
    F['aptx_nofreq'] = Session(cap, 10).stream(a(1), 1, TRANSPORT + APTX_CHAN, [bytes(16)])
    F['aptx_nochan'] = Session(cap, 11).stream(a(1), 1, TRANSPORT + APTX_NOCHAN, [bytes(16)])
    F['aptx_48m'] = Session(cap, 18).stream(a(1), 1, TRANSPORT + APTX_48M, [bytes(16)])
    F['aptx_16j'] = Session(cap, 19).stream(a(1), 1, TRANSPORT + APTX_16J, [bytes(16)])
    # The remote side is INT: DISCOVER and SET_CONFIGURATION come from it
    s = Session(cap, 20)
    s.raw(RECV, sig(1, CMD, DISCOVER))
    s.raw(SENT, sig(1, ACC, DISCOVER, sep(2, 0, False)))
    F['setconf_recv'] = s.raw(RECV, sig(2, CMD, SET_CONF, seid(2) + seid(6) + TRANSPORT + SBC_CFG))
    s.raw(SENT, sig(2, ACC, SET_CONF))
    s = Session(cap, 12)
    F['ldac'] = s.stream(a(1), 1, TRANSPORT + LDAC,
            [rtp(1, 0, bytes([2]) + ldac_frame(0, 2, 20) + ldac_frame(1, 0, 10))])
    # LDAC sampling frequencies 88.2k to 192k and an unknown one
    s.media_pkt(rtp(2, 128, bytes([5]) + ldac_frame(2, 1, 8) + ldac_frame(3, 2, 8) +
                    ldac_frame(4, 2, 8) + ldac_frame(5, 2, 8) + ldac_frame(6, 2, 8)))

    F['opus'] = Session(cap, 13).stream(a(1), 1, TRANSPORT + OPUS, [rtp(1, 0, bytes(20))])
    # Media type 2 (neither audio nor video), no START: stream number 1
    F['other_media'] = Session(cap, 16).stream([sep(1, 2, True)], 1, TRANSPORT + OTHER_MEDIA,
            [b'\x01\x02\x03\x04'], start=False)

    # ---- Exported PDUs (dissectors called by name)
    def exp(name, payload, p2p=None):
        tlv = struct.pack('>HH', 12, len(name)) + name.encode()
        if p2p is not None:
            tlv += struct.pack('>HHi', 35, 4, p2p)
        tlv += struct.pack('>HH', 0, 0)
        return cap.add(LT_EXP_PDU, tlv + payload)

    F['exp_avdtp_dir'] = exp('btavdtp', b'\x00\x01', SENT)        # the fix: no btl2cap_data_t
    F['exp_avdtp'] = exp('btavdtp', b'\x00\x01')
    F['exp_a2dp'] = exp('bta2dp', rtp(1, 0, sbc_payload([sbc_frame(0xbd, 53)])), SENT)
    exp('btvdp', rtp(1, 0, h263_payload(), pt=97))
    exp('bta2dp', rtp(2, 0, sbc_payload([sbc_frame(0xbd, 53)])), RECV)
    exp('bta2dp', rtp(3, 0, sbc_payload([sbc_frame(0xbd, 53)])))
    exp('btvdp', rtp(2, 0, h263_payload(), pt=97), RECV)
    F['exp_aptx'] = exp('aptx', bytes(32), RECV)
    exp('aptx', bytes(8))
    F['exp_ldac'] = exp('ldac', bytes([1]) + ldac_frame(2, 1, 12), SENT)
    exp('bta2dp_content_protection_header_scms_t', b'\x03')
    exp('btvdp_content_protection_header_scms_t', b'\x02')

    cap.write(path)
    return F


def build_malformed(path):
    cap = Pcapng()
    s = Session(cap, 1)
    s.cmd(DISCOVER)
    s.rsp(ACC, DISCOVER, sep(1, 0, True) + sep(2, 1, True))
    # Short LOSC / truncated capabilities
    for caps in (cat(3, b'\x01'), codec(0, 0, b'\x21'), cat(4, b'\x02'), cat(6, b''),
                 cat(5), codec(0, 0xff, struct.pack('<IH', 0x4f, 2)),
                 codec(0, 0xff, struct.pack('<IH', 0x12d, 2)),
                 codec(0, 0xff, struct.pack('<IH', 0xe0, 3)),
                 codec(0, 0xff, struct.pack('<IH', 0x0a, 1)),
                 codec(1, 0xff, struct.pack('<IH', 0x0a, 1)),
                 codec(1, 0x09, b''), codec(2, 0, b''), codec(0, 3, b''),
                 b'\x07\x05\x00\x00\x21'):
        s.cmd(GET_CAP, seid(1))
        s.rsp(ACC, GET_CAP, caps)
    s.cmd(DELAY, seid(1))               # delay value missing
    s.cmd(GET_CAP)                      # SEID missing
    s.rsp(REJ, SET_CONF, b'\x01')       # error code missing
    s.rsp(ACC, DISCOVER, b'\x04')       # half a SEP
    s.raw(SENT, b'\x04')                # START packet without NOSP
    # Media before the OPEN accept and RECONFIGURE of a used stream
    # (pass 2 decodes the earlier media with the later state)
    s.cmd(SET_CONF, seid(1) + seid(2) + TRANSPORT + SBC_CFG)
    s.rsp(ACC, SET_CONF)
    s.cmd(OPEN, seid(1))
    s.connect('media', (0x41, 0x51))
    s.media_pkt(rtp(1, 0, sbc_payload([sbc_frame(0xbd, 53)])))
    s.rsp(ACC, OPEN)
    s.media_pkt(rtp(2, 0, sbc_payload([sbc_frame(0xbd, 53)])))
    s.cmd(RECONF, seid(1) + TRANSPORT + LDAC)
    s.rsp(ACC, RECONF)
    s.media_pkt(rtp(3, 0, bytes([1]) + ldac_frame(0, 2, 40)))       # LDAC frame longer than data
    s.media_pkt(rtp(4, 0, bytes([1, 0x55])))                         # bad LDAC syncword
    s.media_pkt(rtp(5, 0, bytes([1, 0xaa])))
    s.media_pkt(rtp(6, 0, bytes([1, 0xaa, 0x00])))
    s.media_pkt(b'\x80')                                               # short RTP
    # aptX with a short configuration and SBC with a truncated frame
    s2 = Session(cap, 2)
    s2.stream([sep(1, 0, True)], 1, TRANSPORT + codec(0, 0xff, struct.pack('<IH', 0x4f, 1)),
              [bytes(8)])
    s3 = Session(cap, 3)
    s3.stream([sep(1, 0, True)], 1, TRANSPORT + SBC_CFG, [rtp(1, 0, bytes([1, 0x9c, 0xbd, 53]))])
    cap.write(path)


if __name__ == '__main__':
    F = build_main(f'{OUT}/btavdtp-coverage.pcapng')
    build_malformed(f'{OUT}/btavdtp-coverage-malformed.pcapng')
    for k, n in F.items():
        print(k, n)
