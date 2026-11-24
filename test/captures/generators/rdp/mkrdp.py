#!/usr/bin/env python3
# Generates test/captures/rdp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDP (MS-RDPBCGR) captures for packet-rdp.c.  Usage: mkrdp.py <outdir> [-v]
# Everything is built with struct; nothing comes from a real network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import (
    blk, Cap, chan_pdu, connect_initial, connect_response, cotp_cc, cotp_cr, cotp_dt, cs_cluster,
    cs_core, cs_monitor, cs_monitor_ex, cs_msgchannel, cs_multitransport, cs_net, cs_security,
    mcs_attach_conf, mcs_attach_req, mcs_erect, mcs_join_conf, mcs_join_req, neg_fail, neg_req,
    neg_rsp, sc_core, sc_msgchannel, sc_multitransport, sc_net, sc_security, sec_hdr,
    send_data_ind, send_data_req, share_ctrl, share_data, Tcp,
)

VERBOSE = '-v' in sys.argv
OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
MARKS = []


def mark(cap, title):
    MARKS.append((len(cap.frames) + 1, title))


def finish(cap, name):
    cap.write(os.path.join(OUT, name))
    if VERBOSE:
        print(name, len(cap.frames), 'frames')
        for i, (n, t) in enumerate(MARKS):
            end = MARKS[i + 1][0] - 1 if i + 1 < len(MARKS) else len(cap.frames)
            print('  %d-%d: %s' % (n, end, t))


CHANNELS = ['drdynvc', 'rdpdr', 'rdpsnd', 'cliprdr', 'rail', 'conctrl', 'unknown1']
IDS = [1004, 1005, 1006, 1007, 1008, 1009, 1010]
MSGCHAN = 1011
MCSCHAN = 1003


def uni(s):
    return s.encode('utf-16le')


def unistr0(s):
    return uni(s) + b'\0\0'


# ------------------------------------------------------------ RDP PDU bodies
def client_info(unicode_=True, flags_extra=0, enc=False):
    fl = 0x00000033 | flags_extra
    if unicode_:
        fl |= 0x10
    else:
        fl &= ~0x10
    enc_s = (lambda s: unistr0(s)) if unicode_ else (lambda s: s.encode() + b'\0')
    cb = (lambda s: len(enc_s(s)) - 2) if unicode_ else (lambda s: len(s))
    # cb* excludes the terminating null; the dissector adds 2
    strs = ['DOMAIN', 'alice', 'secret', 'C:\\shell.exe', 'C:\\work']
    if not unicode_:
        enc_s = lambda s: s.encode() + b'\0\0'
    b = struct.pack('<II', 0x409, fl)
    for s in strs:
        b += struct.pack('<H', cb(s))
    for s in strs:
        b += enc_s(s)
    addr = '192.0.2.2'
    dr = 'C:\\Windows'
    b += struct.pack('<HH', 2, len(enc_s(addr)))
    b += enc_s(addr)
    b += struct.pack('<H', len(enc_s(dr)))
    b += enc_s(dr)
    tz = struct.pack('<i', -60) + uni('Std').ljust(64, b'\0')
    tz += struct.pack('<8H', 2026, 10, 0, 1, 3, 0, 0, 0) + struct.pack('<i', 0)
    tz += uni('Dst').ljust(64, b'\0') + struct.pack('<8H', 2026, 3, 0, 5, 2, 0, 0, 0) + struct.pack('<i', -60)
    b += tz
    b += struct.pack('<II', 5, 0x80)
    cookie = bytes(range(28))
    b += struct.pack('<H', len(cookie)) + cookie
    b += struct.pack('<HH', 0, 0)
    key = uni('W. Europe Standard Time')
    b += struct.pack('<H', len(key)) + key
    b += struct.pack('<H', 1)
    return b


def lic_alert(valid=True, code=7):
    return struct.pack('<BBH', 0xff, 3, 16) + struct.pack('<IIHH', code if valid else 6, 2, 1, 4) + b'\0\0\0\0'


def caps(items):
    return b''.join(struct.pack('<HH', t, len(d) + 4) + d for t, d in items)


def cap_general(flags=0x040d, osmaj=1, osmin=3):
    return (1, struct.pack('<HHHHHHHHHBB', osmaj, osmin, 0x200, 0, 0, flags, 0, 0, 0, 1, 1))


def cap_rail(flags=0x7f):
    return (0x17, struct.pack('<I', flags))


def demand_active(cap_items, src=b'RDP\0', share=0x103ea):
    cp = caps(cap_items)
    b = struct.pack('<IHH', share, len(src), len(cp) + 4) + src + struct.pack('<HH', len(cap_items), 0) + cp
    b += struct.pack('<I', 0x1234)
    return b


def confirm_active(cap_items, src=b'MSTSC\0', share=0x103ea):
    cp = caps(cap_items)
    return struct.pack('<IHHH', share, 1002, len(src), len(cp) + 4) + src + struct.pack('<HH', len(cap_items), 0) + cp


def autodetect(typ, seq, rt, body=b''):
    return struct.pack('<BBHH', 6, typ, seq, rt) + body


# ------------------------------------------------------------ main capture
def build_main():
    cap = Cap()

    # ---- Connection 1: no encryption, with a routing cookie, correlation info
    mark(cap, 'connection 1 (TCP 50000): negotiation, MCS setup, ClientData (all blocks), ServerData, no encryption')
    t = Tcp(cap, sport=50000)
    t.open()
    corr = struct.pack('<BBHH', 6, 0, 36, 0)[:4] + bytes(range(16)) + bytes(16)
    t.send(True, cotp_cr(b'Cookie: mstshash=alice\r\n' + neg_req(0x0b, 0x08 | 0x01 | 0x02, corr)))
    t.send(False, cotp_cc(neg_rsp(0x01, 0x0f)))
    cblocks = [cs_core(), cs_security(0x1b, 0), cs_net(CHANNELS), cs_cluster(), cs_monitor(
        [(0, 0, 1023, 767, 1), (1024, 0, 2047, 767, 0)]), cs_monitor_ex(2), cs_msgchannel(0),
        cs_multitransport(0x305), blk(0xC0F0, b'unk!')]
    t.send(True, cotp_dt(connect_initial(cblocks)))
    sblocks = [sc_core(), sc_security(0, 0), sc_net(MCSCHAN, IDS), sc_msgchannel(MSGCHAN),
               sc_multitransport(0x305), blk(0x0CF0, b'unk!')]
    t.send(False, cotp_dt(connect_response(sblocks)))
    t.send(True, cotp_dt(mcs_erect()))
    t.send(True, cotp_dt(mcs_attach_req()))
    t.send(False, cotp_dt(mcs_attach_conf(1001)))
    t.send(True, cotp_dt(mcs_join_req(1001)))
    t.send(False, cotp_dt(mcs_join_conf(1001)))
    t.send(True, cotp_dt(mcs_join_req(MCSCHAN)))
    t.send(False, cotp_dt(mcs_join_conf(MCSCHAN)))
    for cid in IDS + [MSGCHAN]:
        t.send(True, cotp_dt(mcs_join_req(cid)))
        t.send(False, cotp_dt(mcs_join_conf(cid)))

    mark(cap, 'licensing stage: ClientInfo (Unicode and ANSI), license error alert')
    t.send(True, cotp_dt(send_data_req(MCSCHAN, sec_hdr(0x0040) + client_info(True))))
    t.send(True, cotp_dt(send_data_req(MCSCHAN, sec_hdr(0x0040) + client_info(False))))
    t.send(False, cotp_dt(send_data_ind(MCSCHAN, sec_hdr(0x0080) + lic_alert())))

    mark(cap, 'share control: demand/confirm active with capabilities, data PDUs, deactivate')
    capitems = [cap_general(), cap_rail(), (2, bytes(24)), (3, bytes(16)), (0x1a, b'\0\0\0\0')]
    t.send(False, cotp_dt(send_data_ind(MCSCHAN, share_ctrl(1, demand_active(capitems)))))
    t.send(True, cotp_dt(send_data_req(MCSCHAN, share_ctrl(3, confirm_active(capitems)))))
    t.send(False, cotp_dt(send_data_ind(MCSCHAN, share_ctrl(6, struct.pack('<I', 0x103ea) + b'\0\0'))))
    for p2, body in [(0x14, struct.pack('<HHI', 4, 1002, 0x3ea)), (0x1f, struct.pack('<HH', 1, 1002)),
                     (0x28, struct.pack('<HHHH', 0, 0, 3, 4)), (0x2b, struct.pack('<5H5HBBH', *([0] * 10), 0, 0, 0)),
                     (0x36, struct.pack('<I', 1)), (0x2, b''), (0x1b, b''), (0x1c, b''), (0x21, b''), (0x22, b''),
                     (0x23, b''), (0x24, b''), (0x25, b''), (0x26, b''), (0x27, b''), (0x29, b''), (0x2c, b''),
                     (0x2d, b''), (0x2e, b''), (0x2f, b''), (0x30, b''), (0x31, b''), (0x32, b''), (0x37, b''),
                     (0x7f, b'')]:
        t.send(False, cotp_dt(send_data_ind(MCSCHAN, share_data(p2, body))))
    t.send(False, cotp_dt(send_data_ind(MCSCHAN, share_ctrl(0xa, b'\0' * 8))))
    t.send(False, cotp_dt(send_data_ind(MCSCHAN, share_ctrl(0x9, b'\0' * 8))))

    # ---- virtual channels on connection 1
    mark(cap, 'static virtual channels: one PDU for each known channel, an unknown channel, reassembly, flags')

    def ch_c(i, payload, flags=3, length=None):
        t.send(True, cotp_dt(send_data_req(IDS[i], chan_pdu(len(payload) if length is None else length, flags, payload))))

    def ch_s(i, payload, flags=3, length=None):
        t.send(False, cotp_dt(send_data_ind(IDS[i], chan_pdu(len(payload) if length is None else length, flags, payload))))

    ch_s(0, bytes([0x10, 0x05]) + b'foo\0')                       # drdynvc create request
    ch_s(1, struct.pack('<HHHHI', 0x4472, 0x496e, 1, 12, 7))      # rdpdr server announce
    ch_s(2, struct.pack('<BBHHH', 6, 0, 4, 0x1234, 0))            # rdpsnd training
    ch_s(3, struct.pack('<HHI', 1, 0, 0))                         # cliprdr monitor ready
    ch_s(4, struct.pack('<HHI', 5, 8, 19041))                     # rail handshake
    ch_s(5, struct.pack('<H', 2))                                 # conctrl
    ch_c(5, struct.pack('<H', 1))
    ch_c(5, struct.pack('<H', 8))
    ch_s(5, struct.pack('<HIII', 0x10, 0, 0, 0) + struct.pack('<II', 10, 10) + uni('realm') + uni('login'))
    ch_s(6, b'unknown channel data', 3)                           # not a known channel
    ch_c(6, b'client data')
    # a channel PDU whose length has bit 0x08 set: not encrypted (16 bytes + 4)
    ch_s(6, bytes(12), 3, 12)
    cl = struct.pack('<HHI', 0x0002, 0, 36) + struct.pack('<I', 1) + b'CF_TEXT'.ljust(32, b'\0')
    ch_s(3, cl[:16], 1, len(cl))                                  # cliprdr format list in three chunks
    ch_s(3, cl[16:32], 0, len(cl))
    ch_s(3, cl[32:], 2, len(cl))
    ch_c(3, cl[:20], 1, len(cl))                                  # and from the client
    ch_c(3, cl[20:], 2, len(cl))
    ch_s(6, b'FIRST' * 3, 1, 15)
    ch_s(6, b'last', 2, 15)                                       # last chunk of an unknown channel
    ch_s(6, b'orphan', 2, 6)                                      # LAST without FIRST
    ch_s(3, b'x' * 8, 3 | 0x00200000, 8)                          # compressed (not implemented)
    ch_s(6, b'flags', 3 | 0x10 | 0x20 | 0x40, 5)                  # show protocol, suspend, resume
    ch_s(6, b'flags2', 3 | 0x00400000 | 0x00800000 | 0x00020000, 6)

    mark(cap, 'message channel: multitransport request/response, autodetect request/response, heartbeat')
    mc_s = lambda body: t.send(False, cotp_dt(send_data_ind(MSGCHAN, body)))
    mc_c = lambda body: t.send(True, cotp_dt(send_data_req(MSGCHAN, body)))
    cookie = bytes(range(16))
    mc_s(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x11223344, 1, 0) + cookie)
    mc_s(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x11223344, 1, 0) + cookie)   # same key again
    mc_s(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x55667788, 2, 0) + cookie)   # lossy
    mc_c(struct.pack('<HH', 0x0004, 0) + struct.pack('<II', 0x11223344, 0))
    mc_s(struct.pack('<HH', 0x1000, 0) + autodetect(0, 1, 0x0001))
    for i, rt in enumerate((0x1001, 0x0014, 0x0114, 0x1014)):
        mc_s(struct.pack('<HH', 0x1000, 0) + autodetect(0, 2 + i, rt))
    mc_s(struct.pack('<HH', 0x1000, 0) + autodetect(0, 7, 0x0002, struct.pack('<H', 4) + b'data'))
    mc_s(struct.pack('<HH', 0x1000, 0) + autodetect(0, 8, 0x002b, struct.pack('<H', 2) + b'xy'))
    mc_s(struct.pack('<HH', 0x1000, 0) + autodetect(0, 9, 0x0429))
    mc_s(struct.pack('<HH', 0x1000, 0) + autodetect(0, 10, 0x0629))
    mc_s(struct.pack('<HH', 0x1000, 0) + autodetect(0, 11, 0x0840, struct.pack('<II', 5, 6)))
    mc_s(struct.pack('<HH', 0x1000, 0) + autodetect(0, 12, 0x0880, struct.pack('<I', 7)))
    mc_s(struct.pack('<HH', 0x1000, 0) + autodetect(0, 13, 0x08c0, struct.pack('<III', 8, 9, 10)))
    mc_s(struct.pack('<HH', 0x1000, 0) + autodetect(0, 14, 0x7777))
    mc_c(struct.pack('<HH', 0x2000, 0) + autodetect(1, 1, 0x0000))
    mc_c(struct.pack('<HH', 0x2000, 0) + autodetect(1, 2, 0x0003, struct.pack('<II', 100, 2000)))
    mc_c(struct.pack('<HH', 0x2000, 0) + autodetect(1, 3, 0x000b, struct.pack('<II', 101, 2001)))
    mc_c(struct.pack('<HH', 0x2000, 0) + autodetect(1, 4, 0x7777))
    mc_c(struct.pack('<HH', 0x1000, 0) + autodetect(0, 5, 0x0001))          # request flag from the client
    mc_s(struct.pack('<HH', 0x2000, 0) + autodetect(1, 6, 0x0003, struct.pack('<II', 1, 2)))
    mc_s(struct.pack('<HH', 0x4000, 0) + bytes([0, 5, 1, 2]))
    mc_c(struct.pack('<HH', 0x4000, 0) + bytes([0, 5, 3, 4]))
    mc_s(struct.pack('<HH', 0x0000, 0))                                      # no flag set

    mark(cap, 'multitransport: RDPMT tunnel create request and DRDYNVC data on the UDP side (Exported PDUs), linked to the TCP connection')
    udp_kw = dict(sport=50050, pt=3)
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x55667788, 0) + cookie, True, **udp_kw)
    cap.exp('rdp_drdynvc', bytes([0x10, 0x09]) + b'udp\0', False, **udp_kw)
    cap.exp('rdp_drdynvc', bytes([0x10, 0x09]) + b'udp\0', True, **udp_kw)

    mark(cap, 'fast-path: client input events (every type) and server updates (every type, fragments, compression)')

    # Fast-path and RDSTLS PDUs travel inside TLS in real life, and a decrypted
    # TLS stream reaches RDP through the "rdp_tls" heuristic dissector: use an
    # Exported PDU naming it, on the addresses and ports of the TCP connection.
    def X(c2s, payload, sport=50000):
        cap.exp('rdp_tls', payload, c2s, sport=sport, heur=True)

    def fp_c(events, nev_in_hdr=True, flags=0):
        body = b''.join(events)
        n = len(events)
        hdr = ((n if nev_in_hdr and n < 16 else 0) << 2) | (flags << 6)
        extra = b''
        if flags & 2:
            body = b'\0' * 8 + b''
        if not (nev_in_hdr and n < 16):
            extra = bytes([n])
        pay = extra + body
        if flags & 2:
            pay = b'\0' * 8 + extra + b''.join(events)
        total = 2 + len(pay)
        if total > 127:
            total += 1
            return bytes([hdr]) + bytes([0x80 | (total >> 8), total & 0xff]) + pay
        return bytes([hdr, total]) + pay

    ev_scan = bytes([0x00 | (0 << 5) | 0x01, 0x1e])
    ev_scan2 = bytes([0x03 | 0x04, 0x1f])
    ev_mouse = bytes([(1 << 5)]) + struct.pack('<HHH', 0x9000, 100, 200)
    ev_mouse2 = bytes([(1 << 5)]) + struct.pack('<HHH', 0x0800 | 0x4000 | 0x1000 | 0x2000 | 0x0200 | 0x0100, 1, 2)
    ev_mousex = bytes([(2 << 5)]) + struct.pack('<HHH', 0x8000 | 0x0001, 300, 400)
    ev_sync = bytes([(3 << 5) | 0x0f])
    ev_uni = bytes([(4 << 5) | 1]) + struct.pack('<H', 0x20ac)
    ev_rel = bytes([(5 << 5)]) + struct.pack('<HhH', 0x0800 | 0x1000, -3, 4)
    ev_qoe = bytes([(6 << 5)]) + struct.pack('<I', 123456)
    ev_unk = bytes([(7 << 5)])
    for evs in ([ev_scan], [ev_scan2], [ev_mouse, ev_mouse2], [ev_mousex], [ev_sync], [ev_uni], [ev_rel],
                [ev_qoe], [ev_unk], [ev_scan, ev_sync, ev_uni, ev_rel, ev_qoe]):
        X(True, fp_c(evs))
    X(True, fp_c([ev_scan] * 20, nev_in_hdr=False))                     # more than 15 events: count byte
    X(True, fp_c([ev_scan], flags=1))                                   # secure checksum flag
    X(True, fp_c([ev_scan], flags=2))                                   # encrypted: 8 octets skipped
    X(True, fp_c([ev_scan] * 70, nev_in_hdr=False))                     # two-octet length

    def fp_s(updates, flags=0):
        body = b''
        for code, frag, comp, data, cflags in updates:
            hdr = code | (frag << 4) | (comp << 6)
            body += bytes([hdr])
            if comp:
                body += bytes([cflags])
            body += struct.pack('<H', len(data)) + data
        total = 2 + len(body)
        hdr = flags << 6
        if total > 127:
            total += 1
            return bytes([hdr, 0x80 | (total >> 8), total & 0xff]) + body
        return bytes([hdr, total]) + body

    for code in (0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 7, 13):
        X(False, fp_s([(code, 0, 0, bytes(4), 0)]))
    X(False, fp_s([(1, 2, 0, bytes(6), 0), (1, 3, 0, bytes(6), 0), (1, 1, 0, bytes(6), 0)]))
    X(False, fp_s([(0, 0, 1, bytes(5), 0x20)]))
    X(False, fp_s([(0, 0, 2, bytes(5), 0x00)]))
    X(False, fp_s([(1, 0, 0, bytes(300), 0)]))                           # two-octet length
    X(False, fp_s([(3, 0, 0, b'', 0)], flags=1))

    # ---- Connection 2: negotiation variants, each on its own TCP connection
    mark(cap, 'negotiation variants: tsv/mth cookies, negotiate failure, only a negotiate request')
    for sport, cr_user, cc in ((50001, b'tsv:abc123\r\n' + neg_req(3, 0), neg_rsp(2, 0)),
                               (50002, b'mth://host/x\r\n', neg_fail(5)),
                               (50003, neg_req(0, 0), neg_fail(0x80)),
                               (50004, b'Cookie: mstshash=bob\r\n', neg_rsp(0, 0x03)),
                               (50005, neg_req(0x1f, 0x03), neg_rsp(0x0b, 0x0c))):
        t2 = Tcp(cap, sport=sport)
        t2.open()
        t2.send(True, cotp_cr(cr_user))
        t2.send(False, cotp_cc(cc))

    # ---- RDSTLS
    mark(cap, 'RDSTLS (negotiate response selecting protocol 4): capabilities, password and cookie requests, response')
    t3 = Tcp(cap, sport=50010)
    t3.open()
    X3 = lambda c, p: X(c, p, 50010)
    t3.send(True, cotp_cr(neg_req(4, 0)))
    t3.send(False, cotp_cc(neg_rsp(4, 0)))
    X3(False, struct.pack('<HHHH', 1, 1, 1, 2))
    X3(True, struct.pack('<HHHH', 1, 1, 1, 2))
    g = uni('guid')
    X3(True, struct.pack('<HHH', 1, 2, 1) + struct.pack('<H', len(g)) + g + struct.pack('<H', 10) + uni('alice')
            + struct.pack('<H', 12) + uni('DOMAIN') + struct.pack('<H', 6) + b'secret')
    X3(True, struct.pack('<HHH', 1, 2, 2) + struct.pack('<I', 5) + struct.pack('<H', 4) + b'ckie')
    X3(False, struct.pack('<HHHI', 1, 4, 1, 0))
    X3(False, struct.pack('<HHH', 1, 3, 1) + b'\0\0')                    # unknown PDU type: not RDSTLS
    X3(True, struct.pack('<HHH', 1, 2, 9) + b'\0\0')                     # unknown data type
    X3(True, struct.pack('<HHH', 1, 1, 7) + b'\0\0')                      # capabilities with another data type
    X3(True, struct.pack('<HH', 1, 1))                                      # too short
    X3(True, struct.pack('<HHH', 1, 2, 2) + b'\0\0')                      # cookie request cut short
    X3(True, struct.pack('<HHH', 1, 2, 1) + struct.pack('<H', 2) + b'ab')   # password request with one string only
    X3(True, struct.pack('<HHH', 1, 2, 1) + struct.pack('<H', 50) + b'ab')  # string longer than the PDU
    X3(True, struct.pack('<HHH', 1, 4, 7) + b'\0\0\0\0')                  # response with another data type
    X3(True, struct.pack('<HHHH', 2, 1, 1, 2))                              # wrong version

    mark(cap, 'data that is not fast-path (length octet 0, wrong length) and a connection without negotiation data')
    X(True, bytes([0x04, 0x00, 0x00]))
    X(True, bytes([0x04, 0x20, 0x00, 0x1e]))
    X(True, bytes([0x04, 0x00]))
    tn = Tcp(cap, sport=50030)
    tn.open()
    tn.send(True, cotp_cr(b''))
    tn.send(False, cotp_cc(b''))
    tn.send(False, cotp_cc(b'\x00\x00\x00\x00'))      # user data that is not a negotiate response
    # a fast-path PDU and a channel PDU on a connection whose start is not in the capture
    X(False, fp_s([(3, 0, 0, b'', 0)]), 50031)
    t5 = Tcp(cap, sport=50032)
    t5._seg(True, 0x02, ack=0, opts=b'\x02\x04\x05\xb4')
    X(False, fp_s([(3, 0, 0, b'', 0)]), 50032)
    t6 = Tcp(cap, sport=50033)
    t6.cseq += 5000; t6.sseq += 9000
    t6.send(False, cotp_dt(send_data_ind(1004, chan_pdu(8, 3, struct.pack('<HHI', 1, 0, 0)))))
    t6.send(False, cotp_dt(send_data_ind(1011, struct.pack('<HH', 0x1000, 0) + autodetect(0, 1, 0x0001))))
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x99999999, 0) + cookie, True, sport=50060, pt=3)

    # ---- encrypted sessions (the data is never decrypted: placeholder octets)
    def setup(sport, cblocks, sblocks, neg=True, mcs=MCSCHAN):
        tt = Tcp(cap, sport=sport)
        tt.open()
        if neg:
            tt.send(True, cotp_cr(neg_req(0, 0)))
            tt.send(False, cotp_cc(neg_rsp(0, 0)))
        tt.send(True, cotp_dt(connect_initial(cblocks)))
        tt.send(False, cotp_dt(connect_response(sblocks)))
        return tt

    PH = b'\xee' * 16      # placeholder for data the dissector reports as [Encrypted]
    SIG = bytes(range(8))
    for sport, method, level, title in ((50020, 2, 3, '128-bit, high'), (50021, 0x10, 4, 'FIPS'),
                                        (50022, 1, 1, '40-bit, low'), (50023, 8, 2, '56-bit, client compatible')):
        mark(cap, 'encrypted session, %s: security exchange, encrypted ClientInfo/license/channel PDUs (placeholder data)' % title)
        e = setup(sport, [cs_core(), cs_security(method, 0), cs_net(['cliprdr', 'drdynvc'])],
                  [sc_core(), sc_security(method, level, bytes(range(32)), b'\xcc' * 24),
                   sc_net(MCSCHAN, [1004, 1005])])
        if method == 0x10:
            es = lambda f, rest: sec_hdr(f) + struct.pack('<HBB', 0x10, 1, 3) + SIG + rest
        elif method in (1, 2, 8):
            es = lambda f, rest: sec_hdr(f) + SIG + rest
        if method != 0x10:
            e.send(True, cotp_dt(send_data_req(MCSCHAN, sec_hdr(0x0001) + struct.pack('<I', 64) + b'\x5a' * 64)))
        e.send(True, cotp_dt(send_data_req(MCSCHAN, es(0x0048, PH))))                       # ClientInfo, encrypted
        e.send(False, cotp_dt(send_data_ind(MCSCHAN, es(0x0288, PH))))                      # license, encrypted
        e.send(False, cotp_dt(send_data_ind(MCSCHAN, es(0x0008, PH))))                      # share control, encrypted
        e.send(True, cotp_dt(send_data_req(1004, es(0x0008, PH))))                          # channel PDU, encrypted
        e.send(False, cotp_dt(send_data_ind(MCSCHAN, es(0x0000, share_ctrl(6, struct.pack('<I', 1) + b'\0\0')))))
        e.send(False, cotp_dt(send_data_ind(1004, es(0x0000, chan_pdu(8, 3, struct.pack('<HHI', 1, 0, 0))))))

    # ---- security exchange / license variants without encryption
    mark(cap, 'license variants (unencrypted): license request, platform challenge, new license, error alert, redirection')
    e = setup(50024, [cs_core(), cs_net(['cliprdr'])], [sc_core(), sc_security(0, 0), sc_net(MCSCHAN, [1004])])
    e.send(False, cotp_dt(send_data_ind(MCSCHAN, share_ctrl(6, struct.pack('<I', 1) + b'\0\0'))))    # before the license: no security flags
    for bt in (0x01, 0x02, 0x03, 0x04, 0x12, 0x13, 0x15, 0x42):
        e.send(False, cotp_dt(send_data_ind(MCSCHAN, sec_hdr(0x0080) + struct.pack('<BBH', bt, 3, 8) + bytes(4))))
    e.send(False, cotp_dt(send_data_ind(MCSCHAN, sec_hdr(0x0400) + b'\0' * 12)))                    # redirection
    e.send(True, cotp_dt(send_data_req(MCSCHAN, sec_hdr(0x0040) + client_info(True))))
    e.send(False, cotp_dt(send_data_ind(MCSCHAN, sec_hdr(0x0080) + lic_alert(False, 6))))
    e.send(False, cotp_dt(send_data_ind(MCSCHAN, share_ctrl(6, struct.pack('<I', 1) + b'\0\0'))))

    # ---- ClientData with every number of optional core fields
    mark(cap, 'ClientData core block cut after 0..10 optional fields; short ServerData core blocks')
    e = Tcp(cap, sport=50025)
    e.open()
    for n in range(0, 11):
        e.send(True, cotp_dt(connect_initial([cs_core(optional=n), cs_security(0x0b, 0x1)])))
    for core in (blk(0x0C01, struct.pack('<I', 0x80004)), blk(0x0C01, struct.pack('<II', 0x80004, 1)),
                 blk(0x0C01, struct.pack('<IIH', 0x80004, 1, 0x8001)), blk(0x0C01, struct.pack('<IIHH', 0x80004, 1, 1, 0))):
        e.send(False, cotp_dt(connect_response([core, sc_security(0, 0), sc_net(MCSCHAN, [1004, 1005, 1006])])))
    e.send(False, cotp_dt(connect_response([blk(0x0C01, struct.pack('<I', 0x80004)), blk(0x0C03, struct.pack('<HH', MCSCHAN, 0)),
                                            blk(0x0C08, struct.pack('<I', 1))])))

    # ---- channel PDUs for a channel the client did not announce, many channel ids
    mark(cap, 'ServerData with more channel ids than the client announced and than the dissector keeps (fix: handle leak/bounds)')
    e = setup(50026, [cs_core(), cs_net(['cliprdr', 'drdynvc'])],
              [sc_core(), sc_security(0, 0), sc_net(MCSCHAN, list(range(2000, 2040)))])
    e.send(True, cotp_dt(send_data_req(MCSCHAN, sec_hdr(0x0080) + lic_alert())))
    e.send(False, cotp_dt(send_data_ind(MCSCHAN, sec_hdr(0x0080) + lic_alert())))
    mr = struct.pack('<HHI', 1, 0, 0)
    e.send(False, cotp_dt(send_data_ind(2000, chan_pdu(8, 3, mr))))             # known channel (cliprdr)
    e.send(False, cotp_dt(send_data_ind(2020, chan_pdu(8, 3, mr))))             # announced id, no channel definition
    e.send(False, cotp_dt(send_data_ind(2035, chan_pdu(8, 3, mr))))             # id beyond the 31 the dissector keeps
    for k in range(3):                                                          # repeated ServerData (handle leak fix)
        e.send(False, cotp_dt(connect_response([sc_core(), sc_security(0, 0), sc_net(MCSCHAN, list(range(3000, 3600)))])))

    # ---- reproducers of the fixes on the branch
    mark(cap, 'reproducers: channel PDU with a huge first length, reassembly with more data than announced')
    e = setup(50027, [cs_core(), cs_net(['drdynvc', 'cliprdr'])], [sc_core(), sc_security(0, 0), sc_net(MCSCHAN, [1004, 1005])])
    e.send(False, cotp_dt(send_data_ind(MCSCHAN, sec_hdr(0x0080) + lic_alert())))
    for i in range(4):
        e.send(False, cotp_dt(send_data_ind(1005, chan_pdu(0xFFFE0000, 1, b'A' * 16))))   # 4 GiB announced
    cl2 = struct.pack('<HHI', 0x0001, 0, 8) + bytes(8)
    e.send(False, cotp_dt(send_data_ind(1005, chan_pdu(0x10, 1, cl2))))               # 16 announced
    e.send(False, cotp_dt(send_data_ind(1005, chan_pdu(0x10, 2, b'B' * 32))))         # 48 received
    e.send(False, cotp_dt(send_data_ind(1005, chan_pdu(12, 3, bytes(12)))))             # length with bit 0x08: not "encrypted"

    finish(cap, 'rdp-coverage.pcapng')


def build_malformed():
    cap = Cap()
    MARKS.clear()
    mark(cap, 'negotiate request/correlation info with wrong type or length')
    t = Tcp(cap, sport=51000)
    t.open()
    t.send(True, cotp_cr(b'Cookie: x\r\n' + struct.pack('<BBHI', 1, 0, 9, 0)))
    t = Tcp(cap, sport=51001)
    t.open()
    t.send(True, cotp_cr(neg_req(0, 0x08, struct.pack('<BBHH', 7, 0, 36, 0) + bytes(30))))
    t.send(True, cotp_cr(neg_req(0, 0x08, struct.pack('<BBHH', 6, 0, 20, 0) + bytes(14))))
    mark(cap, 'ClientData/ServerData with block lengths that are too short or run past the PDU; truncated PDUs')
    t = Tcp(cap, sport=51002)
    t.open()
    t.send(True, cotp_cr(neg_req(0, 0)))
    t.send(False, cotp_cc(neg_rsp(0, 0)))
    t.send(True, cotp_dt(connect_initial([struct.pack('<HH', 0xC001, 0), cs_core()[:40], cs_net(['a', 'b'])[:20],
                                         struct.pack('<HH', 0xC003, 0xfff0) + struct.pack('<I', 5000)])))
    t.send(False, cotp_dt(connect_response([struct.pack('<HH', 0x0C03, 2), sc_core()[:10], sc_net(MCSCHAN, [1004, 1005])[:9]])))
    t.send(False, cotp_dt(connect_response([sc_core(), sc_security(0, 0), sc_net(MCSCHAN, [1004]), sc_msgchannel(1011)])))
    t.send(True, cotp_dt(connect_initial([cs_core(), cs_net(['cliprdr', 'drdynvc'])])))
    t.send(False, cotp_dt(connect_response([sc_core(), sc_security(0, 0), sc_net(MCSCHAN, [1004, 1005]), sc_msgchannel(1011)])))
    mark(cap, 'the reproducer of the CLIPRDR malformed packet (reassembled channel PDU with more data than announced)')
    t.send(False, cotp_dt(send_data_ind(MCSCHAN, sec_hdr(0x0080) + lic_alert())))
    cl = struct.pack('<HHI', 0x0002, 0, 0x30) + b'\x01\x00\x00\x00' + b'A' * 28
    t.send(False, cotp_dt(send_data_ind(1004, chan_pdu(0x10, 1, cl))))
    t.send(False, cotp_dt(send_data_ind(1004, chan_pdu(0x10, 2, b'B' * 32))))
    mark(cap, 'truncated channel PDU headers, share control, capabilities, message channel PDUs')
    t.send(False, cotp_dt(send_data_ind(1004, b'\x04\x00')))
    t.send(False, cotp_dt(send_data_ind(MCSCHAN, share_ctrl(1, demand_active([cap_general()])[:30]))))
    t.send(False, cotp_dt(send_data_ind(MCSCHAN, struct.pack('<HHH', 200, 0x11, 1002) + struct.pack('<IHHH', 1, 4, 100, 0xffff) + b'RDP\0' + struct.pack('<HH', 9, 0) + struct.pack('<HH', 3, 0xff00))))
    t.send(False, cotp_dt(send_data_ind(MCSCHAN, share_data(0x14, b'\0\0'))))
    t.send(False, cotp_dt(send_data_ind(1011, struct.pack('<HH', 0x0002, 0) + b'\0' * 6)))
    t.send(False, cotp_dt(send_data_ind(1011, struct.pack('<HH', 0x1000, 0) + autodetect(0, 1, 0x0002, struct.pack('<H', 500)))))
    t.send(False, cotp_dt(send_data_ind(1011, struct.pack('<HH', 0x1000, 0) + b'\x06')))
    t.send(True, cotp_dt(send_data_req(MCSCHAN, sec_hdr(0x0040) + client_info(True)[:40])))
    mark(cap, 'truncated fast-path PDUs (Exported PDU, rdp_tls)')
    X = lambda c2s, payload, sport=50000: cap.exp('rdp_tls', payload, c2s, sport=sport, heur=True)
    t = Tcp(cap, sport=51003)
    t.open()
    t.send(True, cotp_cr(neg_req(0, 0)))
    t.send(False, cotp_cc(neg_rsp(0, 0)))
    t.send(True, cotp_dt(connect_initial([cs_core(), cs_net(['cliprdr'])])))
    for payload, c2s in ((bytes([0x20, 4, 0x00, 0xe0]), True), (bytes([0x08, 5, 0x00, 0xe0, 0x01]), True),
                         (bytes([0x00, 6, 0x01, 0xff, 0xff, 0x00]), False), (bytes([0x00, 4, 0x03, 0x00]), False)):
        cap.exp('rdp_tls', payload, c2s, sport=51003, heur=True)
    finish(cap, 'rdp-coverage-malformed.pcapng')


if __name__ == '__main__':
    build_main()
    build_malformed()
