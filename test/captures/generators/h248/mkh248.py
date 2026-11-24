#!/usr/bin/env python3
# Generates test/captures/h248_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the H.248 (MEGACO, binary BER encoding)
dissector, packet-h248.c, built from the H.248.1 v3 ASN.1 module and
the package tables of packet-h248*.c.  Usage: mkh248.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
import struct

from asn1enc import Gen
from h248lib import (
    action, ber_int, exported_pdu, install_hooks, megaco, MID_DOM, MID_IP4, mtp3, NSAPS, pcapng,
    PKGS, Sweep, TCP, term_id, term_list, tlv, tpkt, trx_req, u32, udp, udp6, UNREGISTERED,
    v1_text, value,
)

HERE = os.path.dirname(os.path.abspath(__file__))
# The ASN.1 module(s) of the tree.
ASN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..', 'epan', 'dissectors', 'asn1', 'h248')


def newgen(seed, sw, v1=False):
    text = open(os.path.join(ASN_DIR, 'h248v3.asn')).read()
    if v1:
        text = v1_text(text, open(os.path.join(ASN_DIR, 'h248v1support.asn')).read())
    g = Gen(text, seed=seed, maxdepth=30)
    install_hooks(g, sw)
    g.skip = {'errorDescriptor'}
    return g


def msg_from(g, sw, trx, version=2, mid=None):
    sw.version = version
    return megaco(trx, version, mid)


def b4(pid, it):
    return struct.pack('>HH', pid, it)


def pkg_sweep(pkgs=None, passes=2):
    """Every property, signal, event and statistic of the package tables
    with every parameter, several per message (the dissector reads the
    package name and then the value with the table entry's decoder)."""
    pkgs = pkgs if pkgs is not None else sorted(p for p in PKGS if p not in UNREGISTERED)
    props, sigs, evts, stats = [], [], [], []
    for pid in pkgs:
        for d in PKGS[pid]:
            props += [(pid,) + e for e in d['props']]
            sigs += [(pid, it, ps) for it, ps in d['sigs']]
            evts += [(pid, it, ps) for it, ps in d['evts']]
            stats += [(pid, it, ps) for it, ps in d['stats']]
    F = []
    k = [0]
    idl = [2, 1, 4, 3]

    def pname(pid_):
        n = idl[k[0] % 4]
        return pid_.to_bytes(n, 'big') if pid_ < 1 << (8 * n) else pid_.to_bytes(4, 'big')

    def val(f, dat, pid, ft):
        k[0] += 1
        return value(f, dat, pid, k[0], ft)

    def chunks(lst, n):
        return [lst[i:i + n] for i in range(0, len(lst), n)]

    t = term_id(b'\x01\x02')

    def msg(cmds, version, n):
        return udp(megaco([trx_req(100 + len(F), [action(1, cmds)])], version))

    for ps in range(passes):
        ver = 2 + ps
        for ch in chunks(props, 7):
            pp = [tlv(0x30, tlv(0x80, b4(p, i)), tlv(0xA1, *[tlv(4, val(f, dat, i, ft)) for _ in range(1 + ps)]))
                  for p, i, f, dat, ft in ch]
            F.append(msg([command(0, term_list(t), A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, *pp)))))], ver, 0))
        for ch in chunks(sigs, 6):
            sg = []
            for p, i, params in ch:
                pars = [tlv(0x30, tlv(0x80, pname(pid2)), tlv(0xA1, tlv(4, val(f, dat, pid2, ft))))
                        for pid2, f, dat, ft in params]
                sg.append(tlv(0xA0, tlv(0x80, b4(p, i)), tlv(0xA6, *pars)))
            F.append(msg([command(0, term_list(t), A(1, tlv(0xA5, *sg)))], ver, 0))
        for ch in chunks(evts, 6):
            evs, req = [], []
            for p, i, params in ch:
                pars = [tlv(0x30, tlv(0x80, pname(pid2)), tlv(0xA1, tlv(4, val(f, dat, pid2, ft))))
                        for pid2, f, dat, ft in params]
                evs.append(tlv(0x30, tlv(0x80, b4(p, i)), tlv(0xA2, *pars)))
                req.append(tlv(0x30, tlv(0x80, b4(p, i))))
            obs = A(1, tlv(0x80, b'\x09'), A(1, *evs))
            F.append(msg([command(6, term_list(t), obs)], ver, 0))
            F.append(msg([command(2, term_list(t), A(1, tlv(0xA3, tlv(0x80, b'\x07'), tlv(0xA1, *req))))], ver, 0))
        for ch in chunks(stats, 6):
            st = [tlv(0x30, tlv(0x80, b4(p, i)), tlv(0xA1, tlv(4, b'\x01'))) for p, i, params in ch]
            F.append(msg([command(1, term_list(t), A(1, tlv(0xA8, *st)))], ver, 0))
    return F


def retag(b, tag):
    """Replace the outer tag of a BER encoding (IMPLICIT tagging)."""
    n = b[1]
    hl = 2 if n < 0x80 else 2 + (n & 0x7f)
    return tlv(tag, b[hl:])


def A(kind, *parts):
    return tlv(0xA0 + kind, *parts)


def command(kind, *body, optional=False, wildret=False):
    """CommandRequest { command [0] { addReq [0] ... } , optional [1] NULL, wildcardReturn [2] NULL }"""
    tail = (tlv(0x81, b'') if optional else b'') + (tlv(0x82, b'') if wildret else b'')
    return tlv(0x30, A(0, A(kind, *body)), tail)


def tid(n):
    return ber_int(n) if n < 0x80000000 else u32(n)


def reply_cmd(kind, *body):
    return A(kind, *body)           # CommandReply alternative


def action_reply(ctx, replies, err=None, ctx_reply=b''):
    return tlv(0x30, tlv(0x80, tid(ctx)), err or b'', ctx_reply, A(3, *replies))


def error_desc(code, text=None, tag=0xA1):
    return tlv(tag, tlv(0x80, ber_int(code)), tlv(0x81, text.encode()) if text else b'')


def trx_reply(t, replies=None, err=None, imm=False, seg=None, segcomplete=False):
    res = A(2, err) if err else A(2, A(1, *replies))
    return A(2, tlv(0x80, tid(t)), tlv(0x81, b'') if imm else b'', res,
             tlv(0x83, ber_int(seg)) if seg is not None else b'', tlv(0x84, b'') if segcomplete else b'')


def trx_pending(t):
    return A(1, tlv(0x80, tid(t)))


def trx_ack(*pairs):
    return A(3, *[tlv(0x30, tlv(0x80, tid(a)), tlv(0x81, tid(b)) if b is not None else b'') for a, b in pairs])


def trx_seg(t, seg, complete=False):
    return A(4, tlv(0x80, tid(t)), tlv(0x81, ber_int(seg)), tlv(0x82, b'') if complete else b'')


def msg_error(code, text, version=2, mid=None):
    body = tlv(0xA2, error_desc(code, text, tag=0xA0))
    m = tlv(0xA1, tlv(0x80, bytes([version])), mid or MID_DOM, body)
    return tlv(0x30, m)


def auth_header():
    return tlv(0xA0, tlv(0x80, b'\x00\x00\x00\x01'), tlv(0x81, b'\x00\x00\x00\x02'), tlv(0x82, bytes(12)))


def flows(g, sw):
    """Request/reply sequences for the transaction and context tracking."""
    F = []
    mgc, mg = ('192.0.2.10', '192.0.2.11')

    def req(p, version=2, mid=MID_IP4):
        F.append(udp(megaco(p, version, mid), mgc, 2945, mg, 2945))

    def rep(p, version=2, mid=MID_DOM):
        F.append(udp(megaco(p, version, mid), mg, 2945, mgc, 2945))

    CH, ALL = 0xfffffffe, 0xffffffff
    t1, t2 = term_id(b'\x01\x02\x03', None), term_id(b'', [b'\x80'])
    t3 = term_id(b'RTP/1', None)
    ds = [g.make_alt('AmmDescriptor', i) for i in range(9)]
    # a context created with $ and two terminations (one wildcarded choose)
    req([trx_req(1, [action(CH, [command(0, term_list(t1), A(1, ds[0], ds[3])),
                                command(0, term_list(term_id(b'', [b'\x80'])), A(1, ds[5]), optional=True)],
                          ctx_req=retag(g.make('ContextRequest'), 0xA1))])])
    rep([trx_reply(1, [action_reply(5, [reply_cmd(0, term_list(t1)), reply_cmd(0, term_list(t3))])])])
    # modify in the context, then a second modify with the same terminations
    req([trx_req(2, [action(5, [command(2, term_list(t1), A(1, ds[0], ds[4])),
                               command(2, term_list(t3), A(1, ds[8]))])])])
    rep([trx_reply(2, [action_reply(5, [reply_cmd(2, term_list(t1)), reply_cmd(2, term_list(t3))])])])
    # pending and then the reply asking for an acknowledgement, and the ack
    req([trx_req(3, [action(5, [command(3, term_list(t3), A(1, tlv(0x80, b'\x06\xff\xc0')))])])])
    rep([trx_pending(3)])
    rep([trx_pending(3)])
    rep([trx_reply(3, [action_reply(5, [reply_cmd(3, term_list(t3))])], imm=True)])
    req([trx_ack((3, None))])
    req([trx_ack((3, 3), (4, 9))])
    # a segmented reply
    rep([trx_reply(8, [action_reply(0, [reply_cmd(5, term_list(t1))])], seg=1)])
    rep([trx_reply(8, [action_reply(0, [reply_cmd(5, term_list(t1))])], seg=2, segcomplete=True)])
    req([trx_seg(8, 1), trx_seg(8, 2, True)])
    # wildcard ALL terminations, all contexts
    req([trx_req(4, [action(ALL, [command(3, term_list(term_id(b'', [b'\xc0'])), A(1, ))])])])
    rep([trx_reply(4, [action_reply(ALL, [reply_cmd(3, term_list(term_id(b'', [b'\xc0'])))])])])
    # other contexts and commands: audit, notify, service change, move
    tok = tlv(0x80, b'\x06\xff\xc0')
    req([trx_req(5, [action(0, [command(4, retag(t1, 0xA0), A(1, tok)),
                               command(5, retag(t1, 0xA0), A(1, tok), wildret=True)],
                          audit=A(2, tlv(0x80, b''), tlv(0x82, b'')))])])
    obs = A(1, tlv(0x80, b'\x00\x00\x00\x09'), A(1, g.make('ObservedEvent'), g.make('ObservedEvent')))
    req([trx_req(6, [action(5, [command(6, term_list(t1), obs)])])])
    rep([trx_reply(6, [action_reply(5, [reply_cmd(6, term_list(t1))])])])
    scp = retag(g.make('ServiceChangeParm'), 0xA1)
    req([trx_req(7, [action(0, [command(7, term_list(term_id(b'\x00', [b'\x00'])), scp)])])])
    rep([trx_reply(7, [action_reply(0, [reply_cmd(7, term_list(t1), A(1, A(1, retag(g.make('ServiceChangeResParm'), 0xA1))))])])])
    return F


MIDS = [MID_IP4,
        tlv(0xA1, tlv(0xA1, tlv(0x80, bytes(range(1, 17))), tlv(0x81, b'\x0b\x80'))),
        tlv(0xA1, tlv(0xA2, tlv(0x80, b'mgc.example.invalid'))),
        tlv(0xA1, tlv(0x83, b'MG-1/Slot3')),
        tlv(0xA1, tlv(0x84, b'\x12\x34')),
        tlv(0xA1, tlv(0x84, b'\x00\x20\x44\x21'))]


def misc(g, sw, g1):
    F = []
    # every kind of MId
    for k, mid in enumerate(MIDS):
        t = trx_req(20 + k, [action(0, [command(2, term_list(term_id(b'\x07')), A(1, g.make_alt('AmmDescriptor', k)))])])
        F.append(udp(megaco([t], 2 + k % 2, mid)))
    # authentication header (placeholder bytes)
    F.append(udp(megaco([trx_pending(30)], 2, MID_IP4, auth_header())))
    # message errors
    F.append(udp(msg_error(406, 'Version Not Supported')))
    F.append(udp(msg_error(401, None, version=3, mid=MIDS[1])))
    # transaction errors in a reply
    F.append(udp(megaco([trx_reply(31, err=error_desc(430, 'Unknown TerminationID', tag=0xA0))])))
    F.append(udp(megaco([trx_reply(32, [action_reply(3, [], err=error_desc(500))])])))
    F.append(udp(megaco([trx_reply(33, [action_reply(3, [reply_cmd(0, term_list(term_id(b'\x05')), A(1, error_desc(440, tag=0xA0)))])])])))
    # several transactions in one message
    F.append(udp(megaco([trx_pending(34), trx_pending(35), trx_ack((34, 35))], 3)))
    # version 1 messages: AuditReplyV1, EventParameterV1, SigParameterV1
    for i in range(30):
        g1.mode = ['full', 'mix', 'full', 'min'][i % 4]
        t = g1.make_alt('Transaction', [2, 0, 2, 0, 2][i % 5])
        F.append(udp(megaco([t], 1)))
    # random messages of every kind of transaction, versions 2 and 3
    for i in range(100):
        sw.version = [2, 3][i % 2]
        g.mode = ['mix', 'full', 'mix', 'min'][i % 4]
        t = g.make_alt('Transaction', i % 5)
        F.append(udp(megaco([t], sw.version, MIDS[i % len(MIDS)])))
    return F


def tcp_frames(g):
    F = []
    c = TCP()
    F += c.handshake()
    m1 = megaco([trx_req(1, [action(0, [command(2, term_list(term_id(b'\x01')), A(1, g.make_alt('AmmDescriptor', 3)))])])])
    m2 = megaco([trx_reply(1, [action_reply(0, [reply_cmd(2, term_list(term_id(b'\x01')))])])])
    F.append(c.c2s(tpkt(m1)))
    F.append(c.s2c(tpkt(m2)))
    # one message in two segments, then two messages in one segment
    p = tpkt(m1)
    F.append(c.c2s(p[:20]))
    F.append(c.c2s(p[20:]))
    F.append(c.s2c(tpkt(m2) + tpkt(m2)))
    return F


def other_frames(g):
    F = []
    # IPv6 and Exported PDU (no addresses) transports
    ms = [megaco([trx_req(50 + k, [action(0, [command(2, term_list(term_id(b'\x03')), A(1, g.make_alt('AmmDescriptor', k)))])])])
          for k in range(3)]
    F.append(udp6(ms[0]))
    F.append(udp6(megaco([trx_reply(50, [action_reply(0, [reply_cmd(2, term_list(term_id(b'\x03')))])])]),
                  '2001:db8::2', 2945, '2001:db8::1', 2945))
    F.append(exported_pdu('h248', ms[1]))
    F.append(exported_pdu('h248', megaco([trx_reply(51, [action_reply(0, [reply_cmd(2, term_list(term_id(b'\x03')))])])])))
    # a wildcard "all" termination followed by a named one in the same context and message
    all_t = term_id(b'', [b'\x40'])
    F.append(udp(megaco([trx_req(52, [action(7, [command(3, term_list(all_t)),
                                                command(3, term_list(term_id(b'\x04\x05')))])])]), '192.0.2.12', 2945, '192.0.2.13', 2945))
    F.append(udp(megaco([trx_req(53, [action(8, [command(2, term_list(term_id(b'\x04\x06')), A(1)),
                                                command(2, term_list(all_t), A(1))])])]), '192.0.2.12', 2945, '192.0.2.13', 2945))
    # a request for all terminations answered with the named terminations (context tracking)
    F.append(udp(megaco([trx_req(59, [action(12, [command(3, term_list(all_t))])])]), '192.0.2.12', 2945, '192.0.2.13', 2945))
    F.append(udp(megaco([trx_reply(59, [action_reply(12, [reply_cmd(3, term_list(term_id(b'\x0a'), term_id(b'\x0b')))])])]),
                 '192.0.2.13', 2945, '192.0.2.12', 2945))
    # bearer information reference and NSAP address of an ATM termination
    import repro_ber as r
    bir = r.prop(b'\x00\x00\x30\x02', b'\x04\x02\x00\x01')
    nsap = r.prop(b'\x00\x00\x30\x03', r.tlv(0x04, NSAPS[0]))
    F.append(udp(megaco([trx_req(54, [action(9, [command(0, term_list(term_id(b'\x06')), A(1, r.media_desc(bir, nsap)))])])]), '192.0.2.12', 2945, '192.0.2.13', 2945))
    F.append(udp(megaco([trx_req(55, [action(9, [command(0, term_list(term_id(b'\x07')), A(1, r.media_desc(bir, nsap)))])])]), '192.0.2.12', 2945, '192.0.2.13', 2945))
    # a termination identifier that is an empty constructed string
    F.append(udp(megaco([trx_req(60, [action(5, [command(2, term_list(tlv(0x30, tlv(0xA0, b''), tlv(0xA1, b''))), A(1))])])])))
    # event and signal names that are empty constructed strings, and an event parameter name of 5 octets
    ev = tlv(0x30, tlv(0xA0, b''), tlv(0xA2, tlv(0x30, tlv(0x80, b'\x00\x01'), tlv(0xA1, tlv(0x04, b'\x01')))))
    obs = A(1, tlv(0x80, b'\x09'), A(1, ev))
    F.append(udp(megaco([trx_req(56, [action(5, [command(6, term_list(term_id()), obs)])])])))
    sp = tlv(0x30, tlv(0x80, b'\x00\x01'), tlv(0xA1, tlv(0x04, b'\x01')))
    sig = A(0, tlv(0xA0, b''), A(6, sp))
    F.append(udp(megaco([trx_req(57, [action(5, [command(0, term_list(term_id()), A(1, tlv(0xA5, sig)))])])])))
    ev = tlv(0x30, tlv(0x80, b'\x00\x04\x00\x01'), tlv(0xA2, tlv(0x30, tlv(0x80, b'\x00\x00\x00\x00\x01'), tlv(0xA1, tlv(0x04, b'\x01')))))
    obs = A(1, tlv(0x80, b'\x09'), A(1, ev))
    F.append(udp(megaco([trx_req(58, [action(5, [command(6, term_list(term_id()), obs)])])])))
    return F


def mtp_frames(g):
    F = []
    for k in range(3):
        m = megaco([trx_req(40 + k, [action(0, [command(2, term_list(term_id(b'\x02')), A(1, g.make_alt('AmmDescriptor', k)))])])])
        F.append(mtp3(m, opc=0x1234 + k, dpc=0x0567))
    F.append(mtp3(megaco([trx_reply(40, [action_reply(0, [reply_cmd(2, term_list(term_id(b'\x02')))])])]), opc=0x0567, dpc=0x1234))
    return F


def text_frames():
    return [udp(b'MEGACO/2 [192.0.2.1]:2944 Transaction = 9 { Context = - { Add = $ } }'),
            udp(b'!/2 [192.0.2.1]:2944 T=10{C=-{AV=*{AT{MD}}}}')]


def repro_frames():
    """Reproducers of the bugs fixed on the branch (repro_ber.py) that decode
    without an error: an empty constructed wildcard field and signal
    parameter name, and context tracking with a reused transaction id."""
    import repro_ber as r
    F = []
    F.append(r.megaco([r.trans_req(1, [r.action_req(1, [r.add_req([], terms=[r.term_id(wild=b'\x24\x00')])])])]))
    sig = r.signal(b'\x00\x1d\x00\x02', r.sigpar(b'\xA0\x00', b'\x00'))
    F.append(r.megaco([r.trans_req(1, [r.action_req(1, [r.add_req([r.tlv(0xA5, sig)])])])]))
    # apv signal with the specific parameters (sp) as OCTET STRING
    sig = r.signal(b'\x00\x1d\x00\x02', r.sigpar(r.tlv(0x80, b'\x00\x06'), r.tlv(0x04, b'abc')))
    F.append(r.megaco([r.trans_req(1, [r.action_req(1, [r.add_req([r.tlv(0xA5, sig)])])])]))
    # context tracking with a reused transaction id (h248.ctx_info)
    CHOOSE = 0xfffffffe
    for trx, ctx in ((1, CHOOSE), (1, 5), (2, 5), (1, 9)):
        F.append(r.megaco([r.trans_req(trx, [r.action_req(ctx, [r.add_req([])])])]))
    return [udp(p, '192.0.2.31', 2945, '192.0.2.32', 2945) for p in F]


def malformed_frames(g, base_payloads):
    """Paths only malformed input reaches."""
    import repro_ber as r
    F = []

    def trx(cmds, t=1, ctx=1):
        return r.megaco([r.trans_req(t, [r.action_req(ctx, cmds)])])

    def prop_raw(pkgd, *vals):
        return r.tlv(0x30, r.tlv(0x80, pkgd), r.tlv(0xA1, *vals))

    def prop_cmd(pkgd, *vals):
        return trx([r.add_req([r.media_desc(prop_raw(pkgd, *vals))])])

    def notify(evname, parname, *vals, raw_evt=None):
        par = r.tlv(0x30, r.tlv(0x80, parname), r.tlv(0xA1, *vals)) if parname is not None else b''
        ev = r.tlv(0x30, r.tlv(0x80, evname), r.tlv(0xA2, par))
        obs = r.tlv(0xA1, r.tlv(0x80, b'\x09'), r.tlv(0xA1, ev))
        return trx([r.tlv(0x30, r.tlv(0xA0, r.tlv(0xA6, r.tlv(0xA0, r.term_id()), obs)))])

    def sigcmd(signame, parname, *vals):
        sp = r.tlv(0x30, r.tlv(0x80, parname), r.tlv(0xA1, *vals))
        sig = r.tlv(0xA0, r.tlv(0x80, signame), r.tlv(0xA6, sp))
        return trx([r.add_req([r.tlv(0xA5, sig)])])

    # the integer decoder for the apv specific parameters and a non-OCTET STRING Annex C ACodec
    F.append(sigcmd(b'\x00\x1d\x00\x02', b'\x00\x06', r.tlv(0x02, b'\x05')))
    F.append(prop_cmd(b'\x00\x00\x10\x06', r.tlv(0x02, b'\x00')))
    # value that is not an OCTET STRING: property, signal and event parameters
    F.append(prop_cmd(b'\x00\x00\x10\x01', r.tlv(0x02, r.tlv(0x02, b'\x01'))))
    F.append(sigcmd(b'\x00\x1d\x00\x02', b'\x00\x01', r.tlv(0x30, b'')))
    F.append(notify(b'\x00\x04\x00\x03', b'\x00\x01', r.tlv(0x02, b'\x01')))
    # SDP media port that does not fit an int
    F.append(prop_cmd(b'\x00\x00\xb0\x0f', r.tlv(0x04, r.tlv(0x16, b'audio 99999999999 RTP/AVP 0'))))
    # names shorter than four octets (exceptions)
    F.append(prop_cmd(b'\x00', r.tlv(0x04, r.tlv(0x02, b'\x01'))))
    F.append(notify(b'\x00', b'\x00\x01', r.tlv(0x04, b'')))
    F.append(sigcmd(b'\x00\x1d', b'\x00\x01', r.tlv(0x04, b'')))
    # empty names
    F.append(sigcmd(b'', b'', r.tlv(0x04, b'')))
    F.append(notify(b'', b'', r.tlv(0x04, b'')))
    # an unknown package: the default package names
    F.append(sigcmd(b'\x7f\x7f\x00\x01', b'\x01', r.tlv(0x04, b'x')))
    F.append(notify(b'\x7f\x7f\x00\x01', b'\x01', r.tlv(0x04, b'x')))
    # transaction and context ids that do not fit 32 bits, or have 0 or 9 octets
    def raw_ids(tbytes, cbytes):
        act = r.tlv(0x30, r.tlv(0x80, cbytes), r.tlv(0xA3, r.add_req([])))
        t = r.tlv(0xA0, r.tlv(0x80, tbytes), r.tlv(0xA1, act))
        return r.megaco([t])
    F.append(raw_ids(b'\x01\x00\x00\x00\x00', b'\x01'))
    F.append(raw_ids(b'\x01', b'\x01\x00\x00\x00\x00\x00'))
    F.append(raw_ids(b'\x01' * 9, b'\x01'))
    F.append(raw_ids(b'\x01', b'\x01' * 9))
    F.append(raw_ids(b'', b'\x01'))
    F.append(raw_ids(b'\x01', b''))
    # a wildcard field with a different tag, a MtpAddress of 5 octets
    F.append(r.megaco([r.trans_req(1, [r.action_req(1, [r.add_req([], terms=[r.term_id(wild=b'\x02\x01\x80')])])])]))
    F.append(r.megaco([r.trans_req(1, [r.action_req(1, [r.add_req([])])])]))
    # truncations and mutations of the good messages
    rnd = random.Random(2945)
    for i in range(120):
        p = bytearray(rnd.choice(base_payloads))
        kind = i % 5
        if kind == 0:
            p = p[:rnd.randrange(2, len(p))]
        elif kind == 1:
            p[rnd.randrange(len(p))] = rnd.randrange(256)
        elif kind == 2:
            k = rnd.randrange(1, len(p))
            p[k:k] = bytes([rnd.randrange(256)])
        elif kind == 3:
            k = rnd.randrange(len(p))
            del p[k:k + rnd.randrange(1, 4)]
        else:
            for _ in range(3):
                p[rnd.randrange(len(p))] = rnd.choice([0x00, 0x04, 0x30, 0x80, 0xa0, 0xff])
        F.append(bytes(p))
    return [udp(p, '192.0.2.41', 2945, '192.0.2.42', 2945) for p in F]


def tcp_malformed():
    F = []
    c = TCP('192.0.2.43', 40001, '192.0.2.44', 2945)
    F += c.handshake()
    F.append(c.c2s(b'\x03\x00\x00\x08\x30\x02'))            # TPKT longer than the data, then stops
    F.append(c.c2s(b'\x03\x00\x00\x04'))                    # TPKT without a message
    return F


def pkg_main(out, name, pk, specific, specific_bad, seed, passes=2, nrand=45, nv1=10):
    """Captures for a package dissector: specific(g, sw) -> frames,
    specific_bad() -> payloads for the malformed capture."""
    import random
    frames = []
    marks = {}

    def add(label, fr):
        marks[label] = (len(frames) + 1, len(frames) + len(fr))
        frames.extend(fr)

    sw = Sweep(pkgs=pk)
    g = newgen(seed, sw)
    g1 = newgen(seed + 1, sw, v1=True)
    add('specific', specific(g, sw))
    add('sweep', pkg_sweep(pk, passes=passes))
    sw.q = {k: [] for k in sw.q}
    R = []
    for i in range(nrand):
        sw.version = [2, 3][i % 2]
        g.mode = ['full', 'mix', 'full', 'min'][i % 4]
        R.append(udp(megaco([g.make_alt('Transaction', i % 5)], sw.version)))
    for i in range(nv1):
        g1.mode = ['full', 'mix'][i % 2]
        R.append(udp(megaco([g1.make_alt('Transaction', [2, 0][i % 2])], 1)))
    add('random', R)
    for k, v in marks.items():
        print('%-8s frames %d-%d' % (k, v[0], v[1]))
    pcapng(os.path.join(out, name + '-coverage.pcapng'), frames)
    base = [f[1][42:] for f in frames if f[0] == 0][::3]
    rnd = random.Random(seed)
    M = list(specific_bad())
    for i in range(60):
        p = bytearray(rnd.choice(base))
        if i % 3 == 0:
            p = p[:rnd.randrange(2, len(p))]
        elif i % 3 == 1:
            p[rnd.randrange(len(p))] = rnd.randrange(256)
        else:
            for _ in range(3):
                p[rnd.randrange(len(p))] = rnd.choice([0x00, 0x04, 0x30, 0x80, 0xa0, 0xff])
        M.append(bytes(p))
    pcapng(os.path.join(out, name + '-coverage-malformed.pcapng'),
           [udp(p, '192.0.2.41', 2945, '192.0.2.42', 2945) for p in M])
    print('malformed frames', len(M))
    return frames


def sig_msg(t, sigs, ver=2, tid=1):
    """Add with a signals descriptor; sigs are tlv(0xA0 ...) signals."""
    return udp(megaco([trx_req(tid, [action(0, [command(0, term_list(t), A(1, tlv(0xA5, *sigs)))])])], ver))


def evt_msg(t, evs, ver=2, tid=1):
    obs = A(1, tlv(0x80, b'\x09'), A(1, *evs))
    return udp(megaco([trx_req(tid, [action(0, [command(6, term_list(t), obs)])])], ver))


def prop_msg(t, props, ver=2, tid=1):
    return udp(megaco([trx_req(tid, [action(0, [command(2, term_list(t), A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, *props)))))])])], ver))


def main(out):
    frames = []
    sw = Sweep()
    g = newgen(11, sw)
    g1 = newgen(12, sw, v1=True)
    marks = {}

    def add(name, fr):
        marks[name] = (len(frames) + 1, len(frames) + len(fr))
        frames.extend(fr)
    add('sweep', pkg_sweep())
    sw.q = {k: [] for k in sw.q}
    add('flows', flows(g, sw))
    add('misc', misc(g, sw, g1))
    add('tcp', tcp_frames(g))
    add('mtp3', mtp_frames(g))
    add('text', text_frames())
    add('other', other_frames(g))
    add('repro', repro_frames())
    for k, v in marks.items():
        print('%-8s frames %d-%d' % (k, v[0], v[1]))
    pcapng(os.path.join(out, 'h248-coverage.pcapng'), frames)
    base = [f[1][42:] for f in frames if f[0] == 0 and f[1][23] == 17 and len(f[1]) > 60][::7]
    bad = malformed_frames(g, base) + tcp_malformed()
    pcapng(os.path.join(out, 'h248-coverage-malformed.pcapng'), bad)
    print('malformed frames', len(bad))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
