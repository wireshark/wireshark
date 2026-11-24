#!/usr/bin/env python3
# Generates test/captures/tpncp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
# Builds tpncp-coverage.pcap and tpncp-coverage-malformed.pcap from the
# field database tpncp.dat (resources/protocols/tpncp/tpncp.dat of the source
# tree, installed as run/tpncp/tpncp.dat). The dissector only runs with
# -o tpncp.load_db:TRUE.
import struct
import sys
from pcaplib import Flow, write, udp

DAT = os.environ.get('TPNCP_DAT', os.path.join(SRCDIR, 'resources/protocols/tpncp/tpncp.dat'))
EVENT_PORT = 2424

def load():
    lines = open(DAT).read().split('\n')
    sections, cur = [], []
    for l in lines[1:]:
        if l.startswith('#####'):
            sections.append(cur); cur = []
        else:
            cur.append(l)
    events = {int(l.split()[1]): l.split()[0] for l in sections[0] if len(l.split()) == 2}
    commands = {int(l.split()[1]): l.split()[0] for l in sections[1] if len(l.split()) == 2}
    enums = {}
    for l in sections[2]:
        p = l.split()
        if len(p) == 3:
            enums.setdefault(p[0], []).append(int(p[2]))
    def fields(sec):
        d = {}
        for l in sec:
            p = l.split()
            if len(p) < 6 or not p[0].isdigit():
                continue
            if p[1][0].isdigit():                 # a line without a name
                p = [p[0], 'unnamed'] + p[1:]
            d.setdefault(int(p[0]), []).append(p[1:])
        return d
    return events, commands, enums, fields(sections[3]), fields(sections[4])

def reg_fields(raw, enums, tid=0):
    """The registration of the dissector: IP address fields after an address family are merged."""
    out, ip_left, is_af = [], 0, False
    for name, sign, size, adim, ipf, enum in [(p[0], int(p[1]), int(p[2]), int(p[3]), int(p[4]), p[5]) for p in raw]:
        ip = bool(sign and ipf)
        if ip_left > 0:
            seq = name[-2:]
            ip_left -= 1
            if len(name) > 2 and seq[0] == '_':
                if seq[1] in '123':
                    continue
                if is_af:
                    size, ip = 128, True
                else:
                    ip_left = 0
        is_af = False
        known = enum != 'primitive' and enum in enums
        if known:
            ip = False
            if enum == 'AddressFamily':
                is_af, ip_left = True, 4
        since = 7401 if ((tid == 4 and 'secondary_rtp_seq_num' in name) or (tid == 1611 and 'dtls_remote_fingerprint_alg' in name)) else 0
        out.append(dict(name=name, sign=sign, size=size, adim=adim, ip=ip, enum=enum if known else None, af=is_af, since=since))
    return out

def layout(fields, le, ver=7600):
    """Offsets of the fields as the dissector walks them (no jumps); returns [(offset, field)], length."""
    offset, bitindex, pos, touched = 0, 7 if le else 0, [], False
    for f in fields:
        if f['since'] and f['since'] > ver:
            continue
        s = f['size']
        pos.append((offset, bitindex, f))
        if 1 <= s <= 8:
            if f['adim']:
                offset += f['adim']
            elif s == 8:
                offset += 1
            else:
                touched = True
                bitindex += s
                offset += bitindex // 8
                bitindex %= 8
        elif s == 16: offset += 2
        elif s == 32: offset += 4
        elif s == 64: offset += 8
        elif s == 128: offset += 16
    return pos, offset + (1 if touched and bitindex else 0)

def specials(tid, name):
    if name == 'cmd_rev_lsb': return 'OCS'
    if name == 'rtp_authentication_algorithm': return 'SECSTART'
    if name == 'security_cmd_offset': return 'SECOFF'
    if tid != 1611 and name == 'ssrc': return 'RTPSTART'
    if name == 'rtp_tx_state_ssrc': return 'RTPSTART'
    if name == 'rtp_state_offset': return 'RTPOFF'
    if name == 'state_update_time_stamp': return 'RTPEND'
    if tid == 1611 and 'configuration_type_updated' in name: return 'CHAN'
    return None

def simulate(tid, fields, Labs, base, le, secoff, rtpoff, ver=7600):
    """Port of dissect_tpncp_data(); returns (final offset, ok)."""
    offset = base
    bitindex = 7 if le else 0
    ocs, security_offset, rtp_state_offset, chan_b, rtp_tx, rtp_size = -1, 0, 0, 0, 0, 0
    def need(n):
        return offset + n <= Labs
    for f in fields:
        if f['since'] and f['since'] > ver:
            continue
        sp = specials(tid, f['name'])
        s = f['size']
        if sp == 'OCS':
            ocs = offset
        elif sp == 'SECOFF':
            if not need(4): return offset, False
            if secoff > 0 and ocs >= 0: security_offset = ocs + secoff
        elif sp == 'SECSTART':
            offset = security_offset; ocs = -1; security_offset = 0
        elif sp == 'RTPOFF':
            if not need(4): return offset, False
            rtp_state_offset = rtpoff
            if rtp_state_offset > 0: rtp_state_offset += base + 4
        elif sp == 'RTPSTART':
            offset = rtp_state_offset; rtp_state_offset = 0
            if rtp_tx == 0:
                rtp_size = (Labs - offset - 4) // 2   # tvb remaining - 4, C integer division (may be negative)
                if Labs - offset - 4 < 0: rtp_size = -((-(Labs - offset - 4)) // 2)
                rtp_tx = offset + rtp_size
            else:
                offset = rtp_tx; rtp_tx += rtp_size
        elif sp == 'RTPEND':
            rtp_tx = 0
        elif sp == 'CHAN':
            if chan_b == 0:
                chan_b = offset + (Labs - offset) // 2
            else:
                offset = chan_b; chan_b = 0
        else:
            if ocs != -1 and security_offset > 0 and offset >= security_offset: continue
            if rtp_state_offset > 0 and offset >= rtp_state_offset: continue
            if rtp_tx > 0 and offset >= rtp_tx: continue
            if chan_b > 0 and offset >= chan_b: continue
        if s <= 8 and f['adim']:
            n = min(f['adim'], Labs - offset)
            if n < 0: return offset, False
            offset += n
        elif s == 8:
            if not need(1): return offset, False
            offset += 1
        elif 1 <= s < 8:
            bitindex += s
            offset += bitindex // 8
            bitindex %= 8
        elif s in (16, 32, 64):
            if not need(s // 8): return offset, False
            offset += s // 8
        elif s == 128:
            offset += 16
        if Labs - offset <= 0: break
    return offset, True


def special_plan(tid, fields, base, le, ver=7600):
    """For ids with offset fields (security, RTP state, channel configuration): values of the offset fields
    that make the dissector's jumps consistent and the largest body length that it walks exactly
    to its end. Returns None for ids without such fields, False when no length works."""
    has_special = any(specials(tid, f['name']) for f in fields)
    pos, n = layout(fields, le, ver)
    nat = {specials(tid, f['name']): o for o, b, f in pos if specials(tid, f['name'])}
    ocs, nsec, rs = nat.get('OCS'), nat.get('SECSTART'), nat.get('RTPSTART')
    secoff = nsec - ocs if (ocs is not None and nsec is not None) else 0
    rtpoff = rs - 4 if rs is not None else 0
    best = None
    for L in (range(n + 60, max(n - 80, 1), -1) if has_special else range(n + 3, max(n - 4, 1), -1)):
        fo, ok = simulate(tid, fields, base + L, base, le, secoff, rtpoff, ver)
        if ok and fo == base + L:
            best = L
            break
    if best is None:
        return False
    return dict(L=best, secoff=secoff, rtpoff=rtpoff, nat=nat, pos=pos)

def body_for(tid, fields, enums, le, plan=None, ver=7600):
    pos, n = layout(fields, le, ver)
    if plan:
        n = plan['L']
    b = bytearray(((tid * 31 + i * 7) & 0x3f) + 0x41 for i in range(n))     # printable pattern (strings, bytes)
    e = '<' if le else '>'
    fmt = {16: 'H', 32: 'I', 64: 'Q'}
    for k, (off, bi, f) in enumerate(pos):
        s = f['size']
        if off >= n:
            continue
        if f['adim'] and 1 <= s <= 8:
            f = dict(f, adim=min(f['adim'], n - off))
            pat = ('str%d_' % k).encode()
            b[off:off + f['adim']] = (pat * (f['adim'] // len(pat) + 1))[:f['adim']]
        elif f['enum'] and s in (16, 32, 64) and off + s // 8 <= n:
            vals = enums[f['enum']]
            v = (10 if (f['af'] and tid % 2) else vals[(tid + k) % len(vals)])
            if f['af']:
                v = 10 if tid % 2 else 2
            if v < 0:
                v &= (1 << s) - 1
            struct.pack_into(e + fmt[s], b, off, v & ((1 << s) - 1))
        elif s in (16, 32, 64) and off + s // 8 <= n:
            struct.pack_into(e + fmt[s], b, off, ((tid * 977 + k * 131) & ((1 << min(s, 30)) - 1)) | 1 if s > 8 else 1)
        elif s == 8 and not f['adim'] and off < n:
            b[off] = (tid + k) & 0x7f
    if plan:
        for off, bi, f in pos:
            sp = specials(tid, f['name'])
            if sp == 'SECOFF' and off + 4 <= n:
                struct.pack_into(e + 'I', b, off, plan['secoff'])
            elif sp == 'RTPOFF' and off + 4 <= n:
                struct.pack_into(e + 'I', b, off, plan['rtpoff'])
    return bytes(b)

def pdu(tid, body, event, le, ver, seq, cid=1):
    """Header: version, length (without the first 4 octets, split into a 16 bit length and an extension
    byte counting 0xffff), sequence number, reserved, id, [cid for events]."""
    e = '<' if le else '>'
    total = 12 + (4 if event else 0) + len(body) - 4
    ext = total // 0xffff
    hdr = struct.pack(e + 'HHHBBI', ver, total - 0xffff * ext, seq & 0xffff, ext, 0, tid)
    if event:
        hdr += struct.pack(e + 'i', cid)
    return hdr + body

def main(out):
    events, commands, enums, efields, cfields = load()
    fr, tcp_pdus = [], []
    ids_dbg = []
    odd = []
    seq = 0
    for ids, names, fdict, event in ((sorted(events), events, efields, True), (sorted(commands), commands, cfields, False)):
        for tid in ids:
            raw = fdict.get(tid)
            fields = reg_fields(raw, enums, tid) if raw else []
            for le in ((False, True) if tid % 3 == 0 and tid else (False,)):
                for ver in ((7400, 7600) if tid in (4, 1611) else (7600,)):
                    seq += 1
                    plan = special_plan(tid, fields, 16 if event else 12, le, ver) if fields else None
                    if plan is False:                       # offsets the dissector cannot walk consistently
                        odd.append((tid, event))
                        continue
                    body = body_for(tid, fields, enums, le, plan, ver) if fields else b''
                    if not event and 0 < len(body) < 4:     # the dissector reads a 4 octet CID at offset 12
                        odd.append((tid, event))
                        continue
                    p = pdu(tid, body, event, le, ver, seq)
                    sp, dp = (EVENT_PORT, 41000) if event else (41000, EVENT_PORT)
                    if len(p) > 1400:                       # too big for a datagram here: TCP only (segmented)
                        if len(p) <= 40000 and not le:
                            tcp_pdus.append((event, p))
                        continue
                    fr.append(udp(sp, dp, p))
                    ids_dbg.append((len(fr), tid, event, le, len(p)))
                    if tid % 9 == 0 and not le:             # the TCP length field is always read big endian
                        tcp_pdus.append((event, p))
    # ids that are not in the database (an event and a command): shown without a body
    for event in (True, False):
        sp, dp = (EVENT_PORT, 41000) if event else (41000, EVENT_PORT)
        fr.append(udp(sp, dp, pdu(0xfff0, bytes(range(20)), event, False, 7600, 1)))
        fr.append(udp(sp, dp, pdu(0xfff0, b'', event, False, 7600, 2)))
    # event with the header only, the High Availability port, and a 'long' length with an extension byte
    fr.append(udp(2442, 41000, pdu(1, b'', True, False, 7600, 3)))
    # TCP: PDUs in one segment, split in two and three segments, 4 octet header split
    flows = {True: Flow(2424, 41001), False: Flow(41002, 2424)}
    # events travel from port 2424: client side of Flow(2424, 41001) is the "sender"
    from pcaplib import tcp
    def tseg(event, data, seqs):
        s = seqs[event]
        sp, dp = (EVENT_PORT, 41001) if event else (41002, EVENT_PORT)
        for k in range(0, len(data), 1400):
            fr.append(tcp(sp, dp, s[0], data[k:k + 1400]))
            s[0] += len(data[k:k + 1400])
    seqs = {True: [1000], False: [5000]}
    # every PDU alone in its stream order: whole, split in two, header split after 2 octets, two PDUs in one
    # segment; a PDU above 1400 octets is segmented in 1400 octet pieces
    k, i = 0, 0
    while i < len(tcp_pdus):
        event, p = tcp_pdus[i]
        if len(p) > 1400:
            tseg(event, p, seqs)
            i += 1
            continue
        mode = k % 5
        k += 1
        nxt = tcp_pdus[i + 1] if i + 1 < len(tcp_pdus) else None
        if mode == 0 and nxt and nxt[0] == event and len(nxt[1]) <= 1400:
            tseg(event, p + nxt[1], seqs)
            i += 2
            continue
        if mode == 1 and len(p) >= 14:
            tseg(event, p[:len(p) // 2], seqs); tseg(event, p[len(p) // 2:], seqs)
        elif mode == 2:
            tseg(event, p[:2], seqs); tseg(event, p[2:], seqs)
        else:
            tseg(event, p, seqs)
        i += 1
    write(os.path.join(out, 'tpncp-coverage.pcap'), fr)
    if os.environ.get('TPNCP_DBG'):
        open(os.environ['TPNCP_DBG'], 'w').write('\n'.join(repr(x) for x in ids_dbg))
    print('main frames', len(fr), 'events', len(events), 'commands', len(commands), 'tcp pdus', len(tcp_pdus))

    m = []
    for tid, event in odd:                                           # the ids set aside above
        raw = (efields if event else cfields)[tid]
        fl = reg_fields(raw, enums, tid)
        body = body_for(tid, fl, enums, False)
        sp, dp = (EVENT_PORT, 41000) if event else (41000, EVENT_PORT)
        m.append(udp(sp, dp, pdu(tid, body, event, False, 7600, 5)))
    # events 4 and 5 of tpncp_broken.dat: an address family followed by the merged IP address
    for fam in (2, 10):
        body = struct.pack('>I', fam) + bytes([10, 0, 0, fam]) * 4 + struct.pack('>I', 7)
        m.append(udp(EVENT_PORT, 41000, pdu(4, body, True, False, 7600, 8)))
        m.append(udp(EVENT_PORT, 41000, pdu(5, struct.pack('>I', fam) + bytes(range(16)) + struct.pack('>I', 9), True, False, 7600, 9)))
    # event 7 of tpncp_broken.dat: a receive and a transmit RTP state block at the offset in rtp_state_offset
    body7 = struct.pack('>IIIIIII', 4, 0, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555)
    m.append(udp(EVENT_PORT, 41000, pdu(7, body7, True, False, 7600, 10)))
    # truncated PDUs and a length beyond the data (reassembly pending / bounds)
    p = pdu(2, body_for(2, reg_fields(cfields[2], enums, 2), enums, False), False, False, 7600, 1)
    for cut in (13, 40, len(p) // 2, len(p) - 1):
        m.append(udp(41000, EVENT_PORT, p[:cut]))
    p = pdu(1, body_for(1, reg_fields(efields[1], enums, 1), enums, False), True, False, 7600, 1)
    for cut in (10, 14, 20, len(p) - 3):
        m.append(udp(EVENT_PORT, 41000, p[:cut]))
    m.append(udp(41000, EVENT_PORT, p[:8]))                                      # shorter than the header
    m.append(udp(41000, EVENT_PORT, p + b'\xaa' * 7))                            # data after the last field: Unknown Data
    m.append(udp(EVENT_PORT, 41000, struct.pack('<HHHBBIi', 7600, 100, 1, 0, 0, 1, 1) + bytes(20)))   # little endian, length beyond the data
    # a PDU header cut after 6 octets: the length function reads the extension byte at offset 6
    from pcaplib import tcp
    q = pdu(2, body_for(2, reg_fields(cfields[2], enums, 2), enums, False), False, False, 7600, 1)
    m.append(tcp(41099, EVENT_PORT, 1, q[:6]))
    m.append(tcp(41099, EVENT_PORT, 7, q[6:]))
    write(os.path.join(out, 'tpncp-coverage-malformed.pcap'), m)

def broken_dat(out):
    """A small tpncp.dat full of malformed lines (for runcov.sh only: registration error paths)."""
    ev = ['Test data file', 'evA 1', 'evB 2', 'evC 3', 'evD 4', 'evE 5', 'evF 6', 'evG 7', 'bad line', '', '#####']
    cm = ['cmdA 1', 'cmdB 2', '#####']
    en = ['AddressFamily AF_IPV4 2', 'AddressFamily AF_IPV6 10', 'Other O1 1', 'Other O2 -1', 'broken enum line', '#####']
    ef = ['1 f1 0 32 0 0 primitive', '1 f2 1 8 5 0 primitive', '1 f3 1 3 0 0 primitive', 'badline', '-3 neg 0 32 0 0 primitive',
          '2 onlyid', '2 n 0', '2 n 0 32', '2 n 0 32 0', '2 n 0 32 0 0', '3 0 32 0 0 primitive',
          '4 af 0 32 0 0 AddressFamily', '4 ipa_0 0 32 0 0 primitive', '4 ipa_1 0 32 0 0 primitive',
          '4 ipa_2 0 32 0 0 primitive', '4 ipa_3 0 32 0 0 primitive', '4 tail 0 32 0 0 Other',
          '5 af 0 32 0 0 AddressFamily', '5 a_0 0 32 0 0 primitive', '5 b_0 0 32 0 0 primitive',
          '5 c_1 0 32 0 0 primitive', '5 d_2 0 32 0 0 primitive',
          '6 e 0 32 0 0 NoSuchEnum', '6 x 0 7 0 0 primitive', '6 y 1 16 0 0 primitive', '6 z 0 64 0 0 primitive',
          '6 w 0 128 0 0 primitive', '6 s1 1 32 0 1 primitive',
          '6 s2 1 32 0 1 Other', '6 t 1 8 0 0 primitive', '6 u 0 8 0 0 primitive',
          '7 rtp_state_offset 0 32 0 0 primitive', '7 pre 0 32 0 0 primitive', '7 ssrc 1 32 0 0 primitive', '7 rx_a 1 32 0 0 primitive',
          '7 rtp_tx_state_ssrc 1 32 0 0 primitive', '7 tx_a 1 32 0 0 primitive', '7 state_update_time_stamp 1 32 0 0 primitive',
          '1 again 0 32 0 0 primitive', '\0nul at the start of the line', '', '#####']
    cf = ['1 c1 0 32 0 0 primitive', '1 c2 0 32 0 0 Other', '2 cmd_rev_lsb 1 8 0 0 primitive', '2 security_cmd_offset 0 32 0 0 primitive',
          '2 rtp_authentication_algorithm 1 8 0 0 primitive', '2 last 1 32 0 0 primitive', '#####']
    open(os.path.join(out, 'tpncp_broken.dat'), 'w').write('\n'.join(ev + cm + en + ef + cf) + '\nlast line without a newline')

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
    broken_dat(sys.argv[1] if len(sys.argv) > 1 else '.')
