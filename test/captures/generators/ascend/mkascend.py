#!/usr/bin/env python3
# Generates test/captures/ascend_coverage.txt.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic Lucent/Ascend text traces for coverage of
# epan/dissectors/packet-ascend.c and the wiretap Ascend reader
# (wiretap/ascendtext.c, ascend_scanner.l, ascend_parser.lemon).
#
# Every packet is built with struct; nothing comes from a real network.
# Usage: mkascend.py <outdir>
#
# Writes:
#   ascend_coverage.txt            main trace (clean)
#   malformed/*.txt                traces that end in a read error or that
#                                  reach reader/dissector error paths
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident=1, ttl=64):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                    ttl, proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def udp(src, dst, sport, dport, data):
    u = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]


def icmp_echo(ident, seq, data, typ=8):
    m = struct.pack('!BBHHH', typ, 0, 0, ident, seq) + data
    return m[:2] + struct.pack('!H', csum(m)) + m[4:]


A = [10, 1, 0, 1]
B = [10, 1, 0, 2]
C = [192, 0, 2, 10]
D = [198, 51, 100, 20]
MAC1 = bytes.fromhex('020000000001')
MAC2 = bytes.fromhex('020000000002')


def eth(dst, src, etype, payload):
    return dst + src + struct.pack('!H', etype) + payload


# ---- payloads -------------------------------------------------------------

def ppp(proto, data):
    return b'\xff\x03' + struct.pack('!H', proto) + data


def lcp(code, ident, opts=b''):
    return ppp(0xc021, struct.pack('!BBH', code, ident, 4 + len(opts)) + opts)


LCP_OPTS = (bytes([1, 4, 0x05, 0xdc])            # MRU 1500
            + bytes([3, 5, 0xc2, 0x23, 0x05])    # Auth CHAP MD5
            + bytes([5, 6, 0x12, 0x34, 0x56, 0x78]))  # magic number


def ipcp(code, ident, addr):
    return ppp(0x8021, struct.pack('!BBH', code, ident, 10) + bytes([3, 6]) + bytes(addr))


def pap_req(peer, pw):
    body = bytes([len(peer)]) + peer + bytes([len(pw)]) + pw
    return ppp(0xc023, struct.pack('!BBH', 1, 1, 4 + len(body)) + body)


def chap_challenge(name):
    val = bytes(range(16))
    body = bytes([len(val)]) + val + name
    return ppp(0xc223, struct.pack('!BBH', 1, 7, 4 + len(body)) + body)


def ppp_ip(payload_ip):
    return ppp(0x0021, payload_ip)


# Syslog over UDP inside PPP (no request/response tracking, so one and
# two passes give the same output)
ping = ppp_ip(ipv4(A, B, 17, udp(A, B, 514, 514, b'<14>ascend ppp up'), ident=0x10))
pong = ppp_ip(ipv4(B, A, 17, udp(B, A, 514, 514, b'<14>ascend ppp ok'), ident=0x11))
def udp_eth(qid):
    msg = b'<13>ascend wdd test %04x' % qid
    return eth(MAC2, MAC1, 0x0800, ipv4(C, D, 17, udp(C, D, 40000 + qid % 1000, 514, msg),
                                        ident=qid & 0xffff))

arp = eth(b'\xff' * 6, MAC1, 0x0806,
          struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, MAC1, bytes(C),
                      b'\0' * 6, bytes(D)))
# A UDP datagram whose Ethernet frame is longer than the 128 octets the
# reader keeps (ASCEND_MAX_PKT_LEN): the trace shows only the first 128.
big_udp = eth(MAC1, MAC2, 0x0800,
              ipv4(D, C, 17, udp(D, C, 5060, 5060, b'X' * 300), ident=0x30))

# LAPD (with the ISDN pseudo-header): RR S-frame, and an I-frame with a
# Q.931 SETUP split over two "deferred" PRI-XMIT records.
lapd_rr_x = bytes([0x00, 0x01, 0x01, 0x05])     # SAPI 0 C/R=0 TEI 0, RR N(R)=2
lapd_rr_r = bytes([0x02, 0x01, 0x01, 0x07])     # SAPI 0 C/R=1, RR N(R)=3
lapd_i_hdr = bytes([0x00, 0x01, 0x04, 0x06])    # I-frame N(S)=2 N(R)=3
q931_setup = (bytes([0x08, 0x02, 0x00, 0x05, 0x05])        # SETUP, cref 5
              + bytes([0x04, 0x03, 0x80, 0x90, 0xa2])       # bearer cap
              + bytes([0x18, 0x03, 0xa9, 0x83, 0x81])       # channel id
              + bytes([0x70, 0x05, 0x81]) + b'5551')        # called number
lapd_ui = bytes([0xfc, 0xff, 0x03, 0x0f, 0x00, 0x01, 0x01, 0xff])  # TEI mgmt ID request


# ---- text formatting ------------------------------------------------------

def hexdump(data, new=False, disp=True):
    """old (TAOS 7 and earlier): upper case, no character display;
    new (TAOS 8): lower case, gap after 8 octets, character display."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        if new:
            hx = ' '.join('%02x' % b for b in chunk[:8])
            if len(chunk) > 8:
                hx += '  ' + ' '.join('%02x' % b for b in chunk[8:])
            line = '  [%04x]: %s' % (i, hx)
            if disp:
                ch = ''.join(chr(b) if 0x20 <= b < 0x7f and chr(b) not in '[]' else '.'
                             for b in chunk)
                line = line.ljust(10 + 49) + '    ' + ch[:8] + ' ' + ch[8:]
        else:
            line = '  [%04X]: %s' % (i, ' '.join('%02X' % b for b in chunk))
        lines.append(line)
    return '\n'.join(lines) + '\n'


recs = []   # (text, description)


def add(text, desc, glue=False):
    recs.append((text, desc, glue))


def wds(direction, user, sess, task, t, data, addr='8003BD94', octets=None):
    # wandsess (TAOS 6/7): RECV-iguana:241:(task: B02614C0, time: 1975432.85) 49 octets @ 8003BD94
    n = len(data) if octets is None else octets
    return '%s-%s:%d:(task: %s, time: %s) %d octets @ %s\n%s' % (
        direction, user, sess, task, t, n, addr, hexdump(data))


def wds8(direction, user, sess, task, t, data):
    # wandsess (TAOS 8): RECV-Max7:20: (task "_brouterControlTask" at 0xb094ac20, time: 1481.50) 20 octets @ 0x8000d198
    return '%s-%s:%d: (task "%s" at 0xb094ac20, time: %s) %d octets @ 0x8000d198\n%s' % (
        direction, user, sess, task, t, len(data), hexdump(data, new=True))


def wdp7(direction, sess, task, t, data):
    # wandisp (TAOS 7.2): RECV-187:(task: B050B480, time: 18042248.03) 100 octets @ 800012C0
    return '%s-%d:(task: %s, time: %s) %d octets @ 800012C0\n%s' % (
        direction, sess, task, t, len(data), hexdump(data))


def wdp8(direction, sess, task, t, data):
    # wandisp (TAOS 8): XMIT-44: (task "freedm_task" at 0xe051fd10, time: 6258.66) 29 octets @ 0x606d1f00
    return '%s-%d: (task "%s" at 0xe051fd10, time: %s) %d octets @ 0x606d1f00\n%s' % (
        direction, sess, task, t, len(data), hexdump(data, new=True))


def wdd(chunk, task, t, data, date=None, callnum=None):
    s = ''
    if date:
        s += 'Date: %s.  Time: %s\n' % date
        s += 'Cause an attempt to place call to %s\n' % callnum
    s += 'WD_DIALOUT_DISP: chunk %s type IP.\n' % chunk
    s += '(task: %s, time: %s) %d octets @ 2782B8\n%s' % (task, t, len(data), hexdump(data))
    return s


def pri(direction, chan, task, t, data, suffix='', sep=':  ', octets=None):
    n = len(data) if octets is None else octets
    return 'PRI-%s-%s%s%s(task "%s" at 0x10216fe0, time: %s) %d octets @ 0x1027c5b0\n%s' % (
        direction, chan, suffix, sep, task, t, n, hexdump(data, new=True))


def ether(name, direction, t, data, octets=None, disp=True):
    n = len(data) if octets is None else octets
    return '%s %s: (task "_sarTask" at 0x802c6eb0, time: %s) %d octets @ 0xa8fb2020\n%s' % (
        name, direction, t, n, hexdump(data, new=True, disp=disp))


# 1  WDD with a Date/Time and called number (first record: the trace's
#    time base comes from it, not from the file's ctime)
add(wdd('2515EE', '251790', '994953.28', udp_eth(0x1001), date=('01/12/1999', '12:22:33'),
        callnum='5551234567'), 'WDD with Date: and called number')
# 2  WDD without a Date: header (no called number)
add(wdd('2515EF', '251790', '994953.40', arp), 'WDD without Date:')
# 3,4  The stale-user reproducer (ascend_stale_user.txt): two
#      wandsess records from different users
add(wds('RECV', 'alice', 241, 'B02614C0', '994954.85', lcp(1, 1)), 'wandsess RECV alice')
add(wds('XMIT', 'bob', 242, 'B04E12C0', '994954.86', lcp(1, 1), addr='8009EB16'),
    'wandsess XMIT bob')
# 5-8  TAOS 8 wandsess (user Max7, session 20), with character display
add(wds8('RECV', 'Max7', 20, '_brouterControlTask', '994955.50', lcp(1, 2, LCP_OPTS)),
    'TAOS 8 wandsess RECV LCP Conf-Req')
add(wds8('XMIT', 'Max7', 20, '_brouterControlTask', '994955.51', lcp(2, 2, LCP_OPTS)),
    'TAOS 8 wandsess XMIT LCP Conf-Ack')
add(wds8('RECV', 'Max7', 20, '_brouterControlTask', '994955.52', chap_challenge(b'max7')),
    'TAOS 8 wandsess CHAP challenge')
add(wds8('XMIT', 'Max7', 20, '_brouterControlTask', '994955.53', ipcp(1, 3, A)),
    'TAOS 8 wandsess IPCP')
# 9,10  TAOS 7.2 wandisp: no user name (shown as <none>)
add(wdp7('RECV', 187, 'B050B480', '994956.03', ping), 'TAOS 7 wandisp RECV syslog')
add(wdp7('XMIT', 187, 'B0292CA0', '994956.04', pong), 'TAOS 7 wandisp XMIT syslog')
# 11,12  TAOS 8 wandisp: no user name
add(wdp8('XMIT', 44, 'freedm_task', '994957.66', pap_req(b'carol', b'secret')),
    'TAOS 8 wandisp XMIT PAP')
add(wdp8('RECV', 44, 'freedm_task', '994957.67', lcp(9, 4, b'\x12\x34\x56\x78')),
    'TAOS 8 wandisp RECV LCP Echo-Request')
# 13,14  "XMIT:" / "RECV:" prefixes
add('XMIT:dave:9:(task: B0100000, time: 994958.10) %d octets @ 8003BD94\n%s'
    % (len(lcp(5, 5)), hexdump(lcp(5, 5))), 'XMIT: prefix, user dave')
add('RECV:dave:9:(task: B0100000, time: 994958.11) %d octets @ 8003BD94\n%s'
    % (len(lcp(6, 5)), hexdump(lcp(6, 5))), 'RECV: prefix, user dave')
# 15,16  "PPP-OUT" / "PPP-IN" prefixes (the user name is what follows the
#        prefix up to the colon)
add('PPP-OUT_erin:11:(task: B0100010, time: 994959.20) %d octets @ 8003BD94\n%s'
    % (len(ping), hexdump(ping)), 'PPP-OUT prefix')
add('PPP-IN_erin:11:(task: B0100010, time: 994959.21) %d octets @ 8003BD94\n%s'
    % (len(pong), hexdump(pong)), 'PPP-IN prefix')
# 17,18  pridisp, one record per frame
add(pri('XMIT', '27', 'l1Task', '994960.01', lapd_rr_x), 'PRI-XMIT LAPD RR')
add(pri('RCV', '27', 'idle task', '994960.02', lapd_rr_r), 'PRI-RCV LAPD RR')
# 19  pridisp, I-frame header and contents in two records, one frame
add(pri('XMIT', '19', 'l1Task', '994960.98', lapd_i_hdr, suffix='/1')
    + pri('XMIT', '19', 'l1Task', '994960.98', q931_setup, suffix='/2', sep=' '),
    'PRI-XMIT deferred (two records, Q.931 SETUP)')
# 20  PRI-RCV UI frame (TEI management)
add(pri('RCV', '0', 'idle task', '994961.00', lapd_ui), 'PRI-RCV LAPD UI TEI management')
# 21  ether-display, 128 octets shown of a longer frame (header says the
#     full length; the reader keeps at most 128 octets)
add(ether('ETHER3ND', 'RECV', '994962.03', big_udp[:128], octets=len(big_udp)),
    'ETHER RECV 128 of %d octets' % len(big_udp))
# 22  ether-display XMIT, no character display, short frame
add(ether('ETHER3ND', 'XMIT', '994962.11', arp, disp=False), 'ETHER XMIT ARP')
# 23  header claims fewer octets than the data lines hold: only the
#     claimed number is kept
add('RECV-frank:300:(task: B0200000, time: 994963.00) 8 octets @ 8003BD94\n%s'
    % hexdump(lcp(1, 6) + b'\xde\xad\xbe\xef'), 'more data than octets')
# 24  WDD record with a Date: header later in the trace, year before 1970
add(wdd('2515F0', '251790', '994964.00', udp_eth(0x1002), date=('06/30/1969', '23:59:59'),
        callnum='18005550199'), 'WDD with a 1969 Date:')
# 25,26  wandsess followed by the next record without a blank line
add(wds('XMIT', 'gina', 12, 'B0300000', '994965.00', ping), 'wandsess, next record without blank line',
    glue=True)
add(wds('RECV', 'gina', 12, 'B0300000', '994965.01', pong), 'wandsess RECV gina')
# 27,28  WDD followed by an ETHER record without a blank line
add(wdd('2515F1', '251791', '994966.00', arp), 'WDD before ETHER without blank line', glue=True)
add(ether('ETHER0', 'RECV', '994966.10', udp_eth(0x1003)), 'ETHER0 RECV syslog')
# 29  task as "0X" hex, user name of digits, a two digit session
add('XMIT-12:34:(task: 0XB0400000, time: 994967.00) %d octets @ 8003BD94\n%s'
    % (len(ipcp(2, 3, A)), hexdump(ipcp(2, 3, A))), 'numeric user name 12, session 34')
# 30  stale-user check after records without a user: wandsess user again
add(wds('RECV', 'hank', 5, 'B0500000', '994968.00', lcp(10, 4, b'\x12\x34\x56\x78')),
    'wandsess RECV hank after v7/WDD/ISDN records')
# 31  time with six fraction digits (only the first two are used: .12 s)
add(wds('XMIT', 'hank', 5, 'B0500000', '994969.123456', lcp(11, 5, b'\x12\x34\x56\x78')),
    'wandsess with a six digit time fraction')

# Separator text between records: console noise, a blank line or none.
NOISE = [
    'ascend% wandsess on\n',
    '\n',
    'Console: some output that is not a packet (task list follows)\n  idle 0x1234 0x5678\n\n',
]


def build_main():
    out = ['** Synthetic Lucent/Ascend debug trace for Wireshark tests **\n',
           'ascend% wdd\n']
    i = 0
    for text, desc, glue in recs:
        out.append(text)
        if not glue:
            out.append(NOISE[i % len(NOISE)])
            i += 1
    return ''.join(out)


def main():
    os.makedirs(OUT, exist_ok=True)
    txt = build_main()
    open(os.path.join(OUT, 'ascend_coverage.txt'), 'w').write(txt)

    md = os.path.join(OUT, 'malformed')
    os.makedirs(md, exist_ok=True)
    m = {}
    # Header but no data: "no data returned by parse" read error after
    # one good packet
    m['nodata'] = (wds('RECV', 'ivy', 1, 'B0600000', '1.00', lcp(1, 1))
                   + '\nXMIT-ivy:1:(task: B0600000, time: 1.01) 8 octets @ 8003BD94\n\n'
                   + 'garbage after header\n')
    # Date: before a PPP record: parse error with no data
    m['date_ppp'] = (wds('RECV', 'ivy', 1, 'B0600000', '1.00', lcp(1, 1))
                     + 'Date: 01/12/1999.  Time: 12:22:33\n'
                     + wds('XMIT', 'ivy', 1, 'B0600000', '1.01', lcp(1, 1)))
    # A line longer than ASCEND_MAX_LINE_LEN in the data
    m['longline'] = (wds('RECV', 'ivy', 1, 'B0600000', '1.00', lcp(1, 1))
                     + 'XMIT-ivy:1:(task: B0600000, time: 1.01)' + ' ' * 1100
                     + '8 octets @ 8003BD94\n' + hexdump(lcp(1, 1)))
    # A record whose data is followed by a line longer than
    # ASCEND_MAX_LINE_LEN: the record is kept, the error is dropped
    m['longline_after_data'] = (wds('RECV', 'ivy', 1, 'B0600000', '1.00', lcp(1, 1))
                                + 'x' * 1100 + '\n'
                                + wds('XMIT', 'ivy', 1, 'B0600000', '1.01', lcp(1, 1)))
    # A second record that claims 0 octets but has data: parse error with
    # no data kept
    m['zerooctets'] = (wds('RECV', 'ivy', 1, 'B0600000', '1.00', lcp(1, 1))
                       + wds('XMIT', 'ivy', 1, 'B0600000', '1.01', lcp(1, 1), octets=0)
                       + wds('RECV', 'ivy', 1, 'B0600000', '1.02', lcp(1, 1)))
    # Text without any record header
    m['nomagic'] = 'This is a text file without any Ascend record header.\n' * 10
    # Only a header: not an Ascend file (open fails: no data)
    m['notmine'] = 'RECV-ivy:1:(task: B0600000, time: 1.00) 8 octets @ 8003BD94\nnothing\n'
    # Long run of text with no record header: the scanner for headers
    # gives up after 256 KB
    m['excessive'] = (wds('RECV', 'ivy', 1, 'B0600000', '1.00', lcp(1, 1))
                      + ('z' * 79 + '\n') * 3400
                      + wds('XMIT', 'ivy', 1, 'B0600000', '1.01', lcp(1, 1)))
    # First record without a Date: (time base from the file ctime), then
    # a user name longer than 20 characters
    m['longuser'] = (wds('RECV', 'ivy', 1, 'B0600000', '1.00', lcp(1, 1))
                     + wds('XMIT', 'a' * 25, 2, 'B0600000', '1.01', lcp(1, 1)))
    # A user name of 1 character
    m['shortuser'] = (wds('RECV', 'ivy', 1, 'B0600000', '1.00', lcp(1, 1))
                      + wds('XMIT', 'b', 3, 'B0600000', '1.02', lcp(1, 1)))
    # More than 8 data lines (truncated at 128 octets, the 9th line is a
    # syntax error that ends the record), with the 9th line holding a
    # header magic in the character display
    m['ninelines'] = (ether('ETHER3ND', 'RECV', '1.00', big_udp[:144], octets=len(big_udp))
                      + wds('RECV', 'ivy', 1, 'B0600000', '1.01', lcp(1, 1)))
    # Truncated records for the dissectors: PPP, Ethernet and LAPD with
    # one octet; unknown WDD chunk / bogus fields
    m['short_ppp'] = wds('RECV', 'ivy', 1, 'B0600000', '1.00', b'\xff')
    m['short_eth'] = ether('ETHER3ND', 'RECV', '1.01', b'\x02\x00')
    m['short_isdn_x'] = pri('XMIT', '1', 'l1Task', '1.02', b'\x00')
    m['short_isdn_r'] = pri('RCV', '1', 'l1Task', '1.03', b'\x02')
    m['short_wdd'] = wdd('1', '251790', '1.04', b'\x00\x01')
    # A record with a single data octet followed by the next record
    # without a blank line: the reader records the position of the first
    # data octet only when it reduces the octet, after it has scanned the
    # next header's "ETHER", so the search for the next record starts
    # inside that header, finds "RECV:" in "ETHER3ND RECV:" and the read
    # ends with "no data returned by parse".
    m['onebyte'] = (wds('RECV', 'ivy', 1, 'B0600000', '1.00', b'\xff')
                    + ether('ETHER3ND', 'RECV', '1.01', arp))
    # File ending in the middle of a record (EOF in the scanner)
    m['eof'] = (wds('RECV', 'ivy', 1, 'B0600000', '1.00', lcp(1, 1))
                + 'XMIT-ivy:1:(task: B0600000, time: 1.01) 8 octets @ 8003BD94\n  [0000]: FF 03')
    for k, v in m.items():
        open(os.path.join(md, 'ascend-%s.txt' % k), 'w').write(v)

    # Exported PDU (linktype 252) naming the "ascend" dissector (as in
    # ascend_exported_pdu.py): the record has no Ascend
    # pseudo-header, so the dissector sees link type 0, the only way to
    # reach its default cases.
    def tag(t, v):
        return struct.pack('>HH', t, len(v)) + v + b'\0' * ((-len(v)) % 4)
    pdu = tag(12, b'ascend') + struct.pack('>HH', 0, 0) + bytes(range(0x40))
    with open(os.path.join(md, 'ascend-exported-pdu.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252))
        f.write(struct.pack('<IIII', 1, 0, len(pdu), len(pdu)) + pdu)

    with open(os.path.join(OUT, 'records.txt'), 'w') as f:
        for n, (text, desc, glue) in enumerate(recs):
            f.write('%d\t%s\n' % (n + 1, desc))


main()
