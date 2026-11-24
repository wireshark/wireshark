#!/usr/bin/env python3
# Generates test/captures/ucp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Generate the UCP coverage captures (synthetic).

usage: mkucp.py OUTDIR [-v]

UCP (the SMSC Universal Computer Protocol) has no registered port. It is
found by the TCP heuristic dissector "ucp_tcp" (enabled by default) on any
port, the first PDU of the connection selects it. Messages are
<STX>TRN/LEN/O|R/OT/fields.../CS<ETX>. Writes ucp-coverage.pcap and
ucp-coverage-malformed.pcap.
'''
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from u9lib import Pcap, Tcp

CLIENT = [192, 0, 2, 1]
SMSC = [192, 0, 2, 2]

sections = []


def pdu(trn, o_r, ot, fields, bad_cs=False, bad_len=0, last_slash=True):
    '''<STX>TRN/LEN/O_R/OT/f1/f2/.../CS<ETX>; fields is a list of strings, each
    is followed by a slash'''
    body = '/' + ''.join(f + '/' for f in fields)
    if not last_slash:
        body = body[:-1]
    head = lambda L: '%02d/%05d/%s/%02d' % (trn, L, o_r, ot) + body
    L = len(head(0)) + 2 + bad_len
    h = head(L)
    cs = sum(h.encode()) & 0xFF
    if bad_cs:
        cs ^= 0x55
    return b'\x02' + h.encode() + ('%02X' % cs).encode() + b'\x03'


def raw_pdu(text):
    '''A PDU with the checksum of text and the given text exactly (for broken ones)'''
    cs = sum(text.encode()) & 0xFF
    return b'\x02' + text.encode() + ('%02X' % cs).encode() + b'\x03'


class Gen:
    def __init__(self):
        self.pc = Pcap(1)
        self.trn = 0
        self.t = None

    def sec(self, name):
        sections.append([name, len(self.pc) + 1, None])

    def end(self):
        sections[-1][2] = len(self.pc)

    def conn(self, cport=50123, sport=50457):
        self.t = Tcp(CLIENT, SMSC, cport, sport)
        for f in self.t.handshake():
            self.pc.add(f)

    def send(self, d, data, flags=0x18):
        self.pc.add(self.t.seg(d, data, flags))

    def op(self, ot, fields, **kw):
        '''operation from the client, result from the SMSC follows when given'''
        self.trn = (self.trn + 1) % 100
        self.send(0, pdu(self.trn, 'O', ot, fields, **kw))
        return self.trn

    def res(self, ot, fields, trn=None, **kw):
        self.send(1, pdu(self.trn if trn is None else trn, 'R', ot, fields, **kw))

    def close(self):
        for f in self.t.close():
            self.pc.add(f)


# strings used in the fields
ADC = '0612345678'
OADC = '0687654321'
AC = '1234'
HELLO_IRA = '48656C6C6F20776F726C64'          # "Hello world" as IRA hex
TM = '0101231200'                              # DDMMYYhhmm
TS = '010123120030'                            # DDMMYYhhmmss
OADC_ALNUM = '0AC8329BFD06'                    # alphanumeric "Hello" (OTOA 5039)


def mt_fields(mt):
    if mt == '1':
        return ['1']
    if mt == '2':
        return ['2', '3132333435']
    if mt == '3':
        return ['3', HELLO_IRA]
    if mt == '4':
        return ['4', '40', '0102030405FF']
    if mt == '5':
        return ['5', 'A', '12', '3', '45']
    if mt == '6':
        return ['6', '414243', '1234']
    return ['9']


def p5x(mt, otoa='', oadc=OADC):
    return [ADC, oadc, AC, '1', '0699999999', '3', '0539', '1', 'LRA', '0539', '1', TM, TM, 'RPID', TS, '0', '000', TS,
            mt, '40', '0102030405FF' if mt != '3' else HELLO_IRA, '', '', '', '', '', '', '', otoa, '', '', '', '']


def build_main(g):
    g.sec('TCP connection, enquiry, call input (operations 00 to 03) and their results')
    g.conn()
    g.op(0, [ADC, OADC, AC])
    g.res(0, ['A', '1', '0', '1', '0', '1', '0', '1', '0', '10', '20', '30', 'enquiry ok'])
    g.op(0, ['', '', ''])
    g.res(0, ['N', '02', 'syntax error'])
    for mt in '1234569':
        g.op(1, [ADC, OADC, AC] + mt_fields(mt))
        g.res(1, ['A', 'ok'])
    g.op(1, ['', '', ''] + ['1'])
    g.res(1, ['N', '04', 'invalid'])
    g.op(1, [ADC, OADC, AC] + ['3', ''])               # empty message text
    g.res(1, ['A', ''])
    g.op(2, ['02', ADC, '0611111111', OADC, AC] + mt_fields('3'))
    g.res(2, ['A', 'ok'])
    g.op(2, ['00', OADC, AC] + mt_fields('1'))
    g.res(2, ['N', '21', 'no address'])
    g.op(3, [ADC, OADC, AC, '02', 'GA1', 'GA2', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', 'x', TM, '2', '3132'])
    g.res(3, ['A', 'ok'])
    g.op(3, [ADC, OADC, AC, '00', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '1'])
    g.res(3, ['N', '05', 'invalid range'])
    g.end()

    g.sec('Operations 04 to 14: address lists, charges, passwords, standard text, roaming, retrieval')
    g.op(4, ['GA', AC, OADC, AC])
    g.res(4, ['A', '02', ADC, '0611111111', 'GA', 'ok'])
    g.res(4, ['N', '11', 'no group'])
    g.op(5, ['GA', AC, OADC, AC, '02', ADC, '0611111111', 'A'])
    g.res(5, ['A', 'ok'])
    g.op(6, [ADC, AC])
    g.res(6, ['A', TM, '1250', 'charges'])
    g.res(6, ['N', '12', 'no charge'])
    g.op(7, [ADC, AC, 'NEWPW'])
    g.res(7, ['A', 'ok'])
    g.op(8, [ADC, AC, 'LAC', 'L1P', 'L3P', 'LRC', 'LUM', 'LRP', 'LST'])
    g.res(8, ['A', 'ok'])
    g.op(9, ['01', 'LST'])
    g.res(9, ['A', '02', 'LST1', 'LST2', 'ok'])
    g.res(9, ['N', '13', 'no text'])
    g.op(10, [ADC, AC, '01', '02', '414243', '4321'])
    g.res(10, ['A', 'ok'])
    g.op(11, [ADC, AC])
    g.res(11, ['A', '02', 'GA1', 'GA2', 'ok'])
    g.res(11, ['N', '14', 'no roaming'])
    g.op(12, [ADC, AC, '02', 'GA1', 'GA2'])
    g.res(12, ['A', 'ok'])
    g.op(13, [ADC, AC])
    g.res(13, ['A', 'ok'])
    g.op(14, [ADC, AC, 'MNO', 'A'])
    g.res(14, ['A', '02', '4142', '4344'])
    g.res(14, ['N', '15', 'nothing to retrieve'])
    g.end()

    g.sec('Operations 15 to 24 and 22: barring, diversion, deferred delivery, status, version, feature status')
    g.op(15, [ADC, AC, TM, '0201231200'])
    g.res(15, ['A', 'ok'])
    for ot in (16, 18, 20, 21):
        g.op(ot, [ADC, AC])
        g.res(ot, ['A', 'ok'])
    g.op(17, [ADC, AC, '0699999999', TM, '0201231200'])
    g.res(17, ['A', 'ok'])
    g.op(19, [ADC, AC, TM, '0201231200'])
    g.res(19, ['A', 'ok'])
    g.op(22, [ADC, OADC, AC, '4142', '4321'])
    g.res(22, ['A', 'ok'])
    g.op(23, ['5', '1'])
    g.res(23, ['A', '5', '02', '51', '52', 'ok'])               # the reproducer of the fix
    g.op(23, ['', ''])
    g.res(23, ['A', '', '00', 'none'])
    g.res(23, ['N', '06', 'not supported'])
    g.op(24, [ADC, AC, 'S'])
    # feature status: roaming, call barring, deferred delivery, diversion, last message number, new messages
    g.res(24, ['A', 'N', 'N', 'N', 'N', '07', 'N', 'SM'])
    g.res(24, ['A', '02', 'GA1', 'GA2', '01', 'CB1', '02', 'DD1', 'DD2', '01', 'DIV1', '12', '05', 'ok'])
    g.res(24, ['A', '', '', '', '', '', '', ''])
    g.res(24, ['N', '16', 'no status'])
    g.end()

    g.sec('SMS transfer and alert (30, 31), submit/deliver/notification (51-58), session management (60, 61)')
    g.op(30, [ADC, OADC, AC, '1', '0699999999', '0539', '1', TM, TM, HELLO_IRA])
    g.res(30, ['A', TM, 'ok'])
    g.res(30, ['N', '07', 'invalid'])
    g.op(31, [ADC, '0539'])
    g.res(31, ['A', 'ok'])

    for ot in range(51, 59):
        g.op(ot, p5x('2'))
        g.res(ot, ['A', TM, 'ok'])
    g.op(52, p5x('3'))
    g.op(53, p5x('4'))
    g.op(51, p5x('3', otoa='5039', oadc=OADC_ALNUM))
    g.res(51, ['A', TM, 'ok'])
    g.op(51, p5x('3', otoa='6039'))
    # reserved code page and reply type (shown as reserved), the alphanumeric OAdC, extended
    # services: type 01 with 2 octets and type 03 without data
    f = p5x('3', otoa='5039', oadc=OADC_ALNUM)
    f[26], f[27], f[29], f[30], f[31], f[32] = 'x', 'y', 'H', '010201AA0300', 'a', 'b'
    g.op(53, f)
    f = p5x('3')
    f[30], f[31], f[32] = '0102ABCD0300', 'a', 'b'
    g.op(52, f)
    f = p5x('2')
    f[28] = '1'
    g.op(54, f)
    g.op(60, [OADC, '6', '1', '1', '48656C6C6F', '4E5057', '0100', 'LA', '5', '1', '0539', 'res1'])
    g.res(60, ['A', 'ok'])
    g.op(61, [OADC, '6', '1', '1', '48656C6C6F', '4E5057', '0100', 'LA', '5', '1', 'res1', 'res2'])
    g.res(61, ['N', '01', 'checksum error'])
    g.op(60, ['', '', '', '', '', '', '', '', '', '', '', ''])
    g.end()

    g.sec('Several PDUs in one segment, a PDU split over segments, invalid checksum, result for an unknown operation')
    a = pdu(90, 'O', 6, [ADC, AC])
    b = pdu(91, 'O', 13, [ADC, AC])
    g.send(0, a + b)
    g.send(1, pdu(90, 'R', 6, ['A', TM, '10', 'ok']) + pdu(91, 'R', 13, ['A', 'ok']))
    c = pdu(92, 'O', 1, [ADC, OADC, AC] + mt_fields('3'))
    g.send(0, c[:5])
    g.send(0, c[5:30])
    g.send(0, c[30:])
    g.send(1, pdu(92, 'R', 1, ['A', 'ok']))
    g.send(0, pdu(93, 'O', 6, [ADC, AC], bad_cs=True))
    g.send(1, pdu(93, 'R', 6, ['A', TM, '10', 'ok'], bad_cs=True))
    g.send(0, pdu(94, 'O', 99, ['x', 'y']))
    g.send(1, pdu(94, 'R', 99, ['A', 'ok']))
    g.send(1, pdu(95, 'R', 0, ['N', '99', 'unknown error']))
    g.close()
    g.end()


def build_malformed(g):
    g.sec('Broken PDUs: integers that are not numbers, truncated fields, missing STX')
    g.conn()
    g.op(2, ['xx', ADC, OADC, AC] + mt_fields('3'))             # NPL not a number
    g.res(0, ['A', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'zz', '34', '56', 'x'])
    g.res(23, ['A', '5', 'qq', 'ok'])
    g.res(24, ['N', '9999999999999', 'big'])
    g.op(10, [ADC, AC, '01', '02', '414243', 'abc'])
    g.op(1, [ADC, OADC, AC, '6', '414243', 'zz'])
    g.op(1, [ADC, OADC, AC, '3', 'ZZZZ'])                       # invalid IRA hex
    g.op(1, [ADC, OADC, AC, '3', '4142ZZ4344'])                 # invalid pair in the middle of the IRA string
    g.op(1, [ADC, OADC, AC, '3', 'ZZ4142'])
    g.op(1, [ADC, OADC, AC, '3', '4142ZZ'])
    g.op(1, [ADC, OADC, AC, '3', '4'])                          # odd IRA hex
    g.send(0, pdu(77, 'O', 30, [ADC, OADC, AC, '1', '0699999999', '0539', '1', TM, TM, '4142'], last_slash=False))   # IRA string without terminator
    g.send(0, pdu(78, 'O', 15, [ADC, AC, TM, '0201231200'], last_slash=False))   # time without terminator
    g.send(0, pdu(79, 'O', 0, [ADC, OADC, 'AC'], last_slash=False))              # string without terminator
    g.send(0, pdu(80, 'O', 1, [ADC, OADC, AC, '4'], last_slash=False))           # message type 4 without NB
    g.send(0, pdu(81, 'O', 22, [ADC, OADC, AC, '4142', '12'], last_slash=False))  # integer without terminator
    g.op(1, [ADC, OADC, AC, '3', '48656C6C6F2'])
    for oadc in ('0AC832', 'OADC_ZZZZ', '', '0A'):                # short data, invalid hex, empty, no data
        g.op(51, p5x('3', otoa='5039', oadc=oadc))
    f = p5x('2')
    f[30] = '010200AA0300'                                       # extended services length 2, data missing
    g.op(53, f)
    f[30] = '0102AB'
    g.op(53, f)
    g.op(0, [ADC])                                               # fields missing
    g.op(1, [ADC, OADC])
    g.op(3, [ADC, OADC, AC, '05', 'GA1'])                        # NPL larger than the list
    g.op(14, [ADC, AC])
    g.res(14, ['A', '05', '41'])
    g.res(24, ['A', 'N', 'N'])
    g.res(9, ['A', '09', 'LST'])
    g.send(0, raw_pdu('01/00020/O/00/'))                          # fields cut short
    g.send(0, b'\x02' + b'01/0010/O/99/ab/')                      # no ETX, LEN field with 4 digits
    g.send(1, b'\x02' + b'02/00017/R/00/AA/')
    g.end()
    g.sec('TCP segments that continue a PDU without STX')
    g.send(0, pdu(50, 'O', 6, [ADC, AC])[:10])
    g.send(0, b'rest of the PDU\x03')
    g.send(0, pdu(51, 'O', 6, [ADC, AC]) + b'trailing')
    g.close()
    g.end()
    g.sec('Connection whose first segments are not UCP, then UCP (the heuristic keeps trying; on the second pass the conversation dissector is set for the whole connection, so the earlier segments are dissected as UCP)')
    g.conn(cport=50200, sport=50500)
    g.send(0, bytes(range(0x80, 0x8D)))                          # shorter than a UCP header
    g.send(1, bytes(range(0x80, 0x94)))                          # long enough, not UCP
    g.send(0, b'\x02' + bytes(range(0x30, 0x3A)) + b'//////')   # STX, but the slashes are in the wrong places
    g.send(1, pdu(2, 'X', 6, [ADC, AC]))                         # right slashes, but not O or R
    g.send(0, pdu(1, 'O', 6, [ADC, AC]))
    g.send(1, pdu(1, 'R', 6, ['A', TM, '10', 'ok']))
    g.close()
    g.end()


def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    g = Gen()
    build_main(g)
    g.pc.write(os.path.join(out, 'ucp-coverage.pcap'))
    if verbose:
        print('main: %d frames' % len(g.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))
    del sections[:]
    m = Gen()
    build_malformed(m)
    m.pc.write(os.path.join(out, 'ucp-coverage-malformed.pcap'))
    if verbose:
        print('malformed: %d frames' % len(m.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))


if __name__ == '__main__':
    main()
