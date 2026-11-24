#!/usr/bin/env python3
# Generates test/captures/lnpdqp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic LNPDQP (packet-lnpdqp.c) coverage captures.

LNP database queries (ConnectionControlArg, ProvideInstructionArg) are the
parameter sets of the ANSI TCAP national operations 0x0401 (Connection
Control) and 0x0301 (Provide Instruction).  They are carried as in an SS7
over IP network: Ethernet / IPv4 / SCTP (PPID 3) / M3UA DATA / SCCP UDT /
ANSI TCAP (decode with -o mtp3.standard:ANSI, cfg/profiles/lnpdqp does it).
The SS7 and TCAP framing comes from ansilib.py (a copy of the ANSI TCAP
coverage generator).  Nothing comes from a real network.

Usage: mklnpdqp.py <outdir>
"""
import os
import struct
import sys

import ansilib as A

PRI, CON = A.PRI, A.CON
MSC, HLR = A.MSC, A.HLR
PI, CC = 0x8301, 0x0401      # national opcodes, with and without the H bit
PI_NOH = 0x0301


def digits(tag, tod, digs, nol=2, np_enc=0x21, nod=None, raw=None):
    """[tag] Digits: type of digits, nature of number, numbering plan and
    encoding, number of digits, then the digits."""
    if raw is not None:
        return A.tlv(CON, False, tag, raw)
    body = A.bcd(digs) if (np_enc & 0xf) == 1 else digs.encode()
    n = len(digs) if nod is None else nod
    return A.tlv(CON, False, tag, bytes([tod, nol, np_enc, n]) + body)


def service_key(tod, digs, **kw):
    return A.tlv(CON, True, 10, digits(4, tod, digs, **kw))


def oli(v):
    return A.tlv(PRI, False, 69, bytes([v]))


def billing(b):
    return A.tlv(PRI, False, 65, b)


def pi_arg(called, dig, o=None, order=(0, 1, 2)):
    parts = [called, dig, oli(0) if o is None else o]
    return A.pset(*[parts[i] for i in order])


def cc_arg(dig, bill=None, order=(0, 1)):
    parts = [dig, billing(b'\x00\x01\x02\x03') if bill is None else bill]
    return A.pset(*[parts[i] for i in order])


def build():
    clean, malformed = [], []
    tidn = [0x00b00000]

    def tid():
        tidn[0] += 1
        return struct.pack('!I', tidn[0])

    def add(caps, src, dst, tcap, note):
        caps.append((A.frame(src, dst, tcap, len(caps) & 0x0f), note))

    def c(src, dst, tcap, note):
        add(clean, src, dst, tcap, note)

    def m(src, dst, tcap, note):
        add(malformed, src, dst, tcap, note)

    def query(opc, arg, caps=c, note='', src=MSC, dst=HLR, last=True):
        t = tid()
        caps(src, dst, A.package(A.QUERY_PERM, t, [A.invoke((1,), A.opcode_national(opc), arg, last)]), note)
        return t

    # ---- Provide Instruction: the type of digits picks the field (1-4)
    for tod, digs in ((0, '2015550100'), (1, '2015550101'), (2, '7325550199'), (3, '2015550103'),
                      (4, '2015559999'), (5, '2015550105'), (6, '2015550123'), (7, '732'),
                      (8, '0288'), (9, '2015550109'), (255, '2015550255')):
        query(PI, pi_arg(service_key(6, '2015550123'), digits(4, tod, digs)),
              note='Provide Instruction, digits of type %d' % tod)
    # the same type of digits in the called party number (ServiceKey)
    for tod, digs in ((2, '7325550199'), (4, '2015559999'), (7, '732'), (8, '0288'), (0, '2015550100')):
        query(PI, pi_arg(service_key(tod, digs), digits(4, 6, '2015550123')),
              note='Provide Instruction, called party digits of type %d' % tod)
    # opcode without the H bit, and as a conversation package
    query(PI_NOH, pi_arg(service_key(6, '2015550123'), digits(4, 2, '7325550199')),
          note='Provide Instruction, opcode 0x0301 (no H bit)')
    t = tid()
    c(MSC, HLR, A.package(A.CONV_PERM, t, [A.invoke((3,), A.opcode_national(PI),
                                                      pi_arg(service_key(6, '2015550123'), digits(4, 2, '7325550199')))]),
      'Provide Instruction in a conversationWithPerm package')

    # ---- encodings, numbering plans, natures of number, number of digits
    for npe, digs, note in ((0x21, '2015550123', 'BCD, ISDN numbering plan'),
                            (0x11, '2015550123', 'BCD, telephony numbering plan'),
                            (0x01, '2015550123', 'BCD, unknown numbering plan'),
                            (0x31, '201', 'BCD, data numbering plan'),
                            (0x41, '2015', 'BCD, telex numbering plan'),
                            (0x51, '20155', 'BCD, maritime numbering plan'),
                            (0x61, '201555', 'BCD, land mobile numbering plan'),
                            (0x71, '2015550', 'BCD, private numbering plan'),
                            (0x81, '2015550', 'BCD, numbering plan 8'),
                            (0xf1, '201555', 'BCD, numbering plan 15'),
                            (0x22, 'ABCDE', 'IA5, 5 characters'),
                            (0x22, '12345', 'IA5, 5 characters, numbering plan 2'),
                            (0x23, '1234', 'encoding 3 (not decoded)'),
                            (0x20, '1234', 'encoding 0 (not decoded)'),
                            (0x2f, '1234', 'encoding 15 (not decoded)')):
        query(CC, cc_arg(digits(4, 4, digs, np_enc=npe)), note='Connection Control, ' + note)
    for nol in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255):
        query(CC, cc_arg(digits(4, 4, '2015550123', nol=nol)), note='Connection Control, nature of number %d' % nol)
    # no digits (number of digits 0, BCD and IA5), 4 octets only
    query(CC, cc_arg(digits(4, 4, '', np_enc=0x21)), note='Connection Control, BCD, zero digits')
    query(CC, cc_arg(digits(4, 4, '', np_enc=0x22)), note='Connection Control, IA5, zero digits')
    # number of digits not the number of digits sent
    query(CC, cc_arg(digits(4, 4, '201555', nod=9)), note='Connection Control, number of digits 9 for 6')
    # the longest digits (9 octets): 5 octets of BCD digits, 5 IA5
    query(CC, cc_arg(digits(4, 4, '9876543210')), note='Connection Control, 10 BCD digits (9 octets)')
    query(CC, cc_arg(digits(4, 7, 'abcde', np_enc=0x22)), note='Connection Control, 5 IA5 characters')

    # ---- ConnectionControl and ProvideInstruction details
    query(CC, cc_arg(digits(4, 4, '2015559999'), order=(1, 0)),
          note='Connection Control, SET in the other order')
    query(CC, cc_arg(digits(4, 4, '2015559999'), bill=billing(b'\xff\xfe\xfd\xfc')),
          note='Connection Control, billing indicators ff fe fd fc')
    query(PI, pi_arg(service_key(6, '2015550123'), digits(4, 2, '7325550199'), order=(2, 1, 0)),
          note='Provide Instruction, SET in reverse order')
    query(PI, pi_arg(service_key(6, '2015550123'), digits(4, 2, '7325550199'), o=oli(0x3d)),
          note='Provide Instruction, OLI 61')
    for v in (0, 1, 2, 3, 4, 5, 6, 7, 8, 20, 24, 27, 29, 30, 31, 32, 34, 52, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
              66, 67, 68, 69, 70, 255):
        query(PI, pi_arg(service_key(6, '2015550123'), digits(4, 2, '7325550199'), o=oli(v)),
              note='Provide Instruction, OLI %d' % v)

    # ---- responses and other transaction structures
    t = query(PI, pi_arg(service_key(6, '2015550123'), digits(4, 2, '7325550199')),
              note='Provide Instruction for the response')
    c(HLR, MSC, A.package(A.RESPONSE, t, [A.invoke((2, 1), A.opcode_national(CC),
                                                    cc_arg(digits(4, 4, '2015559999')))]),
      'Connection Control Connect in a response')
    t = tid()
    c(MSC, HLR, A.package(A.QUERY_PERM, t, [
        A.invoke((1,), A.opcode_national(PI), pi_arg(service_key(6, '2015550123'), digits(4, 2, '7325550199')), last=False),
        A.invoke((2,), A.opcode_national(CC), cc_arg(digits(4, 4, '2015559999')))]),
      'two components in one package (Provide Instruction not last, Connection Control)')
    t = tid()
    c(HLR, MSC, A.package(A.CONV_NOPERM, t, [A.invoke((4, 3), A.opcode_national(CC), cc_arg(digits(4, 4, '2015558888')))]),
      'Connection Control in a conversationWithoutPerm package')

    # ---- malformed: fields cut short, wrong tags, wrong sizes
    ok = digits(4, 2, '7325550199')
    sk = service_key(6, '2015550123')
    cases = [
        ('digits of 3 octets (below the minimum size)', PI, pi_arg(sk, digits(4, 0, '', raw=b'\x02\x00\x21'))),
        ('empty parameter set (mandatory fields missing)', PI, A.pset()),
        ('digits of 12 octets (IA5)', PI, pi_arg(sk, digits(4, 2, '12345678', np_enc=0x22))),
        ('digits of 10 octets (above the maximum size)', PI,
         pi_arg(sk, digits(4, 0, '', raw=bytes([2, 0, 0x21, 6]) + b'\x12\x34\x56\x78\x90\x12'))),
        ('digits of 0 octets', PI, pi_arg(sk, digits(4, 0, '', raw=b''))),
        ('billing indicators of 3 octets', CC, cc_arg(ok, bill=billing(b'\x00\x01\x02'))),
        ('billing indicators of 5 octets', CC, cc_arg(ok, bill=billing(b'\x00\x01\x02\x03\x04'))),
        ('OLI of 0 octets', PI, pi_arg(sk, ok, o=A.tlv(PRI, False, 69, b''))),
        ('OLI of 2 octets', PI, pi_arg(sk, ok, o=A.tlv(PRI, False, 69, b'\x00\x01'))),
        ('ServiceKey with another choice tag', PI, pi_arg(A.tlv(CON, True, 10, A.tlv(CON, False, 5, b'\x02\x00\x21\x02ab')), ok)),
        ('empty ServiceKey', PI, pi_arg(A.tlv(CON, True, 10, b''), ok)),
        ('calledPartyNumber primitive instead of constructed', PI, pi_arg(A.tlv(CON, False, 10, ok), ok)),
        ('unknown tag in the set', PI, A.pset(sk, ok, oli(0), A.tlv(CON, False, 31, b'\x01'))),
        ('digits twice', CC, A.pset(ok, ok, billing(b'\x00\x01\x02\x03'))),
        ('CC without billing indicators', CC, A.pset(ok)),
        ('CC without digits', CC, A.pset(billing(b'\x00\x01\x02\x03'))),
        ('PI without OLI', PI, A.pset(sk, ok)),
        ('PI without called party', PI, A.pset(ok, oli(0))),
        ('PI with a primitive set', PI, A.tlv(PRI, False, 18, ok)),
        ('CC with the wrong class and tag', CC, A.tlv(CON, True, 5, ok)),
        ('CC with a truncated set (length past the end)', CC, A.pset(ok, billing(b'\x00\x01\x02\x03'))[:-3]),
    ]
    for note, opc, arg in cases:
        query(opc, arg, caps=m, note=note)
    return clean, malformed


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    clean, malformed = build()
    A.write_pcap(os.path.join(out, 'lnpdqp-coverage.pcap'), clean)
    A.write_pcap(os.path.join(out, 'lnpdqp-coverage-malformed.pcap'), malformed)
    if os.environ.get('LNPDQP_LIST'):
        for i, (_, note) in enumerate(clean, 1):
            print('%4d %s' % (i, note))
        for i, (_, note) in enumerate(malformed, 1):
            print('M%3d %s' % (i, note))
    print('%d + %d frames' % (len(clean), len(malformed)), file=sys.stderr)


if __name__ == '__main__':
    main()
