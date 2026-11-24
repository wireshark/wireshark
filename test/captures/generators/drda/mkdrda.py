#!/usr/bin/env python3
# Generates test/captures/drda_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DRDA dissector
(packet-drda.c, IBM Distributed Relational Database Architecture).

DRDA runs over TCP; the "drda_tcp" heuristic (enabled by default)
recognises the DSS header (length, magic 0xD0, format, correlation ID,
DDM length = length - 6) and sets DRDA as the conversation dissector.
A DSS carries a DDM command, reply or object: a codepoint and
parameters that are each length, codepoint and data. These captures use
TCP port 446. Passwords and security tokens are filler. Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkdrda.py <output directory>

Writes:
  drda-coverage.pcap            connect, security, database access,
                                prepare/describe, open/continue query,
                                execute immediate/statement, commit and
                                rollback at SQLAM levels 5, 6, 7 and 9,
                                SQLCARD/SQLDARD in every encoding
  drda-coverage-malformed.pcap  the nested collection reproducer, bad
                                lengths, SQLAM 10 descriptors (undecoded
                                parts reported as notes)
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct

from pktlib import TcpConn, pcap
from capgen import read_pcap
from repro import reproducer

PORT = 446

RQSDSS, RPYDSS, OBJDSS, CMNDSS, NORPYDSS = 1, 2, 3, 4, 5
CHAINED, CONTINUE, SAMECORR = 0x40, 0x20, 0x10


def e(s):
    return s.encode('cp500')


def p(cp, data):
    """A DDM parameter (length includes the 4 octet header)."""
    return struct.pack('!HH', 4 + len(data), cp) + data


def dss(cp, params, dsstyp=RQSDSS, corr=1, flags=0):
    ddm = struct.pack('!HH', 4 + len(params), cp) + params
    return struct.pack('!HBBH', 6 + len(ddm), 0xD0, flags | dsstyp, corr) + ddm


def u16(v):
    return struct.pack('!H', v)


def u32(v):
    return struct.pack('!I', v)


def u64(v):
    return struct.pack('!Q', v)


# codepoints
EXTNAM, SRVCLSNM, SRVNAM, SRVRLSLV, MGRLVLLS = 0x115E, 0x1147, 0x116D, 0x115A, 0x1404
AGENT, SQLAM, RDB, SECMGR, CMNTCPIP, CCSIDMGR, UNICODEMGR = 0x1403, 0x2407, 0x240F, 0x1440, 0x1474, 0x14CC, 0x1C08
SECMEC, RDBNAM, USRID, PASSWORD, SECTKN, SECCHKCD, SVRCOD = 0x11A2, 0x2110, 0x11A0, 0x11A1, 0x11DC, 0x11A4, 0x1149
RDBACCCL, TYPDEFNAM, TYPDEFOVR, PRDID, CRRTKN, PRDDTA = 0x210F, 0x002F, 0x0035, 0x112E, 0x2135, 0x2104
CCSIDSBC, CCSIDDBC, CCSIDMBC, CCSIDXML, PKGDFTCST, RDBINTTKN = 0x119C, 0x119D, 0x119E, 0x1913, 0x2125, 0x2103
PKGNAMCSN, PKGNAMCT, PKGNAM, RTNSQLDA, TYPSQLDA, SQLATTR, SQLSTT = 0x2113, 0x2112, 0x210A, 0x2116, 0x2146, 0x2450, 0x2414
QRYBLKSZ, MAXBLKEXT, QRYROWSET, DYNDTAFMT, SMLDTASZ, MEDDTASZ, QRYEXTDTASZ = 0x2114, 0x2141, 0x2156, 0x214B, 0x2136, 0x2137, 0x2134
OUTOVROPT, QRYCLSIMP, QRYBLKFCT, MONITOR, ETIME, RESPKTSZ = 0x2147, 0x215D, 0x215F, 0x1900, 0x1901, 0x1908
QRYPRCTYP, SQLCSRHLD, QRYATTUPD, QRYINSID, RDBCMTOK, OUTEXP = 0x2102, 0x211F, 0x2150, 0x215B, 0x2105, 0x2111
MAXRSLCNT, RSLSETFLG, TRGDFTRT, UOWDSP, RLSCONV, RDBALWUPD = 0x2140, 0x2142, 0x213B, 0x2115, 0x119F, 0x211A
RTNSETSTT, PKTOBJ, PKGSNLST, SQLCARD, SQLDARD = 0x210E, 0x1C04, 0x2139, 0x2408, 0x2411
EXCSAT, EXCSATRD, ACCSEC, ACCSECRD, SECCHK, SECCHKRM = 0x1041, 0x1443, 0x106D, 0x14AC, 0x106E, 0x1219
ACCRDB, ACCRDBRM, PRPSQLSTT, OPNQRY, OPNQRYRM, CNTQRY, ENDQRYRM = 0x2001, 0x2201, 0x200D, 0x200C, 0x2205, 0x2006, 0x220B
EXCSQLIMM, EXCSQLSTT, RDBCMM, ENDUOWRM, RDBRLLBCK, CLSQRY, DSCSQLSTT = 0x200A, 0x200B, 0x200E, 0x220C, 0x200F, 0x2005, 0x2008


class Enc:
    """Encoding of FD:OCA data for one flow."""

    def __init__(self, big=False, sbc='utf-8', mbc='utf-8'):
        self.big, self.sbc, self.mbc = big, sbc, mbc

    def i(self, v, n):
        fmt = {2: 'h', 4: 'i', 8: 'q'}[n]
        return struct.pack(('>' if self.big else '<') + fmt, v)

    def vcs(self, s):
        b = s.encode(self.sbc)
        return u16(len(b)) + b

    def vcm(self, s):
        b = s.encode(self.mbc)
        return u16(len(b)) + b

    def fcs(self, s, n):
        b = s.encode(self.sbc)
        return (b + b' ' * n)[:n] if self.sbc == 'utf-8' else (b + ' '.encode(self.sbc) * n)[:n]


def sqlcard(en, sqlam, code=0, state='00000', null=False, msgs=('',), smsg=''):
    if null:
        return b'\xff'
    b = b'\x00' + en.i(code, 4) + en.fcs(state, 5) + en.fcs('DSNXOTL', 8)
    b += b'\x00'                                    # SQLCAXGRP present
    if sqlam < 7:
        b += en.fcs('SAMPLEDB', 18)
    b += b''.join(en.i(v, 4) for v in (1, 2, 3, 4, 5, 6))
    b += en.fcs('W', 1) + en.fcs(' ', 1) * 10
    if sqlam >= 7:
        b += en.vcs('SAMPLEDB')
    m = b'\xff'.join(x.encode(en.mbc) for x in msgs)
    b += u16(len(m)) + m
    sm = b'\xff'.join(x.encode(en.sbc) for x in smsg) if isinstance(smsg, tuple) else smsg.encode(en.sbc)
    b += u16(len(sm)) + sm
    if sqlam >= 7:
        b += b'\xff'                                # SQLDIAGGRP null
    return b


def sqldhgrp(en, sqlam, null=False):
    if null:
        return b'\xff'
    b = b'\x00' + b''.join(en.i(v, 2) for v in (1, 1, 0, 3, 21, 1))
    if sqlam >= 9:
        b += en.i(2, 2)
    b += en.vcs('SAMPLEDB') + en.vcm('') + en.vcs('DB2INST1')
    return b


def sqludtgrp(en, sqlam, null=False):
    if null:
        return b'\xff'
    b = b'\x00'
    if sqlam > 6:
        b += en.i(1, 4) + en.vcs('SAMPLEDB') + en.vcm('') + en.vcs('APP')
    b += en.vcm('') + en.vcs('MONEY')
    return b


def sqldxgrp(en, sqlam, null=False):
    if null:
        return b'\xff'
    b = b'\x00' + b''.join(en.i(v, 2) for v in (1, 0, 2, 1))
    if sqlam >= 9:
        b += en.i(1, 2) + en.i(0, 2)
    b += en.vcs('SAMPLEDB') + en.vcm('') + en.vcs('E') + en.vcm('') + en.vcs('EMPLOYEE')
    b += en.vcm('') + en.vcs('DB2INST1') + en.vcm('') + en.vcs('EMPNO')
    return b


def sqldagrp(en, sqlam, name, sqltype, length, udt_null=True, dx_null=False, opt_null=False):
    b = en.i(0, 2) + en.i(0, 2)
    b += en.i(length, 8) if sqlam >= 6 else en.i(length, 4)
    b += en.i(sqltype, 2) + u16(1208)
    if sqlam >= 9:
        b += en.i(0, 8)
    if sqlam >= 7:
        if opt_null:
            b += b'\xff'
        else:
            b += b'\x00' + en.i(0, 2) + en.vcm('') + en.vcs(name) + en.vcm('') + en.vcs('Label') + \
                en.vcm('comment') + en.vcs('') + sqludtgrp(en, sqlam, udt_null) + sqldxgrp(en, sqlam, dx_null)
    else:
        b += en.vcm('') + en.vcs(name) + en.vcm('') + en.vcs('') + en.vcm('') + en.vcs('')
        if sqlam == 6:
            b += sqludtgrp(en, sqlam, udt_null)
    return b


def sqldard(en, sqlam, cols):
    b = sqlcard(en, sqlam, null=True)
    if sqlam >= 7:
        b += sqldhgrp(en, sqlam)
    b += en.i(len(cols), 2) + b''.join(cols)
    return b


def mgrlvlls(sqlam):
    return b''.join(u16(cp) + u16(lv) for cp, lv in (
        (AGENT, 7), (SQLAM, sqlam), (RDB, 7), (SECMGR, 7), (CMNTCPIP, 5), (CCSIDMGR, 1208), (UNICODEMGR, 1208)))


def pkgnam54():
    return e('SAMPLEDB'.ljust(18)) + e('NULLID'.ljust(18)) + e('SYSSH200'.ljust(18))


def pkgnam_long():
    return u16(24) + e('SAMPLEDB_LONG_NAME'.ljust(24)) + u16(18) + e('NULLID'.ljust(18)) + \
        u16(18) + e('SYSSH200'.ljust(18))


def pkgnamcsn(long=False, sn=1):
    return (pkgnam_long() if long else pkgnam54()) + b'SYSLVL01' + u16(sn)


def connect(c, sqlam, typdefnam, tdn_ebcdic, srv_ccsid, f, ccsid_cli=1208):
    """EXCSAT/ACCSEC chained, EXCSATRD/ACCSECRD, SECCHK/SECCHKRM,
    ACCRDB/ACCRDBRM."""
    excsat = dss(EXCSAT, p(EXTNAM, e('db2jcc_application')) + p(MGRLVLLS, mgrlvlls(sqlam)) +
                 p(SRVCLSNM, e('QDB2/JVM')) + p(SRVNAM, e('client')) + p(SRVRLSLV, e('JCC04330')),
                 RQSDSS, 1, CHAINED)
    accsec = dss(ACCSEC, p(SECMEC, u16(3)) + p(RDBNAM, e('SAMPLEDB'.ljust(18))), RQSDSS, 2)
    f.append(c.send(excsat + accsec))
    f.append(c.send(dss(EXCSATRD, p(EXTNAM, e('db2sysc')) + p(MGRLVLLS, mgrlvlls(sqlam)) +
                        p(SRVCLSNM, e('QDB2/LINUXX8664')) + p(SRVNAM, e('server')) +
                        p(SRVRLSLV, e('SQL11055')), OBJDSS, 1, CHAINED) +
                    dss(ACCSECRD, p(SECMEC, u16(3) + u16(4) + u16(9)) + p(SECCHKCD, b'\x00'), RPYDSS, 2), True))
    f.append(c.send(dss(SECCHK, p(SECMEC, u16(3)) + p(RDBNAM, e('SAMPLEDB'.ljust(18))) +
                        p(USRID, e('db2inst1')) + p(PASSWORD, e('filler')) + p(SECTKN, bytes(range(16))), RQSDSS, 1)))
    f.append(c.send(dss(SECCHKRM, p(SVRCOD, u16(0)) + p(SECCHKCD, b'\x00'), RPYDSS, 1), True))
    tdn = e(typdefnam) if tdn_ebcdic else typdefnam.encode()
    f.append(c.send(dss(ACCRDB, p(RDBNAM, e('SAMPLEDB'.ljust(18))) + p(RDBACCCL, u16(SQLAM)) +
                        p(PRDID, e('JCC04330')) + p(TYPDEFNAM, tdn) +
                        p(TYPDEFOVR, p(CCSIDSBC, u16(ccsid_cli)) + p(CCSIDDBC, u16(1200)) +
                          p(CCSIDMBC, u16(ccsid_cli)) + p(CCSIDXML, u16(1208))) +
                        p(CRRTKN, e('C0A80001.C0A8.012345678901')) + p(PRDDTA, e('JDBC driver')), RQSDSS, 1)))
    f.append(c.send(dss(ACCRDBRM, p(SVRCOD, u16(0)) + p(PRDID, e('SQL11055')) + p(TYPDEFNAM, tdn) +
                        p(TYPDEFOVR, p(CCSIDSBC, u16(srv_ccsid)) + p(CCSIDDBC, u16(1200)) +
                          p(CCSIDMBC, u16(1208)) + p(CCSIDXML, u16(1208))) +
                        p(PKGDFTCST, u16(0x2432)) + p(RDBINTTKN, bytes(8)) + p(RDBALWUPD, b'\xf1') +
                        p(CRRTKN, e('C0A80001.C0A8.012345678901')), RPYDSS, 1), True))


def conv_sqlam7(f):
    """SQLAM 7, Intel types (EBCDIC TYPDEFNAM), UTF-8: prepare, describe,
    queries, immediate and prepared statements, commit, rollback."""
    c = TcpConn(41800, PORT)
    connect(c, 7, 'QTDSQLX86', True, 1208, f)
    en = Enc(False)
    # PRPSQLSTT chained with SQLATTR and SQLSTT objects (no-null form)
    stmt = b'SELECT EMPNO, SALARY FROM EMPLOYEE'
    f.append(c.send(dss(PRPSQLSTT, p(PKGNAMCSN, pkgnamcsn()) + p(RTNSQLDA, b'\xf1') + p(TYPSQLDA, b'\x04'),
                        RQSDSS, 1, CHAINED | SAMECORR) +
                    dss(SQLATTR, (b'\x00' + u32(14) + b'FOR READ ONLY ' + b'\xff'), OBJDSS, 1,
                        CHAINED | SAMECORR) +
                    dss(SQLSTT, (b'\x00' + u32(len(stmt)) + stmt + b'\xff'), OBJDSS, 1)))
    cols = [sqldagrp(en, 7, 'EMPNO', 452, 6, udt_null=True, dx_null=False),
            sqldagrp(en, 7, 'SALARY', 485, 9, udt_null=False, dx_null=True),
            sqldagrp(en, 7, 'X', 497, 4, opt_null=True)]
    f.append(c.send(dss(SQLDARD, (sqldard(en, 7, cols)), OBJDSS, 1), True))
    # DSCSQLSTT, and a SQLDARD with an empty SQLDHGRP
    f.append(c.send(dss(DSCSQLSTT, p(PKGNAMCSN, pkgnamcsn()) + p(TYPSQLDA, b'\x01'), RQSDSS, 2)))
    f.append(c.send(dss(SQLDARD, (sqlcard(en, 7, null=True) + sqldhgrp(en, 7, True) + en.i(0, 2)),
                        OBJDSS, 2), True))
    # OPNQRY with every query parameter (long PKGNAMCSN form) and MONITOR
    f.append(c.send(dss(OPNQRY, p(PKGNAMCSN, pkgnamcsn(True)) + p(QRYBLKSZ, u32(65535)) +
                        p(MAXBLKEXT, u16(0xffff)) + p(QRYROWSET, u32(64)) + p(DYNDTAFMT, b'\xf1') +
                        p(SMLDTASZ, u64(32767)) + p(MEDDTASZ, u64(1048576)) +
                        p(QRYEXTDTASZ, u64(0xffffffffffffffff)) + p(OUTOVROPT, b'\x01') +
                        p(QRYCLSIMP, b'\x01') + p(QRYBLKFCT, u32(1)) + p(MONITOR, u32(0x80000000)), RQSDSS, 3)))
    f.append(c.send(dss(OPNQRYRM, p(SVRCOD, u16(0)) + p(QRYPRCTYP, u16(0x2419)) + p(SQLCSRHLD, b'\xf0') +
                        p(QRYATTUPD, b'\x01') + p(QRYINSID, bytes(8)) + p(ETIME, u64(1234)) +
                        p(RESPKTSZ, u32(4096)), RPYDSS, 3), True))
    # CNTQRY, ENDQRYRM with an SQLCARD (+100 not found, two messages)
    f.append(c.send(dss(CNTQRY, p(PKGNAMCSN, pkgnamcsn()) + p(QRYBLKSZ, u32(65535)) + p(QRYINSID, bytes(8)) +
                        p(QRYROWSET, u32(64)) + p(OUTOVROPT, b'\x02'), RQSDSS, 4)))
    f.append(c.send(dss(ENDQRYRM, p(SVRCOD, u16(4)), RPYDSS, 4, CHAINED | SAMECORR) +
                    dss(SQLCARD, (sqlcard(en, 7, 100, '02000', msgs=('row', 'not found'), smsg='end')),
                        OBJDSS, 4), True))
    # CLSQRY
    f.append(c.send(dss(CLSQRY, p(PKGNAMCSN, pkgnamcsn()) + p(QRYINSID, bytes(8)), RQSDSS, 5)))
    f.append(c.send(dss(SQLCARD, (sqlcard(en, 7, null=True)), OBJDSS, 5), True))
    # EXCSQLIMM with an SQLSTT object (variable length form), an error
    stmt = 'DELETE FROM T WHERE ID = 1'.encode()
    f.append(c.send(dss(EXCSQLIMM, p(PKGNAMCSN, pkgnamcsn(sn=2)) + p(RDBCMTOK, b'\xf1'), RQSDSS, 6,
                        CHAINED | SAMECORR) +
                    dss(SQLSTT, (u16(len(stmt)) + stmt + u16(0)), OBJDSS, 6)))
    f.append(c.send(dss(SQLCARD, (sqlcard(en, 7, -204, '42704', msgs=('T',), smsg='DB2INST1.T'))
                        , OBJDSS, 6), True))
    # EXCSQLSTT with result set parameters, reply
    f.append(c.send(dss(EXCSQLSTT, p(PKGNAMCSN, pkgnamcsn(sn=3)) + p(OUTEXP, b'\xf1') + p(MAXRSLCNT, u16(0xffff)) +
                        p(RSLSETFLG, u32(0x50000000)) + p(RTNSETSTT, b'\xf1') + p(TRGDFTRT, b'\xf1') +
                        p(PKGNAMCT, pkgnam54() + b'SYSLVL01'), RQSDSS, 7)))
    f.append(c.send(dss(SQLCARD, (sqlcard(en, 7, 0, '00000', smsg=('tok1', 'tok2'))), OBJDSS, 7), True))
    # RDBCMM, ENDUOWRM; RDBRLLBCK
    f.append(c.send(dss(RDBCMM, b'', RQSDSS, 8)))
    f.append(c.send(dss(ENDUOWRM, p(SVRCOD, u16(4)) + p(UOWDSP, b'\x01') + p(RDBNAM, e('SAMPLEDB'.ljust(18))) +
                        p(RLSCONV, b'\xf2'), RPYDSS, 8, CHAINED | SAMECORR) +
                    dss(SQLCARD, (sqlcard(en, 7, null=True)), OBJDSS, 8), True))
    f.append(c.send(dss(RDBRLLBCK, b'', RQSDSS, 9)))
    # nested collections: TYPDEFOVR in a PKGSNLST in a TYPDEFOVR
    f.append(c.send(dss(0x2004, p(TYPDEFOVR, p(PKGSNLST, p(TYPDEFOVR, p(CCSIDSBC, u16(819))) +
                                               p(0x7777, b'zz'))) + p(PKTOBJ, b'\x01\x02'), RQSDSS, 10)))
    # an unknown command with a parameter of length 0 (the rest of the
    # DSS) and a NORPYDSS
    f.append(c.send(dss(0x7ABC, struct.pack('!HH', 0, 0x7ABD) + b'opaque', NORPYDSS, 11)))
    # a DSS split over two segments, then two DSS in one segment
    big = dss(EXCSQLIMM, p(PKGNAMCSN, pkgnamcsn(sn=4)) + p(RDBCMTOK, b'\xf0'), RQSDSS, 12)
    f.append(c.send(big[:20]))
    f.append(c.send(big[20:]))
    f.append(c.send(dss(SQLCARD, (sqlcard(en, 7, null=True)), OBJDSS, 12) +
                    dss(SQLCARD, (sqlcard(en, 7, null=True)), OBJDSS, 13), True))


def conv_other(f, cport, sqlam, typdefnam, srv_ccsid, big, sbc):
    """A shorter session at another SQLAM level and encoding: prepare
    with an SQLDARD and an execute with an SQLCARD."""
    c = TcpConn(cport, PORT)
    connect(c, sqlam, typdefnam, False, srv_ccsid, f, ccsid_cli=srv_ccsid)
    en = Enc(big, sbc, 'utf-8')
    f.append(c.send(dss(PRPSQLSTT, p(PKGNAMCSN, pkgnamcsn()) + p(RTNSQLDA, b'\xf1'), RQSDSS, 1,
                        CHAINED | SAMECORR) +
                    dss(SQLSTT, (b'\x00' + u32(8) + 'VALUES 1'.encode(sbc) + b'\xff'), OBJDSS, 1)))
    cols = [sqldagrp(en, sqlam, 'C1', 496, 4, udt_null=False), sqldagrp(en, sqlam, 'C2', 449, 10)]
    f.append(c.send(dss(SQLDARD, (sqldard(en, sqlam, cols)), OBJDSS, 1), True))
    f.append(c.send(dss(EXCSQLSTT, p(PKGNAMCSN, pkgnamcsn()), RQSDSS, 2)))
    f.append(c.send(dss(SQLCARD, (sqlcard(en, sqlam, -803, '23505', msgs=('dup',), smsg='k')),
                        OBJDSS, 2), True))


def conv_mid(f):
    """Sessions captured from the middle: the first DSS seen is an
    EXCSATRD, an RPYDSS or an OBJDSS from the server (direction found
    from the command, the DSS type, or not at all); client CCSIDs that
    map to other encodings; a segment that is not DRDA."""
    c = TcpConn(41805, PORT)
    f.append(c.send(dss(EXCSATRD, p(EXTNAM, e('db2sysc')) + p(MGRLVLLS, mgrlvlls(7)), OBJDSS, 1), True))
    c = TcpConn(41806, PORT)
    f.append(c.send(dss(SECCHKRM, p(SVRCOD, u16(8)) + p(SECCHKCD, b'\x0f'), RPYDSS, 1), True))
    c = TcpConn(41807, PORT)
    f.append(c.send(dss(SQLCARD, sqlcard(Enc(), 7, null=True), OBJDSS, 1), True))
    for i, (sbc, mbc) in enumerate(((850, 1200), (1202, 1252))):
        c = TcpConn(41808 + i, PORT)
        f.append(c.send(dss(ACCRDB, p(RDBNAM, e('SAMPLEDB'.ljust(18))) + p(TYPDEFNAM, b'QTDSQLX86') +
                            p(TYPDEFOVR, p(CCSIDSBC, u16(sbc)) + p(CCSIDMBC, u16(mbc))), RQSDSS, 1)))
    # an SQLSTT with a null mixed part and a single byte statement
    stmt = 'COMMIT'.encode('utf-16-le')   # the single byte CCSID of this session is 1202
    f.append(c.send(dss(EXCSQLIMM, p(PKGNAMCSN, pkgnamcsn()), RQSDSS, 2, CHAINED | SAMECORR) +
                    dss(SQLSTT, b'\xff' + b'\x00' + u32(len(stmt)) + stmt, OBJDSS, 2)))
    f.append(TcpConn(41820, PORT).send(b'GET / HTTP/1.0\r\n\r\n'))


def main_frames():
    f = []
    conv_sqlam7(f)
    conv_mid(f)
    conv_other(f, 41801, 5, 'QTDSQL370', 500, True, 'cp500')
    conv_other(f, 41802, 6, 'QTDSQL400', 37, True, 'cp037')
    conv_other(f, 41803, 9, 'QTDSQLASC', 819, True, 'latin-1')
    conv_other(f, 41804, 7, 'QTDSQLVAX', 367, False, 'ascii')
    return f


def malformed_frames():
    f = []
    # the reproducer: nested TYPDEFOVR parameters (drda_collection_recursion.py)
    f.append(read_pcap(reproducer(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                               'drda_collection_recursion.py'),
                                  'drda_collection_recursion.pcap'))[0])
    c = TcpConn(41810, PORT)
    f.append(c.send(dss(EXCSQLIMM, struct.pack('!HH', 3, 0x2113) + b'xx', RQSDSS, 1)))   # param length 3
    f.append(c.send(dss(0x2004, p(TYPDEFOVR, struct.pack('!HH', 2, CCSIDSBC)), RQSDSS, 2)))
    f.append(c.send(dss(OPNQRY, p(PKGNAM, b'short'), RQSDSS, 3)))
    f.append(c.send(dss(OPNQRY, p(PKGNAM, u16(20) + bytes(20) + u16(10) + bytes(10) + u16(40) + bytes(40)), RQSDSS, 4)))
    f.append(c.send(dss(OPNQRY, p(PKGNAM, u16(20) + bytes(20) + u16(18) + bytes(18) + u16(300) + bytes(40)), RQSDSS, 4)))
    f.append(c.send(dss(OPNQRY, p(PKGNAM, u16(300) + bytes(70)), RQSDSS, 4)))
    f.append(c.send(struct.pack('!HBBHHH', 8, 0xD0, 1, 5, 2, EXCSAT)))   # DSS length below 10
    # SQLAM 10: SQLDARD with module names and the undecoded parts
    c = TcpConn(41811, PORT)
    connect(c, 10, 'QTDSQLX86', False, 1208, f)
    en = Enc(False)
    col = en.i(0, 2) + en.i(0, 2) + en.i(4, 8) + en.i(496, 2) + u16(1208) + en.i(0, 8) + b'\x00\x00' + \
        b'\x00' + en.i(0, 2) + en.vcm('') + en.vcs('C') + en.vcm('') + en.vcs('') + en.vcm('') + en.vcs('') + \
        sqludtgrp(en, 10) + en.vcm('') + en.vcs('MOD') + sqldxgrp(en, 10) + en.vcm('') + en.vcs('MOD') + b'\x00'
    f.append(c.send(dss(SQLDARD, (sqlcard(en, 10, null=True) + sqldhgrp(en, 10) +
                                   en.vcm('') + en.vcs('MOD') + en.i(1, 2) + col), OBJDSS, 1), True))
    f.append(c.send(dss(SQLCARD, (sqlcard(en, 10)[:-1] + b'\x00\x00\x00'), OBJDSS, 2), True))
    # undecoded objects
    f.append(c.send(dss(0x241B, b'\x01\x02', OBJDSS, 3), True))
    return f


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'drda-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'drda-coverage-malformed.pcap'), malformed_frames())
