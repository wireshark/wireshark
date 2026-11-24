#!/usr/bin/env python3
# Generates test/captures/mysql_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic MySQL / MariaDB coverage captures.

Usage: mkmysql.py <outdir>

Writes mysql-coverage.pcap (valid traffic) and mysql-coverage-malformed.pcap
(paths only malformed or unusual input reaches).  Every packet is built with
struct; nothing comes from a real network.  The authentication data, the
public key and the TLS ClientHello are made-up placeholder bytes.
"""
import struct
import sys
import os
import zlib

try:
    from compression import zstd as _zstd
except Exception:      # Python < 3.14
    _zstd = None


# ---------------------------------------------------------------- helpers
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Pcap:
    def __init__(self):
        self.pkts = []
        self.ipid = 1

    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)


class Flow:
    """One TCP connection between a client and a server on `sport`."""
    def __init__(self, pcap, cport, sport=3306, cip='192.0.2.1', sip='192.0.2.2'):
        self.pcap = pcap
        self.c = (bytes(map(int, cip.split('.'))), cport, b'\x02\x00\x00\x00\x00\x01')
        self.s = (bytes(map(int, sip.split('.'))), sport, b'\x02\x00\x00\x00\x00\x02')
        self.seq = {True: 1000, False: 5000}

    def seg(self, from_client, payload, flags=0x18):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0)
        pseudo = src[0] + dst[0] + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.pcap.ipid, 0, 64, 6, 0, src[0], dst[0])
        self.pcap.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.pcap.pkts.append(dst[2] + src[2] + b'\x08\x00' + ip + tcp + payload)
        self.seq[from_client] = (seq + len(payload)) & 0xffffffff

    def c2s(self, *pdus):
        self.seg(True, b''.join(pdus))

    def s2c(self, *pdus):
        self.seg(False, b''.join(pdus))

    def split(self, from_client, data, *cuts):
        """Send `data` in several TCP segments cut at the given offsets."""
        last = 0
        for c in list(cuts) + [len(data)]:
            self.seg(from_client, data[last:c])
            last = c


def lenenc(n):
    if n < 251:
        return bytes([n])
    if n < 1 << 16:
        return b'\xfc' + struct.pack('<H', n)
    if n < 1 << 24:
        return b'\xfd' + struct.pack('<I', n)[:3]
    return b'\xfe' + struct.pack('<Q', n)


def lestr_fd(s):
    return b'\xfd' + u24(len(s)) + s


def lestr_fe(s):
    return b'\xfe' + u64(len(s)) + s


def lestr(s):
    if isinstance(s, str):
        s = s.encode()
    return lenenc(len(s)) + s


def cstr(s):
    if isinstance(s, str):
        s = s.encode()
    return s + b'\0'


def pdu(seq, body):
    return struct.pack('<I', len(body))[:3] + bytes([seq & 0xff]) + body


def u16(n): return struct.pack('<H', n)
def u24(n): return struct.pack('<I', n)[:3]
def u32(n): return struct.pack('<I', n)
def u64(n): return struct.pack('<Q', n)


# capability bits
LP, FR, LF, CD, NS, CP, OB, LI, IS, CU, IA, SL, II, TA, RS, SC = [1 << i for i in range(16)]
MS, MR, PM, PA, CA, AL, EP, ST, DE, RM, ZS, QA, MF, CE, VC = [1 << i for i in range(15)]
# MariaDB extended capabilities
M_PR, M_CM, M_BO, M_EM, M_ME, M_BU = 1, 2, 4, 8, 0x10, 0x20

# server status
S_IT, S_AC, S_MU, S_MR, S_BI, S_NI, S_CR, S_LR, S_DR, S_BS, S_MC = [1 << i for i in range(11)]
S_SLOW, S_PSOUT, S_RO, S_SSC = 0x800, 0x1000, 0x2000, 0x4000

# column types
T_DECIMAL, T_TINY, T_SHORT, T_LONG, T_FLOAT, T_DOUBLE, T_NULL, T_TIMESTAMP, T_LONGLONG, \
    T_INT24, T_DATE, T_TIME, T_DATETIME, T_YEAR = range(14)
T_BIT = 0x10
T_JSON, T_NEWDECIMAL, T_ENUM, T_SET, T_TINYBLOB, T_MEDBLOB, T_LONGBLOB, T_BLOB, \
    T_VARSTRING, T_STRING, T_GEOMETRY = 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff

COM_QUIT, COM_INIT_DB, COM_QUERY, COM_FIELD_LIST, COM_CREATE_DB, COM_DROP_DB, COM_REFRESH, \
    COM_SHUTDOWN, COM_STATISTICS, COM_PROCESS_INFO, COM_CONNECT, COM_PROCESS_KILL, COM_DEBUG, \
    COM_PING = range(1, 15)
COM_CHANGE_USER, COM_BINLOG_DUMP, COM_TABLE_DUMP, COM_CONNECT_OUT, COM_REGISTER_SLAVE, \
    COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_SEND_LONG_DATA, COM_STMT_CLOSE, COM_STMT_RESET, \
    COM_SET_OPTION, COM_STMT_FETCH, COM_DAEMON, COM_BINLOG_DUMP_GTID, COM_RESET_CONNECTION, \
    COM_CLONE = range(17, 33)
COM_STMT_BULK_EXECUTE = 250


# ---------------------------------------------------------------- packets
def greeting(version, thread=11, salt1=b'abcdefgh', caps=0, charset=33, status=2, ext=0,
             plugin=b'mysql_native_password', mariadb_ext=None, salt2=b'ijklmnopqrst',
             stop=None):
    """Server greeting; stop = 'salt' or 'caps' ends the packet early."""
    b = b'\x0a' + cstr(version) + u32(thread) + salt1 + b'\0'
    if stop == 'salt':
        return b
    b += u16(caps)
    if stop == 'caps':
        return b
    b += bytes([charset]) + u16(status) + u16(ext) + bytes([len(salt1 + salt2) + 1])
    if mariadb_ext is None:
        b += b'\0' * 10
    else:
        b += b'\0' * 6 + u32(mariadb_ext)
    b += salt2 + b'\0'
    if plugin:
        b += cstr(plugin)
    return b


def connattrs(items):
    body = b''.join(lestr(k) + lestr(v) for k, v in items)
    return lenenc(len(body)) + body


def login(caps, ext=0, user=b'alice', auth=b'\x01' * 20, db=None, plugin=None, attrs=None,
          collation=33, mariadb_ext=None, max_packet=0x1000000, zstd_level=None, pw_mode=None):
    """Handshake response.  caps is the low 16 bit word, ext the high one."""
    b = u16(caps)
    if caps & CU:
        b += u16(ext) + u32(max_packet) + bytes([collation])
        if mariadb_ext is not None:
            b += b'\0' * 19 + u32(mariadb_ext)
        else:
            b += b'\0' * 23
    else:
        b += u24(max_packet)
    b += cstr(user)
    if pw_mode is None:
        pw_mode = 'lenenc' if caps & CP else ('len8' if caps & SC else 'cstr')
    if pw_mode == 'lenenc':
        b += lenenc(len(auth)) + auth
    elif pw_mode == 'len8':
        b += bytes([len(auth)]) + auth
    else:
        b += cstr(auth)
    if caps & CD and db is not None:
        b += cstr(db)
    if ext & PA and plugin is not None:
        b += cstr(plugin)
    if ext & CA and attrs is not None:
        b += connattrs(attrs)
    if ext & ZS and zstd_level is not None:
        b += bytes([zstd_level])
    return b


def ssl_request(caps, ext, collation=33):
    return u16(caps) + u16(ext) + u32(0x1000000) + bytes([collation]) + b'\0' * 23


def ok(affected=0, insert_id=0, status=2, warnings=0, msg=b'', st=False, track=None, hdr=0):
    b = bytes([hdr]) + lenenc(affected) + lenenc(insert_id) + u16(status) + u16(warnings)
    if st:
        b += lenenc(len(msg)) + msg
        if status & S_SSC:
            b += lenenc(len(track or b'')) + (track or b'')
    else:
        b += msg
    return b


def eof(warnings=0, status=2):
    return b'\xfe' + u16(warnings) + u16(status)


def err(code, msg, sqlstate=b'HY000'):
    b = b'\xff' + u16(code)
    if sqlstate:
        b += b'#' + sqlstate
    return b + msg


DEFEXT = [None]


def fielddef(name, ftype, flags=0, table=b't1', db=b'test', charset=33, length=11, decimals=0,
             lf=True, cu=True, ext=-1, org_name=None, org_table=None):
    if ext == -1:
        ext = DEFEXT[0]
    if cu:
        b = lestr('def') + lestr(db) + lestr(table) + lestr(org_table or table) + lestr(name) + \
            lestr(org_name or name)
        if ext is not None:
            body = b''.join(bytes([k]) + lestr(v) for k, v in ext)
            b += lenenc(len(body)) + body
        b += b'\x0c' + u16(charset) + u32(length) + bytes([ftype])
        b += (u16(flags) if lf else bytes([flags & 0xff])) + bytes([decimals]) + b'\0\0'
        return b
    # pre 4.1: table, name, length (lenenc number of bytes + bytes), type, flags
    b = lestr(table) + lestr(name)
    b += b'\x03' + u24(length) + b'\x01' + bytes([ftype]) + b'\x02'
    b += (u16(flags) if lf else bytes([flags & 0xff])) + bytes([decimals])
    return b


def textrow(*vals):
    b = b''
    for v in vals:
        b += b'\xfb' if v is None else lestr(v)
    return b


def binrow(types, vals):
    """vals: list of bytes (already encoded) or None for NULL"""
    n = len(types)
    nb = bytearray((n + 9) // 8)
    body = b''
    for i, v in enumerate(vals):
        if v is None:
            nb[(i + 2) // 8] |= 1 << ((i + 2) % 8)
        else:
            body += v
    return b'\x00' + bytes(nb) + body


def prepare_ok(stmt_id, ncols, nparams, warnings=0, short=False):
    b = b'\x00' + u32(stmt_id) + u16(ncols) + u16(nparams)
    if not short:
        b += b'\0' + u16(warnings)
    return b


def datetime_val(y=2024, mo=11, d=7, h=13, mi=14, s=15, us=None, n=None):
    if n is None:
        n = 4 if h is None else (11 if us is not None else 7)
    b = struct.pack('<HBB', y, mo, d)
    if n >= 7:
        b += bytes([h, mi, s])
    if n >= 11:
        b += u32(us or 0)
    return bytes([n]) + (b[:{0: 0, 2: 2, 4: 4, 7: 7, 11: 11}[n]]) if n else b'\0'


def time_val(neg=0, days=1, h=2, mi=3, s=4, us=None, n=8):
    b = bytes([neg]) + u32(days) + bytes([h, mi, s])
    if n >= 12:
        b += u32(us or 0)
    return bytes([n]) + b[:n]


class Conn:
    """Packet builder with sequence numbers for one direction pair."""
    pass


# command packet builders (client side), sequence number always 0
def cmd(code, body=b''):
    return pdu(0, bytes([code]) + body)


def exec_params(types, vals, nulls=None, names=None, bound=1):
    """null bitmap + bound flag + types (+names) + values for COM_STMT_EXECUTE."""
    n = len(types)
    nb = bytearray((n + 7) // 8)
    for i in (nulls or []):
        nb[i // 8] |= 1 << (i % 8)
    b = bytes(nb) + bytes([bound])
    if bound:
        for i, t in enumerate(types):
            if isinstance(t, tuple):
                tt, fl = t
            else:
                tt, fl = t, 0
            b += bytes([tt, fl])
            if names is not None:
                b += lestr(names[i])
        for v in vals:
            b += v
    return b


def val_string(s):
    return lestr(s)


# ---------------------------------------------------------------- captures
def build_main(pc):
    port = [50000]

    def flow(sport=3306):
        port[0] += 1
        return Flow(pc, port[0], sport)

    # ============ S1: MySQL 5.7 style: no DEPRECATE_EOF, no SESSION_TRACK ============
    f = flow()
    srv_caps = LP | FR | LF | CD | IS | CU | TA | SC | CP & 0
    f.s2c(pdu(0, greeting(b'5.7.30-log', thread=7, caps=srv_caps, status=S_AC, ext=MS | MR | PM | PA | CA | AL | EP,
                          plugin=b'mysql_native_password')))
    # login: CP bit (0x20) in the low caps makes the dissector read a lenenc password
    f.c2s(pdu(1, login(LP | FR | LF | CD | CU | TA | SC | CP, MS | MR | PM | PA | CA | EP,
                       user=b'alice', auth=b'\x11' * 20, db=b'test', plugin=b'mysql_native_password',
                       attrs=[(b'_client_name', b'libmysql'), (b'_os', b'Linux'), (b'program_name', b'mysql')],
                       collation=45)))
    f.s2c(pdu(2, ok(0, 0, S_AC, 0)))
    # COM_INIT_DB
    f.c2s(cmd(COM_INIT_DB, b'test'))
    f.s2c(pdu(1, ok(0, 0, S_AC, 0, b'Database changed')))
    # COM_QUERY with a text result set (EOF terminated), several collations
    f.c2s(cmd(COM_QUERY, b'SELECT id, name, price, blobcol, note FROM t1'))
    cols = [fielddef(b'id', T_LONG, 0x4003, length=11),
            fielddef(b'name', T_VARSTRING, 0x1, charset=8, length=255),
            fielddef(b'price', T_NEWDECIMAL, 0x20, charset=63, length=12, decimals=2),
            fielddef(b'blobcol', T_BLOB, 0x90, charset=63, length=65535),
            fielddef(b'note', T_VARSTRING, 0, charset=28, length=100)]
    f.s2c(pdu(1, lenenc(5)))
    f.s2c(*[pdu(2 + i, c) for i, c in enumerate(cols)])
    f.s2c(pdu(7, eof(0, S_AC)))
    f.s2c(pdu(8, textrow(b'1', b'caf\xe9', b'9.99', b'\x00\x01\x02', b'ab')),
          pdu(9, textrow(b'2', None, b'0.50', b'', None)))
    f.s2c(pdu(10, b'\x00\x00\x00\x00\x00'))  # a row of empty strings: starts with 0x00
    f.s2c(pdu(11, eof(1, S_AC)))
    # result header with an extra value after the column count
    f.c2s(cmd(COM_QUERY, b'SELECT 1'))
    f.s2c(pdu(1, lenenc(1) + lenenc(77)), pdu(2, fielddef(b'1', T_LONGLONG, charset=999)), pdu(3, eof()))
    f.s2c(pdu(4, textrow(b'1')), pdu(5, eof()))
    # field with a collation of a character set the dissector has no encoding for
    f.c2s(cmd(COM_QUERY, b'SELECT c FROM cp'))
    f.s2c(pdu(1, lenenc(1)), pdu(2, fielddef(b'c', T_VARSTRING, charset=13)), pdu(3, eof()))
    f.s2c(pdu(4, textrow(b'cp1251')), pdu(5, eof()))
    # long row split across TCP segments (reassembly)
    f.c2s(cmd(COM_QUERY, b'SELECT * FROM t1 WHERE id = 3'))
    f.s2c(pdu(1, lenenc(2)), pdu(2, fielddef(b'a', T_VARSTRING)), pdu(3, fielddef(b'b', T_VARSTRING)),
          pdu(4, eof()))
    big = pdu(5, textrow(b'x' * 3000, b'y' * 1500))
    f.split(False, big + pdu(6, eof()), 1000, 2500)
    # query error, error without sqlstate marker
    f.c2s(cmd(COM_QUERY, b'SELECT * FROM nosuchtable'))
    f.s2c(pdu(1, err(1146, b"Table 'test.nosuchtable' doesn't exist", b'42S02')))
    f.c2s(cmd(COM_QUERY, b'BAD'))
    f.s2c(pdu(1, err(1064, b'You have an error in your SQL syntax', sqlstate=None)))
    # QUERY ok with message, affected rows, insert id, warnings
    f.c2s(cmd(COM_QUERY, b"INSERT INTO t1 VALUES (1,'a')"))
    f.s2c(pdu(1, ok(1, 300, S_AC | S_MR, 2, b'Records: 1  Duplicates: 0')))
    # query with a zero length text result (column count then EOF only)
    # COM_FIELD_LIST
    f.c2s(cmd(COM_FIELD_LIST, b't1\0'))
    f.s2c(pdu(1, fielddef(b'id', T_LONG, 0x4003) + lestr(b'0')))
    f.s2c(pdu(2, fielddef(b'name', T_VARSTRING, 0x1)))
    f.s2c(pdu(3, eof()))
    # COM_STATISTICS (message response)
    f.c2s(cmd(COM_STATISTICS))
    f.s2c(pdu(1, b'Uptime: 100  Threads: 1  Questions: 5  Slow queries: 0'))
    # simple ones answered with OK
    for c, body in ((COM_PING, b''), (COM_DEBUG, b''), (COM_CREATE_DB, b'newdb'), (COM_DROP_DB, b'newdb'),
                    (COM_PROCESS_KILL, u32(9)), (COM_REFRESH, bytes([0xff])), (COM_REFRESH, bytes([0x0f])),
                    (COM_SHUTDOWN, bytes([1])), (COM_SET_OPTION, u16(1)), (COM_SET_OPTION, u16(0)),
                    (COM_INIT_DB, b'other')):
        f.c2s(cmd(c, body))
        f.s2c(pdu(1, ok(0, 0, S_AC)))
    # COM_PROCESS_INFO: text result
    f.c2s(cmd(COM_PROCESS_INFO))
    f.s2c(pdu(1, lenenc(2)), pdu(2, fielddef(b'Id', T_LONGLONG, 0x21)), pdu(3, fielddef(b'User', T_VARSTRING)),
          pdu(4, eof()), pdu(5, textrow(b'7', b'alice')), pdu(6, eof()))
    # replication commands the dissector only partly decodes
    f.c2s(cmd(COM_TABLE_DUMP, b'\x02db\x02t1'))
    f.s2c(pdu(1, ok()))
    f.c2s(cmd(COM_CONNECT_OUT, b'\x01\x02'))
    f.s2c(pdu(1, ok()))
    f.c2s(cmd(COM_REGISTER_SLAVE, u32(100) + b'\x05slave' + b'\x04repl' + b'\x06secret' + u16(3307) +
              u32(0) + u32(0)))
    f.s2c(pdu(1, ok()))
    # COM_CHANGE_USER (lenenc password: CP set, collation, plugin, attributes)
    f.c2s(cmd(COM_CHANGE_USER, cstr(b'bob') + lenenc(20) + b'\x22' * 20 + cstr(b'test2') + u16(33) +
              cstr(b'mysql_native_password') + connattrs([(b'_pid', b'1234')])))
    f.s2c(pdu(1, ok()))
    # COM_RESET_CONNECTION, unknown command, COM_STMT_CLOSE without a statement
    f.c2s(cmd(COM_RESET_CONNECTION))
    f.s2c(pdu(1, ok()))
    f.c2s(cmd(0x7f, b'\x01\x02\x03'))
    f.s2c(pdu(1, err(1047, b'Unknown command', b'08S01')))
    f.c2s(cmd(COM_STMT_CLOSE, u32(99)))
    # LOAD DATA LOCAL INFILE
    f.c2s(cmd(COM_QUERY, b"LOAD DATA LOCAL INFILE '/tmp/x.csv' INTO TABLE t1"))
    f.s2c(pdu(1, b'\xfb/tmp/x.csv'))
    f.c2s(pdu(2, b'1,a\n2,b\n'))
    f.c2s(pdu(3, b''))
    f.s2c(pdu(4, ok(2, 0, S_AC, 0, b'Records: 2')))

    # ---- prepared statements (binary protocol), MySQL 5.7 style (EOF packets) ----
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT a, b FROM t1 WHERE c = ? AND d = ?'))
    f.s2c(pdu(1, prepare_ok(1, 2, 2)))
    f.s2c(pdu(2, fielddef(b'?', T_VARSTRING)), pdu(3, fielddef(b'?', T_LONG)), pdu(4, eof()))
    f.s2c(pdu(5, fielddef(b'a', T_LONG)), pdu(6, fielddef(b'b', T_DOUBLE)), pdu(7, eof()))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1) +
              exec_params([T_VARSTRING, T_LONG], [val_string(b'abc'), u32(42)])))
    f.s2c(pdu(1, lenenc(2)), pdu(2, fielddef(b'a', T_LONG)), pdu(3, fielddef(b'b', T_DOUBLE)), pdu(4, eof()))
    f.s2c(pdu(5, binrow([T_LONG, T_DOUBLE], [u32(7), struct.pack('<d', 1.5)])),
          pdu(6, binrow([T_LONG, T_DOUBLE], [None, struct.pack('<d', 2.5)])),
          pdu(7, binrow([T_LONG, T_DOUBLE], [u32(9), None])))
    f.s2c(pdu(8, eof()))
    # execute again, parameters not re-bound, one NULL parameter
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1) +
              exec_params([T_VARSTRING, T_LONG], [], nulls=[1], bound=0)))
    f.s2c(pdu(1, lenenc(2)), pdu(2, fielddef(b'a', T_LONG)), pdu(3, fielddef(b'b', T_DOUBLE)), pdu(4, eof()))
    f.s2c(pdu(5, binrow([T_LONG, T_DOUBLE], [u32(1), None])), pdu(6, eof()))
    # statement with no result columns and one parameter, OK reply to the execute
    f.c2s(cmd(COM_STMT_PREPARE, b'INSERT INTO t1 VALUES (?)'))
    f.s2c(pdu(1, prepare_ok(2, 0, 1)))
    f.s2c(pdu(2, fielddef(b'?', T_LONG)), pdu(3, eof()))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(2) + b'\x00' + u32(1) +
              exec_params([(T_LONGLONG, 0x80)], [u64(2 ** 40)])))
    f.s2c(pdu(1, ok(1, 5, S_AC)))
    # statement with no parameters and no columns
    f.c2s(cmd(COM_STMT_PREPARE, b'COMMIT'))
    f.s2c(pdu(1, prepare_ok(3, 0, 0)))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(3) + b'\x00' + u32(1)))
    f.s2c(pdu(1, ok()))
    # statement with columns only
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT 1, 2'))
    f.s2c(pdu(1, prepare_ok(4, 2, 0, short=True)))
    f.s2c(pdu(2, fielddef(b'1', T_LONGLONG)), pdu(3, fielddef(b'2', T_LONGLONG, 0x20)), pdu(4, eof()))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(4) + b'\x00' + u32(1)))
    f.s2c(pdu(1, lenenc(2)), pdu(2, fielddef(b'1', T_LONGLONG)), pdu(3, fielddef(b'2', T_LONGLONG, 0x20)),
          pdu(4, eof()))
    f.s2c(pdu(5, binrow([T_LONGLONG, T_LONGLONG], [u64(1), u64(2 ** 63)])), pdu(6, eof()))
    # cursor: COM_STMT_FETCH
    f.c2s(cmd(COM_STMT_FETCH, u32(4) + u32(10)))
    f.s2c(pdu(1, eof(0, S_AC | S_LR)))
    f.c2s(cmd(COM_STMT_RESET, u32(4)))
    f.s2c(pdu(1, ok()))
    f.c2s(cmd(COM_STMT_CLOSE, u32(4)))
    # statement using every parameter type; COM_STMT_SEND_LONG_DATA for the second one
    ptypes = [T_TINY, (T_TINY, 0x80), T_SHORT, (T_SHORT, 0x80), T_LONG, (T_LONG, 0x80), T_LONGLONG,
              (T_LONGLONG, 0x80), T_FLOAT, T_DOUBLE, T_NULL, T_TIMESTAMP, T_DATE, T_DATETIME, T_TIME,
              T_YEAR, T_INT24, (T_BIT, 0x80), T_JSON, T_NEWDECIMAL, T_BLOB, T_VARSTRING, T_STRING,
              T_GEOMETRY]
    n = len(ptypes)
    f.c2s(cmd(COM_STMT_PREPARE, b'INSERT INTO alltypes VALUES (' + b','.join([b'?'] * n) + b')'))
    f.s2c(pdu(1, prepare_ok(5, 0, n)))
    f.s2c(*[pdu(2 + i, fielddef(b'?', T_VARSTRING)) for i in range(n)], pdu(2 + n, eof()))
    pvals = [bytes([0xfe]), bytes([0xff]), u16(0xfffe), u16(0xffff), u32(0x7fffffff), u32(0xffffffff),
             u64(2 ** 62), u64(2 ** 64 - 1), struct.pack('<f', 3.25), struct.pack('<d', 6.5), b'',
             datetime_val(), datetime_val(h=None, n=4), datetime_val(us=123456), time_val(1, 3, 4, 5, 6),
             u16(2024), u32(77), lestr(b'\x05'), lestr(b'{"a": [1, 2, {"b": null}], "c": "x"}'),
             lestr(b'12345.67'), lestr(b'\x89PNG\x00'), lestr(b'varstr'), lestr(b'str'), lestr(b'\x00\x00\x00\x00')]
    pvals[12] = datetime_val(2024, 1, 2, 0, 0, 0, n=4)
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(5) + b'\x00' + u32(1) + exec_params(ptypes, pvals, nulls=[10])))
    f.s2c(pdu(1, ok(1)))
    # one more with the short date/time forms and a zero length time
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT ?, ?, ?, ?'))
    f.s2c(pdu(1, prepare_ok(6, 0, 4)))
    f.s2c(pdu(2, fielddef(b'?', T_VARSTRING)), pdu(3, fielddef(b'?', T_VARSTRING)),
          pdu(4, fielddef(b'?', T_VARSTRING)), pdu(5, fielddef(b'?', T_VARSTRING)), pdu(6, eof()))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(6) + b'\x00' + u32(1) +
              exec_params([T_DATETIME, T_TIME, T_TIME, T_DATE],
                          [b'\x00', b'\x00', time_val(0, 0, 0, 0, 0, 999, n=12), datetime_val(2000, 2, 29, n=4)])))
    f.s2c(pdu(1, ok()))
    # send long data for a two parameter statement, then execute it: streamed parameter
    f.c2s(cmd(COM_STMT_PREPARE, b'INSERT INTO t2 VALUES (?, ?)'))
    f.s2c(pdu(1, prepare_ok(7, 0, 2)))
    f.s2c(pdu(2, fielddef(b'?', T_VARSTRING)), pdu(3, fielddef(b'?', T_BLOB)), pdu(4, eof()))
    f.c2s(cmd(COM_STMT_SEND_LONG_DATA, u32(7) + u16(1) + b'first chunk of a blob'))
    f.c2s(cmd(COM_STMT_SEND_LONG_DATA, u32(7) + u16(1) + b'second chunk'))
    f.c2s(cmd(COM_STMT_SEND_LONG_DATA, u32(7) + u16(5)))     # parameter out of range, no data
    f.c2s(cmd(COM_STMT_SEND_LONG_DATA, u32(77) + u16(0) + b'unknown statement'))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(7) + b'\x00' + u32(1) +
              exec_params([T_VARSTRING, T_BLOB], [val_string(b'plain')])))
    f.s2c(pdu(1, ok(1)))
    # execute of a statement whose prepare was not captured
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(500) + b'\x00' + u32(1) + b'\x00\x01\x03\x00\x01\x00\x00\x00'))
    f.s2c(pdu(1, ok()))
    # prepare error
    f.c2s(cmd(COM_STMT_PREPARE, b'SELEC'))
    f.s2c(pdu(1, err(1064, b'syntax error', b'42000')))
    # quit
    f.c2s(cmd(COM_QUIT))

    # ============ S2: MySQL 8.0, caching_sha2_password, DEPRECATE_EOF, SESSION_TRACK, QUERY_ATTRIBUTES ============
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=21, caps=LP | FR | LF | CD | IS | CU | TA | SC | SL & 0,
                          status=S_AC, charset=255, plugin=b'caching_sha2_password',
                          ext=MS | MR | PM | PA | CA | AL | EP | ST | DE | RM | ZS & 0 | QA)))
    cext = MS | MR | PM | PA | CA | AL | EP | ST | DE | QA
    f.c2s(pdu(1, login(LP | FR | LF | CD | CU | TA | SC, cext, user=b'carol', auth=b'\x33' * 32, db=b'app',
                       plugin=b'caching_sha2_password', attrs=[(b'_client_name', b'libmysql')], collation=255)))
    f.s2c(pdu(2, b'\x01\x04'))                      # perform_full_authentication
    f.c2s(pdu(3, b'\x02'))                          # request public key
    # a well formed but meaningless SubjectPublicKeyInfo: modulus and exponent are made-up numbers
    import base64
    def der(tag, body):
        n = len(body)
        l = bytes([n]) if n < 128 else (b'\x81' + bytes([n]) if n < 256 else b'\x82' + struct.pack('>H', n))
        return bytes([tag]) + l + body
    rsa = der(0x30, der(2, b'\x00' + b'\xab' * 64) + der(2, b'\x01\x00\x01'))
    spki = der(0x30, der(0x30, der(6, bytes.fromhex('2a864886f70d010101')) + der(5, b'')) + der(3, b'\x00' + rsa))
    b64 = base64.b64encode(spki)
    pem = (b'\x01-----BEGIN PUBLIC KEY-----\n' + b'\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64)) +
           b'\n-----END PUBLIC KEY-----\n')
    f.s2c(pdu(4, pem))
    f.c2s(pdu(5, b'\x44' * 128))                    # encrypted password (placeholder bytes)
    f.s2c(pdu(6, ok(0, 0, S_AC)))
    # OK with session tracking: all tracker types
    trk = b''
    trk += bytes([0]) + lenenc(len(lestr(b'character_set_client')) + len(lestr(b'latin1'))) + \
        lestr(b'character_set_client') + lestr(b'latin1')
    trk += bytes([0]) + lenenc(len(lestr(b'character_set_results')) + len(lestr(b'utf8mb4'))) + \
        lestr(b'character_set_results') + lestr(b'utf8mb4')
    trk += bytes([0]) + lenenc(len(lestr(b'sql_mode')) + len(lestr(b'ANSI'))) + lestr(b'sql_mode') + lestr(b'ANSI')
    trk += bytes([1]) + lenenc(len(lestr(b'app2'))) + lestr(b'app2')
    trk += bytes([2]) + lenenc(1) + b'1'
    trk += bytes([3]) + lenenc(1 + len(lestr(b'uuid:1-5'))) + b'\x00' + lestr(b'uuid:1-5')
    trk += bytes([4]) + lenenc(len(lestr(b'START TRANSACTION'))) + lestr(b'START TRANSACTION')
    trk += bytes([5]) + lenenc(len(lestr(b'T_______'))) + lestr(b'T_______')
    trk += bytes([9]) + lenenc(3) + b'\x01\x02\x03'
    f.c2s(cmd(COM_QUERY, b'\x00\x01' + b'SET NAMES latin1'))
    f.s2c(pdu(1, ok(0, 0, S_AC | S_SSC, 0, b'', st=True, track=trk)))
    # OK with SESSION_TRACK capability but status without the flag, and with an info string
    f.c2s(cmd(COM_QUERY, b'\x00\x01' + b'UPDATE t1 SET a=1'))
    f.s2c(pdu(1, ok(3, 0, S_AC, 0, b'Rows matched: 3  Changed: 3', st=True)))
    f.c2s(cmd(COM_PING))
    f.s2c(pdu(1, ok(0, 0, S_AC, 0, b'', st=True)))
    # COM_CHANGE_USER: one byte password length (CLIENT_SECURE_CONNECTION), no collation, no plugin data
    f.c2s(cmd(COM_CHANGE_USER, cstr(b'carol2') + bytes([20]) + b'\x23' * 20 + cstr(b'app2') + u16(255) +
              cstr(b'caching_sha2_password') + connattrs([(b'_x', b'y')])))
    f.s2c(pdu(1, ok(0, 0, S_AC, 0, b'', st=True)))
    # latin1 result set (charset_results utf8mb4 set above), DEPRECATE_EOF: rows end with an OK packet
    f.c2s(cmd(COM_QUERY, b'\x00\x01' + b'SELECT name FROM t1'))
    f.s2c(pdu(1, lenenc(1)), pdu(2, fielddef(b'name', T_VARSTRING, charset=8)))
    f.s2c(pdu(3, textrow('héllo'.encode('latin1'))), pdu(4, textrow(None)))
    f.s2c(pdu(5, b'\xfe' + lenenc(0) + lenenc(0) + u16(S_AC) + u16(0)))
    # query with attributes: two parameters (a string and an int) with names
    qa = (b'\x02\x01' + b'\x00' + b'\x01' + bytes([T_VARSTRING, 0]) + lestr(b'who') +
          bytes([T_LONG, 0]) + lestr(b'n') + lestr(b'carol') + u32(5))
    f.c2s(cmd(COM_QUERY, qa + b'SELECT ?'))
    f.s2c(pdu(1, ok()))
    # query with attributes: zero parameters
    f.c2s(cmd(COM_QUERY, b'\x00\x01' + b'SELECT 2'))
    f.s2c(pdu(1, ok()))
    # query attribute with an empty name
    f.c2s(cmd(COM_QUERY, b'\x01\x01\x00\x01' + bytes([T_LONG, 0]) + lestr(b'') + u32(1) + b'SELECT 3'))
    f.s2c(pdu(1, ok()))
    # prepared statement over DEPRECATE_EOF with metadata (no EOFs)
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT id, v FROM t3 WHERE k = ? AND n > ?'))
    f.s2c(pdu(1, prepare_ok(1, 2, 2)))
    f.s2c(pdu(2, fielddef(b'k', T_VARSTRING)), pdu(3, fielddef(b'n', T_LONG)))
    f.s2c(pdu(4, fielddef(b'id', T_LONG, 0x4003)), pdu(5, fielddef(b'v', T_JSON, 0x90, charset=63)))
    # execute with a parameter count (flag 8) and names, extra parameter beyond the prepare
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x08' + u32(1) + lenenc(3) +
              exec_params([T_VARSTRING, T_LONG, T_LONG], [val_string(b'key'), u32(3), u32(4)],
                          names=[b'k', b'', b'extra'])))
    f.s2c(pdu(1, lenenc(2)), pdu(2, fielddef(b'id', T_LONG, 0x4003)), pdu(3, fielddef(b'v', T_JSON, 0x90, charset=63)))
    f.s2c(pdu(4, binrow([T_LONG, T_JSON], [u32(1), lestr(b'{"k": [true, false, null, 1.5]}')])))
    f.s2c(pdu(5, b'\xfe' + lenenc(0) + lenenc(0) + u16(S_AC) + u16(0)))
    # execute without the count flag
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1) +
              exec_params([T_VARSTRING, T_LONG], [val_string(b'k2'), u32(8)], names=[b'a', b'b'])))
    f.s2c(pdu(1, lenenc(1)), pdu(2, fielddef(b'id', T_LONG, 0x4003)))
    f.s2c(pdu(3, binrow([T_LONG], [None])), pdu(4, b'\xfe' + lenenc(0) + lenenc(0) + u16(S_AC) + u16(0)))
    # a statement whose parameters and columns are all described, then the last prepared id (0xffffffff)
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT 5'))
    f.s2c(pdu(1, prepare_ok(2, 1, 0)))
    f.s2c(pdu(2, fielddef(b'5', T_LONGLONG)))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(0xffffffff) + b'\x00' + u32(1)))
    f.s2c(pdu(1, lenenc(1)), pdu(2, fielddef(b'5', T_LONGLONG)))
    f.s2c(pdu(3, binrow([T_LONGLONG], [u64(5)])), pdu(4, b'\xfe\x00\x00\x02\x00\x00\x00'))
    # character_set_client = binary: string parameters are shown as bytes
    trk2 = bytes([0]) + lenenc(len(lestr(b'character_set_client')) + len(lestr(b'binary'))) + \
        lestr(b'character_set_client') + lestr(b'binary')
    f.c2s(cmd(COM_QUERY, b'\x00\x01' + b'SET character_set_client = binary'))
    f.s2c(pdu(1, ok(0, 0, S_AC | S_SSC, 0, b'', st=True, track=trk2)))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1) +
              exec_params([T_VARSTRING, T_LONG], [val_string(b'\x01\x02bin'), u32(8)], names=[b'a', b'b'])))
    f.s2c(pdu(1, ok()))
    f.c2s(cmd(COM_QUIT))

    # ============ S3: MySQL 8.0, auth switch request (plugin auth) and OK ============
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=22, caps=LP | LF | CD | CU | SC, status=S_AC,
                          ext=PA | CA | AL | DE, plugin=b'caching_sha2_password')))
    f.c2s(pdu(1, login(LP | LF | CD | CU | SC, PA | CA | AL | DE, user=b'dave', auth=b'\x55' * 20, db=b'app',
                       plugin=b'mysql_native_password', attrs=[(b'a', b'b')])))
    f.s2c(pdu(2, b'\xfe' + cstr(b'mysql_clear_password') + cstr(b'salt-for-switch')))
    f.c2s(pdu(3, cstr(b'\x66' * 8)))
    f.s2c(pdu(4, ok()))
    f.c2s(cmd(COM_QUERY, b'SELECT 1'))
    f.s2c(pdu(1, ok()))
    # same, with the caching_sha2_password switch: fast_auth_success then OK; unknown byte
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=23, caps=LP | LF | CD | CU | SC, status=S_AC,
                          ext=PA | CA | AL | DE, plugin=b'caching_sha2_password')))
    f.c2s(pdu(1, login(LP | LF | CD | CU | SC, PA | CA | AL | DE, user=b'erin', auth=b'\x56' * 20, db=b'app',
                       plugin=b'caching_sha2_password')))
    f.s2c(pdu(2, b'\x01\x03'))
    f.s2c(pdu(3, ok()))
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=24, caps=LP | LF | CD | CU | SC, status=S_AC,
                          ext=PA | CA | AL | DE, plugin=b'caching_sha2_password')))
    f.c2s(pdu(1, login(LP | LF | CD | CU | SC, PA | CA | AL | DE, user=b'frank', auth=b'\x57' * 20, db=b'app',
                       plugin=b'caching_sha2_password')))
    f.s2c(pdu(2, b'\x01\x09'))                       # unknown more-data byte
    f.s2c(pdu(3, err(1045, b"Access denied for user 'frank'", b'28000')))
    # switch request, response, then the caching_sha2 exchange in the AUTH_SHA2 state
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=25, caps=LP | LF | CD | CU | SC, status=S_AC,
                          ext=PA | CA | AL | DE, plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(LP | LF | CD | CU | SC, PA | CA | AL | DE, user=b'gina', auth=b'\x58' * 20, db=b'app',
                       plugin=b'mysql_native_password')))
    f.s2c(pdu(2, b'\xfe' + cstr(b'caching_sha2_password') + cstr(b'switchsalt')))
    f.c2s(pdu(3, b'\x59' * 32))                      # response; auth method is caching_sha2_password
    f.s2c(pdu(4, b'\x01\x03'))                       # fast_auth_success
    f.s2c(pdu(5, ok()))
    f.c2s(cmd(COM_QUIT))
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=26, caps=LP | LF | CD | CU | SC, status=S_AC,
                          ext=PA | CA | AL | DE, plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(LP | LF | CD | CU | SC, PA | CA | AL | DE, user=b'hank', auth=b'\x5a' * 20, db=b'app',
                       plugin=b'mysql_native_password')))
    f.s2c(pdu(2, b'\x01' + cstr(b'dualfactor') + cstr(b'xxxxxxxxxxxxxxxxxxxx')))   # longer AuthMoreData
    f.c2s(pdu(3, cstr(b'\x5b' * 8)))
    f.s2c(pdu(4, ok()))
    # login that ends after the user name
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=27, caps=LP | LF | CD | CU | SC, status=S_AC,
                          ext=PA | CA | AL | DE, plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(LP | LF | CU | SC, PA | CA | AL | DE, user=b'nopass', auth=b'')[:-1]))
    f.s2c(pdu(2, ok()))

    # ============ S4: MariaDB: progress, extended metadata, cache metadata, bulk execute ============
    DEFEXT[0] = []
    f = flow()
    mcaps = LF | CD | CU | SC | IS | TA          # no CLIENT_MYSQL (LP): MariaDB
    mext = MS | MR | PM | PA | CA | AL | EP | ST | DE
    mdb = M_PR | M_CM | M_BO | M_EM | M_ME
    f.s2c(pdu(0, greeting(b'5.5.5-10.11.6-MariaDB', thread=31, caps=mcaps, status=S_AC, charset=45,
                          ext=mext, mariadb_ext=mdb, plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(mcaps, mext, user=b'maria', auth=b'\x77' * 20, db=b'mdb', plugin=b'mysql_native_password',
                       attrs=[(b'_client_name', b'libmariadb')], collation=45, mariadb_ext=mdb)))
    f.s2c(pdu(2, ok(0, 0, S_AC)))
    # progress report followed by the OK
    f.c2s(cmd(COM_QUERY, b'ALTER TABLE big ADD INDEX (a)'))
    f.s2c(pdu(1, b'\xff\xff\xff\x01' + bytes([1, 3]) + u24(33333) + lestr(b'Copying to tmp table')))
    f.s2c(pdu(2, b'\xff\xff\xff\x01' + bytes([2, 3]) + u24(100000) + lestr(b'')))
    f.s2c(pdu(3, ok(0, 0, S_AC, 0)))
    # result set with extended metadata (type/format names and an unknown key)
    f.c2s(cmd(COM_QUERY, b'SELECT g, u, j FROM t'))
    f.s2c(pdu(1, lenenc(3) + b'\x01'))                       # column count, send_meta = 1
    f.s2c(pdu(2, fielddef(b'g', T_GEOMETRY, 0x90, charset=63, ext=[(0, b'point')])))
    f.s2c(pdu(3, fielddef(b'u', T_STRING, 0x1, ext=[(0, b'inet6'), (1, b'uuid')])))
    f.s2c(pdu(4, fielddef(b'j', T_BLOB, 0x90, ext=[(1, b'json'), (9, b'unknown')])))
    f.s2c(pdu(5, textrow(b'\x00\x01', b'0123', b'{}')))
    f.s2c(pdu(6, b'\xfe\x00\x00\x02\x00\x00\x00'))
    # prepare, execute with the metadata cached (send_meta = 0): the columns of the prepare are used
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT a, b FROM t WHERE c = ?'))
    f.s2c(pdu(1, prepare_ok(1, 2, 1)))
    f.s2c(pdu(2, fielddef(b'c', T_LONG, ext=[(0, b'int')])))
    f.s2c(pdu(3, fielddef(b'a', T_LONG, 0x4003, ext=[])), pdu(4, fielddef(b'b', T_VARSTRING, ext=[])))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1) +
              exec_params([T_LONG], [u32(10)])))
    f.s2c(pdu(1, lenenc(2) + b'\x00'))
    f.s2c(pdu(2, binrow([T_LONG, T_VARSTRING], [u32(5), lestr(b'five')])))
    f.s2c(pdu(3, b'\xfe\x00\x00\x02\x00\x00\x00'))
    # a statement with cache metadata and send_meta = 1 and an extra value
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1) +
              exec_params([T_LONG], [u32(11)])))
    f.s2c(pdu(1, lenenc(1) + b'\x01'))
    f.s2c(pdu(2, fielddef(b'x', T_LONG, ext=[(0, b'int')])))
    f.s2c(pdu(3, binrow([T_LONG], [u32(1)])), pdu(4, b'\xfe\x00\x00\x02\x00\x00\x00'))
    # bulk execute
    f.c2s(cmd(COM_STMT_PREPARE, b'INSERT INTO t VALUES (?, ?, ?)'))
    f.s2c(pdu(1, prepare_ok(2, 0, 3)))
    f.s2c(pdu(2, fielddef(b'?', T_LONG)), pdu(3, fielddef(b'?', T_VARSTRING)), pdu(4, fielddef(b'?', T_DOUBLE)))
    brow1 = b'\x00' + u32(1) + b'\x00' + lestr(b'one') + b'\x00' + struct.pack('<d', 1.0)
    brow2 = b'\x00' + u32(2) + b'\x01' + b'\x00' + struct.pack('<d', 2.0)
    brow3 = b'\x02' + b'\x03' + b'\x04'
    f.c2s(pdu(0, bytes([COM_STMT_BULK_EXECUTE]) + u32(2) + u16(128 | 64) +
              bytes([T_LONG, 0, T_VARSTRING, 0, T_DOUBLE, 0]) + brow1 + brow2 + brow3))
    f.s2c(pdu(1, ok(3, 0, S_AC)))
    # bulk execute without the types, last prepared statement id
    f.c2s(pdu(0, bytes([COM_STMT_BULK_EXECUTE]) + u32(0xffffffff) + u16(0) + brow1))
    f.s2c(pdu(1, ok(1, 0, S_AC)))
    # bulk execute of a statement without parameters (reproducer of "Fix an infinite loop in MariaDB bulk execute")
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT 1'))
    f.s2c(pdu(1, prepare_ok(3, 0, 0)))
    f.c2s(pdu(0, bytes([COM_STMT_BULK_EXECUTE]) + u32(3) + u16(0) + b'\x00'))
    f.s2c(pdu(1, ok()))
    # a bulk execute for an unknown statement
    f.c2s(pdu(0, bytes([COM_STMT_BULK_EXECUTE]) + u32(99) + u16(0)))
    f.s2c(pdu(1, ok()))
    f.c2s(cmd(COM_QUIT))

    # MariaDB without DEPRECATE_EOF: cached metadata (send_meta = 0) is followed by an EOF
    DEFEXT[0] = []
    f = flow()
    mext2 = MS | MR | PM | PA | CA | AL | EP | ST
    f.s2c(pdu(0, greeting(b'5.5.5-10.6.16-MariaDB', thread=32, caps=mcaps, status=S_AC, charset=45,
                          ext=mext2, mariadb_ext=M_EM | M_ME, plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(mcaps, mext2, user=b'maria2', auth=b'\x78' * 20, db=b'mdb', plugin=b'mysql_native_password',
                       collation=45, mariadb_ext=M_EM | M_ME)))
    f.s2c(pdu(2, ok(0, 0, S_AC)))
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT a FROM t'))
    f.s2c(pdu(1, prepare_ok(1, 1, 0)))
    f.s2c(pdu(2, fielddef(b'a', T_LONG)), pdu(3, eof()))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1)))
    f.s2c(pdu(1, lenenc(1) + b'\x00'), pdu(2, eof()))
    f.s2c(pdu(3, binrow([T_LONG], [u32(6)])), pdu(4, eof()))
    f.c2s(cmd(COM_QUIT))
    DEFEXT[0] = None
    # reproducer flow as the review wrote it: no login at all (defaults)
    f = flow()
    f.c2s(pdu(0, b'\x16SELECT 1'))
    f.s2c(pdu(1, b'\x00' + struct.pack('<IHH', 1, 0, 0) + b'\x00' + struct.pack('<H', 0)))
    f.c2s(pdu(0, b'\xfa' + struct.pack('<IH', 1, 0) + b'\x00'))

    # ============ S5: binary log dump with semi-sync ============
    f = flow()
    f.c2s(cmd(COM_BINLOG_DUMP, u32(4) + u16(0) + u32(1001) + b'mysql-bin.000001'))

    def hdr(ts, typ, sid, size, pos, fl=0):
        return u32(ts) + bytes([typ]) + u32(sid) + u32(size) + u32(pos) + u16(fl)
    ev = lambda typ, body, pre=b'': pdu(1, b'\x00' + pre + hdr(1700000000, typ, 1, 19 + len(body) + 4, 120)
                                        + body + u32(0xdeadbeef))
    f.s2c(ev(4, u64(4) + b'mysql-bin.000002'))                    # ROTATE
    f.s2c(ev(15, b'\x04\x00' + b'8.0.36'.ljust(50, b'\0') + u32(0) + b'\x13'))  # FORMAT_DESCRIPTION
    f.s2c(ev(2, u32(7) + u32(0) + b'\x04\x00' + u16(0) + b'\x00' + b'\0' + b'test\0' + b'BEGIN'))
    f.s2c(ev(162, b'\x00' + b'\x01' * 16 + u64(5), pre=b'\xef\x01'))   # semisync marker + ack requested
    f.c2s(pdu(2, b'\xef' + u64(1234) + b'mysql-bin.000002'))           # semisync ack
    f.c2s(pdu(3, u64(2345) + b'mysql-bin.000002'))                     # ack without marker
    f.s2c(ev(16, u64(77)))                                              # XID
    hb = b'\x00' + lenenc(16) + b'mysql-bin.000002' + b'\x01' + lenenc(1) + lenenc(1234) + b'\x02'
    f.s2c(ev(41, hb))                                                   # HEARTBEAT_LOG_EVENT_V2
    f.s2c(ev(250, b'unknown'))                                          # unknown event type

    f = flow()
    f.c2s(cmd(COM_BINLOG_DUMP_GTID, u16(4) + u32(1002) + u32(16) + b'mysql-bin.000009' + u64(4) +
              u32(24) + b'\x01\x00\x00\x00\x00\x00\x00\x00' + b'\xab' * 16))
    f.s2c(pdu(1, b'\x00' + hdr(1700000001, 3, 1, 23, 99) + u32(1)))

    # ============ S6: native clone ============
    f = flow()
    f.c2s(cmd(COM_CLONE))
    f.s2c(pdu(1, ok()))
    for code in (1, 2, 3, 4, 5):
        f.c2s(pdu(0, bytes([code])))
        f.s2c(pdu(code, bytes([code])))
    for code in (1, 2, 3, 4, 5, 6, 7, 8, 100, 55):
        f.s2c(pdu(10 + code, bytes([code])))
    f.c2s(pdu(0, bytes([77])))
    f.c2s(pdu(0, bytes([6])))                                # COM_EXIT
    f.s2c(pdu(20, bytes([99])))                              # COMPLETE ends the clone
    f.c2s(cmd(COM_PING))
    f.s2c(pdu(1, ok()))

    # ============ S7: compressed protocol (zlib) ============
    f = flow()
    ccaps = LP | LF | CD | CU | SC | CP
    f.s2c(pdu(0, greeting(b'8.0.36', thread=41, caps=ccaps, status=S_AC, ext=MS | MR | PA | CA | DE,
                          plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(ccaps, MS | MR | PA | CA | DE, user=b'zed', auth=b'\x12' * 20, db=b'z',
                       plugin=b'mysql_native_password')))
    f.s2c(pdu(2, ok()))                          # compression starts after this packet

    def cpk(seq, plain, compress=True, level=None):
        if compress:
            z = zlib.compress(plain)
            return u24(len(z)) + bytes([seq]) + u24(len(plain)) + z
        return u24(len(plain)) + bytes([seq]) + u24(0) + plain

    f.c2s(cpk(0, cmd(COM_QUERY, b'SELECT repeat("x", 3000), 1')))
    cols = [pdu(2, fielddef(b'a', T_VARSTRING)), pdu(3, fielddef(b'b', T_LONG))]
    # whole result set in one compressed packet
    f.s2c(cpk(1, pdu(1, lenenc(2)) + b''.join(cols) + pdu(4, textrow(b'v', b'1')) +
              pdu(5, b'\xfe\x00\x00\x02\x00\x00\x00')))
    # a large row split across two compressed packets (reassembly)
    f.c2s(cpk(0, cmd(COM_QUERY, b'SELECT big')))
    big = pdu(4, textrow(b'q' * 3000, b'2')) + pdu(5, b'\xfe\x00\x00\x02\x00\x00\x00')
    head = pdu(1, lenenc(2)) + b''.join(cols)
    stream = head + big
    cut = len(head) + 1500
    f.s2c(cpk(1, stream[:cut]))
    f.s2c(cpk(2, stream[cut:]))
    # small packets sent uncompressed (uncompressed length 0), also two PDUs in one packet
    f.c2s(cpk(0, cmd(COM_PING), compress=False))
    f.s2c(cpk(1, pdu(1, ok()), compress=False))
    f.c2s(cpk(0, cmd(COM_PING) + cmd(COM_PING), compress=False))
    f.s2c(cpk(1, pdu(1, ok()) + pdu(1, ok()), compress=False))
    f.c2s(cpk(0, cmd(COM_QUIT)))

    # ============ S8: SSL request then a TLS ClientHello ============
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=51, caps=LP | LF | CD | CU | SC | SL, status=S_AC, ext=PA | QA | DE,
                          plugin=b'mysql_native_password')))
    f.c2s(pdu(1, ssl_request(LP | LF | CD | CU | SC | SL, PA | QA | DE)))
    hello = (b'\x03\x03' + bytes(range(32)) + b'\x00' + u16(4)[::-1] + b'\x13\x01\x13\x02' + b'\x01\x00' +
             b'\x00\x00')
    hs = b'\x01' + u24(len(hello)) + hello
    f.c2s(b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs)

    # ============ S9: pre-4.1 protocol (greeting stops after the salt) ============
    f = flow()
    f.s2c(pdu(0, greeting(b'3.23.58', thread=61, stop='salt')))
    f.c2s(pdu(1, login(LP | CD, 0, user=b'old', auth=b'oldpw', db=b'olddb')))
    f.s2c(pdu(2, b'\x00\x00\x00' + u16(S_AC)))
    f.c2s(cmd(COM_QUERY, b'SELECT a FROM t'))
    f.s2c(pdu(1, lenenc(2)))
    f.s2c(pdu(2, fielddef(b'a', T_LONG, 0x03, cu=False, lf=False)),
          pdu(3, fielddef(b'b', T_VARSTRING, 0x01, cu=False, lf=False)))
    f.s2c(pdu(4, textrow(b'1', b'x', b'surplus')), pdu(5, textrow(None, b'y')),
          pdu(6, lestr_fd(b'wide') + lestr_fe(b'wider')))
    f.s2c(pdu(7, b'\xfe'))               # DEPRECATE_EOF is assumed by default: this ends the rows
    f.c2s(cmd(COM_CHANGE_USER, cstr(b'old3') + cstr(b'pw3') + cstr(b'db3')))
    f.s2c(pdu(1, ok()))
    f.c2s(cmd(COM_QUERY, b'SELECT bad'))
    f.s2c(pdu(1, err(1054, b"Unknown column 'bad'", sqlstate=None)))
    f.c2s(cmd(COM_QUERY, b'UPDATE t SET a=1'))
    f.s2c(pdu(1, b'\x00\x02\x00' + u16(S_AC) + lestr(b'Rows matched')))
    f.c2s(cmd(COM_QUIT))

    # ============ S10: pre-4.1 server using LONG_FLAG: two byte flags, SHOW FIELDS default ============
    f = flow()
    f.s2c(pdu(0, greeting(b'4.0.27', thread=62, caps=LP | LF | CD, stop='caps')))
    f.c2s(pdu(1, login(LP | LF | CD, 0, user=b'old2', auth=b'pw', db=b'd')))
    f.s2c(pdu(2, b'\x00\x00\x00' + u16(S_AC)))
    f.c2s(cmd(COM_FIELD_LIST, b't\0'))
    f.s2c(pdu(1, fielddef(b'a', T_LONG, 0x0203, cu=False, lf=True) + lestr(b'0')))
    f.s2c(pdu(2, b'\xfe' + u16(0) + u16(S_AC)))

    # ============ S11: greeting is an error ============
    f = flow()
    f.s2c(pdu(0, b'\xff' + u16(1129) + b"Host '192.0.2.1' is blocked because of many connection errors"))

    # ============ S12: capture starts mid-session (all defaults) ============
    f = flow()
    f.c2s(cmd(COM_QUERY, b'SELECT 1'))
    f.s2c(pdu(1, lenenc(1)), pdu(2, fielddef(b'1', T_LONGLONG)), pdu(3, textrow(b'1')),
          pdu(4, b'\xfe\x00\x00\x02\x00\x00\x00'))
    f.c2s(cmd(COM_QUERY, b'\x00\x01SELECT 2'))               # looks like query attributes: skipped
    f.s2c(pdu(1, ok(0, 0, S_AC)))
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT ?'))
    # pipelined: statements sent before the prepare response
    f.c2s(cmd(COM_STMT_SEND_LONG_DATA, u32(1) + u16(0) + b'abc'))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(0xffffffff) + b'\x00' + u32(1) + b'\x00\x01\xfd\x00\x03xyz'))
    f.c2s(pdu(0, bytes([COM_STMT_BULK_EXECUTE]) + u32(0xffffffff) + u16(0) + b'\x00'))
    f.s2c(pdu(1, prepare_ok(1, 1, 1)))
    f.s2c(pdu(2, fielddef(b'?', T_VARSTRING)), pdu(3, fielddef(b'a', T_LONG)))
    f.c2s(cmd(COM_QUIT))


def cpk_z(seq, plain):
    z = zlib.compress(plain)
    return u24(len(z)) + bytes([seq]) + u24(len(plain)) + z


def build_malformed(pc):
    cpk = cpk_z
    ccaps = LP | LF | CD | CU | SC | CP
    port = [51000]

    def flow(sport=3306):
        port[0] += 1
        return Flow(pc, port[0], sport)

    # ---- fixed reproducer for the -2 state bug the review found (not fixed on the branch):
    # an execute that came before COM_STMT_SEND_LONG_DATA decodes differently in the second pass
    f = flow()
    f.c2s(pdu(0, b'\x16SELECT ?'))
    f.s2c(pdu(1, b'\x00' + struct.pack('<IHH', 1, 0, 1) + b'\x00' + struct.pack('<H', 0)))
    f.c2s(pdu(0, b'\x17' + struct.pack('<IBI', 1, 0, 1) + b'\x00' + b'\x01' + b'\xfe\x00' + b'\x03abc'))
    f.c2s(pdu(0, b'\x18' + struct.pack('<IH', 1, 0) + b'longdata'))
    # bulk with SEND_TYPES for a statement: changes the stored types on each pass
    f = flow()
    f.c2s(pdu(0, b'\x16SELECT ?'))
    f.s2c(pdu(1, b'\x00' + struct.pack('<IHH', 1, 0, 1) + b'\x00' + struct.pack('<H', 0)))
    f.c2s(pdu(0, bytes([COM_STMT_BULK_EXECUTE]) + u32(1) + u16(128) + bytes([T_LONG, 0]) + b'\x00' + u32(1)))
    f.c2s(pdu(0, bytes([COM_STMT_BULK_EXECUTE]) + u32(1) + u16(128) + bytes([T_VARSTRING, 0]) + b'\x00' + lestr(b'a')))

    # ---- result header with a column count above the limit, unknown responses, bad field counts
    f = flow()
    f.c2s(cmd(COM_QUERY, b'SELECT many'))
    f.s2c(pdu(1, b'\xfc\xff\xff'))                     # 65535 columns
    f.c2s(cmd(COM_QUERY, b'SELECT 1'))
    f.s2c(pdu(1, lenenc(1)), pdu(2, fielddef(b'a', T_LONG)), pdu(3, eof()))
    f.s2c(pdu(4, textrow(b'1')), pdu(5, eof()))
    # more field packets than announced
    f.c2s(cmd(COM_QUERY, b'SELECT 2'))
    f.s2c(pdu(1, lenenc(1)), pdu(2, fielddef(b'a', T_LONG)), pdu(3, fielddef(b'b', T_LONG)))
    f.s2c(pdu(4, eof()))
    f.s2c(pdu(5, eof()))
    # response bytes in a state that does not expect them
    f.c2s(cmd(COM_PING))
    f.s2c(pdu(1, ok()))
    f.s2c(pdu(2, b'\x05abcde'))                        # response while idle: result header or unknown
    f.c2s(cmd(COM_INIT_DB, b'x'))
    f.s2c(pdu(1, ok()))
    f.c2s(cmd(COM_STMT_CLOSE, u32(1)))
    f.s2c(pdu(1, b'\x07zzzzzzz'))

    # ---- a field packet whose first byte is 0 (an empty table name before 4.1) is not counted:
    # the dissector then needs a third field packet to leave the field state (see README)
    f = flow()
    f.s2c(pdu(0, greeting(b'3.23.58', thread=77, stop='salt')))
    f.c2s(pdu(1, login(LP | CD, 0, user=b'old', auth=b'oldpw', db=b'olddb')))
    f.s2c(pdu(2, b'\x00\x00\x00' + u16(S_AC)))
    f.c2s(cmd(COM_QUERY, b'SELECT a, b FROM t'))
    f.s2c(pdu(1, lenenc(2)))
    f.s2c(pdu(2, fielddef(b'a', T_LONG, 0x03, table=b'', cu=False, lf=False)),
          pdu(3, fielddef(b'b', T_LONG, 0x03, cu=False, lf=False)),
          pdu(4, fielddef(b'c', T_LONG, 0x03, cu=False, lf=False)))
    f.s2c(pdu(5, textrow(b'1', b'2')), pdu(6, b'\xfe'))

    # ---- field packets that do not fit the result header, huge lengths, unknown response
    f = flow()
    f.c2s(cmd(COM_QUERY, b'SELECT a'))
    f.s2c(pdu(1, lenenc(1)), pdu(2, lestr(b'def')))                     # field packet with only a catalog
    f.s2c(pdu(3, textrow(b'v')))
    f.s2c(pdu(4, b'\xfe\x00\x00\x02\x00\x00\x00'))
    f.c2s(cmd(COM_QUERY, b'SELECT a, b'))
    f.s2c(pdu(1, lenenc(2)), pdu(2, fielddef(b'a', T_LONG)), pdu(3, fielddef(b'b', T_LONG)))
    f.s2c(pdu(4, lestr(b'a') + b'\xfe' + u64(0xffffffff) + b'abc'))      # length that overflows an int
    f.s2c(pdu(5, b'\xfe\x00\x00\x02\x00\x00\x00'))
    f.c2s(cmd(COM_PING))
    f.s2c(pdu(1, b'\x05abcd'))                                         # unknown response in the OK state
    # cached metadata, no DEPRECATE_EOF, but the server sends a field packet anyway
    f = flow()
    mcaps = LF | CD | CU | SC | IS | TA
    mext2 = MS | MR | PM | PA | CA | AL | EP | ST
    f.s2c(pdu(0, greeting(b'5.5.5-10.6.16-MariaDB', thread=78, caps=mcaps, status=S_AC, charset=45,
                          ext=mext2, mariadb_ext=M_ME, plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(mcaps, mext2, user=b'maria3', auth=b'\x79' * 20, db=b'mdb', plugin=b'mysql_native_password',
                       collation=45, mariadb_ext=M_ME)))
    f.s2c(pdu(2, ok(0, 0, S_AC)))
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT a FROM t'))
    f.s2c(pdu(1, prepare_ok(1, 1, 0)))
    f.s2c(pdu(2, fielddef(b'a', T_LONG)), pdu(3, eof()))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1)))
    f.s2c(pdu(1, lenenc(1) + b'\x00'), pdu(2, fielddef(b'a', T_LONG)))
    # query attributes with an unsupported parameter type
    f = flow()
    qext = PA | CA | AL | DE | QA
    f.s2c(pdu(0, greeting(b'8.0.36', thread=79, caps=LP | LF | CD | CU | SC, status=S_AC, ext=qext,
                          plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(LP | LF | CD | CU | SC, qext, user=b'qa', auth=b'\x5c' * 20, db=b'd',
                       plugin=b'mysql_native_password')))
    f.s2c(pdu(2, ok()))
    f.c2s(cmd(COM_QUERY, b'\x01\x01\x00\x01' + bytes([0x20, 0]) + lestr(b'x') + b'\x01\x02\x03' + b'SELECT ?'))
    f.s2c(pdu(1, ok()))
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT ?'))
    f.s2c(pdu(1, prepare_ok(1, 0, 1)))
    f.s2c(pdu(2, fielddef(b'?', T_LONG)))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1) +
              exec_params([0x20], [b'\x01\x02'], names=[b'p'])))
    f.s2c(pdu(1, ok()))
    # a truncated PDU inside a compressed packet raises an exception that is caught per PDU
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=80, caps=ccaps, status=S_AC, ext=PA | DE, plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(ccaps, PA | DE, user=b'exc', auth=b'\x16' * 20, db=b'z', plugin=b'mysql_native_password')))
    f.s2c(pdu(2, ok()))
    f.c2s(cpk(0, cmd(COM_QUERY, b'SELECT 1')))
    f.s2c(cpk(1, pdu(1, lenenc(1)) + pdu(2, b'\x03def\x04te') + pdu(3, textrow(b'1'))))

    # ---- prepared statement field count larger than the field packets, execute of unsupported types
    f = flow()
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT ?, ?'))
    f.s2c(pdu(1, prepare_ok(1, 1, 2)))
    f.s2c(pdu(2, fielddef(b'?', T_VARSTRING)), pdu(3, fielddef(b'?', T_VARSTRING)), pdu(4, eof()))
    f.s2c(pdu(5, fielddef(b'a', T_LONG)), pdu(6, eof()))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1) +
              exec_params([0x20, T_LONG], [b'\x01\x02\x03\x04'])))
    f.s2c(pdu(1, lenenc(1)), pdu(2, fielddef(b'a', 0x20)), pdu(3, eof()))
    f.s2c(pdu(4, binrow([0x20], [b'\x01\x02'])), pdu(5, eof()))
    f.c2s(pdu(0, bytes([COM_STMT_BULK_EXECUTE]) + u32(1) + u16(128) + bytes([T_LONG, 0, 0x20, 0]) + b'\x00' + u32(1)))
    # EXECUTE shorter than its null bitmap and with a bogus statement id
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x00' + u32(1)))
    # unknown binlog / replication leftovers
    f.c2s(cmd(COM_QUERY, b'\x00'))
    # a compression failure: bad zlib data in a compressed packet
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=71, caps=ccaps, status=S_AC, ext=PA | DE, plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(ccaps, PA | DE, user=b'bad', auth=b'\x14' * 20, db=b'z', plugin=b'mysql_native_password')))
    f.s2c(pdu(2, ok()))
    f.c2s(u24(10) + b'\x00' + u24(12) + b'not zlib data')
    f.s2c(u24(4) + b'\x01' + u24(40) + zlib.compress(b'a' * 40)[:4])   # truncated zlib stream
    z = zlib.compress(pdu(1, ok()))
    f.s2c(u24(len(z)) + b'\x02' + u24(len(pdu(1, ok()))) + z)          # a good one afterwards
    # a PDU header split 2 + 2 bytes across two compressed packets: the dissector asks for the missing
    # header bytes without setting pinfo->desegment_offset; reassemble.c asserts (see README)
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=76, caps=ccaps, status=S_AC, ext=PA | DE, plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(ccaps, PA | DE, user=b'hdr', auth=b'\x15' * 20, db=b'z', plugin=b'mysql_native_password')))
    f.s2c(pdu(2, ok()))

    cols = [pdu(2, fielddef(b'a', T_VARSTRING)), pdu(3, fielddef(b'b', T_LONG))]
    f.c2s(cpk(0, cmd(COM_QUERY, b'SELECT 7')))
    last = pdu(5, b'\xfe\x00\x00\x02\x00\x00\x00')
    stream = pdu(1, lenenc(2)) + b''.join(cols) + pdu(4, textrow(b'7', b'7')) + last
    f.s2c(cpk(1, stream[:-len(last) + 2]))
    f.s2c(cpk(2, stream[-len(last) + 2:]))
    # a PDU that spans two TCP segments without reassembly being possible is covered by
    # the preference runs; a compressed PDU whose length field wraps:
    f.s2c(u24(0) + b'\x03' + u24(0))

    # ---- login packets: connection attributes longer than the packet, no password, short packets
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=72, caps=LP | LF | CD | CU | SC, status=S_AC, ext=PA | CA | AL,
                          plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(LP | LF | CD | CU | SC, PA | CA | AL, user=b'u', auth=b'', db=None, plugin=None, attrs=None)[:-0 or None]))
    f.s2c(pdu(2, ok()))
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=73, caps=LP | LF | CD | CU | SC, status=S_AC, ext=PA | CA | AL,
                          plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(LP | LF | CU | SC, PA, user=b'nopass', auth=b'')[:36]))   # ends after the user name
    f.s2c(pdu(2, ok()))
    f = flow()
    f.s2c(pdu(0, greeting(b'8.0.36', thread=74, caps=LP | LF | CD | CU | SC, status=S_AC, ext=PA | CA | AL,
                          plugin=b'mysql_native_password')))
    f.c2s(pdu(1, login(LP | LF | CD | CU | SC, PA | CA, user=b'u', auth=b'a', db=b'd', plugin=b'p') +
              lenenc(300) + b'\x01a\x01b'))                      # connection attributes longer than the data
    # greeting variants that stop early or are MariaDB without extended caps
    f = flow()
    f.s2c(pdu(0, greeting(b'5.5.5-10.3.1-MariaDB', thread=75, caps=LF | CU | SC, status=S_AC, ext=PA,
                          mariadb_ext=0, plugin=None, salt2=b'')))
    f.c2s(pdu(1, login(LF | CU | SC, PA, user=b'm', auth=b'x', plugin=b'y', mariadb_ext=0)))

    # ---- session tracking with unknown lengths, extended metadata etc. (need the preferences
    # assume_deprecate_eof and assume_extended_metadata/assume_cache_metadata, no handshake)
    f = flow()
    f.c2s(cmd(COM_QUERY, b'SELECT 1'))
    f.s2c(pdu(1, lenenc(1) + b'\x01'))
    f.s2c(pdu(2, fielddef(b'a', T_LONG, ext=[(0, b'int')])))
    f.s2c(pdu(3, textrow(b'1')), pdu(4, b'\xfe\x00\x00\x02\x00\x00\x00'))
    f.c2s(cmd(COM_STMT_PREPARE, b'SELECT a FROM t WHERE b=?'))
    f.s2c(pdu(1, prepare_ok(1, 1, 1)))
    f.s2c(pdu(2, fielddef(b'b', T_LONG, ext=[(0, b'int')])), pdu(3, fielddef(b'a', T_LONG, ext=[])))
    f.c2s(pdu(0, bytes([COM_STMT_EXECUTE]) + u32(1) + b'\x08' + u32(1) + lenenc(1) +
              exec_params([T_LONG], [u32(3)], names=[b'b'])))
    f.s2c(pdu(1, lenenc(1) + b'\x00'))
    f.s2c(pdu(2, binrow([T_LONG], [u32(4)])), pdu(3, b'\xfe\x00\x00\x02\x00\x00\x00'))
    f.c2s(cmd(COM_QUERY, b'\x00\x01SELECT 9'))
    f.s2c(pdu(1, ok(0, 0, S_AC | S_SSC, 0, b'', st=True, track=bytes([1]) + lenenc(3) + lestr(b'db'))))
    f.c2s(cmd(COM_QUERY, b'\x01\x01\x00\x01' + bytes([T_VARSTRING, 0]) + lestr(b'p') + lestr(b'v') + b'SELECT ?'))
    f.s2c(pdu(1, ok(0, 0, S_AC, 0, b'info', st=True)))
    f.s2c(pdu(2, err(1, b'x')))
    # error packets as progress reports without the capabilities
    f.s2c(pdu(3, b'\xff\xff\xff\x01' + bytes([1, 3]) + u24(1) + lestr(b's')))

    # zstd compressed protocol (only decoded by builds with Zstandard, so not in the main capture)
    if _zstd is not None:
        f = flow()
        zext = MS | MR | PA | CA | DE | ZS
        f.s2c(pdu(0, greeting(b'8.0.36', thread=42, caps=LP | LF | CD | CU | SC, status=S_AC, ext=zext,
                              plugin=b'mysql_native_password')))
        f.c2s(pdu(1, login(LP | LF | CD | CU | SC, zext, user=b'zst', auth=b'\x13' * 20, db=b'z',
                           plugin=b'mysql_native_password', attrs=[(b'a', b'b')], zstd_level=3)))
        f.s2c(pdu(2, ok()))

        def zpk(seq, plain):
            z = _zstd.compress(plain)
            return u24(len(z)) + bytes([seq]) + u24(len(plain)) + z
        f.c2s(zpk(0, cmd(COM_QUERY, b'SELECT 1')))
        f.s2c(zpk(1, pdu(1, lenenc(1)) + pdu(2, fielddef(b'a', T_LONG)) + pdu(3, textrow(b'1')) +
                  pdu(4, b'\xfe\x00\x00\x02\x00\x00\x00')))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    pc = Pcap()
    build_main(pc)
    pc.write(os.path.join(out, 'mysql-coverage.pcap'))
    n_main = len(pc.pkts)
    pc = Pcap()
    build_malformed(pc)
    pc.write(os.path.join(out, 'mysql-coverage-malformed.pcap'))
    print('main frames:', n_main, 'malformed frames:', len(pc.pkts))


if __name__ == '__main__':
    main()
