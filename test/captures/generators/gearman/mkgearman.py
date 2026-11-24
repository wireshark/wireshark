#!/usr/bin/env python3
# Generates test/captures/gearman_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the Gearman coverage captures. Usage: mkgearman.py <outdir>
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from common import pcap, Flow

Z = b'\0'
def pdu(magic, t, *args, size=None, last_nul=False):
    """magic b'REQ'/b'RES'; args are NUL separated"""
    body = Z.join(args)
    if last_nul:
        body += Z
    return b'\0' + magic + struct.pack('>II', t, len(body) if size is None else size) + body

def build():
    main = []
    # ---- flow 1: a client and a job server, request side and responses
    f = Flow(40001, 4730, main)
    f.open()
    f.c2s(pdu(b'REQ', 16, b'ping'))                        # ECHO_REQ
    f.s2c(pdu(b'RES', 17, b'ping'))                        # ECHO_RES
    f.c2s(pdu(b'REQ', 26, b'exceptions'))                  # OPTION_REQ
    f.s2c(pdu(b'RES', 27, b'exceptions'))                  # OPTION_RES
    f.c2s(pdu(b'REQ', 7, b'reverse', b'u1', b'hello'))     # SUBMIT_JOB
    f.s2c(pdu(b'RES', 8, b'H:host:1'))                     # JOB_CREATED
    f.c2s(pdu(b'REQ', 18, b'reverse', b'u2', b'bg arg'))   # SUBMIT_JOB_BG
    f.s2c(pdu(b'RES', 8, b'H:host:2'))
    f.c2s(pdu(b'REQ', 21, b'reverse', b'u3', b'high'))     # HIGH
    f.c2s(pdu(b'REQ', 32, b'reverse', b'u4', b'high bg'))  # HIGH_BG
    f.c2s(pdu(b'REQ', 33, b'reverse', b'u5', b'low'))      # LOW
    f.c2s(pdu(b'REQ', 34, b'reverse', b'u6', b'low bg'))   # LOW_BG
    f.c2s(pdu(b'REQ', 35, b'cron', b'u7', b'30', b'12', b'1', b'6', b'3', b'sched arg'))  # SCHED
    f.c2s(pdu(b'REQ', 36, b'later', b'u8', b'1700000000', b'epoch arg'))                  # EPOCH
    f.c2s(pdu(b'REQ', 37, b'map', b'u9', b'reducefn', b'', b'reduce arg'))                # REDUCE_JOB
    f.c2s(pdu(b'REQ', 38, b'map', b'u10', b'reducefn', b'', b'reduce bg'))                # REDUCE_JOB_BG
    f.c2s(pdu(b'REQ', 15, b'H:host:1'))                    # GET_STATUS
    f.s2c(pdu(b'RES', 20, b'H:host:1', b'1', b'1', b'50', b'100'))        # STATUS_RES
    f.c2s(pdu(b'REQ', 41, b'u1'))                          # GET_STATUS_UNIQUE
    f.s2c(pdu(b'RES', 42, b'u1', b'1', b'1', b'50', b'100', b'2'))        # STATUS_RES_UNIQUE
    f.s2c(pdu(b'RES', 12, b'H:host:1', b'50', b'100'))     # WORK_STATUS
    f.s2c(pdu(b'RES', 28, b'H:host:1', b'partial'))        # WORK_DATA
    f.s2c(pdu(b'RES', 29, b'H:host:1', b'careful'))        # WORK_WARNING
    f.s2c(pdu(b'RES', 25, b'H:host:1', b'boom'))           # WORK_EXCEPTION
    f.s2c(pdu(b'RES', 13, b'H:host:1', b'olleh'))          # WORK_COMPLETE
    f.s2c(pdu(b'RES', 14, b'H:host:2'))                    # WORK_FAIL
    f.c2s(pdu(b'REQ', 24))                                 # ALL_YOURS (no data)
    f.c2s(pdu(b'REQ', 5))                                  # type 5 UNUSED
    f.close()

    # ---- flow 2: a worker
    w = Flow(40002, 4730, main)
    w.open()
    w.c2s(pdu(b'REQ', 1, b'reverse'))                      # CAN_DO
    w.c2s(pdu(b'REQ', 23, b'slow', b'30'))                 # CAN_DO_TIMEOUT
    w.c2s(pdu(b'REQ', 2, b'reverse'))                      # CANT_DO
    w.c2s(pdu(b'REQ', 3))                                  # RESET_ABILITIES
    w.c2s(pdu(b'REQ', 22, b'worker-7'))                    # SET_CLIENT_ID
    w.c2s(pdu(b'REQ', 9))                                  # GRAB_JOB
    w.s2c(pdu(b'RES', 10))                                 # NO_JOB
    w.c2s(pdu(b'REQ', 30))                                 # GRAB_JOB_UNIQ
    w.c2s(pdu(b'REQ', 39))                                 # GRAB_JOB_ALL
    w.c2s(pdu(b'REQ', 4))                                  # PRE_SLEEP
    w.s2c(pdu(b'RES', 6))                                  # NOOP
    w.s2c(pdu(b'RES', 11, b'H:host:3', b'reverse', b'worker arg'))        # JOB_ASSIGN
    w.s2c(pdu(b'RES', 31, b'H:host:3', b'reverse', b'u11', b'worker arg'))  # JOB_ASSIGN_UNIQ
    w.s2c(pdu(b'RES', 40, b'H:host:3', b'map', b'u12', b'reducefn', b'worker arg'))  # JOB_ASSIGN_ALL
    # unknown / reserved types: with data (expert info) and without
    w.s2c(pdu(b'RES', 99, b'stuff'))
    w.s2c(pdu(b'RES', 100))
    w.s2c(pdu(b'RES', 0, b'text'))                         # TEXT type 0 with data: default arm
    w.close()

    # ---- flow 3: several PDUs in one segment and PDUs split across segments
    g = Flow(40003, 4730, main)
    g.open()
    a = pdu(b'REQ', 16, b'one'); b = pdu(b'REQ', 16, b'two'); c = pdu(b'REQ', 7, b'fn', b'uid', b'args')
    g.c2s(a + b + c)                                        # three PDUs, one segment
    big = pdu(b'REQ', 7, b'bigfn', b'bigid', b'X' * 300)
    g.c2s(big[:5])                                          # header split
    g.c2s(big[5:100])                                       # part of the data
    g.c2s(big[100:] + pdu(b'REQ', 3))                       # the rest plus another PDU
    g.s2c(pdu(b'RES', 8, b'H:h:9') + pdu(b'RES', 13, b'H:h:9', b'R' * 50)[:20])
    g.s2c(pdu(b'RES', 13, b'H:h:9', b'R' * 50)[20:])
    g.close()

    # ---- flow 4: management protocol (text lines)
    m = Flow(40004, 4730, main)
    m.open()
    m.c2s(b'workers\n')
    m.s2c(b'32 10.0.0.1 worker-7 : reverse slow\n.\n')
    m.c2s(b'status\r\n')
    m.s2c(b'reverse\t1\t1\t1\n.\n')
    m.c2s(b'maxqueue reverse 10\n')                         # not exactly a command: first line shown as text
    m.c2s(b'maxqueue\n')
    m.c2s(b'version\nworkers\nstatus\n')                    # several commands in one segment
    m.s2c(b'OK 1.1.19\n')
    m.c2s(b'foo\nworkers\nbar\nbaz\n')                      # unknown first, known, unknown again
    m.c2s(b'workers\nunknown line\n')                        # known first, then unknown line (append sep)
    m.c2s(b'shutdown\n')
    m.c2s(b'\n')                                             # empty line
    m.close()

    # a client on a second TCP port that uses Decode As would need -d; keep to 4730.
    # flow 5: second connection with the "wrong" case: RES magic with a client request
    h = Flow(40005, 4730, main)
    h.open()
    h.c2s(pdu(b'RES', 17, b'echo from the other side'))
    h.s2c(pdu(b'REQ', 16, b'server side request'))
    # a PDU whose declared size is larger than the data in its segment, completed later
    h.c2s(pdu(b'REQ', 7, b'fn', b'id', b'0123456789', size=None)[:-4])
    h.c2s(b'6789')
    h.close()

    mal = []
    # ---- malformed capture
    x = Flow(40010, 4730, mal)
    x.open()
    x.c2s(pdu(b'REQ', 7, b'nonulfunction'))                 # SUBMIT_JOB without NUL: strsize throws
    x.c2s(pdu(b'REQ', 13, b'handle-without-nul'))           # WORK_COMPLETE
    x.c2s(pdu(b'REQ', 20, b'H:a\0', b'1'))                  # STATUS_RES: truncated
    x.c2s(pdu(b'REQ', 11, b'H:a'))                          # JOB_ASSIGN
    x.c2s(pdu(b'REQ', 31, b'H:a', b'fn'))                   # JOB_ASSIGN_UNIQ
    x.c2s(pdu(b'REQ', 35, b'cron', b'u'))                   # SCHED truncated
    x.c2s(pdu(b'REQ', 36, b'cron'))                         # EPOCH
    x.c2s(pdu(b'REQ', 37, b'cron', b'u'))                   # REDUCE
    x.c2s(pdu(b'REQ', 40, b'a', b'b'))                      # JOB_ASSIGN_ALL
    x.c2s(pdu(b'REQ', 12, b'h'))                            # WORK_STATUS
    x.c2s(pdu(b'REQ', 23, b'f'))                            # CAN_DO_TIMEOUT
    x.c2s(pdu(b'REQ', 42, b'h', b'1'))                      # STATUS_RES_UNIQUE
    x.c2s(pdu(b'REQ', 19, b'E'))                            # ERROR
    x.s2c(pdu(b'RES', 19, b'ERR_UNKNOWN', b'something broke'))  # every valid ERROR: err_text is FT_STRINGZ
    x.c2s(pdu(b'REQ', 16, size=0))                          # ECHO with no data
    x.c2s(b'\0REQ' + struct.pack('>II', 16, 20) + b'short')  # declared 20, 5 sent then FIN
    x.fin_c()
    return main, mal

if __name__ == '__main__':
    out = sys.argv[1]
    main, mal = build()
    pcap(os.path.join(out, 'gearman-coverage.pcap'), main)
    pcap(os.path.join(out, 'gearman-coverage-malformed.pcap'), mal)
