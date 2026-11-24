#!/usr/bin/env python3
# Generates test/captures/sapigs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the SAP IGS (Internet Graphics Server) coverage captures.
# Usage: mksapigs.py <outdir>
# SAP IGS is reached through SAP NI on TCP port 40000 (sapni.port).
# Nothing is captured from a network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from sapcov_lib import Cap, Flow, ni

CLI, SRV = '192.0.2.1', '192.0.2.2'
n = [49000]


def flow(c):
    n[0] += 1
    f = Flow(c, CLI, SRV, n[0], 40000)
    f.syn()
    return f


def pad(s, n_, fill=b'\0'):
    if isinstance(s, str):
        s = s.encode()
    return s.ljust(n_, fill)[:n_]


def hdr(func, listener='IGS_LISTENER', host='igs.example.com', id_='0042', flag1=b'1', flag2=b'0'):
    return (pad(func, 32, b'\0') + pad(listener, 32) + pad(host, 81) + pad(id_, 4) + pad('', 15) +
            flag1 + pad('', 20) + flag2 + pad('', 6))


def pw(name='PW001'):
    return pad(name, 32)


def table(name='TAB', lines='3', width='20', col='COL1', ncol='1', cwidth='10'):
    rows = [('VERSION ', '1.0'), ('TABLE   ', name), ('LINENO  ', lines), ('WIDTH   ', width),
            ('COLNAME ', col), ('COLNO   ', ncol), ('COLWIDTH', cwidth)]
    return b''.join(pad(a, 8) + pad(b, 40) for a, b in rows)


def datamsg(func, tables, data, codepage='1100'):
    '''ZIPPER, IMGCONV, XMLCHART or ADM:GETDUMP: eye catcher, codepage, data
    offset (relative to the end of this 48 byte header), data size, tables,
    data.'''
    tbl = b''.join(tables)
    return (hdr(func) + pad('IGSDATA', 10) + b'  ' + pad(codepage, 4) +
            pad(str(len(tbl)), 16, b'\0') + pad(str(len(data)), 16, b'\0') + tbl + data)


def build_main(out):
    c = Cap()
    f = flow(c)
    # --- administration -----------------------------------------------------
    f.send(ni(hdr('ADM:PING') + pw()))
    f.send(ni(hdr('ADM:PONG')), False)
    f.send(ni(hdr('ADM:REGPW') + pw() + pad('7.53', 16)))
    f.send(ni(hdr('ADM:REGIP') + pw() + pad('IP01', 32) + pad('7.53', 32) + pad('free', 16)))
    f.send(ni(hdr('ADM:FREEIP') + pw() + pad('IP01', 32) + pad('7.53', 32) + pad('busy', 16)))
    for fn in ('ADM:UNREGPW', 'ADM:UNREGIP', 'ADM:ABORT', 'ADM:SHUTDOWNIGS', 'ADM:SHUTDOWNPW',
               'ADM:CHECKCONSUMER', 'ADM:FREECONSUMER', 'ADM:GETLOGFILE', 'ADM:GETCONFIGFILE',
               'ADM:DELETEDUMP', 'ADM:INSTALL', 'ADM:SWITCH', 'ADM:GETVERSION', 'ADM:STATUS',
               'ADM:STATISTIC', 'ADM:STATISTICNEW', 'ADM:GETSTATCHART', 'ADM:SIM',
               'RSPOCONNECTOR', 'BWGIS', 'SAPGISXML', 'NOSUCHFUNCTION'):
        f.send(ni(hdr(fn) + b'\0' * 8))
    # --- call back: raw TransMagic data, sized data, size with no data -----
    f.send(ni(hdr('ADM:ILLBEBACK') + pad('TransMagic', 16) + b'RAW DATA FOLLOWS' * 4))
    f.send(ni(hdr('ADM:ILLBEBACK') + b'00012' + b'sized data!!'))
    f.send(ni(hdr('ADM:ILLBEBACK') + b'00000' + b'junk-junk'))
    # --- data messages with definition tables ------------------------------
    f.send(ni(datamsg('ZIPPER', [], b'PK\x03\x04zipdata' * 3)))
    f.send(ni(datamsg('IMGCONV', [table('IMG', '1')], b'\x89PNG\r\n\x1a\n' + b'\0' * 40)))
    xml = b'<chart type="bar"><v>1</v><v>2</v></chart>'
    f.split(ni(datamsg('XMLCHART', [table('T1'), table('T2', '9', '40', 'COLX', '2', '12')], xml)), 3)
    f.send(ni(datamsg('ADM:GETDUMP', [], b'dump text\n' * 5)), False)
    # --- chart: config and data ---------------------------------------------
    f.send(ni(hdr('CHART') + pad('CHARTCONFIG01', 32) + b'1;2;3;4;5\n' * 4))
    f.send(ni(hdr('CHART') + pad('CHARTCONFIG02', 32)))                     # config only
    # --- the fixed header only / short messages (cleanly decoded) ---------
    f.send(ni(hdr('ADM:PING')))                                              # no port watcher
    f.send(ni(hdr('ADM:REGPW') + pw()))                                      # no version
    f.send(ni(pad('ADM:PING', 32, b'\0')))                                          # function name only
    # --- review reproducer: data offset 0xffffff00 in the ASCII field -----
    # (data_offset is read from packet data; the data item is skipped)
    bad = (hdr('ZIPPER') + pad('IGSDATA', 10) + b'  ' + pad('1100', 4) +
           pad('4294967040', 16, b'\0') + pad('8', 16, b'\0') + b'12345678')
    f.send(ni(bad))
    # --- review reproducer: the registration messages end right after the
    # port watcher name, so the next field starts past the end of the packet
    # (sapigs_tvb_has_remaining() used to wrap the negative remaining length
    # into a large unsigned value and the next item threw an exception)
    f.send(ni(hdr('ADM:REGPW') + b'PW001'))
    f.send(ni(hdr('ADM:REGIP') + b'PW001'))
    # the data offset 0xffffffff plus the header size wraps to 239: not rejected by the
    # INT_MAX check, the data item is then added from inside the header (README)
    wrap = (hdr('ZIPPER') + pad('IGSDATA', 10) + b'  ' + pad('1100', 4) +
            pad('4294967295', 16, b'\0') + pad('8', 16, b'\0') + b'12345678')
    f.send(ni(wrap))
    c.write(os.path.join(out, 'sapigs-coverage.pcap'))


def build_malformed(out):
    c = Cap()
    f = flow(c)
    # ILLBEBACK with 5..9 bytes after the header: only the size item
    f.send(ni(hdr('ADM:ILLBEBACK') + b'00007'))
    f.send(ni(hdr('ADM:ILLBEBACK') + b'0'))                  # fewer than 5 bytes
    f.send(ni(hdr('ADM:ILLBEBACK') + b'00099' + b'short'))   # declared size beyond data
    f.send(ni(hdr('ADM:ILLBEBACK') + pad('TransMagic', 10)))  # eye catcher, then offset+16 is past the end
    # short data message: < 48 bytes after the header
    f.send(ni(hdr('ZIPPER') + b'short'))
    # data offset and size beyond the packet
    f.send(ni(datamsg('XMLCHART', [], b'abc')[:-1]))
    big = (hdr('ZIPPER') + pad('IGSDATA', 10) + b'  ' + pad('1100', 4) + pad('0', 16, b'\0') +
           pad('1000', 16, b'\0') + b'abc')
    f.send(ni(big))
    # table definition cut short (less than 336 bytes)
    f.send(ni(datamsg('IMGCONV', [table('X')], b'')[:-100]))
    # CHART without room for a config
    f.send(ni(hdr('CHART') + b'abc'))
    # ADM:PING / REGIP with less than the fields
    f.send(ni(hdr('ADM:PING') + b'ab'))
    f.send(ni(hdr('ADM:REGIP') + pw()[:3]))
    f.send(ni(hdr('ADM:REGIP') + pw() + pad('IP01', 32)[:10]))
    f.send(ni(hdr('ADM:REGIP') + pw() + pad('IP01', 32) + pad('7', 32)[:10]))
    f.send(ni(hdr('ADM:REGIP') + pw() + pad('IP01', 32) + pad('7', 32) + b'abc'))
    f.send(ni(hdr('ADM:REGPW') + pw() + b'xy'))
    # header cut short
    f.send(ni(hdr('ZIPPER')[:100]))
    f.send(ni(b'ADM:PI'))
    c.write(os.path.join(out, 'sapigs-coverage-malformed.pcap'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main(out)
    build_malformed(out)
