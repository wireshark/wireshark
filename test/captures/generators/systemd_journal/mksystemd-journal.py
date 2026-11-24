#!/usr/bin/env python3
# Generates test/captures/systemd_journal_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the systemd Journal Entry coverage captures: mksystemd-journal.py <outdir> [-v].  All data is synthetic.

The entries are systemd journal export format records in pcapng Systemd
Journal Export Blocks (block type 9). packet-systemd-journal.c registers
its dissector only in Stratoshark (an event dissector), not in tshark, so
tshark reads the records but does not dissect them."""
import os
import struct
import sys

def blk(btype, body):
    body += b'\0' * ((4 - len(body) % 4) % 4)
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)

def shb():
    return blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

def sje(entry):
    return blk(9, entry)

def entry(rt=1700000000123456, mono=1000000, cursor='s=0123456789abcdef;i=1;b=0;m=1;t=1;x=1', fields=(), tail=b''):
    e = ('__CURSOR=%s\n__REALTIME_TIMESTAMP=%d\n__MONOTONIC_TIMESTAMP=%d\n' % (cursor, rt, mono)).encode()
    for f in fields:
        e += f if isinstance(f, bytes) else f.encode()
    return e + tail + b'\n'

def binfield(name, data):
    """A binary field of the export format: name, newline, 64 bit little endian length, data, newline."""
    return name.encode() + b'\n' + struct.pack('<Q', len(data)) + data + b'\n'

def main(out, verbose):
    marks = []
    es = []
    def add(text, e):
        marks.append((len(es) + 1, text))
        es.append(e)
    add('A syslog style message with priority, facility, identifier, PID, process fields, unit, boot and machine IDs, host name and transport',
        entry(fields=('MESSAGE=Started synthetic service.\n', 'MESSAGE_ID=39f53479d3a045ac8e11786248231fbf\n', 'PRIORITY=6\n', 'SYSLOG_FACILITY=3\n',
                      'SYSLOG_IDENTIFIER=systemd\n', 'SYSLOG_PID=1\n', '_PID=1\n', '_UID=0\n', '_GID=0\n', '_COMM=systemd\n', '_EXE=/usr/lib/systemd/systemd\n',
                      '_CMDLINE=/sbin/init\n', '_CAP_EFFECTIVE=1ffffffffff\n', '_SYSTEMD_CGROUP=/init.scope\n', '_SYSTEMD_UNIT=init.scope\n', '_SYSTEMD_SLICE=-.slice\n',
                      '_BOOT_ID=00112233445566778899aabbccddeeff\n', '_MACHINE_ID=ffeeddccbbaa99887766554433221100\n', '_HOSTNAME=synthetic-host\n', '_TRANSPORT=journal\n')))
    add('A kernel message with device fields and an error number', entry(1700000001000000, 2000000, fields=('MESSAGE=usb 1-1: new device\n', 'PRIORITY=5\n', '_TRANSPORT=kernel\n',
        '_KERNEL_DEVICE=c189:0\n', '_KERNEL_SUBSYSTEM=usb\n', '_UDEV_SYSNAME=1-1\n', '_UDEV_DEVNODE=/dev/bus/usb/001/002\n', '_UDEV_DEVLINK=/dev/usb\n', 'ERRNO=-5\n')))
    add('Code location, result, audit, SELinux, session and user unit fields', entry(1700000002000000, 3000000, fields=('MESSAGE=audit event\n', 'CODE_FILE=src/core/job.c\n',
        'CODE_LINE=123\n', 'CODE_FUNC=job_finish\n', 'CODE_FUNCTION=job_finish\n', 'RESULT=done\n', '_AUDIT_SESSION=4\n', '_AUDIT_LOGINUID=1000\n', '_AUDIT_TYPE=1006\n',
        '_AUDIT_ID=77\n', '_AUDIT_FIELD_APPARMOR=ALLOWED\n', '_AUDIT_FIELD_OPERATION=open\n', '_AUDIT_FIELD_PROFILE=/usr/bin/x\n', '_AUDIT_FIELD_NAME=/etc/x\n',
        '_SELINUX_CONTEXT=unconfined\n', '_SYSTEMD_USER_UNIT=app.service\n', '_SYSTEMD_USER_SLICE=app.slice\n', '_SYSTEMD_SESSION=4\n', '_SYSTEMD_OWNER_UID=1000\n',
        '_SYSTEMD_INVOCATION_ID=0123456789abcdef0123456789abcdef\n', 'UNIT=sshd.service\n', 'USER_UNIT=app.service\n', 'COREDUMP_UNIT=x.service\n', 'COREDUMP_USER_UNIT=y.service\n')))
    add('Source timestamps, stream and line break', entry(1700000003000000, 4000000, fields=('MESSAGE=stdout line\n', '_SOURCE_REALTIME_TIMESTAMP=1700000003000100\n',
        '_SOURCE_MONOTONIC_TIMESTAMP=3999900\n', '_STREAM_ID=abcdef0123456789abcdef0123456789\n', '_LINE_BREAK=nul\n', 'SYSLOG_IDENTIFIER=app\n')))
    add('Fields about another object (OBJECT_*) for a message from a trusted process', entry(1700000004000000, 5000000, fields=('MESSAGE=object message\n', 'OBJECT_PID=99\n',
        'OBJECT_UID=1000\n', 'OBJECT_GID=1000\n', 'OBJECT_COMM=other\n', 'OBJECT_EXE=/usr/bin/other\n', 'OBJECT_CMDLINE=other --flag\n', 'OBJECT_AUDIT_SESSION=2\n',
        'OBJECT_AUDIT_LOGINUID=1000\n', 'OBJECT_CAP_EFFECTIVE=0\n', 'OBJECT_SELINUX_CONTEXT=ctx\n', 'OBJECT_SYSTEMD_CGROUP=/user.slice\n', 'OBJECT_SYSTEMD_SESSION=2\n',
        'OBJECT_SYSTEMD_OWNER_UID=1000\n', 'OBJECT_SYSTEMD_UNIT=session-2.scope\n', 'OBJECT_SYSTEMD_USER_UNIT=u.service\n', 'OBJECT_SYSTEMD_SLICE=user.slice\n',
        'OBJECT_SYSTEMD_USER_SLICE=app.slice\n', 'OBJECT_SYSTEMD_INVOCATION_ID=fedcba9876543210fedcba9876543210\n')))
    add('Journal status fields (disk usage, limits) and logind fields', entry(1700000005000000, 6000000, fields=('MESSAGE=Runtime Journal is using 8.0M\n', 'MESSAGE_ID=ec387f577b844b8fa948f33cad9a75e6\n',
        'JOURNAL_NAME=Runtime Journal\n', 'JOURNAL_PATH=/run/log/journal/x\n', 'CURRENT_USE=8388608\n', 'CURRENT_USE_PRETTY=8.0M\n', 'MAX_USE=100663296\n', 'MAX_USE_PRETTY=96.0M\n',
        'DISK_KEEP_FREE=1000\n', 'DISK_KEEP_FREE_PRETTY=1000B\n', 'DISK_AVAILABLE=2000\n', 'DISK_AVAILABLE_PRETTY=2000B\n', 'LIMIT=100663296\n', 'LIMIT_PRETTY=96.0M\n',
        'AVAILABLE=90000\n', 'AVAILABLE_PRETTY=90K\n', 'SEAT_ID=seat0\n', 'KERNEL_USEC=1000\n', 'USERSPACE_USEC=2000\n', 'SESSION_ID=4\n', 'USER_ID=1000\n', 'LEADER=1234\n',
        'JOB_TYPE=start\n', 'JOB_RESULT=done\n', 'USER_INVOCATION_ID=00ff00ff00ff00ff00ff00ff00ff00ff\n')))
    add('A binary MESSAGE field (length prefixed, with a newline and non-text bytes) and a binary field that is not a text field', entry(1700000006000000, 7000000,
        fields=(binfield('MESSAGE', b'multi\nline \xff\xfe binary message'), binfield('_CMDLINE', b'a b\nc'), binfield('COREDUMP_X', b'\x00\x01\x02\x03'), 'PRIORITY=4\n')))
    add('Fields that are not known, an empty value, a line that is too short and a line without a value', entry(1700000007000000, 8000000,
        fields=('MESSAGE=\n', 'X_UNKNOWN_FIELD=something\n', 'AB\n', 'PRIORITY=\n', '_PID=notanumber\n', 'ERRNO=-x\n', 'CODE_LINE=4294967296\n', 'PRIORITY=99999999999\n', '_UID=-1\n',
                '__REALTIME_TIMESTAMP=zz\n', '_SOURCE_REALTIME_TIMESTAMP=abc\n', 'A=B=C\n', '=\n', '==\n', '_HOSTNAME=h\n')))
    add('A binary field with a huge length that runs past the entry (the length is not checked against the entry)', entry(1700000008000000, 9000000, fields=('MESSAGE=before\n',),
        tail=b'MESSAGE\n' + struct.pack('<Q', 0xffffffff) + b'abc'))
    add('A binary field with a length of 2^64-1 and one of 2^32+3', entry(1700000009000000, 10000000, fields=('PRIORITY=3\n',),
        tail=b'MESSAGE\n' + struct.pack('<Q', 0xffffffffffffffff) + b'abc\n_PID\n' + struct.pack('<Q', 0x100000003) + b'12\n'))

    mk = shb() + b''.join(sje(e) for e in es[:8])
    open(os.path.join(out, 'systemd-journal-coverage.pcapng'), 'wb').write(mk)
    # entries that make the pcapng reader or the dissector stop early
    mal = shb() + b''.join(sje(e) for e in es[8:])
    mal += sje(b'MESSAGE=a message without a time stamp but long enough to be an entry\n')
    mal += sje(b'__REALTIME_TIMESTAMP=')
    mal += sje(b'__REALTIME_TIMESTAMP=notanumber and more text to be long enough\n')
    open(os.path.join(out, 'systemd-journal-coverage-malformed.pcapng'), 'wb').write(mal)
    if verbose:
        for n, tx in marks[:8]:
            print(n, tx)
        print(8, 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
