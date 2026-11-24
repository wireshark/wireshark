#!/usr/bin/env python3
# Generates test/captures/nvme_mi_mi_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-nvme-mi-mi.c (NVMe-MI MI commands).

    python3 mknvme_mi_mi.py <outdir> [-v]

writes nvme-mi-mi-coverage.pcapng (decodes without malformed packets or
errors) and nvme-mi-mi-coverage-malformed.pcapng.  Messages are NVMe-MI
MI commands (NMIMT 1) in MCTP over Linux cooked capture (interface 0) and
over SMBus (interface 1).  Only struct is used (helpers in nvme_mi_lib.py).
"""
import struct
import sys

from nvme_mi_lib import (
    admin_sqe, Cap, DEV, exported_pdu, fill, HOST, Link, mctp, mi_cmd, mi_msg, NMIMT_ADMIN,
    NMIMT_MI, resp_body, sll,
)


# ---------------------------------------------------------- data structures
def subsys_info(nump=0, mjr=1, mnr=2, nnsc=1):
    return bytes([nump, mjr, mnr, nnsc]) + bytes(28)


def port_pcie():
    return struct.pack('<BBHI', 1, 0x03, 64, 0) + bytes([2, 0x3f, 4, 4, 4, 0]) + bytes(18)


def port_2wire():
    return struct.pack('<BBHI', 2, 0x03, 64, 0) + bytes([0xa0, 2, 0x1d, 0x03, 0x01]) + bytes(19)


def port_inactive():
    return struct.pack('<BBHI', 0, 0, 0, 0) + fill(24, 2)


def port_reserved():
    return struct.pack('<BBHI', 3, 0, 0, 0) + fill(24, 3)


def ctrl_list(ids):
    return struct.pack('<H', len(ids)) + b''.join(struct.pack('<H', i) for i in ids)


def ctrl_info(portid=0, riv=1, bus=3, dev=0, fn=0):
    pri = (bus << 8) | (dev << 3) | fn
    return (bytes([portid]) + bytes(4) + bytes([riv]) + struct.pack('<H', pri)
            + struct.pack('<HHHH', 0x1b36, 0x0010, 0x1af4, 0x1100) + bytes([1]) + bytes(15))


def cmd_list(entries):
    return struct.pack('<H', len(entries)) + b''.join(bytes([nm << 3, opc]) for nm, opc in entries)


def nshds(nss=0x7f, sw=0x7f, ctemp=0x30, pdlu=5, ccs=0x1fff):
    return bytes([nss, sw, ctemp, pdlu]) + struct.pack('<H', ccs) + bytes(2)


def chds(ctlid, csts=0x00ff, ctemp=300, pdlu=7, spare=100, cwarn=0x5, chsc=0x0102):
    """Controller Health Data Structure (16 bytes)"""
    return (struct.pack('<HHHBB', ctlid, csts, ctemp, pdlu, spare)
            + bytes([cwarn & 0xff]) + struct.pack('<H', chsc) + bytes(5)).ljust(16, b'\0')


def ae_list(entries, ver=1, hdr_len=5, num=None, total=None):
    """AE list: 5 byte header and entries of (length, flag|id)"""
    body = b''.join(bytes([ln]) + struct.pack('<H', info) for ln, info in entries)
    n = len(entries) if num is None else num
    t = hdr_len + len(body) if total is None else total
    return bytes([n, ver]) + struct.pack('<H', t) + bytes([hdr_len]) + bytes(max(0, hdr_len - 5)) + body


class Exch:
    def __init__(self, lk):
        self.lk, self.n = lk, 0

    def go(self, body, resp, csi=0, req_data=b'', **kw):
        t = self.n & 7
        self.n += 1
        self.lk.req(mi_msg(NMIMT_MI, 0, csi, body + req_data, **kw), tag=t)
        if resp is not None:
            self.lk.resp(mi_msg(NMIMT_MI, 1, csi, resp, **kw), tag=t)
        return t


def rds(dtyp, portid=0, ctrlid=0, iocsi=0):
    return mi_cmd(0x00, (dtyp << 24) | (portid << 16) | ctrlid, iocsi)


def ok(data=b'', nmresp=None):
    return resp_body(0, len(data) if nmresp is None else nmresp, data)


def build():
    cap = Cap()
    lk = Link(cap)
    x = Exch(lk)
    cap.mark('Read NVMe-MI Data Structure: NVM Subsystem Information, Port Information (PCIe, '
             '2-Wire, inactive, reserved port type), Controller List, Controller Information, '
             'Optionally Supported and MEB Supported Command Lists, a reserved DTYP')
    x.go(rds(0), ok(subsys_info(1, 1, 2, 1)))
    x.go(rds(0, iocsi=3), ok(subsys_info()), csi=1)
    x.go(rds(1, portid=0), ok(port_pcie()))
    x.go(rds(1, portid=1), ok(port_2wire()))
    x.go(rds(1, portid=2), ok(port_inactive()))
    x.go(rds(1, portid=3), ok(port_reserved()))
    x.go(rds(2, ctrlid=0), ok(ctrl_list([0, 1, 2, 0x100])))
    x.go(rds(2, ctrlid=5), ok(ctrl_list([])))
    x.go(rds(3, ctrlid=1), ok(ctrl_info(0, 1, 3, 0, 0)))
    x.go(rds(3, ctrlid=2), ok(ctrl_info(1, 0, 4, 2, 1)))
    x.go(rds(4), ok(cmd_list([(1, 0x00), (1, 0x01), (1, 0x02), (1, 0x05), (2, 0x06), (2, 0x02),
                              (2, 0x0a), (4, 0x00), (0, 0x03), (5, 0x01)])))
    x.go(rds(5), ok(cmd_list([(1, 0x0a), (1, 0x0b), (2, 0x0a)])))
    x.go(rds(5), ok(cmd_list([])))
    x.go(rds(6), ok(bytes(8)))
    x.go(rds(0xff), ok(bytes(4)))
    cap.mark('NVM Subsystem Health Status Poll (CS clear/set) and Controller Health Status Poll '
             '(all flags, selected controller, entries); every NSHDS temperature encoding')
    x.go(mi_cmd(0x01, 0, 0), ok(nshds(), nmresp=0))
    x.go(mi_cmd(0x01, 0, 0x80000000), ok(nshds(0xff, 0x00, 0x7e, 0, 0x0000)), csi=1)
    for ct in (0x00, 0x2a, 0x7f, 0x80, 0x81, 0x90, 0xc3, 0xc4, 0xc5, 0xe0, 0xff):
        x.go(mi_cmd(0x01, 0, 0), ok(nshds(0x01, 0x55, ct)))
    x.go(mi_cmd(0x02, 0x80000000 | (3 << 8) | 2, 0x00ffffff), ok(chds(1) + chds(2), nmresp=0x020000))
    x.go(mi_cmd(0x02, 0x00ff0000 | 0x1f00 | 0x01, 0x80ff3fff),
         ok(chds(0, 0xffff, 0xffff, 0xff, 0xff, 0xff, 0xffff), nmresp=0x010000))
    x.go(mi_cmd(0x02, 0x0f000000 | 0x08000000, 0), ok(chds(1) + chds(2) + chds(3) + chds(4), nmresp=0x040000))
    cap.mark('Configuration Get/Set: SMBus/I2C frequency, Health Status Change, MCTP Transmission '
             'Unit Size, Asynchronous Event (with the AE Enable/Supported List); reserved and vendor '
             'CONFIGIDs')
    x.go(mi_cmd(0x04, 0x01 | (0 << 8), 0), ok(nmresp=0x02))
    x.go(mi_cmd(0x04, 0x01 | (1 << 8), 0), ok(nmresp=0x03), csi=1)
    x.go(mi_cmd(0x03, 0x01 | (1 << 8) | (2 << 16), 0), ok())
    x.go(mi_cmd(0x04, 0x02, 0), ok())
    x.go(mi_cmd(0x03, 0x02, 0x00ffffff), ok())
    x.go(mi_cmd(0x03, 0x02, 0x80002fff), ok())
    x.go(mi_cmd(0x04, 0x03 | (1 << 8), 0), ok(nmresp=0x0040))
    x.go(mi_cmd(0x03, 0x03 | (1 << 8), 0x0040), ok())
    x.go(mi_cmd(0x04, 0x04, 0), ok(ae_list([(3, 0x8000), (3, 0x0001), (3, 0x800e)]), nmresp=1))
    x.go(mi_cmd(0x04, 0x04, 0), ok(ae_list([(3, 0x0000)], hdr_len=8), nmresp=1))
    x.go(mi_cmd(0x03, 0x04 | 0x1f00 | (1 << 16), 0, data=ae_list([(3, 0x8000), (3, 0x0002)])), ok())
    x.go(mi_cmd(0x03, 0x04, 0, data=ae_list([(3, 0x8001), (3, 0x8004), (3, 0xc0)], hdr_len=7)), ok())
    # AE lists that are consistent enough to walk: a bogus entry length, a header length
    # below five, a list declaring more entries than it carries, an entry cut by the end
    x.go(mi_cmd(0x03, 0x04, 0, data=ae_list([(1, 0x8000), (0, 0x0001), (3, 0x8003)])), ok())
    x.go(mi_cmd(0x03, 0x04, 0, data=ae_list([(3, 0x8000)], hdr_len=2)), ok())
    x.go(mi_cmd(0x03, 0x04, 0, data=ae_list([(3, 0x8000), (3, 0x8001)], num=9)), ok())
    x.go(mi_cmd(0x03, 0x04, 0, data=ae_list([(3, 0x8000), (9, 0x8001)])), ok())
    x.go(mi_cmd(0x04, 0x04, 0), ok(ae_list([(3, 0x8000)], num=4), nmresp=1))
    x.go(mi_cmd(0x04, 0x04, 0), ok(ae_list([(2, 0x8000), (200, 0x8001)]), nmresp=1))
    x.go(mi_cmd(0x04, 0x03, 0), ok(bytes(8)))             # data for a CONFIGID that has none
    for cid in (0x00, 0x05, 0x40, 0xbf):
        x.go(mi_cmd(0x04, cid, 0), ok())
        x.go(mi_cmd(0x03, cid, 0x1234), ok())
    for cid in (0xc0, 0xff):
        x.go(mi_cmd(0x04, cid, 0), ok(bytes(4), nmresp=4))
    cap.mark('VPD Read and Write, Reset and Shutdown (reserved types), SES, MEB and vendor commands')
    x.go(mi_cmd(0x05, 0x0000, 0x0040), ok(fill(64, 1)))
    x.go(mi_cmd(0x05, 0x0100, 0x0100), ok(fill(256, 2)))
    x.go(mi_cmd(0x06, 0x0020, 0x0020, data=fill(32, 3)), ok())
    x.go(mi_cmd(0x07, 0x00000000, 0), ok())
    x.go(mi_cmd(0x07, 0x01000000, 0), ok())
    x.go(mi_cmd(0x0c, 0x00000000, 0), ok())
    x.go(mi_cmd(0x0c, 0x01000000, 0), ok())
    x.go(mi_cmd(0x0c, 0x02000000, 0), ok())
    for op in (0x08, 0x09, 0x0a, 0x0b, 0x0d, 0x20, 0xc0, 0xff):
        x.go(mi_cmd(op, 0x11223344, 0x55667788), ok(fill(8, op)))
    x.go(mi_cmd(0x09, 1, 2, data=fill(40, 5)), ok())
    cap.mark('error and interim responses: Invalid Parameter, More Processing Required (twice), '
             'generic errors, a vendor status, errors with trailing data')
    x.go(rds(1), resp_body(0x04, 0x000103))
    x.go(rds(2), resp_body(0x04, 0x000f20), csi=1)
    t = x.go(rds(3), None)
    lk.resp(mi_msg(NMIMT_MI, 1, 0, bytes([0x01, 0x00, 0x14, 0x00])), tag=t)
    lk.resp(mi_msg(NMIMT_MI, 1, 0, bytes([0x01, 0x00, 0xff, 0xff])), tag=t)
    lk.resp(mi_msg(NMIMT_MI, 1, 0, ok(ctrl_info())), tag=t)
    for st in (0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x20, 0x21, 0x2a, 0xe0, 0xff):
        x.go(mi_cmd(0x01, 0, 0), resp_body(st, 0))
    x.go(mi_cmd(0x01, 0, 0), resp_body(0x07, 0, b'trailing'))
    cap.mark('responses with no request, one whose request is an Admin command, a request '
             'superseded by the next request on the slot')
    lk.resp(mi_msg(NMIMT_MI, 1, 0, ok(bytes(8))), tag=6)
    lk.req(mi_msg(NMIMT_ADMIN, 0, 0, admin_sqe(0x06, cdw10=1, dlen=64)), tag=7)
    lk.resp(mi_msg(NMIMT_MI, 1, 0, ok(bytes(8))), tag=7)
    lk.req(mi_msg(NMIMT_MI, 0, 0, mi_cmd(0x01, 0, 0)), tag=5)
    lk.req(mi_msg(NMIMT_MI, 0, 0, rds(0)), tag=5)
    lk.resp(mi_msg(NMIMT_MI, 1, 0, ok(subsys_info())), tag=5)
    cap.mark('MIC, MEB and CIAP bits, the same over SMBus, Exported PDUs naming nvme-mi.mi')
    x.go(rds(0), ok(subsys_info()), ic=True, ciap=1)
    x.go(mi_cmd(0x01, 0, 0), ok(nshds()), ic=True, meb=1)
    sm = Link(cap, smbus=True)
    sx = Exch(sm)
    sx.go(mi_cmd(0x01, 0, 0), ok(nshds()))
    sx.go(rds(2), ok(ctrl_list([0, 1])))
    sx.go(mi_cmd(0x02, 0x80000000, 0), ok(chds(1), nmresp=0x010000))
    cap.add(2, exported_pdu('nvme-mi.mi', rds(0)))
    cap.add(2, exported_pdu('nvme-mi.mi', ok(subsys_info())))
    return cap


def build_malformed():
    cap = Cap()
    lk = Link(cap)
    x = Exch(lk)
    cap.mark('requests shorter than the command dwords (empty, opcode only, 11 bytes); responses '
             'with no status or fewer than 4 bytes')
    lk.req(mi_msg(NMIMT_MI, 0, 0, b''), tag=1)
    lk.resp(mi_msg(NMIMT_MI, 1, 0, b''), tag=1)
    lk.req(mi_msg(NMIMT_MI, 0, 0, bytes([0x00])), tag=2)
    lk.resp(mi_msg(NMIMT_MI, 1, 0, bytes([0x00])), tag=2)
    lk.req(mi_msg(NMIMT_MI, 0, 0, mi_cmd(0x01, 0, 0)[:11]), tag=3)
    lk.resp(mi_msg(NMIMT_MI, 1, 0, bytes([0x00, 0x00, 0x00])), tag=3)
    cap.mark('response data structures that are too short for their layout: one for every DTYP, '
             'NSHDS, CHDS, the AE lists and the controller and command lists')
    for dtyp, sizes in ((0, (3,)), (1, (7, 13, 5)), (2, (1,)), (3, (16,)), (4, (1,)),
                        (5, (1,))):
        for n in sizes:
            body = {0: subsys_info(), 1: port_pcie(), 2: ctrl_list([1]), 3: ctrl_info(),
                    4: cmd_list([(1, 0)]), 5: cmd_list([(1, 0)])}[dtyp]
            data = body[:n]
            if dtyp == 1 and n == 13:
                data = port_pcie()[:13]
            if dtyp == 1 and n == 5:
                data = port_2wire()[:12]
            x.go(rds(dtyp), ok(data))
    x.go(rds(1), ok(port_2wire()[:12]))
    x.go(rds(2), ok(struct.pack('<H', 5) + struct.pack('<HH', 1, 2)))
    x.go(rds(4), ok(struct.pack('<H', 5) + bytes([8, 0])))
    x.go(mi_cmd(0x01, 0, 0), ok(bytes(7)))
    x.go(mi_cmd(0x02, 0, 0), ok(chds(1) + bytes(5)))
    x.go(mi_cmd(0x04, 0x04, 0), ok(bytes([1, 1, 5])), )
    x.go(mi_cmd(0x04, 0x04, 0), ok(bytes([1, 1, 5, 0])), )
    x.go(mi_cmd(0x03, 0x04, 0, data=bytes([1, 1, 5])), ok())
    cap.mark('requests shorter than the command dwords followed by a response: the response is '
             'decoded without the request context (raw data, no layout)')
    for req_body, resp_data in ((bytes([0x00, 0, 0, 0, 1]), subsys_info()),
                                (bytes([0x04]), bytes(4)),
                                (bytes([0x00, 0, 0, 0, 1]), bytes(16))):
        t = x.n & 7
        x.n += 1
        lk.req(mi_msg(NMIMT_MI, 0, 0, req_body), tag=t)
        lk.resp(mi_msg(NMIMT_MI, 1, 0, ok(resp_data)), tag=t)
    cap.mark('a Success response whose status is cut by the snaplen, a wrong MIC')
    t = x.n & 7
    x.n += 1
    lk.req(mi_msg(NMIMT_MI, 0, 0, rds(0)), tag=t)
    msg = mi_msg(NMIMT_MI, 1, 0, ok(subsys_info()), ic=True)
    cap.add(0, sll(mctp(msg, DEV, HOST, t, 0), False), cap=4 + 8 + 4 + 2)
    lk.req(mi_msg(NMIMT_MI, 0, 0, rds(0), ic=True, bad_mic=True), tag=1)
    lk.resp(mi_msg(NMIMT_MI, 1, 0, ok(subsys_info()), ic=True, bad_mic=True), tag=1)
    return cap


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    c = build()
    c.write(out + '/nvme-mi-mi-coverage.pcapng')
    if '-v' in sys.argv:
        c.report('main')
    print('main: %d frames' % len(c.frames))
    c = build_malformed()
    c.write(out + '/nvme-mi-mi-coverage-malformed.pcapng')
    if '-v' in sys.argv:
        c.report('malformed')
    print('malformed: %d frames' % len(c.frames))
