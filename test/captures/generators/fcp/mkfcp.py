# Generates test/captures/fcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (synthetic data only) ----
import struct
import sys
import os
import zlib

def pcap(fname, frames, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            wl = len(fr)
            if isinstance(fr, tuple):
                fr, wl = fr
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), wl))
            f.write(fr)

def eth(payload, ethertype, src=1, dst=2):
    return (bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) +
            struct.pack('>H', ethertype) + payload)

def fchdr(r_ctl, d_id, s_id, ftype, f_ctl, oxid, rxid=0xffff, seq_id=0, seqcnt=0, param=0, df_ctl=0, cs_ctl=0):
    return (bytes([r_ctl]) + d_id + bytes([cs_ctl]) + s_id + bytes([ftype]) +
            struct.pack('>I', f_ctl)[1:] + bytes([seq_id, df_ctl]) +
            struct.pack('>HHHI', seqcnt, oxid, rxid, param))

def fcoe(fc, sof=0x2E, eof=0x42, crc=None, ver=0):
    hdr = bytes([ver << 4]) + bytes(12) + bytes([sof])
    if crc is None:
        crc = zlib.crc32(fc) & 0xffffffff
    return eth(hdr + fc + struct.pack('<I', crc) + bytes([eof, 0, 0, 0]), 0x8906)

A = bytes([0x01, 0x02, 0x03])
B = bytes([0x01, 0x04, 0x05])
FIRST = 0x200000
LAST = 0x100000
SEQLAST = 0x080000
RESP = 0x800000
# ---- end common helpers ----
#!/usr/bin/env python3
# Generator for the FCP coverage captures.  Usage: mkfcp.py <outdir>
# Writes fcp-coverage.pcap (clean) and fcp-coverage-malformed.pcap.
# FCP is FC type 0x08, carried here over FCoE.  SCSI CDBs and data are
# made up.

ox = [0x100]

def cmnd(rw, cdb, dl, lun=b'\0' * 8, crn=0, attr=0, mgmt=0, addl=0, bidir=None):
    b11 = (addl << 2) | rw
    cdb = cdb.ljust(16 + addl, b'\0')
    body = lun + bytes([crn, attr, mgmt, b11]) + cdb + struct.pack('>I', dl)
    if bidir is not None:
        body += struct.pack('>I', bidir)
    return body

def rsp(flags=0, status=0, snslen=0, rsplen=0, resid=0, extra=b'', retry=0):
    return bytes(8) + struct.pack('>HBBIII', retry, flags, status, resid, snslen, rsplen) + extra

def lun_single(n):
    return bytes([0, n]) + bytes(6)

def lun_multi(a, b):
    return bytes([0x40 | a, b]) + bytes(6)

def init(payload, oxid, rxid=0xffff, seq=0, r_ctl=0x06, ftype=0x08, extra_fctl=0):
    """From the initiator A to the target B: the first sequence of an exchange."""
    return fcoe(fchdr(r_ctl, B, A, ftype, FIRST | SEQLAST | 0x010000 | extra_fctl, oxid, rxid, seq_id=seq) + payload)

def data_to_init(payload, oxid, rxid, seqcnt=0, param=0, extra_fctl=0, r_ctl=0x01):
    return fcoe(fchdr(r_ctl, A, B, 0x08, RESP | SEQLAST | extra_fctl, oxid, rxid, seqcnt=seqcnt, param=param) + payload)

def data_to_tgt(payload, oxid, rxid, seqcnt=0, param=0, extra_fctl=0):
    return fcoe(fchdr(0x01, B, A, 0x08, SEQLAST | extra_fctl, oxid, rxid, seqcnt=seqcnt, param=param) + payload)

def xfer_rdy(oxid, rxid, ro, burst):
    return fcoe(fchdr(0x05, A, B, 0x08, RESP | SEQLAST | 0x010000, oxid, rxid) + struct.pack('>II', ro, burst))

def response(payload, oxid, rxid, extra_fctl=0):
    return fcoe(fchdr(0x07, A, B, 0x08, RESP | LAST | SEQLAST | extra_fctl, oxid, rxid) + payload)

SENSE = bytes([0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x24, 0, 0, 0, 0, 0])
rx = [0x500]

def exchange(f, cdb, rw, dl, data=b'', lun=None, resp=None, mgmt=0, attr=0, crn=0, addl=0, bidir=None, oxid=None, xfer=False):
    if oxid is None:
        ox[0] += 1
        oxid = ox[0]
    rx[0] += 1
    r = rx[0]
    f.append(init(cmnd(rw, cdb, dl, lun or lun_single(0), crn, attr, mgmt, addl, bidir), oxid))
    if rw == 1:
        if xfer:
            f.append(xfer_rdy(oxid, r, 0, len(data)))
        f.append(data_to_tgt(data, oxid, r))
    elif rw == 2:
        f.append(data_to_init(data, oxid, r))
    f.append(response(resp if resp is not None else rsp(), oxid, r))
    return oxid

def build():
    f = []
    inquiry = bytes([0x12, 0, 0, 0, 36, 0])
    tur = bytes(6)
    read10 = bytes([0x28, 0, 0, 0, 0, 0x10, 0, 0, 1, 0])
    write10 = bytes([0x2a, 0, 0, 0, 0, 0x20, 0, 0, 1, 0])
    # the two exchanges of the "FCP: Fix response length checks and request matching" reproducer
    f.append(init(cmnd(2, read10, 512), 0x100))
    f.append(data_to_init(bytes(range(256)) * 2, 0x100, 0x500))
    f.append(response(rsp(), 0x100, 0x500))
    f.append(init(cmnd(1, write10, 512), 0x200))
    f.append(data_to_tgt(bytes(range(255, -1, -1)) * 2, 0x200, 0x600))
    f.append(response(rsp(), 0x200, 0x600))
    # INQUIRY with data, task attributes and command reference number
    exchange(f, inquiry, 2, 36, data=bytes([0, 0, 5, 2, 31, 0, 0, 0x32]) + b'VENDOR  PRODUCT         0001' + bytes(5), attr=1, crn=7)
    exchange(f, tur, 0, 0, attr=2)
    # WRITE with XFER_RDY and a residual (under) count
    exchange(f, write10, 1, 1024, data=bytes(1024), xfer=True, attr=4, resp=rsp(flags=0x04, resid=512))
    # multi-level LUN, residual over
    exchange(f, read10, 2, 512, data=bytes(512), lun=lun_multi(1, 5), resp=rsp(flags=0x08, resid=16))
    exchange(f, tur, 0, 0, lun=lun_single(5), attr=7)
    # response with sense data and CHECK CONDITION
    exchange(f, tur, 0, 0, resp=rsp(flags=0x02, status=2, snslen=len(SENSE), extra=SENSE))
    # response with response info (rsp code 0, 2) and with sense
    rspinfo = bytes([0, 0, 0, 0]) + bytes(4)
    exchange(f, tur, 0, 0, resp=rsp(flags=0x01, status=0, rsplen=8, extra=rspinfo))
    exchange(f, tur, 0, 0, resp=rsp(flags=0x03, status=2, snslen=len(SENSE), rsplen=8, extra=rspinfo[:3] + b'\x02' + bytes(4) + SENSE))
    # statuses: GOOD, BUSY, RESERVATION CONFLICT, TASK SET FULL, retry delay, confirm requested
    for st in (0x08, 0x18, 0x28, 0x30):
        exchange(f, tur, 0, 0, resp=rsp(status=st, retry=0x0100, flags=0x10))
    # bidirectional command and response
    exchange(f, read10, 3, 512, data=b'', bidir=256, lun=lun_single(1), resp=rsp(flags=0xe4, resid=1, extra=struct.pack('>I', 9)))
    # additional CDB length
    exchange(f, read10, 2, 512, data=bytes(512), addl=4, mgmt=0x01)
    # task management flags
    for m in (0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x06):
        ox[0] += 1
        f.append(init(cmnd(0, bytes(16), 0, lun_single(2), mgmt=m), ox[0]))
        f.append(response(rsp(), ox[0], 0xffff))
    # a single frame exchange (command with exchange first and last), and a
    # response that is also the first frame of its exchange
    ox[0] += 1
    f.append(init(cmnd(0, tur, 0, lun_single(4)), ox[0], extra_fctl=LAST))
    f.append(response(rsp(), ox[0], 0xffff, extra_fctl=FIRST))
    # interleaved exchanges on the same LUN (4 commands, then data/responses in a different order)
    o = []
    for i in range(4):
        ox[0] += 1
        o.append(ox[0])
        f.append(init(cmnd(2, read10, 64, lun_single(9)), ox[0]))
    for i in (2, 0, 3, 1):
        f.append(data_to_init(bytes([i]) * 64, o[i], 0x700 + i))
    for i in (3, 1, 2, 0):
        f.append(response(rsp(), o[i], 0x700 + i))
    # the same OX_ID is used again for a new command on the same LUN
    f.append(init(cmnd(2, read10, 64, lun_single(9)), o[0]))
    f.append(data_to_init(bytes(64), o[0], 0x710))
    f.append(response(rsp(), o[0], 0x710))
    # data and response without a command in the capture
    f.append(data_to_init(bytes(32), 0x3000, 0x3001))
    f.append(response(rsp(), 0x3000, 0x3001))
    # a data frame with the relative offset bit and a parameter
    f.append(data_to_init(bytes(64), o[1], 0x701, seqcnt=1, param=0x40, extra_fctl=0x08))
    # information categories without special handling: control (2), confirm (3), reserved (4)
    f.append(init(bytes(16), 0x3100, r_ctl=0x02))
    f.append(data_to_init(bytes(16), 0x3100, 0x3101, r_ctl=0x03))
    f.append(data_to_init(bytes(16), 0x3100, 0x3101, r_ctl=0x04))
    # FC-4 link services for FCP (information category 2/3 of link data): SRR and other
    f.append(fcoe(fchdr(0x32, B, A, 0x08, FIRST | SEQLAST | 0x010000, 0x3200) +
                  bytes([0x14, 0, 0, 0]) + struct.pack('>HHI', 0x100, 0x500, 0x40) + bytes([1, 0, 0, 0])))
    f.append(fcoe(fchdr(0x33, A, B, 0x08, RESP | LAST | SEQLAST, 0x3200, 0x3201) + bytes([0x02, 0, 0, 0]) + bytes(8)))
    f.append(fcoe(fchdr(0x32, B, A, 0x08, FIRST | SEQLAST | 0x010000, 0x3300) + bytes([0x77, 0, 0, 0]) + bytes(8)))
    return f

def main(out):
    pcap(os.path.join(out, 'fcp-coverage.pcap'), build())

    bad = []
    sense = SENSE
    # reproducers of "FCP: Fix response length checks and request matching"
    # rsplen = -16, snslen = 0xFFFFFFF0, large positive values
    bad.append(response(rsp(flags=0x03, status=2, snslen=18, rsplen=0xFFFFFFF0, extra=sense), 0x300, 0x700))
    bad.append(response(rsp(flags=0x02, status=2, snslen=0xFFFFFFF0, extra=sense), 0x301, 0x701))
    bad.append(response(rsp(flags=0x03, status=2, snslen=0x7FFFFFFF, rsplen=0x7FFFFFF8, extra=sense), 0x302, 0x702))
    # lengths one beyond the remaining data
    bad.append(response(rsp(flags=0x02, status=2, snslen=len(sense) + 1, extra=sense), 0x303, 0x703))
    bad.append(response(rsp(flags=0x01, rsplen=9, extra=bytes(8)), 0x304, 0x704))
    # a command with a short CDB (fewer octets than 16 + additional length)
    ox[0] += 1
    bad.append(init((lun_single(3) + bytes([0, 0, 0, 0]) + bytes(6) + struct.pack('>I', 0)), ox[0]))
    # truncated CMND, DATA-less XFER_RDY, RSP
    bad.append(init(cmnd(2, bytes(10), 0)[:20], 0x310))
    bad.append(init(cmnd(2, bytes(10), 0)[:30], 0x311))
    bad.append(init(cmnd(3, bytes(10), 0, bidir=1)[:-2], 0x312))
    bad.append(fcoe(fchdr(0x05, A, B, 0x08, RESP | SEQLAST, 0x313, 0x713) + bytes(5)))
    bad.append(response(bytes(15), 0x314, 0x714))
    bad.append(response(bytes(12) + bytes([0x80]) + bytes(5), 0x315, 0x715))
    # FC-4 link service shorter than the SRR
    bad.append(fcoe(fchdr(0x32, B, A, 0x08, FIRST | SEQLAST, 0x3200) + bytes([0x14, 0, 0, 0, 0, 1])))
    # empty FCP payload
    bad.append(fcoe(fchdr(0x32, B, A, 0x08, FIRST | SEQLAST, 0x3201)))
    pcap(os.path.join(out, 'fcp-coverage-malformed.pcap'), bad)

    # FCP called by name from Exported PDU, which passes no FC header
    name = b'fcp'
    tlv = struct.pack('>HH', 12, len(name)) + name + b'\0' + struct.pack('>HH', 0, 0)
    pkt = tlv + bytes(32)
    pcap(os.path.join(out, 'fcp-coverage-exported-pdu.pcap'), [pkt], 252)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
