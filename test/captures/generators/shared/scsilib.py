# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helper for the SCSI coverage generators: iSCSI over TCP/3260.

Synthetic addresses only (192.0.2.1 initiator, 192.0.2.2 target).  The
initiator source port is 41000, outside the default SAP NI range, so the
SAPIGS heuristic does not claim the segments.
"""
import os
import struct


def pad4(b):
    return b + b'\x00' * ((4 - len(b) % 4) % 4)


class Pcap:
    SPORT = 41000
    DPORT = 3260

    def __init__(self, path):
        self.f = open(path, 'wb')
        self.f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.t = 1700000000
        self.seq = {0: 1000, 1: 50000}
        self.itt = 0x100
        self.cmdsn = 1
        self.statsn = 1
        self.nframes = 0
        self.marks = []

    @staticmethod
    def _csum(h):
        s = 0
        for i in range(0, len(h), 2):
            s += (h[i] << 8) | h[i + 1]
        while s >> 16:
            s = (s & 0xffff) + (s >> 16)
        return (~s) & 0xffff

    def seg(self, payload, to_target=True, flags=0x18, snap=None):
        d = 0 if to_target else 1
        if to_target:
            src, dst = b'\xc0\x00\x02\x01', b'\xc0\x00\x02\x02'
            sp, dp = self.SPORT, self.DPORT
            md, ms = b'\x02\x00\x00\x00\x00\x02', b'\x02\x00\x00\x00\x00\x01'
        else:
            src, dst = b'\xc0\x00\x02\x02', b'\xc0\x00\x02\x01'
            sp, dp = self.DPORT, self.SPORT
            md, ms = b'\x02\x00\x00\x00\x00\x01', b'\x02\x00\x00\x00\x00\x02'
        seq = self.seq[d]
        ack = self.seq[1 - d]
        self.seq[d] += len(payload)
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)
        ip = bytearray(struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                                   1, 0x4000, 64, 6, 0, src, dst))
        struct.pack_into('>H', ip, 10, self._csum(ip))
        frame = md + ms + b'\x08\x00' + bytes(ip) + tcp + payload
        self.t += 1
        cap = len(frame) if snap is None else min(snap, len(frame))
        self.f.write(struct.pack('<IIII', self.t, 0, cap, len(frame)))
        self.f.write(frame[:cap])
        self.nframes += 1

    def mark(self, name):
        self.marks.append((name, self.nframes + 1))

    def close(self):
        self.f.close()
        if os.environ.get('MKVERBOSE'):
            for (n, a), (_, b) in zip(self.marks, self.marks[1:] + [('end', self.nframes + 1)]):
                print('%-12s frames %d-%d' % (n, a, b - 1))

    # ---- iSCSI PDUs -------------------------------------------------
    def next_itt(self):
        self.itt += 1
        return self.itt

    @staticmethod
    def lunb(lun):
        return struct.pack('>BB6x', 0, lun) if lun < 256 else struct.pack('>HHHH', 0x4000 | lun, 0, 0, 0)

    def command(self, cdb, lun=0, edtl=0, read=True, write=False, data=b'', itt=None,
                attr=1, bidir=None):
        """SCSI Command PDU.  A CDB longer than 16 bytes goes into an extended-CDB AHS."""
        itt = itt or self.next_itt()
        flags = 0x80 | (0x40 if read else 0) | (0x20 if write else 0) | attr
        ahs = b''
        if bidir is not None:
            ahs = struct.pack('>HBBI', 5, 2, 0, bidir)
        if len(cdb) > 16:
            ext = cdb[16:]
            ahs += pad4(struct.pack('>HBB', len(ext) + 1, 1, 0) + ext)
            cdb16 = cdb[:16]
        else:
            cdb16 = cdb + b'\x00' * (16 - len(cdb))
        bhs = struct.pack('>BBHB', 0x01, flags, 0, len(ahs) // 4)
        bhs += struct.pack('>I', len(data))[1:]
        bhs += self.lunb(lun)
        bhs += struct.pack('>IIII', itt, edtl, self.cmdsn, self.statsn)
        bhs += cdb16
        self.cmdsn += 1
        self.seg(bhs + ahs + pad4(data))
        return itt

    def data_in(self, itt, data, status=None, offset=0, datasn=0, lun=0, final=True, snap=None):
        flags = 0x80 if final else 0
        st = 0
        if status is not None:
            flags |= 0x01
            st = status
        bhs = struct.pack('>BBBB', 0x25, flags, 0, st) + b'\x00' + struct.pack('>I', len(data))[1:]
        bhs += self.lunb(lun)
        bhs += struct.pack('>IIIIIIII', itt, 0xffffffff, self.statsn, self.cmdsn, self.cmdsn + 8,
                           datasn, offset, 0)
        if status is not None:
            self.statsn += 1
        self.seg(bhs + pad4(data), to_target=False, snap=snap)

    def data_out(self, itt, data, offset=0, datasn=0, lun=0, final=True, ttt=0xffffffff):
        bhs = struct.pack('>BBBB', 0x05, 0x80 if final else 0, 0, 0) + b'\x00' + struct.pack('>I', len(data))[1:]
        bhs += self.lunb(lun)
        bhs += struct.pack('>IIIIIIII', itt, ttt, 0, self.statsn, 0, datasn, offset, 0)
        self.seg(bhs + pad4(data))

    def r2t(self, itt, offset, length, lun=0, ttt=0x1234):
        bhs = struct.pack('>BBBB', 0x31, 0x80, 0, 0) + b'\x00' + b'\x00\x00\x00'
        bhs += self.lunb(lun)
        bhs += struct.pack('>IIIIIIII', itt, ttt, self.statsn, self.cmdsn, self.cmdsn + 8, 0, offset, length)
        self.seg(bhs, to_target=False)

    def response(self, itt, status=0, sense=b'', resp=0, flags=0x80, resid=0):
        data = struct.pack('>H', len(sense)) + sense if sense else b''
        if resid > 0:
            flags |= 0x02
        bhs = struct.pack('>BBBB', 0x21, flags, resp, status) + b'\x00' + struct.pack('>I', len(data))[1:]
        bhs += b'\x00' * 8
        bhs += struct.pack('>IIIIIIII', itt, 0, self.statsn, self.cmdsn, self.cmdsn + 8, 0, 0, resid)
        self.statsn += 1
        self.seg(bhs + pad4(data), to_target=False)

    # ---- whole exchanges --------------------------------------------
    def xchg(self, cdb, lun=0, din=None, dout=None, status=0, sense=b'', edtl=None,
             split=None, resid=0):
        """One SCSI exchange: command, optional data, response.  din is the data
        returned by the target (carried in Data-In with the status in the last PDU
        when split is None and sense is empty, else followed by a Response);
        dout is data sent by the initiator (immediate)."""
        if edtl is None:
            edtl = len(din) if din is not None else (len(dout) if dout is not None else 0)
        if dout is not None:
            itt = self.command(cdb, lun, edtl=edtl, read=False, write=True, data=dout)
        else:
            itt = self.command(cdb, lun, edtl=edtl, read=din is not None or edtl == 0)
        if din is not None:
            if split:
                pieces = []
                o = 0
                while o < len(din):
                    pieces.append((o, din[o:o + split]))
                    o += split
                for i, (o, piece) in enumerate(pieces):
                    last = i == len(pieces) - 1
                    if last and not sense and status == 0:
                        self.data_in(itt, piece, status=0, offset=o, datasn=i, lun=lun)
                    else:
                        self.data_in(itt, piece, offset=o, datasn=i, lun=lun, final=last)
                        if last:
                            self.response(itt, status, sense, resid=resid)
            elif sense or status != 0:
                self.data_in(itt, din, lun=lun)
                self.response(itt, status, sense, resid=resid)
            else:
                self.data_in(itt, din, status=0, lun=lun)
        else:
            self.response(itt, status, sense, resid=resid)
        return itt

    def write_pieces(self, cdb, lun, data, piece):
        """A write whose data comes in several R2T driven Data-Out PDUs (the SCSI
        dissector reassembles them when scsi.defragment is on)."""
        itt = self.command(cdb, lun, edtl=len(data), read=False, write=True)
        o = 0
        sn = 0
        while o < len(data):
            part = data[o:o + piece]
            self.r2t(itt, o, len(part), lun)
            self.data_out(itt, part, o, sn, lun, final=True)
            o += piece
            sn += 1
        self.response(itt, 0)
        return itt

    def inquiry(self, lun, devtype, vendor=b'WSTEST  ', product=b'SYNTHETIC DEVICE', rev=b'0001',
                removable=False):
        cdb = bytes([0x12, 0, 0, 0, 36, 0])
        inq = bytes([devtype, 0x80 if removable else 0, 5, 2, 31, 0, 0, 0]) + vendor + product + rev
        self.xchg(cdb, lun, din=inq)


def fixed_sense(key, asc, ascq, info=None, cmd_info=0, fru=0, sks=None, length=None, valid=None):
    """Fixed format sense data (0x70)."""
    b = bytearray(18)
    b[0] = 0x70 | (0x80 if (info is not None) else 0)
    b[2] = key
    if info is not None:
        struct.pack_into('>I', b, 3, info)
    b[7] = 10
    struct.pack_into('>I', b, 8, cmd_info)
    b[12] = asc
    b[13] = ascq
    b[14] = fru
    if sks is not None:
        b[15] = 0x80 | sks[0]
        b[16] = sks[1]
        b[17] = sks[2]
    return bytes(b)


def desc_sense(key, asc, ascq, descs=b''):
    return bytes([0x72, key, asc, ascq, 0, 0, 0, len(descs)]) + descs


def cdb_len(op):
    """CDB length from the opcode group (SPC-4 table 4)."""
    g = op >> 5
    return {0: 6, 1: 10, 2: 10, 3: 10, 4: 16, 5: 12, 6: 12, 7: 10}[g] if op != 0x7f else 10


def rand_cdb(rng, op, **fixed):
    """CDB with random fields; fixed={index: value} pins single bytes."""
    n = cdb_len(op)
    b = bytearray(rng.randrange(256) for _ in range(n))
    b[0] = op
    for k, v in fixed.items():
        b[int(k[1:])] = v
    return bytes(b)
