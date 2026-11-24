#!/usr/bin/env python3
# Generates test/captures/dcerpc_rdpdr_smartcard_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic captures for the RDPDR smart card dissector
# (packet-dcerpc-rdpdr_smartcard.c, [MS-RDPESC] calls packed with NDR) and
# its only caller, the RDPDR device redirection channel dissector
# (packet-rdp_dr.c).
#
# RDPDR runs in an RDP static virtual channel inside TLS, so the frames are
# Exported PDUs (link type 252) naming the "rdpdr" dissector, between the
# RDP client 192.0.2.1:50000 (which redirects its devices) and the server
# 192.0.2.2:3389.  The client announces a smart card, a file system and a
# printer; the server then sends smart card IOCTLs (IRP_MJ_DEVICE_CONTROL)
# whose NDR input buffers the smart card dissector decodes, and the client
# completes them with NDR output buffers.
#
# Every packet is built with struct; nothing comes from a real network.
#
# Usage: mkdcerpc_rdpdr_smartcard.py <outdir>
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))









import struct

from ndrenc import U32, I32, Raw, Ptr, Struct, CArr, CVStr, U16, ndr
from repro import reproducer_dir

C = bytes([192, 0, 2, 1])      # RDP client, redirects its devices
S = bytes([192, 0, 2, 2])      # RDP server
CPORT, SPORT = 50000, 3389

CORE, PRN = 0x4472, 0x5052
SERVER_ANNOUNCE, CLIENTID_CONFIRM, CLIENT_NAME = 0x496E, 0x4343, 0x434E
DEVICELIST_ANNOUNCE, DEVICE_REPLY = 0x4441, 0x6472
IOREQUEST, IOCOMPLETION = 0x4952, 0x4943
SERVER_CAPABILITY, CLIENT_CAPABILITY = 0x5350, 0x4350
DEVICELIST_REMOVE, USER_LOGGEDON = 0x444D, 0x554C
PRN_CACHE_DATA, PRN_USING_XPS = 0x5043, 0x5543

SCARD_ID, FS_ID, PRN_ID = 1, 2, 3

IRP_MJ_CREATE, IRP_MJ_CLOSE, IRP_MJ_READ, IRP_MJ_WRITE = 0, 2, 3, 4
IRP_MJ_QUERY_INFORMATION, IRP_MJ_SET_INFORMATION = 5, 6
IRP_MJ_QUERY_VOLUME_INFORMATION, IRP_MJ_SET_VOLUME_INFORMATION = 0xA, 0xB
IRP_MJ_DIRECTORY_CONTROL, IRP_MJ_DEVICE_CONTROL = 0xC, 0xE
IRP_MJ_LOCK_CONTROL = 0x11

ESTABLISHCONTEXT = 0x00090014
RELEASECONTEXT = 0x00090018
ISVALIDCONTEXT = 0x0009001C
LISTREADERSA = 0x00090028
LISTREADERSW = 0x0009002C
INTRODUCEREADERGROUPA = 0x00090050
INTRODUCEREADERGROUPW = 0x00090054
FORGETREADERGROUPA = 0x00090058
FORGETREADERGROUPW = 0x0009005C
INTRODUCEREADERA = 0x00090060
INTRODUCEREADERW = 0x00090064
FORGETREADERA = 0x00090068
FORGETREADERW = 0x0009006C
ADDREADERTOGROUPA = 0x00090070
ADDREADERTOGROUPW = 0x00090074
REMOVEREADERFROMGROUPA = 0x00090078
REMOVEREADERFROMGROUPW = 0x0009007C
LOCATECARDSA = 0x00090098
GETSTATUSCHANGEA = 0x000900A0
GETSTATUSCHANGEW = 0x000900A4
CANCEL = 0x000900A8
CONNECTA = 0x000900AC
CONNECTW = 0x000900B0
RECONNECT = 0x000900B4
DISCONNECT = 0x000900B8
BEGINTRANSACTION = 0x000900BC
ENDTRANSACTION = 0x000900C0
STATE = 0x000900C4
STATUSA = 0x000900C8
STATUSW = 0x000900CC
TRANSMIT = 0x000900D0
CONTROL = 0x000900D4
GETATTRIB = 0x000900D8
SETATTRIB = 0x000900DC
ACCESSSTARTEDEVENT = 0x000900E0
READCACHEA = 0x000900F0
READCACHEW = 0x000900F4
WRITECACHEA = 0x000900F8
WRITECACHEW = 0x000900FC
GETDEVICETYPEID = 0x00090108


def tlv(t, v):
    pad = (4 - len(v) % 4) % 4
    return struct.pack('>HH', t, len(v) + pad) + v + b'\0' * pad


def exp_pdu(name, payload, src=None, dst=None, sport=None, dport=None):
    t = tlv(12, name.encode())
    if src:
        t += tlv(20, src) + tlv(21, dst)
    if sport is not None:
        t += tlv(24, struct.pack('>I', 2))          # EXP_PDU_PT_TCP
        t += tlv(25, struct.pack('>I', sport)) + tlv(26, struct.pack('>I', dport))
    return t + struct.pack('>HH', 0, 0) + payload


def to_client(pdu):
    return exp_pdu('rdpdr', pdu, S, C, SPORT, CPORT)


def to_server(pdu):
    return exp_pdu('rdpdr', pdu, C, S, CPORT, SPORT)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def read_pcap(path):
    d = open(path, 'rb').read()
    off, out = 24, []
    while off < len(d):
        n = struct.unpack_from('<I', d, off + 8)[0]
        out.append(d[off + 16:off + 16 + n])
        off += 16 + n
    return out


def hdr(component, packet_id):
    return struct.pack('<HH', component, packet_id)


# ---------------------------------------------------------------------------
# RDPDR core packets

def device(dtype, dev_id, name, data=b''):
    return struct.pack('<II', dtype, dev_id) + name.ljust(8, b'\0') + struct.pack('<I', len(data)) + data


def devicelist(devs):
    return hdr(CORE, DEVICELIST_ANNOUNCE) + struct.pack('<I', len(devs)) + b''.join(devs)


def ioreq(dev_id, file_id, cid, major, minor=0, body=b''):
    return hdr(CORE, IOREQUEST) + struct.pack('<IIIII', dev_id, file_id, cid, major, minor) + body


def devctl(dev_id, cid, code, inbuf, outlen=2048):
    body = struct.pack('<III', outlen, len(inbuf), code) + b'\0' * 20 + inbuf
    return ioreq(dev_id, 1, cid, IRP_MJ_DEVICE_CONTROL, 0, body)


def iocompl(dev_id, cid, status=0, body=b''):
    return hdr(CORE, IOCOMPLETION) + struct.pack('<III', dev_id, cid, status) + body


def capability(packet_id, caps):
    out = hdr(CORE, packet_id) + struct.pack('<HH', len(caps), 0)
    for ctype, version, data in caps:
        out += struct.pack('<HHI', ctype, 8 + len(data), version) + data
    return out


def general_cap(version):
    d = struct.pack('<IIHHIIIII', 2, 0x000a0000, 1, 0x000c, 0xffff, 0, 7, 1, 0)
    if version == 2:
        d += struct.pack('<I', 1)
    return (1, version, d)


# ---------------------------------------------------------------------------
# Smart card NDR

TYPE_HDR = bytes([1, 0x10, 8, 0]) + b'\xcc' * 4


def scard_in(node):
    """IOCTL input buffer: type header, private header, NDR."""
    body = ndr(node, b'\0' * 16)[16:]
    return TYPE_HDR + struct.pack('<II', len(body), 0) + body


def scard_out(node, rc=0):
    """IOCTL output buffer: OutputBufferLength, type header, private
    header (its filler is shown as the return code), NDR."""
    body = ndr(node, b'\0' * 20)[20:]
    out = TYPE_HDR + struct.pack('<Ii', len(body), rc) + body
    return struct.pack('<I', len(out)) + out


def ctx(n=4, seed=0x10):          # REDIR_SCARDCONTEXT
    if n is None:
        return Struct(U32(0), Ptr(None))
    return Struct(U32(n), Ptr(CArr(bytes(range(seed, seed + n)))))


def hcard(n=4):                   # REDIR_SCARDHANDLE
    return Struct(ctx(), U32(n), Ptr(CArr(bytes(range(0x20, 0x20 + n)))))


def stra(text):                   # [string] char *
    return Ptr(CVStr(text, nul=True, width=1))


def strw(text):                   # [string] wchar_t *
    return Ptr(CVStr(text, nul=True))


def common_state(cur, ev, atr):
    return Struct(U32(cur), U32(ev), U32(len(atr)), Raw(atr.ljust(36, b'\0')))


ATR = bytes.fromhex('3bfe1800008031fe45803180664090a4162a0083019000e1')
READER = 'Example Reader 0'


def calls():
    """(ioControlCode, request NDR or raw bytes or None, response NDR or None)."""
    c = []
    c.append((ESTABLISHCONTEXT, Struct(U32(2)), Struct(I32(0), ctx())))
    c.append((ISVALIDCONTEXT, Struct(ctx()), Struct(I32(0))))
    c.append((LISTREADERSA,
              Struct(ctx(), U32(9), Ptr(CVStr('SCard$', nul=True, width=1)), I32(0), U32(0xffffffff)),
              Struct(I32(0), U32(len(READER) + 2), Ptr(CArr(READER.encode() + b'\0\0')))))
    groups = [ord(x) for x in 'SCard$AllReaders'] + [0, 0]
    c.append((LISTREADERSW,
              Struct(ctx(), U32(2 * len(groups)), Ptr(CArr([U16(x) for x in groups])), I32(0), U32(0xffffffff)),
              Struct(I32(0), U32(2 * len(READER) + 4), Ptr(CArr(READER.encode('utf-16-le') + b'\0' * 4)))))
    # ListReaders with NULL groups and an empty result
    c.append((LISTREADERSA, Struct(ctx(), U32(0), Ptr(None), I32(1), U32(0)),
              Struct(I32(-2146435026), U32(0), Ptr(None))))
    c.append((GETDEVICETYPEID, Struct(ctx(), strw(READER)), Struct(I32(0), U32(0x1f))))
    c.append((GETSTATUSCHANGEA,
              Struct(ctx(), U32(0xffffffff), U32(2), Ptr(CArr([
                  Struct(stra(READER), common_state(0, 0, b'')),
                  Struct(stra('\\\\?PnP?\\Notification'), common_state(0x10, 0, b''))]))),
              Struct(I32(0), U32(2), Ptr(CArr([common_state(0x22, 0x122, ATR),
                                               common_state(0x10, 0x10, b'')])))))
    c.append((GETSTATUSCHANGEW,
              Struct(ctx(), U32(1000), U32(1), Ptr(CArr([
                  Struct(strw(READER), common_state(0x22, 0, ATR))]))),
              Struct(I32(0), U32(1), Ptr(CArr([common_state(0x22, 0x22, ATR)])))))
    c.append((CONNECTA, Struct(stra(READER), Struct(ctx(), U32(2), U32(3))),
              Struct(I32(0), hcard(), U32(2))))
    c.append((CONNECTW, Struct(strw(READER), Struct(ctx(), U32(2), U32(3))),
              Struct(I32(0), hcard(), U32(1))))
    c.append((BEGINTRANSACTION, Struct(hcard(), U32(0)), Struct(I32(0))))
    c.append((STATE, Struct(hcard(), I32(0), U32(36)), None))
    c.append((STATUSA, Struct(hcard(), I32(0), U32(64), U32(32)),
              Struct(I32(0), U32(len(READER) + 2), Ptr(CArr(READER.encode() + b'\0\0')),
                     U32(6), U32(2), Raw(ATR.ljust(32, b'\0')), U32(len(ATR)))))
    c.append((STATUSW, Struct(hcard(), I32(1), U32(0), U32(32)),
              Struct(I32(0), U32(0), Ptr(None), U32(6), U32(2), Raw(ATR.ljust(32, b'\0')), U32(len(ATR)))))
    apdu = bytes.fromhex('00a4040007a0000000041010')
    c.append((TRANSMIT,
              Struct(hcard(), Struct(U32(2), U32(0), Ptr(None)), U32(len(apdu)), Ptr(CArr(apdu)),
                     Ptr(Struct(U32(2), U32(4), Ptr(CArr(b'\x01\x02\x03\x04')))), I32(0), U32(258)),
              Struct(I32(0), Ptr(Struct(U32(2), U32(0), Ptr(None))), U32(4), Ptr(CArr(b'\x6f\x10\x90\x00')))))
    c.append((TRANSMIT,
              Struct(hcard(), Struct(U32(1), U32(2), Ptr(CArr(b'\xaa\xbb'))), U32(5), Ptr(CArr(b'\x00\xb0\x00\x00\x00')),
                     Ptr(None), I32(1), U32(0)),
              Struct(I32(0), Ptr(None), U32(0), Ptr(None))))
    c.append((GETATTRIB, Struct(hcard(), U32(0x00090303), I32(0), U32(36)),
              Struct(I32(0), U32(len(ATR)), Ptr(CArr(ATR)))))
    c.append((READCACHEA, Struct(stra('Cache/A'), Struct(ctx(), U32(1), I32(0), U32(64))),
              Struct(I32(0), U32(8), Ptr(CArr(b'cachedat')))))
    c.append((READCACHEW, Struct(strw('Cache/W'), Struct(ctx(), U32(2), I32(1), U32(0))),
              Struct(I32(-2146434967), U32(0), Ptr(None))))
    c.append((WRITECACHEA, Struct(stra('Cache/A'), Struct(ctx(), U32(3), U32(8), Ptr(CArr(b'cachedat')))),
              Struct(I32(0))))
    c.append((WRITECACHEW, Struct(strw('Cache/W'), Struct(ctx(), U32(4), U32(0), Ptr(None))),
              Struct(I32(0))))
    c.append((RECONNECT, Struct(hcard(), U32(2), U32(3), U32(1)), Struct(I32(0), U32(2))))
    c.append((ENDTRANSACTION, Struct(hcard(), U32(0)), Struct(I32(0))))
    c.append((DISCONNECT, Struct(hcard(), U32(0)), Struct(I32(0))))
    c.append((CANCEL, Struct(ctx()), Struct(I32(0))))
    c.append((ACCESSSTARTEDEVENT, struct.pack('<I', 0), Struct(I32(0))))
    # Codes whose request the dissector does not decode; the response is
    # a long_Return for most of them, not decoded for the rest
    for code in (INTRODUCEREADERGROUPA, INTRODUCEREADERGROUPW,
                 FORGETREADERGROUPA, FORGETREADERGROUPW, INTRODUCEREADERA,
                 INTRODUCEREADERW, FORGETREADERA, FORGETREADERW,
                 ADDREADERTOGROUPA, ADDREADERTOGROUPW,
                 REMOVEREADERFROMGROUPA, REMOVEREADERFROMGROUPW, SETATTRIB):
        c.append((code, Struct(ctx(), strw('Group')), Struct(I32(0))))
    c.append((LOCATECARDSA, Struct(ctx(), U32(0), Ptr(None), U32(0), Ptr(None)),
              Struct(I32(0), U32(0), Ptr(None))))
    c.append((CONTROL, Struct(hcard(), U32(0x313520), U32(0), Ptr(None), I32(0), U32(0)),
              Struct(I32(0), U32(0), Ptr(None))))
    # A NULL context
    c.append((RELEASECONTEXT, Struct(ctx(None)), Struct(I32(0))))
    return c


REPRO = reproducer_dir(os.path.dirname(os.path.abspath(__file__)),
                       ['rdpdr_smartcard_leak.py', ('rdpdr_smartcard_fuzz.py', ['3'])])


def main_frames():
    fr = []
    fr.append(to_client(hdr(CORE, SERVER_ANNOUNCE) + struct.pack('<HHI', 1, 13, 7)))
    fr.append(to_server(hdr(CORE, CLIENTID_CONFIRM) + struct.pack('<HHI', 1, 13, 7)))
    fr.append(to_server(hdr(CORE, CLIENT_NAME) + struct.pack('<III', 1, 0, 8) + 'HOST'.encode('utf-16-le')))
    fr.append(to_client(capability(SERVER_CAPABILITY, [
        general_cap(2), (2, 1, b''), (3, 1, b''), (4, 2, b''), (5, 1, b'')])))
    fr.append(to_server(capability(CLIENT_CAPABILITY, [general_cap(1), (5, 1, b''), (9, 1, b'')])))
    fr.append(to_client(hdr(CORE, USER_LOGGEDON)))
    fr.append(to_server(devicelist([
        device(0x20, SCARD_ID, b'SCARD'),
        device(0x08, FS_ID, b'C:', b'C:\0'),
        device(0x04, PRN_ID, b'PRN1', b'\0' * 24)])))
    fr.append(to_client(hdr(CORE, DEVICE_REPLY) + struct.pack('<II', SCARD_ID, 0)))
    fr.append(to_client(hdr(CORE, DEVICE_REPLY) + struct.pack('<II', FS_ID, 0)))
    fr.append(to_client(hdr(CORE, DEVICE_REPLY) + struct.pack('<II', 99, 0xc0000001)))
    # File system I/O: every major function the dissector names
    cid = 100
    fs_ops = [(IRP_MJ_CREATE, b'\0' * 32), (IRP_MJ_READ, struct.pack('<IQ', 512, 0) + b'\0' * 20),
              (IRP_MJ_WRITE, struct.pack('<IQ', 4, 0) + b'\0' * 20 + b'data'),
              (IRP_MJ_QUERY_VOLUME_INFORMATION, struct.pack('<II', 1, 0) + b'\0' * 24),
              (IRP_MJ_SET_VOLUME_INFORMATION, struct.pack('<II', 2, 0) + b'\0' * 24),
              (IRP_MJ_QUERY_INFORMATION, struct.pack('<II', 4, 0) + b'\0' * 24),
              (IRP_MJ_SET_INFORMATION, struct.pack('<II', 4, 0) + b'\0' * 24),
              (IRP_MJ_DIRECTORY_CONTROL, struct.pack('<IB', 3, 1) + b'\0' * 23),
              (IRP_MJ_LOCK_CONTROL, struct.pack('<II', 1, 0) + b'\0' * 24),
              (IRP_MJ_DEVICE_CONTROL, struct.pack('<III', 0, 0, 0x00090000) + b'\0' * 20),
              (0x09, b''), (IRP_MJ_CLOSE, b'\0' * 32)]
    for major, body in fs_ops:
        fr.append(to_client(ioreq(FS_ID, 5, cid, major, 0, body)))
        resp = struct.pack('<IB', 5, 1) if major == IRP_MJ_CREATE else struct.pack('<I', 0)
        fr.append(to_server(iocompl(FS_ID, cid, 0, resp)))
        cid += 1
    # A create completed without the information octet
    fr.append(to_client(ioreq(FS_ID, 0, cid, IRP_MJ_CREATE, 0, b'\0' * 32)))
    fr.append(to_server(iocompl(FS_ID, cid, 0xc0000034)))
    cid += 1
    # A device nobody announced, and a completion nobody asked for
    fr.append(to_client(ioreq(77, 0, cid, IRP_MJ_READ, 0, b'\0' * 32)))
    fr.append(to_server(iocompl(77, cid, 0)))
    fr.append(to_server(iocompl(SCARD_ID, 9999, 0, scard_out(Struct(I32(0))))))
    # Smart card calls
    cid = 1
    for code, req, resp in calls():
        if isinstance(req, bytes):
            inbuf = req
        else:
            inbuf = scard_in(req)
        fr.append(to_client(devctl(SCARD_ID, cid, code, inbuf)))
        if resp is None:
            out = scard_out(Struct(I32(0), U32(6), U32(2), U32(0), Ptr(None)))
        else:
            out = scard_out(resp)
        fr.append(to_server(iocompl(SCARD_ID, cid, 0, out)))
        cid += 1
    # Printer redirection
    add = (hdr(PRN, PRN_CACHE_DATA) + struct.pack('<I', 1) + b'PRN1\0\0\0\0')
    pnp, drv, name, cached = ('PnP'.encode('utf-16-le') + b'\0\0', 'Driver'.encode('utf-16-le') + b'\0\0',
                              'Printer'.encode('utf-16-le') + b'\0\0', b'\x01\x02\x03\x04')
    add += struct.pack('<IIII', len(pnp), len(drv), len(name), len(cached)) + pnp + drv + name + cached
    fr.append(to_server(add))
    for ev in (2, 3, 4, 9):
        fr.append(to_server(hdr(PRN, PRN_CACHE_DATA) + struct.pack('<I', ev) + b'\0' * 8))
    fr.append(to_client(hdr(PRN, PRN_USING_XPS) + struct.pack('<II', PRN_ID, 0)))
    fr.append(to_client(hdr(PRN, PRN_USING_XPS) + struct.pack('<II', 42, 0)))
    fr.append(to_client(hdr(PRN, 0x1234)))
    # Unknown packet ID and component, device removal
    fr.append(to_client(hdr(CORE, 0x1234)))
    fr.append(to_client(hdr(0x5555, 0x1234)))
    fr.append(to_server(hdr(CORE, DEVICELIST_REMOVE) + struct.pack('<II', 1, PRN_ID)))
    # Reproducers of the fix on the branch (frames copied verbatim; their
    # Exported PDUs have addresses but no ports, so they are a conversation
    # of their own with their own smart card announce)
    fr += read_pcap(os.path.join(REPRO, 'rdpdr_smartcard_leak.pcap'))[:3]
    return fr


def malformed_frames():
    fr = [to_server(devicelist([device(0x20, SCARD_ID, b'SCARD')]))]
    cid = 1
    for code, req, resp in calls():
        if isinstance(req, bytes):
            continue
        inbuf = scard_in(req)
        fr.append(to_client(devctl(SCARD_ID, cid, code, inbuf[:-3])))
        if resp is not None:
            out = scard_out(resp)
            fr.append(to_server(iocompl(SCARD_ID, cid, 0, out[:-3])))
        cid += 1
    # Random NDR bodies for every IOCTL (rdpdr_smartcard_fuzz.pcap, seed 1)
    fr += read_pcap(os.path.join(REPRO, 'rdpdr_smartcard_fuzz.pcap'))
    # Truncated core packets
    fr.append(to_server(hdr(CORE, DEVICELIST_ANNOUNCE) + struct.pack('<I', 3) + device(0x20, 5, b'X')))
    fr.append(to_client(hdr(CORE, IOREQUEST) + struct.pack('<II', SCARD_ID, 0)))
    fr.append(to_client(capability(SERVER_CAPABILITY, [general_cap(2)])[:-6]))
    fr.append(to_server(hdr(PRN, PRN_CACHE_DATA) + struct.pack('<I', 1) + b'PRN1\0\0\0\0' +
                        struct.pack('<IIII', 100, 0, 0, 0)))
    fr.append(to_client(b'\x72'))
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dcerpc-rdpdr_smartcard-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dcerpc-rdpdr_smartcard-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
