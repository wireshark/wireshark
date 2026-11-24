#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic ZigBee Device Profile (ZDP) message builders for the coverage
# captures of packet-zbee-zdp*.c.  Everything here is generated with struct;
# no key material or ciphertext is produced.
#
# Path: 802.15.4 (linktype 230, no FCS) -> ZigBee NWK heuristic -> APS data
# frame, profile 0 (ZDP) -> ZDP.  NWK protocol version 2 is ZigBee 2007 and
# later, version 1 is ZigBee 2004/2003 (8-bit cluster ids, other layouts).
import struct

LINKTYPE_IEEE802_15_4_NOFCS = 230


def write_pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


class Seq:
    n = 0

    @classmethod
    def next(cls):
        cls.n = (cls.n + 1) & 0xff
        return cls.n


def wpan_zdp(cluster, body, ver=2, src=0x0001, dst=0x0000):
    """Wrap a ZDP body (without the sequence number) into an 802.15.4 frame.

    For NWK version 1 (ZigBee 2004) the APS payload goes through the
    Application Framework: 0x21 (message, count 1), then per transaction
    the sequence number, a length byte and the message.  The ZDP
    dissector gets the transaction including the length byte, so the
    length byte plays the role of the first body byte.  To get a clean
    decode the first body byte is set to the number of bytes after it
    (the dissector shows it as the first field, a status or the low
    byte of an address)."""
    seq = Seq.next()
    wpan = struct.pack('<HBHHH', 0x8841, seq, 0x1a62, dst, src)
    nwk = struct.pack('<HHHBB', ver << 2, dst, src, 30, seq)
    if ver >= 2:
        aps = struct.pack('<BBHHBB', 0x00, 0x00, cluster, 0x0000, 0x00, seq)
        return wpan + nwk + aps + bytes([seq]) + body
    c8 = (cluster & 0x7f) | (0x80 if cluster & 0x8000 else 0)
    aps = struct.pack('<BBBHB', 0x00, 0x00, c8, 0x0000, 0x00)
    return wpan + nwk + aps + bytes([0x21, seq, len(body) - 1]) + body[1:]


def eui(n):
    return struct.pack('<Q', n)


def u8(*a):
    return bytes(a)


def u16(v):
    return struct.pack('<H', v)


def u32(v):
    return struct.pack('<I', v)


A1 = 0x00124b0001020304
A2 = 0x00124b00aabbccdd
A3 = 0x1122334455667788


def clusters(lst, ver=2):
    return b''.join(u16(c) if ver >= 2 else u8(c & 0xff) for c in lst)


def node_desc(ver=2, ntype=1, flags=0x0000, cinfo=0x8e, mfr=0x1049, maxbuf=80,
              maxin=128, server=0x2c40, maxout=128, dcf=0x03):
    d = u16((ntype & 7) | flags) + u8(cinfo) + u16(mfr) + u8(maxbuf) + u16(maxin)
    if ver >= 2:
        d += u16(server) + u16(maxout) + u8(dcf)
    return d


def power_desc(mode=0, avail=0x7, source=0x1, level=0xc):
    return u16(mode | (avail << 4) | (source << 8) | (level << 12))


def simple_desc(ep=1, profile=0x0104, dev=0x0100, appver=0, ins=(0x0000, 0x0006),
                outs=(0x0019,), ver=2):
    return (u8(ep) + u16(profile) + u16(dev) + u8(appver) + u8(len(ins)) +
            clusters(ins, ver) + u8(len(outs)) + clusters(outs, ver))


def bind_entry(ver=2, mode=3, src=A1, src_ep=1, cluster=0x0006, dst=A2, dst_ep=2,
               group=0x1234):
    e = eui(src) + u8(src_ep) + (u16(cluster) if ver >= 2 else u8(cluster & 0xff))
    if ver >= 2:
        e += u8(mode)
    else:
        mode = 3
    if mode == 1:
        e += u16(group)
    elif mode == 3:
        e += eui(dst) + u8(dst_ep)
    return e


def nwk_desc(ver=2, beacon=0x0f, chan=15, pan=A3):
    d = eui(pan) if ver >= 2 else u16(0x1a62)
    return d + u8(chan) + u8(0x21) + u8(beacon | 0x10) + u8(0x01)


def lqi_entry(ver=2, ntype=0x01, rel=0x1, idle=1, permit=1, depth=2, lqi=0xc8):
    if ver >= 2:
        return (eui(A3) + eui(A1) + u16(0x0001) +
                u8((ntype & 3) | (idle << 2) | (rel << 4)) + u8(permit) + u8(depth) + u8(lqi))
    return (u16(0x1a62) + eui(A1) + u16(0x0001) +
            u8((ntype & 3) | (idle << 2) | (rel << 3)) + u8(depth) + u8(permit) + u8(lqi))


def rtg_entry(dest=0x0003, status=0x3, nxt=0x0002):
    return u16(dest) + u8(status) + u16(nxt)


# TLV: tag, length-1, value.  Only a harmless local TLV with filler is used.
def tlv(tag, value):
    return u8(tag, len(value) - 1) + value


OK = 0
NOENT = 0x88
NODESC = 0x89
NOTSUP = 0x84


def frames_discovery():
    F = []
    A = lambda name, cl, body, ver=2: F.append((name, wpan_zdp(cl, body, ver)))
    # requests
    A('nwk_addr_req', 0x0000, eui(A1) + u8(0, 0))
    A('nwk_addr_req_ext', 0x0000, eui(A1) + u8(1, 2))
    A('ieee_addr_req', 0x0001, u16(0x1234) + u8(0, 0))
    A('ieee_addr_req_ext', 0x0001, u16(0x1234) + u8(1, 1))
    A('node_desc_req', 0x0002, u16(0x1234))
    A('node_desc_req_2003', 0x0002, u16(0x1234), 1)
    A('power_desc_req', 0x0003, u16(0x1234))
    A('simple_desc_req', 0x0004, u16(0x1234) + u8(1))
    A('active_ep_req', 0x0005, u16(0x1234))
    A('match_desc_req', 0x0006, u16(0xfffd) + u16(0x0104) + u8(2) + clusters([0x0006, 0x0008]) +
      u8(1) + clusters([0x0019]))
    A('match_desc_req_empty', 0x0006, u16(0xfffd) + u16(0xc05e) + u8(0) + u8(0))
    A('match_desc_req_2003', 0x0006, u16(0xfffd) + u16(0x0104) + u8(1) + clusters([0x06], 1) +
      u8(1) + clusters([0x19], 1), 1)
    A('complex_desc_req', 0x0010, u16(0x1234))
    A('user_desc_req', 0x0011, u16(0x1234))
    A('discovery_cache_req', 0x0012, u16(0x1234) + eui(A1))
    A('device_annce', 0x0013, u16(0x1234) + eui(A1) + u8(0x8e))
    A('device_annce_rfd', 0x0013, u16(0x4321) + eui(A2) + u8(0x00))
    A('set_user_desc_req', 0x0014, u16(0x1234) + u8(12) + b'kitchen lamp')
    A('set_user_desc_req_2003', 0x0014, u16(0x1234) + b'kitchen lamp\0\0\0\0', 1)
    A('system_server_disc_req', 0x0015, u16(0x0041))
    A('store_discovery_req', 0x0016, u16(0x1234) + eui(A1) + u8(13, 2, 2, 2, 9, 11))
    A('store_discovery_req_none', 0x0016, u16(0x1234) + eui(A1) + u8(13, 2, 0, 0))
    A('store_node_desc_req', 0x0017, u16(0x1234) + eui(A1) + node_desc())
    A('store_node_desc_req_2003', 0x0017, u16(0x1234) + eui(A1) + node_desc(1), 1)
    A('store_power_desc_req', 0x0018, u16(0x1234) + eui(A1) + power_desc())
    A('store_active_ep_req', 0x0019, u16(0x1234) + eui(A1) + u8(2, 1, 2))
    A('store_simple_desc_req', 0x001a, u16(0x1234) + eui(A1) + u8(18) + simple_desc())
    A('store_simple_desc_req_2003', 0x001a, u16(0x1234) + eui(A1) + u8(16) +
      simple_desc(ver=1), 1)
    A('remove_node_cache_req', 0x001b, u16(0x1234) + eui(A1))
    A('find_node_cache_req', 0x001c, u16(0x1234) + eui(A1))
    A('ext_simple_desc_req', 0x001d, u16(0x1234) + u8(1, 0))
    A('ext_active_ep_req', 0x001e, u16(0x1234) + u8(0))
    A('parent_annce_req', 0x001f, u8(2) + eui(A1) + eui(A2))
    A('parent_annce_req_one', 0x001f, u8(1) + eui(A1))
    A('parent_annce_req_none', 0x001f, u8(0))
    # responses
    A('nwk_addr_rsp', 0x8000, u8(OK) + eui(A1) + u16(0x1234))
    A('nwk_addr_rsp_assoc', 0x8000, u8(OK) + eui(A1) + u16(0x1234) + u8(2, 0) + u16(0x1111) + u16(0x2222))
    A('nwk_addr_rsp_assoc0', 0x8000, u8(OK) + eui(A1) + u16(0x1234) + u8(0, 0))
    A('nwk_addr_rsp_fail', 0x8000, u8(0x81) + eui(A1) + u16(0xffff))
    A('ieee_addr_rsp', 0x8001, u8(OK) + eui(A1) + u16(0x1234))
    A('ieee_addr_rsp_assoc', 0x8001, u8(OK) + eui(A1) + u16(0x1234) + u8(2, 0) + u16(0x1111) + u16(0x2222))
    A('ieee_addr_rsp_fail', 0x8001, u8(0x81) + eui(A1) + u16(0xffff))
    A('node_desc_rsp', 0x8002, u8(OK) + u16(0x1234) + node_desc(flags=0x0008 | 0x0010 | 0x0020 | 0x0100 | 0x0200 | 0x0400 | 0x0800))
    A('node_desc_rsp_coord', 0x8002, u8(OK) + u16(0x0000) + node_desc(ntype=0, server=0x0540))
    A('node_desc_rsp_rfd', 0x8002, u8(OK) + u16(0x4321) + node_desc(ntype=2, server=0x0000))
    A('node_desc_rsp_reserved', 0x8002, u8(OK) + u16(0x4321) + node_desc(ntype=3, server=0x2c00))
    A('node_desc_rsp_fail', 0x8002, u8(NODESC) + u16(0x1234))
    A('power_desc_rsp', 0x8003, u8(OK) + u16(0x1234) + power_desc())
    A('power_desc_rsp_fail', 0x8003, u8(NODESC) + u16(0x1234))
    A('simple_desc_rsp', 0x8004, u8(OK) + u16(0x1234) + u8(18) + simple_desc())
    A('simple_desc_rsp_zll', 0x8004, u8(OK) + u16(0x1234) + u8(14) + simple_desc(profile=0xc05e, dev=0x0100, ins=(0x0000,), outs=()))
    A('simple_desc_rsp_se', 0x8004, u8(OK) + u16(0x1234) + u8(14) + simple_desc(profile=0x0109, dev=0x0001, ins=(0x0700,), outs=()))
    A('simple_desc_rsp_none', 0x8004, u8(OK) + u16(0x1234) + u8(8) + simple_desc(profile=0x0104, dev=0x0000, ins=(), outs=()))
    A('simple_desc_rsp_fail', 0x8004, u8(0x82) + u16(0x1234) + u8(0))
    A('active_ep_rsp', 0x8005, u8(OK) + u16(0x1234) + u8(3, 1, 2, 242))
    A('active_ep_rsp_none', 0x8005, u8(OK) + u16(0x1234) + u8(0))
    A('match_desc_rsp', 0x8006, u8(OK) + u16(0x1234) + u8(2, 1, 5))
    A('match_desc_rsp_none', 0x8006, u8(0x86) + u16(0x1234) + u8(0))
    A('complex_desc_rsp_lang', 0x8010, u8(OK) + u16(0x1234) + u8(4) + u8(1) + b'en' + u8(0))
    A('complex_desc_rsp_lang_other', 0x8010, u8(OK) + u16(0x1234) + u8(4) + u8(1) + b'\x01\xff' + u8(5))
    for tag, name in ((2, 'mfr'), (3, 'model'), (4, 'serial'), (5, 'url'), (7, 'icon_url'), (8, 'reserved')):
        A('complex_desc_rsp_' + name, 0x8010, u8(OK) + u16(0x1234) + u8(8) + u8(tag) + b'Acme-42')
    A('complex_desc_rsp_icon', 0x8010, u8(OK) + u16(0x1234) + u8(3) + u8(6) + b'\x00\x01')
    A('complex_desc_rsp_empty', 0x8010, u8(OK) + u16(0x1234) + u8(0))
    A('complex_desc_rsp_fail', 0x8010, u8(NODESC) + u16(0x1234) + u8(0))
    A('complex_desc_rsp_fail_short', 0x8010, u8(NOTSUP))
    A('user_desc_rsp', 0x8011, u8(OK) + u16(0x1234) + u8(12) + b'kitchen lamp')
    A('user_desc_rsp_fail', 0x8011, u8(NODESC) + u16(0x1234) + u8(0))
    A('user_desc_rsp_2003_fail', 0x8011, u8(NODESC) + u16(0x1234), 1)  # status becomes 2
    A('user_desc_conf', 0x8014, u8(OK) + u16(0x1234))
    A('user_desc_conf_2003', 0x8014, u8(OK), 1)
    A('discovery_cache_rsp', 0x8012, u8(OK))
    A('system_server_disc_rsp', 0x8015, u8(OK) + u16(0x0041))
    A('system_server_disc_rsp_fail', 0x8015, u8(NOTSUP))
    for cl in range(0x8016, 0x801b):
        A('store_rsp_%04x' % cl, cl, u8(OK))
    A('remove_node_cache_rsp', 0x801b, u8(OK))
    A('find_node_cache_rsp', 0x801c, u16(0x1234) + u16(0x1234) + eui(A1))
    A('ext_simple_desc_rsp', 0x801d, u8(OK) + u16(0x1234) + u8(1, 2, 1, 0) + clusters([6, 8]) + clusters([0x19]))
    A('ext_simple_desc_rsp_idx', 0x801d, u8(OK) + u16(0x1234) + u8(1, 2, 1, 1) + clusters([8]) + clusters([0x19]))
    A('ext_simple_desc_rsp_fail', 0x801d, u8(0x82) + u16(0x1234))
    A('ext_active_ep_rsp', 0x801e, u8(OK) + u16(0x1234) + u8(3, 0, 1, 2, 3))
    A('ext_active_ep_rsp_idx', 0x801e, u8(OK) + u16(0x1234) + u8(3, 1, 2, 3))
    A('ext_active_ep_rsp_none', 0x801e, u8(OK) + u16(0x1234) + u8(0, 0))
    A('ext_active_ep_rsp_fail', 0x801e, u8(0x81))
    A('parent_annce_rsp', 0x801f, u8(OK, 2) + eui(A1) + eui(A2))
    A('parent_annce_rsp_one', 0x801f, u8(OK, 1) + eui(A1))
    return F


def frames_binding():
    F = []
    A = lambda name, cl, body, ver=2: F.append((name, wpan_zdp(cl, body, ver)))
    A('end_device_bind_req', 0x0020, u16(0x0000) + eui(A1) + u8(1) + u16(0x0104) + u8(1) + clusters([6]) +
      u8(1) + clusters([8]))
    A('end_device_bind_req_many', 0x0020, u16(0x0000) + eui(A1) + u8(2) + u16(0x0104) +
      u8(2) + clusters([6, 8]) + u8(3) + clusters([0x19, 0x0a, 0x0b]))
    A('end_device_bind_req_none', 0x0020, u16(0x0000) + eui(A1) + u8(2) + u16(0xc05e) + u8(0) + u8(0))
    A('end_device_bind_req_2003', 0x0020, u16(0x0000) + u8(1) + u16(0x0104) + u8(1) + clusters([6], 1) +
      u8(1) + clusters([8], 1), 1)
    for nm, ver in (('', 2), ('_2003', 1)):
        for mode, tag in ((3, 'ucast'), (1, 'group'), (0, 'nodst')):
            body = eui(A1) + u8(1) + (u16(6) if ver >= 2 else u8(6))
            if ver >= 2:
                body += u8(mode)
            if mode == 1 and ver >= 2:
                body += u16(0x1234)
            elif mode == 3 or ver < 2:
                body += eui(A2) + u8(2)
            if ver < 2 and mode != 3:
                continue
            A('bind_req_%s%s' % (tag, nm), 0x0021, body, ver)
            A('unbind_req_%s%s' % (tag, nm), 0x0022, body, ver)
    A('bind_register_req', 0x0023, eui(A1))
    A('replace_device_req', 0x0024, eui(A1) + u8(1) + eui(A2) + u8(2))
    for mode, tag in ((3, 'ucast'), (1, 'group'), (0, 'nodst')):
        body = eui(A1) + u8(1) + u16(6) + u8(mode)
        if mode == 1:
            body += u16(0x1234)
        elif mode == 3:
            body += eui(A2) + u8(2)
        A('store_bak_bind_entry_req_%s' % tag, 0x0025, body)
        A('remove_bak_bind_entry_req_%s' % tag, 0x0026, body)
    A('store_bak_bind_entry_req_2003', 0x0025, eui(A1) + u8(1) + u8(6) + u8(3) + eui(A2) + u8(2), 1)
    A('remove_bak_bind_entry_req_2003', 0x0026, eui(A1) + u8(1) + u8(6) + u8(3) + eui(A2) + u8(2), 1)
    ents = bind_entry() + bind_entry(mode=1) + bind_entry(mode=0)
    A('backup_bind_table_req', 0x0027, u16(5) + u16(0) + u16(3) + ents)
    A('backup_bind_table_req_2003', 0x0027, u16(2) + u16(0) + u16(2) + bind_entry(1) + bind_entry(1, src_ep=2), 1)
    A('backup_bind_table_req_empty', 0x0027, u16(0) + u16(0) + u16(0))
    A('recover_bind_table_req', 0x0028, u16(0))
    A('backup_source_bind_req', 0x0029, u16(3) + u16(0) + u16(3) + eui(A1) + eui(A2) + eui(A3))
    A('recover_source_bind_req', 0x002a, u16(0))
    A('clear_all_bindings_req', 0x002b, b'')
    A('clear_all_bindings_req_tlv', 0x002b, tlv(0x70, b'\x00\x01'))
    # responses
    for cl, nm in ((0x8020, 'end_device_bind'), (0x8021, 'bind'), (0x8022, 'unbind'),
                   (0x8024, 'replace_device'), (0x8025, 'store_bak_bind_entry'),
                   (0x8026, 'remove_bak_bind_entry'), (0x8029, 'backup_source_bind'),
                   (0x802b, 'clear_all_bindings')):
        A(nm + '_rsp', cl, u8(OK))
    A('bind_rsp_fail', 0x8021, u8(0x8e))
    A('end_device_bind_rsp_fail', 0x8020, u8(0x86))
    A('bind_register_rsp', 0x8023, u8(OK) + u16(4) + u16(2) + bind_entry() + bind_entry(mode=1))
    A('bind_register_rsp_empty', 0x8023, u8(OK) + u16(4) + u16(0))
    A('bind_register_rsp_fail', 0x8023, u8(0x8c))
    A('backup_bind_table_rsp', 0x8027, u8(OK) + u16(5))
    A('backup_bind_table_rsp_fail', 0x8027, u8(0x8c))
    A('recover_bind_table_rsp', 0x8028, u8(OK) + u16(5) + u16(0) + u16(2) + bind_entry() + bind_entry(mode=1))
    A('recover_bind_table_rsp_empty', 0x8028, u8(OK) + u16(0) + u16(0) + u16(0))
    A('recover_bind_table_rsp_2003', 0x8028, u8(OK) + u16(1) + u16(0) + u16(1) + bind_entry(1), 1)
    A('recover_bind_table_rsp_fail', 0x8028, u8(0x88))
    A('recover_source_bind_rsp', 0x802a, u8(OK) + u16(3) + u16(0) + u16(2) + eui(A1) + eui(A2))
    A('recover_source_bind_rsp_empty', 0x802a, u8(OK) + u16(0) + u16(0) + u16(0))
    A('recover_source_bind_rsp_fail', 0x802a, u8(0x88))
    return F


def frames_management():
    F = []
    A = lambda name, cl, body, ver=2: F.append((name, wpan_zdp(cl, body, ver)))
    A('mgmt_nwk_disc_req', 0x0030, u32(0x07fff800) + u8(3, 0))
    A('mgmt_nwk_disc_req_sparse', 0x0030, u32(0x00108421) + u8(5, 4))
    A('mgmt_nwk_disc_req_none', 0x0030, u32(0) + u8(3, 0))
    A('mgmt_nwk_disc_req_top', 0x0030, u32(0x07ffffff) + u8(3, 0))
    A('mgmt_lqi_req', 0x0031, u8(0))
    A('mgmt_rtg_req', 0x0032, u8(0))
    A('mgmt_bind_req', 0x0033, u8(0))
    A('mgmt_leave_req', 0x0034, eui(A1) + u8(0x40))
    A('mgmt_leave_req_both', 0x0034, eui(A1) + u8(0xc0))
    A('mgmt_leave_req_2003', 0x0034, eui(A1), 1)
    A('mgmt_direct_join_req', 0x0035, eui(A1) + u8(0x8e))
    A('mgmt_permit_join_req', 0x0036, u8(60, 1))
    A('mgmt_permit_join_req_tlv', 0x0036, u8(0, 1) + tlv(0x70, b'\x00\x01'))
    A('mgmt_cache_req', 0x0037, u8(0))
    A('mgmt_nwkupdate_req_scan', 0x0038, u32(0x07fff800) + u8(3, 2))
    A('mgmt_nwkupdate_req_scan0', 0x0038, u32(0x00108421 | (1 << 27)) + u8(0, 1))
    A('mgmt_nwkupdate_req_hop', 0x0038, u32(0x00008000) + u8(0xfe, 7))
    A('mgmt_nwkupdate_req_params', 0x0038, u32(0x00008000) + u8(0xff, 8) + u16(0x0000))
    A('mgmt_nwkupdate_req_other', 0x0038, u32(0x00000800) + u8(0x20))
    A('mgmt_nwkupdate_req_none', 0x0038, u32(0) + u8(0x20))
    A('mgmt_nwkupdate_enh_req_scan', 0x0039, u8(2) + u32(0x07fff800) + u32(0x08000000 | 0x3ff) + u8(3, 2))
    A('mgmt_nwkupdate_enh_req_hop', 0x0039, u8(1) + u32(0x00008000) + u8(0xfe, 7))
    A('mgmt_nwkupdate_enh_req_params', 0x0039, u8(1) + u32(0x00008000) + u8(0xff, 8) + u16(0x0000))
    A('mgmt_nwkupdate_enh_req_other', 0x0039, u8(0) + u8(0x20))
    A('mgmt_ieee_join_list_req', 0x003a, u8(0))
    A('mgmt_beacon_survey_req', 0x003c, b'')
    for cl in (0x0040, 0x0041, 0x0042, 0x0043, 0x0045, 0x0046, 0x0047):
        A('security_req_%04x' % cl, cl, b'')
    A('security_get_config_req', 0x0044, u8(2, 0x01, 0x02))
    A('security_get_config_req_none', 0x0044, b'')
    # responses
    A('mgmt_nwk_disc_rsp', 0x8030, u8(OK, 2, 0, 2) + nwk_desc() + nwk_desc(beacon=0x05, chan=20))
    A('mgmt_nwk_disc_rsp_2003', 0x8030, u8(OK, 1, 0, 1) + nwk_desc(1), 1)
    A('mgmt_nwk_disc_rsp_none', 0x8030, u8(OK, 0, 0, 0))
    A('mgmt_lqi_rsp', 0x8031, u8(OK, 2, 0, 2) + lqi_entry() + lqi_entry(ntype=0, rel=0, idle=0))
    A('mgmt_lqi_rsp_2003', 0x8031, u8(OK, 1, 0, 1) + lqi_entry(1), 1)
    A('mgmt_lqi_rsp_none', 0x8031, u8(OK, 0, 0, 0))
    A('mgmt_rtg_rsp', 0x8032, u8(OK, 3, 0, 3) + rtg_entry() + rtg_entry(status=0x1, dest=4) + rtg_entry(status=0x7, dest=5))
    A('mgmt_rtg_rsp_none', 0x8032, u8(OK, 0, 0, 0))
    A('mgmt_bind_rsp', 0x8033, u8(OK, 3, 0, 3) + bind_entry() + bind_entry(mode=1) + bind_entry(mode=0))
    A('mgmt_bind_rsp_2003', 0x8033, u8(OK, 1, 0, 1) + bind_entry(1), 1)
    A('mgmt_bind_rsp_none', 0x8033, u8(OK, 0, 0, 0))
    A('mgmt_leave_rsp', 0x8034, u8(OK))
    A('mgmt_direct_join_rsp', 0x8035, u8(OK))
    A('mgmt_permit_join_rsp', 0x8036, u8(OK))
    A('mgmt_cache_rsp', 0x8037, u8(OK, 2, 0, 2) + eui(A1) + u16(0x1111) + eui(A2) + u16(0x2222))
    A('mgmt_cache_rsp_none', 0x8037, u8(OK, 0, 0, 0))
    A('mgmt_nwkupdate_notify', 0x8038, u8(OK) + u32(0x00018000 | 0) + u16(100) + u16(3) + u8(2) + u8(0x40, 0x80))
    A('mgmt_nwkupdate_notify_page', 0x8038, u8(OK) + u32((2 << 27) | 0x0000c000) + u16(10) + u16(0) + u8(2) + u8(0x10, 0x20))
    A('mgmt_nwkupdate_notify_short', 0x8038, u8(OK) + u32(0x0001c000) + u16(10) + u16(1) + u8(2) + u8(0x10, 0x20))
    A('mgmt_nwkupdate_notify_nochan', 0x8038, u8(OK) + u32(0) + u16(0) + u16(0) + u8(0))
    A('mgmt_nwkupdate_enh_notify', 0x8039, u8(OK) + u32(0x00018000) + u16(100) + u16(3) + u8(2) + u8(0x40, 0x80))
    A('mgmt_ieee_join_list_rsp', 0x803a, u8(OK, 5, 1, 2, 0, 2) + eui(A1) + eui(A2))
    A('mgmt_ieee_join_list_rsp_empty', 0x803a, u8(OK, 5, 1, 0))
    A('mgmt_ieee_join_list_rsp_fail', 0x803a, u8(NOTSUP))
    A('mgmt_unsolicited_nwkupdate', 0x803b, u8(OK) + u32(0x00018000) + u16(100) + u16(3) + u16(7) + u8(5))
    A('mgmt_beacon_survey_rsp', 0x803c, u8(OK))
    for cl in range(0x8040, 0x8048):
        A('security_rsp_%04x' % cl, cl, u8(OK))
    return F


def frames_core():
    """Extra frames for packet-zbee-zdp.c itself: the descriptor helpers,
    the 2003 cluster mapping and the default branch of the dispatcher."""
    F = []
    A = lambda name, cl, body, ver=2: F.append((name, wpan_zdp(cl, body, ver)))
    # node descriptor: every type and flag
    for nt in range(4):
        A('node_desc_type%d' % nt, 0x8002, u8(OK) + u16(0x1234) + node_desc(ntype=nt, flags=(0x0ff8 if nt == 2 else 0)))
    A('node_desc_rev', 0x8002, u8(OK) + u16(0x1234) + node_desc(server=0x2c00 | (21 << 9)))
    # channel mask helper (page and ranges, via Network Update)
    for page in range(0, 32, 5):
        A('chan_page%d' % page, 0x0038, u32((page << 27) | 0x07fff800) + u8(2, 1))
    A('chan_one', 0x0038, u32(1 << 11) + u8(2, 1))
    A('chan_two_adjacent', 0x0038, u32(3 << 11) + u8(2, 1))
    A('chan_pair_gap', 0x0038, u32((1 << 11) | (1 << 13) | (3 << 20)) + u8(2, 1))
    A('chan_top', 0x0038, u32(1 << 26) + u8(2, 1))
    A('chan_low', 0x0038, u32(1 << 0) + u8(2, 1))
    A('chan_all', 0x0038, u32(0x07ffffff) + u8(2, 1))
    # an unknown cluster reaches the default branch
    A('unknown_cluster', 0x0099, b'\x01\x02\x03')
    A('unknown_cluster_rsp', 0x8099, b'\x01\x02\x03')
    A('unknown_cluster_2003', 0x0070, b'\x01\x02', 1)
    return F


def truncated(frames, skip=26):
    """Malformed variants: every frame cut one byte short and cut in the
    middle of its ZDP message (the lengths are all derived from the data,
    so the dissector runs off the end)."""
    out = []
    for fr in frames:
        n = len(fr)
        cuts = {n - 1, skip + (n - skip) // 2}
        for c in sorted(cuts):
            if skip < c < n:
                out.append(fr[:c])
    return out
