#!/usr/bin/env python3
# Generates test/captures/zebra_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Zebra coverage captures: mkzebra.py <outdir>.
Zebra (the zebra daemon protocol of Quagga / FRRouting) runs over TCP port 2600,
registered by default. Versions 0-3 (Quagga) and FRRouting ZAPI 4-6 are built.
Addresses and routes are made up."""
import struct
import sys
import os

CMDS4 = [
    'INTERFACE_ADD', 'INTERFACE_DELETE', 'INTERFACE_ADDRESS_ADD', 'INTERFACE_ADDRESS_DELETE',
    'INTERFACE_UP', 'INTERFACE_DOWN', 'IPV4_ROUTE_ADD', 'IPV4_ROUTE_DELETE', 'IPV6_ROUTE_ADD',
    'IPV6_ROUTE_DELETE', 'REDISTRIBUTE_ADD', 'REDISTRIBUTE_DELETE', 'REDISTRIBUTE_DEFAULT_ADD',
    'REDISTRIBUTE_DEFAULT_DELETE', 'ROUTER_ID_ADD', 'ROUTER_ID_DELETE', 'ROUTER_ID_UPDATE',
    'HELLO', 'NEXTHOP_REGISTER', 'NEXTHOP_UNREGISTER', 'NEXTHOP_UPDATE',
    'INTERFACE_NBR_ADDRESS_ADD', 'INTERFACE_NBR_ADDRESS_DELETE', 'INTERFACE_BFD_DEST_UPDATE',
    'IMPORT_ROUTE_REGISTER', 'IMPORT_ROUTE_UNREGISTER', 'IMPORT_CHECK_UPDATE',
    'IPV4_ROUTE_IPV6_NEXTHOP_ADD', 'BFD_DEST_REGISTER', 'BFD_DEST_DEREGISTER',
    'BFD_DEST_UPDATE', 'BFD_DEST_REPLAY', 'REDISTRIBUTE_IPV4_ADD', 'REDISTRIBUTE_IPV4_DEL',
    'REDISTRIBUTE_IPV6_ADD', 'REDISTRIBUTE_IPV6_DEL', 'VRF_UNREGISTER', 'VRF_ADD',
    'VRF_DELETE', 'INTERFACE_VRF_UPDATE', 'BFD_CLIENT_REGISTER', 'INTERFACE_ENABLE_RADV',
    'INTERFACE_DISABLE_RADV', 'IPV4_NEXTHOP_LOOKUP_MRIB', 'INTERFACE_LINK_PARAMS',
    'MPLS_LABELS_ADD', 'MPLS_LABELS_DELETE', 'IPV4_NEXTHOP_ADD', 'IPV4_NEXTHOP_DELETE',
    'IPV6_NEXTHOP_ADD', 'IPV6_NEXTHOP_DELETE', 'IPMR_ROUTE_STATS', 'LABEL_MANAGER_CONNECT',
    'GET_LABEL_CHUNK', 'RELEASE_LABEL_CHUNK', 'PW_ADD', 'PW_DELETE', 'PW_SET', 'PW_UNSET',
    'PW_STATUS_UPDATE',
]
CMDS5 = [
    'INTERFACE_ADD', 'INTERFACE_DELETE', 'INTERFACE_ADDRESS_ADD', 'INTERFACE_ADDRESS_DELETE',
    'INTERFACE_UP', 'INTERFACE_DOWN', 'INTERFACE_SET_MASTER', 'ROUTE_ADD', 'ROUTE_DELETE',
    'ROUTE_NOTIFY_OWNER', 'IPV4_ROUTE_ADD', 'IPV4_ROUTE_DELETE', 'IPV6_ROUTE_ADD',
    'IPV6_ROUTE_DELETE', 'REDISTRIBUTE_ADD', 'REDISTRIBUTE_DELETE', 'REDISTRIBUTE_DEFAULT_ADD',
    'REDISTRIBUTE_DEFAULT_DELETE', 'ROUTER_ID_ADD', 'ROUTER_ID_DELETE', 'ROUTER_ID_UPDATE',
    'HELLO', 'CAPABILITIES', 'NEXTHOP_REGISTER', 'NEXTHOP_UNREGISTER', 'NEXTHOP_UPDATE',
    'INTERFACE_NBR_ADDRESS_ADD', 'INTERFACE_NBR_ADDRESS_DELETE', 'INTERFACE_BFD_DEST_UPDATE',
    'IMPORT_ROUTE_REGISTER', 'IMPORT_ROUTE_UNREGISTER', 'IMPORT_CHECK_UPDATE',
    'IPV4_ROUTE_IPV6_NEXTHOP_ADD', 'BFD_DEST_REGISTER', 'BFD_DEST_DEREGISTER',
    'BFD_DEST_UPDATE', 'BFD_DEST_REPLAY', 'REDISTRIBUTE_ROUTE_ADD', 'REDISTRIBUTE_ROUTE_DEL',
    'VRF_UNREGISTER', 'VRF_ADD', 'VRF_DELETE', 'VRF_LABEL', 'INTERFACE_VRF_UPDATE',
    'BFD_CLIENT_REGISTER', 'INTERFACE_ENABLE_RADV', 'INTERFACE_DISABLE_RADV',
    'IPV4_NEXTHOP_LOOKUP_MRIB', 'INTERFACE_LINK_PARAMS', 'MPLS_LABELS_ADD',
    'MPLS_LABELS_DELETE', 'IPMR_ROUTE_STATS', 'LABEL_MANAGER_CONNECT',
    'LABEL_MANAGER_CONNECT_ASYNC', 'GET_LABEL_CHUNK', 'RELEASE_LABEL_CHUNK', 'FEC_REGISTER',
    'FEC_UNREGISTER', 'FEC_UPDATE', 'ADVERTISE_DEFAULT_GW', 'ADVERTISE_SUBNET',
    'ADVERTISE_ALL_VNI', 'VNI_ADD', 'VNI_DEL', 'L3VNI_ADD', 'L3VNI_DEL', 'REMOTE_VTEP_ADD',
    'REMOTE_VTEP_DEL', 'MACIP_ADD', 'MACIP_DEL', 'IP_PREFIX_ROUTE_ADD', 'IP_PREFIX_ROUTE_DEL',
    'REMOTE_MACIP_ADD', 'REMOTE_MACIP_DEL', 'PW_ADD', 'PW_DELETE', 'PW_SET', 'PW_UNSET',
    'PW_STATUS_UPDATE', 'RULE_ADD', 'RULE_DELETE', 'RULE_NOTIFY_OWNER',
    'TABLE_MANAGER_CONNECT', 'GET_TABLE_CHUNK', 'RELEASE_TABLE_CHUNK', 'IPSET_CREATE',
    'IPSET_DESTROY', 'IPSET_ENTRY_ADD', 'IPSET_ENTRY_DELETE', 'IPSET_NOTIFY_OWNER',
    'IPSET_ENTRY_NOTIFY_OWNER', 'IPTABLE_ADD', 'IPTABLE_DELETE', 'IPTABLE_NOTIFY_OWNER',
]
CMDS6 = [
    'INTERFACE_ADD', 'INTERFACE_DELETE', 'INTERFACE_ADDRESS_ADD', 'INTERFACE_ADDRESS_DELETE',
    'INTERFACE_UP', 'INTERFACE_DOWN', 'INTERFACE_SET_MASTER', 'ROUTE_ADD', 'ROUTE_DELETE',
    'ROUTE_NOTIFY_OWNER', 'REDISTRIBUTE_ADD', 'REDISTRIBUTE_DELETE',
    'REDISTRIBUTE_DEFAULT_ADD', 'REDISTRIBUTE_DEFAULT_DELETE', 'ROUTER_ID_ADD',
    'ROUTER_ID_DELETE', 'ROUTER_ID_UPDATE', 'HELLO', 'CAPABILITIES', 'NEXTHOP_REGISTER',
    'NEXTHOP_UNREGISTER', 'NEXTHOP_UPDATE', 'INTERFACE_NBR_ADDRESS_ADD',
    'INTERFACE_NBR_ADDRESS_DELETE', 'INTERFACE_BFD_DEST_UPDATE', 'IMPORT_ROUTE_REGISTER',
    'IMPORT_ROUTE_UNREGISTER', 'IMPORT_CHECK_UPDATE', 'BFD_DEST_REGISTER',
    'BFD_DEST_DEREGISTER', 'BFD_DEST_UPDATE', 'BFD_DEST_REPLAY', 'REDISTRIBUTE_ROUTE_ADD',
    'REDISTRIBUTE_ROUTE_DEL', 'VRF_UNREGISTER', 'VRF_ADD', 'VRF_DELETE', 'VRF_LABEL',
    'INTERFACE_VRF_UPDATE', 'BFD_CLIENT_REGISTER', 'BFD_CLIENT_DEREGISTER',
    'INTERFACE_ENABLE_RADV', 'INTERFACE_DISABLE_RADV', 'IPV4_NEXTHOP_LOOKUP_MRIB',
    'INTERFACE_LINK_PARAMS', 'MPLS_LABELS_ADD', 'MPLS_LABELS_DELETE', 'IPMR_ROUTE_STATS',
    'LABEL_MANAGER_CONNECT', 'LABEL_MANAGER_CONNECT_ASYNC', 'GET_LABEL_CHUNK',
    'RELEASE_LABEL_CHUNK', 'FEC_REGISTER', 'FEC_UNREGISTER', 'FEC_UPDATE',
    'ADVERTISE_DEFAULT_GW', 'ADVERTISE_SUBNET', 'ADVERTISE_ALL_VNI', 'LOCAL_ES_ADD',
    'LOCAL_ES_DEL', 'VNI_ADD', 'VNI_DEL', 'L3VNI_ADD', 'L3VNI_DEL', 'REMOTE_VTEP_ADD',
    'REMOTE_VTEP_DEL', 'MACIP_ADD', 'MACIP_DEL', 'IP_PREFIX_ROUTE_ADD', 'IP_PREFIX_ROUTE_DEL',
    'REMOTE_MACIP_ADD', 'REMOTE_MACIP_DEL', 'DUPLICATE_ADDR_DETECTION', 'PW_ADD', 'PW_DELETE',
    'PW_SET', 'PW_UNSET', 'PW_STATUS_UPDATE', 'RULE_ADD', 'RULE_DELETE', 'RULE_NOTIFY_OWNER',
    'TABLE_MANAGER_CONNECT', 'GET_TABLE_CHUNK', 'RELEASE_TABLE_CHUNK', 'IPSET_CREATE',
    'IPSET_DESTROY', 'IPSET_ENTRY_ADD', 'IPSET_ENTRY_DELETE', 'IPSET_NOTIFY_OWNER',
    'IPSET_ENTRY_NOTIFY_OWNER', 'IPTABLE_ADD', 'IPTABLE_DELETE', 'IPTABLE_NOTIFY_OWNER',
    'VXLAN_FLOOD_CONTROL',
]

# ZEBRA_* commands of the Quagga / zebra versions 0-3 (value = command number)
CMDS_Q = ['INTERFACE_ADD', 'INTERFACE_DELETE', 'INTERFACE_ADDRESS_ADD', 'INTERFACE_ADDRESS_DELETE', 'INTERFACE_UP',
          'INTERFACE_DOWN', 'IPV4_ROUTE_ADD', 'IPV4_ROUTE_DELETE', 'IPV6_ROUTE_ADD', 'IPV6_ROUTE_DELETE',
          'REDISTRIBUTE_ADD', 'REDISTRIBUTE_DELETE', 'REDISTRIBUTE_DEFAULT_ADD', 'REDISTRIBUTE_DEFAULT_DELETE',
          'IPV4_NEXTHOP_LOOKUP', 'IPV6_NEXTHOP_LOOKUP', 'IPV4_IMPORT_LOOKUP', 'IPV6_IMPORT_LOOKUP',
          'INTERFACE_RENAME', 'ROUTER_ID_ADD', 'ROUTER_ID_DELETE', 'ROUTER_ID_UPDATE', 'HELLO',
          'IPV4_NEXTHOP_LOOKUP_MRIB', 'VRF_UNREGISTER', 'INTERFACE_LINK_PARAMS', 'NEXTHOP_REGISTER',
          'NEXTHOP_UNREGISTER', 'NEXTHOP_UPDATE']
def q(name): return CMDS_Q.index(name) + 1          # Quagga command numbers start at 1

A, B = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
MA, MB = b'\x02\x00\x00\x00\x00\x01', b'\x02\x00\x00\x00\x00\x02'
PORT = 2600

def ipck(ip):
    ck = sum(struct.unpack('>10H', ip)); ck = (ck & 0xffff) + (ck >> 16); ck = (ck & 0xffff) + (ck >> 16)
    return ip[:10] + struct.pack('>H', ~ck & 0xffff) + ip[12:]

class Conn:
    """A TCP connection to the zebra server (port 2600); the client sends requests, the server replies."""
    def __init__(self, cport):
        self.cport = cport
        self.cseq, self.sseq, self.id = 1000, 5000, 1
    def _pkt(self, fromc, payload, seq, ack):
        if fromc:
            s, d, sp, dp, ms, md = A, B, self.cport, PORT, MA, MB
        else:
            s, d, sp, dp, ms, md = B, A, PORT, self.cport, MB, MA
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        self.id += 1
        ip = ipck(struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), self.id, 0, 64, 6, 0, s, d))
        return md + ms + b'\x08\x00' + ip + tcp + payload
    def req(self, payload):
        p = self._pkt(True, payload, self.cseq, self.sseq); self.cseq += len(payload); return p
    def rep(self, payload):
        p = self._pkt(False, payload, self.sseq, self.cseq); self.sseq += len(payload); return p

def u8(x): return bytes([x])
def u16(x): return struct.pack('>H', x)
def u32(x): return struct.pack('>I', x)

def pdu(version, cmd, payload=b'', marker=None, length=None):
    """A zebra message with the header of the given version."""
    if version == 0:
        n = 3 + len(payload)
        return struct.pack('>HB', n if length is None else length, cmd) + payload
    mk = marker if marker is not None else (0xff if version < 4 else 0xfe)
    if version < 3:
        h = struct.pack('>HBBH', 0, mk, version, cmd)
    elif version < 5:
        h = struct.pack('>HBBHH', 0, mk, version, 0, cmd)
    else:
        h = struct.pack('>HBBIH', 0, mk, version, 0, cmd)
    n = len(h) + len(payload)
    return struct.pack('>H', n if length is None else length) + h[2:] + payload

def prefix_bytes(addr, plen):
    return addr[:(plen + 7) // 8]

IP4 = bytes([10, 1, 2, 3]); IP6 = bytes.fromhex('20010db8000000000000000000000001')
NH4 = bytes([192, 0, 2, 254]); NH6 = bytes.fromhex('20010db800000000000000000000fffe')

def iface(version, cmd_add, name=b'eth0', idx=2, status=1, flags=0x1043, metric=1, speed=1000, mtu=1500, mtu6=1280,
          bw=100, lltype=1, mac=b'\x02\x00\x00\x00\x00\x01', haslink=0, maclen=None):
    p = name.ljust(20, b'\0') + u32(idx) + u8(status)
    p += struct.pack('>Q', flags) if version != 0 else u32(flags)
    if version >= 4: p += u8(1) + u8(2)               # PTM enable and status
    p += u32(metric)
    if version >= 4: p += u32(speed)
    p += u32(mtu)
    if version != 0: p += u32(mtu6)
    p += u32(bw)
    if version > 2 or cmd_add:
        if version > 2: p += u32(lltype)
        if version != 0: p += u32(len(mac) if maclen is None else maclen) + mac
        if version > 2: p += u8(haslink)
    return p

def iface_addr(family, plen=24):
    p = u32(3) + u8(0x01) + u8(family)
    if family == 2:
        p += IP4 + u8(plen) + bytes([10, 1, 2, 255])
    elif family == 10:
        p += IP6 + u8(plen) + IP6[:15] + b'\xff'
    return p

def nexthops(version, request, family, hops, fake_count=None):
    """hops: list of (type, ifindex, ifname, bhtype); the addresses are NH4 / NH6 by type."""
    n = len(hops) if fake_count is None else fake_count
    p = u8(n) if version < 5 else u16(n)
    for (t, idx, name, bh) in hops:
        if version > 4: p += u32(0)                          # VRF ID
        if (version < 4 and request) or version >= 4: p += u8(t)
        if version < 4:
            v4 = (request and t in (3, 4, 5)) or (not request and family == 2)
            v6 = (request and t in (6, 7, 8)) or (not request and family == 10)
        else:
            v4 = t in (2, 3)
            v6 = t in (4, 5)
        if v4: p += NH4
        if v6: p += NH6
        if t == 1 or (version < 4 and request and t in (4, 7)) or (version >= 4 and t in (3, 5)):
            p += u32(idx)
        if version < 4 and request and t in (2, 5, 8):
            p += u8(len(name)) + name
        if version > 4 and t == 6:
            p += u8(bh)
    return p

def route(version, request, family, cmd=0, rtype=3, instance=1, rtflags=0x02, message=0, plen=24, hops=None,
          idxs=(2, 3), distance=20, metric=100, mtu=1500, tag=77, tableid=254, srclen=64, rmac=b'\x02\x00\x00\x00\x00\x09',
          safi=1, redist_nh=None, fake_count=None, fake_idxcount=None):
    """A route message. message has the dissector's bit meaning for the version."""
    p = u8(rtype)
    p += (u16(instance) + u32(rtflags)) if version > 3 else u8(rtflags & 0xff)
    p += u8(message)
    four = [CMDS4.index(n) for n in ('IPV4_ROUTE_ADD', 'IPV4_ROUTE_DELETE', 'IPV6_ROUTE_ADD', 'IPV6_ROUTE_DELETE')]
    if 1 < version < 5:
        if ((version in (2, 3)) and request) or (version == 4 and cmd in four):
            p += u16(safi)
    elif version >= 5:
        p += u8(safi)
        if (version == 5 and rtflags & 0x400) or (version > 5 and rtflags & 0x20):
            p += rmac
        p += u8(family)
    addr = IP6 if family == 10 else IP4
    p += u8(plen) + prefix_bytes(addr, plen)
    if (version == 4 and family == 10 and message & 0x40) or (version > 4 and message & 0x20):
        sl = srclen if family == 10 else 32
        p += u8(sl) + prefix_bytes(addr, sl)
    if message & 0x01:
        if redist_nh == 4:
            p += u8(1) + NH4
        elif redist_nh == 6:
            p += u8(1) + NH6
        else:
            p += nexthops(version, request, family, hops or [(3, 2, b'eth0', 0)], fake_count)
    if version < 5 and message & 0x02:
        p += u8(len(idxs) if fake_idxcount is None else fake_idxcount) + b''.join(u32(i) for i in idxs)
    dist_bit = 0x04 if version < 5 else 0x02
    metr_bit = 0x08 if version < 5 else 0x04
    if message & dist_bit: p += u8(distance)
    if message & metr_bit: p += u32(metric)
    mtu_bit = 0x10 if version < 4 else (0x20 if version == 4 else 0x10)
    tag_bit = 0x20 if version < 4 else (0x10 if version == 4 else 0x08)
    if message & mtu_bit: p += u32(mtu)
    if message & tag_bit: p += u32(tag)
    if version > 4 and message & 0x80: p += u32(tableid)
    return p

def redistribute(version, rtype=8, instance=0, afi=2):
    p = u8(afi) if version > 3 else b''
    p += u8(rtype)
    if version > 3: p += u16(instance)
    return p

def hello(version, notify=None):
    p = u8(8)
    if version > 3: p += u16(0)
    if version > 4 and notify is not None: p += u8(notify)
    return p

def nh_register(version, entries):
    p = b''
    for (flags, family, plen) in entries:
        p += u8(flags) + u16(family) + u8(plen) + (NH6 if family == 10 else NH4 if family == 2 else b'')
    return p

def nh_update(version, family, plen, hops, metric=10, labels=()):
    p = u16(family) + u8(plen) + (IP6 if family == 10 else IP4 if family == 2 else b'')
    if version > 4: p += u8(8) + u16(0)
    if version > 3: p += u8(20)
    p += u32(metric) + u8(len(hops))
    for t in hops:
        p += u8(t)
        if version < 4:
            if t in (6, 7, 8): p += NH6
            if t in (3, 4, 5): p += NH4
            if t == 1 or t in (2, 4, 5, 7, 8): p += u32(5)
        else:
            if t in (4, 5): p += NH6
            if t in (2, 3): p += NH4
            if t in (1, 2, 3, 4, 5): p += u32(5)
        if version > 4:
            p += u8(len(labels)) + b''.join(u32(l) for l in labels)
    return p

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), len(fr)))
            f.write(fr)

def quagga_frames(c, version, out):
    """All messages of the Quagga / old zebra protocol, versions 0 to 3."""
    v = version
    def R(name, payload=b''): out.append(c.req(pdu(v, q(name), payload)))      # request (to the server)
    def P(name, payload=b''): out.append(c.rep(pdu(v, q(name), payload)))      # reply (from the server)
    # interfaces: a request only subscribes; the replies carry the interface
    for name in ('INTERFACE_ADD', 'INTERFACE_UP', 'INTERFACE_DOWN', 'INTERFACE_DELETE'):
        R(name)
        P(name, iface(v, name == 'INTERFACE_ADD'))
    if v != 0:
        P('INTERFACE_ADD', iface(v, True, mac=b'', maclen=0xffffffff))                        # negative MAC length (fix)
        P('INTERFACE_ADD', iface(v, True, mac=bytes(range(32, 38))))
    for name in ('INTERFACE_ADDRESS_ADD', 'INTERFACE_ADDRESS_DELETE'):
        P(name, iface_addr(2)); P(name, iface_addr(10, 64)); P(name, iface_addr(1))   # IPv4, IPv6, unknown family
    # routes: every message bit, request and reply
    for fam, name in ((2, 'IPV4_ROUTE_ADD'), (10, 'IPV6_ROUTE_ADD'), (2, 'IPV4_ROUTE_DELETE'), (10, 'IPV6_ROUTE_DELETE')):
        hops_all = [(1, 4, b'', 0), (2, 0, b'eth1', 0), (3, 0, b'', 0), (4, 6, b'', 0), (5, 0, b'ethx', 0),
                    (6, 0, b'', 0), (7, 8, b'', 0), (8, 0, b'ethy', 0), (9, 0, b'', 0)]
        R(name, route(v, True, fam, rtype=3, message=0x3f, plen=24 if fam == 2 else 64, hops=hops_all))
        P(name, route(v, False, fam, rtype=8, message=0x3f, plen=17 if fam == 2 else 63, hops=[(0, 0, b'', 0)] * 2))
        R(name, route(v, True, fam, rtype=2, message=0, plen=0))
    R('IPV4_ROUTE_ADD', route(v, True, 2, message=0x01, plen=32, hops=[(3, 0, b'', 0)], fake_count=200))    # nexthop count larger than the message
    R('IPV4_ROUTE_ADD', route(v, True, 2, message=0x02, plen=8, idxs=(7,) * 4))
    R('IPV4_ROUTE_ADD', route(v, True, 2, message=0x02, plen=8, idxs=(7,), fake_idxcount=250))   # index count larger than the message
    R('REDISTRIBUTE_ADD', redistribute(v)); R('REDISTRIBUTE_DELETE', redistribute(v)[:0] if v == 0 else redistribute(v))
    R('REDISTRIBUTE_DEFAULT_ADD', redistribute(v)); R('REDISTRIBUTE_DEFAULT_DELETE')
    # lookups
    for name, fam in (('IPV4_NEXTHOP_LOOKUP', 2), ('IPV4_IMPORT_LOOKUP', 2), ('IPV6_NEXTHOP_LOOKUP', 10), ('IPV6_IMPORT_LOOKUP', 10)):
        addr = IP6 if fam == 10 else IP4
        R(name, addr)
        P(name, addr + u32(5) + nexthops(v, False, fam, [(0, 0, b'', 0)] * 2))
    R('ROUTER_ID_ADD'); R('ROUTER_ID_DELETE'); P('ROUTER_ID_UPDATE', u8(2) + IP4 + u8(32))
    R('HELLO', hello(v)); R('INTERFACE_RENAME')
    R('IPV4_NEXTHOP_LOOKUP_MRIB'); R('VRF_UNREGISTER'); R('INTERFACE_LINK_PARAMS')
    ent = [(0, 2, 32), (0, 10, 128), (1, 1, 0)]
    R('NEXTHOP_REGISTER', nh_register(v, ent)); R('NEXTHOP_UNREGISTER', nh_register(v, ent[:2]))
    P('NEXTHOP_UPDATE', nh_update(v, 2, 24, [1, 2, 3, 4, 5, 6, 7, 8]))
    P('NEXTHOP_UPDATE', nh_update(v, 10, 64, [6, 3, 1, 9]))
    P('NEXTHOP_UPDATE', nh_update(v, 1, 0, []))
    # a PDU with an unknown command after a known one: "Command Type 0x.." in the Info column
    out.append(c.req(pdu(v, q('HELLO'), hello(v)) + pdu(v, 0x63, b'\x01\x02')))
    # two PDUs, and trailing octets (less than a header) after the PDUs
    out.append(c.rep(pdu(v, q('ROUTER_ID_UPDATE'), u8(2) + IP4 + u8(32)) + pdu(v, q('ROUTER_ID_UPDATE'), u8(2) + NH4 + u8(24)) + b'\x00\x01'))

def frr_frames(c, version, cmds, out):
    """The FRRouting protocols, versions 4 to 6 (and 7 as an unknown later version)."""
    v = version
    def idx(n): return cmds.index(n)
    def R(n, payload=b''): out.append(c.req(pdu(v, idx(n), payload)))
    def P(n, payload=b''): out.append(c.rep(pdu(v, idx(n), payload)))
    for n in ('INTERFACE_ADD', 'INTERFACE_UP', 'INTERFACE_DOWN', 'INTERFACE_DELETE'):
        R(n); P(n, iface(v, True, mac=b'\x02\x00\x00\x00\x00\x01'))
    P('INTERFACE_ADD', iface(v, True, mac=b'', haslink=1))                                       # no MAC address
    P('INTERFACE_ADD', iface(v, True, mac=b'', maclen=0xffffffff))                               # negative MAC length (fix)
    P('INTERFACE_ADD', iface(v, True, mac=bytes(range(32, 38)), maclen=6))
    for n in ('INTERFACE_ADDRESS_ADD', 'INTERFACE_ADDRESS_DELETE'):
        P(n, iface_addr(2)); P(n, iface_addr(10, 64)); P(n, iface_addr(1))
    if v == 4:
        fam_cmds = [(2, 'IPV4_ROUTE_ADD'), (10, 'IPV6_ROUTE_ADD'), (2, 'IPV4_ROUTE_DELETE'), (10, 'IPV6_ROUTE_DELETE')]
        # message bits of ZAPI 4: nexthop 1, ifindex 2, distance 4, metric 8, tag 0x10, mtu 0x20, source prefix 0x40
        for fam, n in fam_cmds:
            R(n, route(v, True, fam, cmd=idx(n), message=0x7f, plen=24 if fam == 2 else 64,
                       hops=[(1, 4, b'', 0), (2, 0, b'', 0), (3, 6, b'', 0), (4, 0, b'', 0), (5, 8, b'', 0)]))
            R(n, route(v, True, fam, cmd=idx(n), message=0x00, plen=0))
            P(n, route(v, False, fam, cmd=idx(n), message=0x0f, rtflags=0x100, plen=16))
        R('IPV4_ROUTE_ADD', route(v, True, 2, cmd=idx('IPV4_ROUTE_ADD'), message=0x01, hops=[(3, 0, b'', 0)], fake_count=200))
        R('IPV4_ROUTE_ADD', route(v, True, 2, cmd=idx('IPV4_ROUTE_ADD'), message=0x02, idxs=(7,) * 4))
        for n, fam, nh in (('REDISTRIBUTE_IPV4_ADD', 2, 4), ('REDISTRIBUTE_IPV4_DEL', 2, 4),
                           ('REDISTRIBUTE_IPV6_ADD', 10, 6), ('REDISTRIBUTE_IPV6_DEL', 10, 6)):
            P(n, route(v, False, fam, cmd=idx(n), message=0x01, redist_nh=nh))
            P(n, route(v, False, fam, cmd=idx(n), message=0x00))
    else:
        route_cmds = ['ROUTE_ADD', 'ROUTE_DELETE', 'REDISTRIBUTE_ROUTE_ADD', 'REDISTRIBUTE_ROUTE_DEL']
        if v == 5:
            route_cmds += ['IPV4_ROUTE_ADD', 'IPV4_ROUTE_DELETE', 'IPV6_ROUTE_ADD', 'IPV6_ROUTE_DELETE']
        evpn = 0x400 if v == 5 else 0x20
        for n in route_cmds:
            fam = 10 if 'IPV6' in n else 2
            if n in ('ROUTE_ADD', 'REDISTRIBUTE_ROUTE_ADD'):
                fam = 10
            # message bits of ZAPI 5/6: nexthop 1, distance 2, metric 4, tag 8, mtu 0x10, source prefix 0x20, label 0x40, table 0x80
            R(n, route(v, True, fam, cmd=idx(n), message=0xbf, plen=64 if fam == 10 else 24,
                       hops=[(1, 4, b'', 0), (2, 0, b'', 0), (3, 6, b'', 0), (4, 0, b'', 0), (5, 8, b'', 0), (6, 0, b'', 2)]))
            R(n, route(v, True, fam, cmd=idx(n), message=0x00, plen=0))
            P(n, route(v, False, 2, cmd=idx(n), message=0x05, rtflags=evpn, plen=24))      # EVPN route with the router MAC
        R('ROUTE_ADD', route(v, True, 2, cmd=idx('ROUTE_ADD'), message=0x01, hops=[(2, 0, b'', 0)], fake_count=200))
    R('REDISTRIBUTE_ADD', redistribute(v)); R('REDISTRIBUTE_DELETE', redistribute(v)); R('REDISTRIBUTE_DEFAULT_ADD', redistribute(v))
    R('REDISTRIBUTE_DEFAULT_DELETE')
    R('ROUTER_ID_ADD'); R('ROUTER_ID_DELETE'); P('ROUTER_ID_UPDATE', u8(2) + IP4 + u8(32))
    R('HELLO', hello(v))
    if v > 4:
        R('HELLO', hello(v, notify=1))
    if v > 4:
        R('CAPABILITIES', u8(1) + u32(16)); P('CAPABILITIES', u8(0) + u32(1))
        R('VRF_ADD', u32(254) + b'ns-red'.ljust(16, b'\0') + b'vrf-red'.ljust(36, b'\0'))
        R('LABEL_MANAGER_CONNECT', u8(8) + u16(0)); R('LABEL_MANAGER_CONNECT_ASYNC', u8(8) + u16(0))
        R('GET_LABEL_CHUNK', u8(8) + u16(0) + u8(0) + u32(100))
        P('GET_LABEL_CHUNK', u8(8) + u16(0) + u8(0) + u32(1000) + u32(1099))
    ent = [(0, 2, 32), (0, 10, 128), (1, 1, 0)]
    R('NEXTHOP_REGISTER', nh_register(v, ent)); R('NEXTHOP_UNREGISTER', nh_register(v, ent[:2]))
    P('NEXTHOP_UPDATE', nh_update(v, 2, 24, [1, 2, 3, 4, 5, 6], labels=(100, 200) if v > 4 else ()))
    P('NEXTHOP_UPDATE', nh_update(v, 10, 64, [4, 5, 3, 1]))
    P('NEXTHOP_UPDATE', nh_update(v, 1, 0, []))
    R('BFD_CLIENT_REGISTER', u32(1234))
    # every other command: header only
    done = set(('INTERFACE_ADD', 'INTERFACE_UP', 'INTERFACE_DOWN', 'INTERFACE_DELETE', 'INTERFACE_ADDRESS_ADD',
                'INTERFACE_ADDRESS_DELETE', 'REDISTRIBUTE_ADD', 'REDISTRIBUTE_DELETE', 'REDISTRIBUTE_DEFAULT_ADD',
                'REDISTRIBUTE_DEFAULT_DELETE', 'ROUTER_ID_ADD', 'ROUTER_ID_DELETE', 'ROUTER_ID_UPDATE', 'HELLO',
                'NEXTHOP_REGISTER', 'NEXTHOP_UNREGISTER', 'NEXTHOP_UPDATE', 'BFD_CLIENT_REGISTER', 'CAPABILITIES',
                'VRF_ADD', 'LABEL_MANAGER_CONNECT', 'LABEL_MANAGER_CONNECT_ASYNC', 'GET_LABEL_CHUNK',
                'REDISTRIBUTE_IPV4_ADD', 'REDISTRIBUTE_IPV4_DEL', 'REDISTRIBUTE_IPV6_ADD', 'REDISTRIBUTE_IPV6_DEL'))
    if v == 4:
        done -= {'VRF_ADD', 'LABEL_MANAGER_CONNECT', 'LABEL_MANAGER_CONNECT_ASYNC', 'GET_LABEL_CHUNK', 'CAPABILITIES'}
        done |= {'IPV4_ROUTE_ADD', 'IPV4_ROUTE_DELETE', 'IPV6_ROUTE_ADD', 'IPV6_ROUTE_DELETE'}
    else:
        done |= set(route_cmds)
    for n in cmds:
        if n not in done and n not in ('INTERFACE_SET_MASTER', 'ROUTE_NOTIFY_OWNER'):    # these two are not in the value strings
            out.append(c.req(pdu(v, idx(n), b'')))
    # unknown command after a known one: "Command Type 0x.." in the Info column
    out.append(c.req(pdu(v, idx('HELLO'), hello(v)) + pdu(v, 0xf3, b'\x01\x02')))
    out.append(c.rep(pdu(v, idx('ROUTER_ID_UPDATE'), u8(2) + IP4 + u8(32)) + pdu(v, idx('ROUTER_ID_UPDATE'), u8(2) + NH4 + u8(24)) + b'\x00\x01'))

def main(out):
    f = []
    for version in (0, 1, 2, 3):
        quagga_frames(Conn(40800 + version), version, f)
    frr_frames(Conn(40804), 4, CMDS4, f)
    frr_frames(Conn(40805), 5, CMDS5, f)
    frr_frames(Conn(40806), 6, CMDS6, f)
    # a later, unknown version (7 and 8 are read with the version 6 layout)
    c = Conn(40807)
    f.append(c.req(pdu(7, CMDS6.index('HELLO'), hello(6, notify=1))))
    f.append(c.rep(pdu(8, CMDS6.index('ROUTER_ID_UPDATE'), u8(2) + IP4 + u8(32))))
    write_pcap(os.path.join(out, 'zebra-coverage.pcap'), f)

    b = []
    c = Conn(40900)
    # not zebra: version 9, unknown commands, too-large length, length below 3, short headers
    b.append(c.req(pdu(9, 1, b'\x00' * 8)))
    b.append(c.req(pdu(5, CMDS5.index('INTERFACE_SET_MASTER'), b'')))                  # commands that are not in the value strings
    b.append(c.req(pdu(6, CMDS6.index('ROUTE_NOTIFY_OWNER'), b'')))
    b.append(c.req(pdu(3, 0x63, b'\x00' * 8)))
    b.append(c.req(pdu(4, 200, b'\x00' * 8)))
    b.append(c.req(pdu(5, 200, b'\x00' * 8)))
    b.append(c.req(pdu(6, 200, b'\x00' * 8)))
    b.append(c.req(pdu(3, q('HELLO'), hello(3), length=2000)))                       # length above 1024
    b.append(c.req(pdu(3, q('HELLO'), hello(3), length=2)))                          # length below 3
    b.append(c.req(b'\x00\x08\xff'))                                                 # header cut after the marker
    b.append(c.req(b'\x00\x08\xff\x03\x00\x00'))                                     # header cut before the command
    b.append(c.req(b'\x00'))
    # messages that are cut short or have wrong lengths (exceptions)
    b.append(c.req(pdu(3, q('IPV4_ROUTE_ADD'), route(3, True, 2, message=0x3f, plen=24, hops=[(3, 0, b'', 0)])[:12])))
    b.append(c.rep(pdu(3, q('INTERFACE_ADD'), iface(3, True)[:40])))
    b.append(c.rep(pdu(3, q('INTERFACE_ADD'), iface(3, True, mac=b'\x02' * 6, maclen=100))))     # MAC length beyond the data
    b.append(c.rep(pdu(0, 1, iface(0, True)[:30])))
    b.append(c.rep(pdu(4, CMDS4.index('INTERFACE_ADDRESS_ADD'), iface_addr(2)[:8])))
    b.append(c.rep(pdu(5, CMDS5.index('NEXTHOP_UPDATE'), nh_update(5, 2, 24, [3, 3, 3])[:20])))
    b.append(c.rep(pdu(6, CMDS6.index('NEXTHOP_UPDATE'), nh_update(6, 10, 64, [5]) [:30])))
    b.append(c.req(pdu(6, CMDS6.index('NEXTHOP_REGISTER'), nh_register(6, [(0, 2, 32)])[:5])))
    b.append(c.req(pdu(5, CMDS5.index('ROUTE_ADD'), route(5, True, 2, message=0xbf, hops=[(3, 6, b'', 0)] * 3)[:25])))
    b.append(c.req(pdu(6, CMDS6.index('VRF_ADD'), u32(254) + b'ns')))
    b.append(c.req(pdu(5, CMDS5.index('GET_LABEL_CHUNK'), u8(8) + u16(0))))
    b.append(c.req(pdu(4, CMDS4.index('IPV4_ROUTE_ADD'), route(4, True, 2, cmd=CMDS4.index('IPV4_ROUTE_ADD'), message=0x7f)[:15])))
    b.append(c.rep(pdu(6, CMDS6.index('ROUTER_ID_UPDATE'), u8(2) + IP4)))                      # router ID mask missing
    b.append(c.rep(pdu(1, q('IPV4_NEXTHOP_LOOKUP'), IP4)[:8]))
    # a PDU longer than the segment
    b.append(c.req(pdu(3, q('HELLO'), hello(3), length=40)))
    write_pcap(os.path.join(out, 'zebra-coverage-malformed.pcap'), b)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
