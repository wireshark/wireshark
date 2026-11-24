#!/usr/bin/env python3
# Generates test/captures/erf_coverage.erf.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ERF dissector
(packet-erf.c, Extensible Record Format, Endace DAG).

The main capture is an ERF file (wiretap "erf"; ERF has no magic
number, wiretap recognises it from the first 20 records), dissected
by the ERF dissector through WTAP_ENCAP_ERF. Each record is a 16
octet ERF header (little endian timestamp, type, flags, big endian
rlen, lctr/color, wlen), optional 8 octet extension headers, a type
specific subheader (2 octets for Ethernet, 4 for the multichannel and
AAL2 types) and the data. Provenance (ERF_TYPE_META, 27) records hold
sections of type/length/value tags. Every record is built from scratch
with struct; no captured traffic is used (addresses from 192.0.2.0/24
and 2001:db8::/32, host IDs and MAC addresses are made up).

Usage: mkerf.py <output directory>

Writes:
  erf-coverage.erf                 every record type, every extension
                                   header type, Provenance records with
                                   every section and every tag, Host ID /
                                   Source ID linking, Anchor ID linking
                                   (more than 64 links, IDs that only
                                   differ above bit 31)
  erf-coverage-malformed.pcap      pcap with link-layer type 197 (ERF):
                                   records with error flags, PAD and
                                   legacy records, truncated and
                                   zero-length tags, wrong section
                                   lengths, the parent_section
                                   reproducer, records cut short
"""

import os
import struct
import sys

# (code, name, field type) of every Provenance tag, as in erf_meta_tags[]
TAGS = [
    (0, 'padding', 'NONE'),
    (1, 'comment', 'STRING'),
    (2, 'gen_time', 'ABSOLUTE_TIME'),
    (3, 'parent_section', 'BYTES'),
    (4, 'reset', 'BYTES'),
    (5, 'event_time', 'ABSOLUTE_TIME'),
    (6, 'host_id', 'UINT64'),
    (7, 'attribute', 'STRING'),
    (8, 'fcs_len', 'UINT32'),
    (9, 'mask_ipv4', 'IPv4'),
    (10, 'mask_cidr', 'UINT32'),
    (11, 'org_name', 'STRING'),
    (12, 'name', 'STRING'),
    (13, 'descr', 'STRING'),
    (14, 'config', 'STRING'),
    (15, 'datapipe', 'STRING'),
    (16, 'app_name', 'STRING'),
    (17, 'os', 'STRING'),
    (18, 'hostname', 'STRING'),
    (19, 'user', 'STRING'),
    (20, 'model', 'STRING'),
    (21, 'fw_version', 'STRING'),
    (22, 'serial_no', 'STRING'),
    (23, 'ts_offset', 'RELATIVE_TIME'),
    (24, 'ts_clock_freq', 'UINT32'),
    (25, 'tzone', 'INT32'),
    (26, 'tzone_name', 'STRING'),
    (27, 'loc_lat', 'INT32'),
    (28, 'loc_long', 'INT32'),
    (29, 'snaplen', 'UINT32'),
    (30, 'card_num', 'UINT32'),
    (31, 'module_num', 'UINT32'),
    (32, 'access_num', 'UINT32'),
    (33, 'stream_num', 'UINT32'),
    (34, 'loc_name', 'STRING'),
    (35, 'parent_file', 'STRING'),
    (36, 'filter', 'STRING'),
    (37, 'flow_hash_mode', 'UINT32'),
    (38, 'tunneling_mode', 'UINT32'),
    (39, 'npb_format', 'BYTES'),
    (40, 'mem', 'UINT64'),
    (41, 'datamine_id', 'STRING'),
    (42, 'rotfile_id', 'STRING'),
    (43, 'rotfile_name', 'STRING'),
    (44, 'dev_name', 'STRING'),
    (45, 'dev_path', 'STRING'),
    (46, 'loc_descr', 'STRING'),
    (47, 'app_version', 'STRING'),
    (48, 'cpu_affinity', 'BYTES'),
    (49, 'cpu', 'STRING'),
    (50, 'cpu_phys_cores', 'UINT32'),
    (51, 'cpu_numa_nodes', 'UINT32'),
    (52, 'dag_attribute', 'STRING'),
    (53, 'dag_version', 'STRING'),
    (54, 'stream_flags', 'UINT32'),
    (55, 'entropy_threshold', 'FLOAT'),
    (56, 'smart_trunc_default', 'UINT32'),
    (57, 'ext_hdrs_added', 'BYTES'),
    (58, 'ext_hdrs_removed', 'BYTES'),
    (59, 'relative_snaplen', 'UINT32'),
    (60, 'temperature', 'FLOAT'),
    (61, 'power', 'FLOAT'),
    (62, 'vendor', 'STRING'),
    (63, 'cpu_threads', 'UINT32'),
    (64, 'if_num', 'UINT32'),
    (65, 'if_vc', 'UINT32'),
    (66, 'if_speed', 'UINT64'),
    (67, 'if_ipv4', 'IPv4'),
    (68, 'if_ipv6', 'IPv6'),
    (69, 'if_mac', 'ETHER'),
    (70, 'if_eui', 'EUI64'),
    (71, 'if_ib_gid', 'IPv6'),
    (72, 'if_ib_lid', 'UINT16'),
    (73, 'if_wwn', 'BYTES'),
    (74, 'if_fc_id', 'BYTES'),
    (75, 'if_tx_speed', 'UINT64'),
    (76, 'if_erf_type', 'UINT32'),
    (77, 'if_link_type', 'UINT32'),
    (78, 'if_sfp_type', 'STRING'),
    (79, 'if_rx_power', 'INT32'),
    (80, 'if_tx_power', 'INT32'),
    (81, 'if_link_status', 'UINT32'),
    (82, 'if_phy_mode', 'STRING'),
    (83, 'if_port_type', 'UINT32'),
    (84, 'if_rx_latency', 'RELATIVE_TIME'),
    (85, 'tap_mode', 'UINT32'),
    (86, 'tap_fail_mode', 'UINT32'),
    (87, 'watchdog_expired', 'UINT32'),
    (88, 'watchdog_interval', 'UINT32'),
    (128, 'src_ipv4', 'IPv4'),
    (129, 'dest_ipv4', 'IPv4'),
    (130, 'src_ipv6', 'IPv6'),
    (131, 'dest_ipv6', 'IPv6'),
    (132, 'src_mac', 'ETHER'),
    (133, 'dest_mac', 'ETHER'),
    (134, 'src_eui', 'EUI64'),
    (135, 'dest_eui', 'EUI64'),
    (136, 'src_ib_gid', 'IPv6'),
    (137, 'dest_ib_gid', 'IPv6'),
    (138, 'src_ib_lid', 'UINT16'),
    (139, 'dest_ib_lid', 'UINT16'),
    (140, 'src_wwn', 'BYTES'),
    (141, 'dest_wwn', 'BYTES'),
    (142, 'src_fc_id', 'BYTES'),
    (143, 'dest_fc_id', 'BYTES'),
    (144, 'src_port', 'UINT32'),
    (145, 'dest_port', 'UINT32'),
    (146, 'ip_proto', 'UINT32'),
    (147, 'flow_hash', 'UINT32'),
    (148, 'filter_match', 'STRING'),
    (149, 'filter_match_name', 'STRING'),
    (150, 'error_flags', 'BYTES'),
    (151, 'initiator_pkts', 'UINT64'),
    (152, 'responder_pkts', 'UINT64'),
    (153, 'initiator_bytes', 'UINT64'),
    (154, 'responder_bytes', 'UINT64'),
    (155, 'initiator_min_entropy', 'FLOAT'),
    (156, 'responder_min_entropy', 'FLOAT'),
    (157, 'initiator_avg_entropy', 'FLOAT'),
    (158, 'responder_avg_entropy', 'FLOAT'),
    (159, 'initiator_max_entropy', 'FLOAT'),
    (160, 'responder_max_entropy', 'FLOAT'),
    (161, 'dpi_application', 'STRING'),
    (162, 'dpi_confidence', 'STRING'),
    (163, 'dpi_state', 'UINT32'),
    (164, 'dpi_protocol_stack', 'STRING'),
    (165, 'flow_state', 'UINT32'),
    (166, 'vlan_id', 'INT32'),
    (167, 'mpls_label', 'INT32'),
    (168, 'vlan_pcp', 'UINT32'),
    (169, 'mpls_tc', 'UINT32'),
    (170, 'dscp', 'UINT32'),
    (171, 'initiator_mpls_label', 'INT32'),
    (172, 'responder_mpls_label', 'INT32'),
    (173, 'initiator_mpls_tc', 'UINT32'),
    (174, 'responder_mpls_tc', 'UINT32'),
    (175, 'initiator_ipv4', 'IPv4'),
    (176, 'responder_ipv4', 'IPv4'),
    (177, 'initiator_ipv6', 'IPv6'),
    (178, 'responder_ipv6', 'IPv6'),
    (179, 'initiator_mac', 'ETHER'),
    (180, 'responder_mac', 'ETHER'),
    (181, 'initiator_port', 'UINT32'),
    (182, 'responder_port', 'UINT32'),
    (183, 'initiator_retx', 'UINT64'),
    (184, 'responder_retx', 'UINT64'),
    (185, 'initiator_zwin', 'UINT64'),
    (186, 'responder_zwin', 'UINT64'),
    (187, 'initiator_tcp_flags', 'BYTES'),
    (188, 'responder_tcp_flags', 'BYTES'),
    (189, 'tcp_irtt', 'RELATIVE_TIME'),
    (193, 'start_time', 'ABSOLUTE_TIME'),
    (194, 'end_time', 'ABSOLUTE_TIME'),
    (195, 'stat_if_drop', 'UINT64'),
    (196, 'stat_frames', 'UINT64'),
    (197, 'stat_bytes', 'UINT64'),
    (198, 'stat_cap', 'UINT64'),
    (199, 'stat_cap_bytes', 'UINT64'),
    (200, 'stat_os_drop', 'UINT64'),
    (201, 'stat_ds_lctr', 'UINT64'),
    (202, 'stat_filter_match', 'UINT64'),
    (203, 'stat_filter_drop', 'UINT64'),
    (204, 'stat_too_short', 'UINT64'),
    (205, 'stat_too_long', 'UINT64'),
    (206, 'stat_rx_error', 'UINT64'),
    (207, 'stat_fcs_error', 'UINT64'),
    (208, 'stat_aborted', 'UINT64'),
    (209, 'stat_proto_error', 'UINT64'),
    (210, 'stat_b1_error', 'UINT64'),
    (211, 'stat_b2_error', 'UINT64'),
    (212, 'stat_b3_error', 'UINT64'),
    (213, 'stat_rei_error', 'UINT64'),
    (214, 'stat_drop', 'UINT64'),
    (215, 'stat_buf_drop', 'UINT64'),
    (216, 'stream_drop', 'UINT32'),
    (217, 'stream_buf_drop', 'UINT32'),
    (218, 'pkt_drop', 'UINT64'),
    (219, 'record_drop', 'UINT64'),
    (220, 'bandwidth', 'UINT64'),
    (221, 'duration', 'RELATIVE_TIME'),
    (222, 'top_index', 'UINT32'),
    (223, 'concurrent_flows', 'UINT32'),
    (224, 'active_flows', 'UINT32'),
    (225, 'created_flows', 'UINT32'),
    (226, 'deleted_flows', 'UINT32'),
    (227, 'active_endpoints', 'UINT32'),
    (228, 'tx_pkts', 'UINT64'),
    (229, 'tx_bytes', 'UINT64'),
    (230, 'rx_bandwidth', 'UINT64'),
    (231, 'tx_bandwidth', 'UINT64'),
    (232, 'records', 'UINT64'),
    (233, 'record_bytes', 'UINT64'),
    (234, 'pkt_drop_bytes', 'UINT64'),
    (235, 'record_drop_bytes', 'UINT64'),
    (236, 'drop_bandwidth', 'UINT64'),
    (237, 'retx_pkts', 'UINT64'),
    (238, 'zwin_pkts', 'UINT64'),
    (256, 'ns_host_ipv4', 'IPv4'),
    (257, 'ns_host_ipv6', 'IPv6'),
    (258, 'ns_host_mac', 'ETHER'),
    (259, 'ns_host_eui', 'EUI64'),
    (260, 'ns_host_ib_gid', 'IPv6'),
    (261, 'ns_host_ib_lid', 'UINT16'),
    (262, 'ns_host_wwn', 'BYTES'),
    (263, 'ns_host_fc_id', 'BYTES'),
    (264, 'ns_dns_ipv4', 'IPv4'),
    (265, 'ns_dns_ipv6', 'IPv6'),
    (321, 'exthdr', 'BYTES'),
    (322, 'pcap_ng_block', 'BYTES'),
    (323, 'asn1', 'BYTES'),
    (324, 'section_ref', 'BYTES'),
    (384, 'clk_source', 'UINT32'),
    (385, 'clk_state', 'UINT32'),
    (386, 'clk_threshold', 'RELATIVE_TIME'),
    (387, 'clk_correction', 'RELATIVE_TIME'),
    (388, 'clk_failures', 'UINT32'),
    (389, 'clk_resyncs', 'UINT32'),
    (390, 'clk_phase_error', 'RELATIVE_TIME'),
    (391, 'clk_input_pulses', 'UINT32'),
    (392, 'clk_rejected_pulses', 'UINT32'),
    (393, 'clk_phc_index', 'UINT32'),
    (394, 'clk_phc_offset', 'RELATIVE_TIME'),
    (395, 'clk_timebase', 'STRING'),
    (396, 'clk_descr', 'STRING'),
    (397, 'clk_out_source', 'UINT32'),
    (398, 'clk_link_mode', 'UINT32'),
    (399, 'ptp_domain_num', 'UINT32'),
    (400, 'ptp_steps_removed', 'UINT32'),
    (401, 'ptp_offset_from_master', 'RELATIVE_TIME'),
    (402, 'ptp_mean_path_delay', 'RELATIVE_TIME'),
    (403, 'ptp_parent_identity', 'EUI64'),
    (404, 'ptp_parent_port_num', 'UINT32'),
    (405, 'ptp_gm_identity', 'EUI64'),
    (406, 'ptp_gm_clock_quality', 'UINT32'),
    (407, 'ptp_current_utc_offset', 'RELATIVE_TIME'),
    (408, 'ptp_time_properties', 'UINT32'),
    (409, 'ptp_time_source', 'UINT32'),
    (410, 'ptp_clock_identity', 'EUI64'),
    (411, 'ptp_port_num', 'UINT32'),
    (412, 'ptp_port_state', 'UINT32'),
    (413, 'ptp_delay_mechanism', 'UINT32'),
    (414, 'clk_port_proto', 'UINT32'),
    (415, 'ntp_status', 'UINT32'),
    (416, 'ntp_stratum', 'UINT32'),
    (417, 'ntp_rootdelay', 'INT32'),
    (418, 'ntp_rootdisp', 'UINT32'),
    (419, 'ntp_offset', 'INT32'),
    (420, 'ntp_frequency', 'INT32'),
    (421, 'ntp_sys_jitter', 'UINT32'),
    (422, 'ntp_peer_remote', 'STRING'),
    (423, 'ntp_peer_refid', 'STRING')

]

SECTIONS = [0xFF00, 0xFF01, 0xFF02, 0xFF03, 0xFF04, 0xFF05, 0xFF06, 0xFF07,
            0xFF08, 0xFF09, 0xFF0A, 0xFF0B, 0xFF0C, 0xFF0D, 0xFF0E, 0xFF0F]

EH_CLASS, EH_INTERCEPT, EH_RAWLINK, EH_BFS = 3, 4, 5, 6
EH_CHAN, EH_SIG, EH_PKTID, EH_FLOW, EH_HOST, EH_ANCHOR, EH_ENTROPY = 12, 14, 15, 16, 17, 18, 19

HOST_A = 0x0000a1b2c3d4
HOST_B = 0x0000b0b1b2b3


class Erf:
    def __init__(self):
        self.recs = []
        self.ts = 1700000000 << 32

    def rec(self, rtype, data, ehdrs=(), flags=0x04, lctr=0, sub=b'', wlen=None, tsstep=1 << 30):
        """ehdrs: list of 64 bit extension header values (the more bit is
        set here)."""
        self.ts += tsstep
        eh = b''
        for k, h in enumerate(ehdrs):
            more = 1 << 63 if k < len(ehdrs) - 1 else 0
            eh += struct.pack('>Q', h | more)
        t = rtype | (0x80 if ehdrs else 0)
        body = eh + sub + data
        rlen = 16 + len(body)
        wl = len(data) if wlen is None else wlen
        hdr = struct.pack('<Q', self.ts) + struct.pack('>BBHHH', t, flags, rlen, lctr, wl)
        self.recs.append(hdr + body)
        return len(self.recs)

    def write_erf(self, path):
        with open(path, 'wb') as f:
            for r in self.recs:
                f.write(r)

    def write_pcap(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 197))
            for i, r in enumerate(self.recs):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(r), len(r)))
                f.write(r)


def ehdr(t, value):
    return (t << 56) | (value & ((1 << 56) - 1))


def host_eh(host, src):
    return ehdr(EH_HOST, (src << 48) | host)


def anchor_eh(anchor, definition=False):
    return ehdr(EH_ANCHOR, ((0x80 if definition else 0) << 48) | anchor)


def tag(code, val, length=None):
    b = struct.pack('>HH', code, len(val) if length is None else length) + val
    while len(b) % 4:
        b += b'\0'
    return b


def section(code, sid, body, slen=None, extra=b''):
    """Section header tag (Section ID, section length) followed by the
    tags. The section length counts the whole section, header included."""
    hdr_len = len(tag(code, struct.pack('>HH', sid, 0) + extra))
    if slen is None:
        slen = hdr_len + len(body)
    return tag(code, struct.pack('>HH', sid, slen) + extra) + body


def erf_ts(secs, frac=0):
    return struct.pack('<Q', (secs << 32) | frac)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4_udp(n, payload=b'erf test', src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    udp = struct.pack('>HHHH', 40000 + n, 9, 8 + len(payload), 0) + payload
    ph = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(udp))
    udp = udp[:6] + struct.pack('>H', csum(ph + udp)) + udp[8:]
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), n, 0x4000,
                      64, 17, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + udp


def ipv6_udp(n, payload=b'erf test v6'):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    udp = struct.pack('>HHHH', 41000 + n, 9, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('>IxxxB', len(udp), 17)
    udp = udp[:6] + struct.pack('>H', csum(ph + udp)) + udp[8:]
    return struct.pack('>IHBB', 0x60000000, len(udp), 17, 64) + src + dst + udp


def eth(n, src=b'\x02\0\0\0\0\x01', dst=b'\x02\0\0\0\0\x02'):
    fr = dst + src + b'\x08\x00' + ipv4_udp(n)
    if len(fr) < 60:
        fr += b'\0' * (60 - len(fr))
    import zlib
    return fr + struct.pack('<I', zlib.crc32(fr) & 0xffffffff)


def eth_sub(off=0, pad=0):
    return struct.pack('>BB', off, pad)


def chdlc(n):
    return b'\x0f\x00\x08\x00' + ipv4_udp(n)


def ppp(n):
    return b'\xff\x03\x00\x21' + ipv4_udp(n)


def frelay(n):
    # Q.922 address DLCI 16, NLPID IP (RFC 2427)
    return b'\x04\x01\x03\xcc' + ipv4_udp(n)


def der(tag_, body):
    return bytes((tag_, len(body))) + body


def ilmi_get():
    """SNMPv1 GetRequest for ILMI atmfPortIndex (1.3.6.1.4.1.353.2.1.1.1)."""
    oid = der(0x06, bytes.fromhex('2b06010401826102010101'))
    varbind = der(0x30, oid + b'\x05\x00')
    pdu = der(0xa0, der(0x02, b'\x01') + der(0x02, b'\x00') + der(0x02, b'\x00') + der(0x30, varbind))
    return der(0x30, der(0x02, b'\x00') + der(0x04, b'ILMI') + pdu)


def atm_hdr(vpi, vci, pti=0):
    return struct.pack('>I', (vpi << 20) | (vci << 4) | (pti << 1))


def tag_value(code, name, ft, i):
    """A valid value for each tag type."""
    special = {
        'parent_section': struct.pack('>HH', 0xFF03, 1),
        'reset': b'\x01\x02\x03\x04',
        'if_speed': struct.pack('>Q', 10000000000),
        'if_tx_speed': struct.pack('>Q', 1000000000),
        'if_rx_power': struct.pack('>i', -350),
        'if_tx_power': struct.pack('>i', 125),
        'temperature': struct.pack('>i', 45250),
        'power': struct.pack('>i', -1500),
        'loc_lat': struct.pack('>i', -36848),
        'loc_long': struct.pack('>i', 174763),
        'mask_cidr': struct.pack('>I', 24),
        'mem': struct.pack('>Q', 64 << 30),
        'if_link_status': struct.pack('>I', 0x00000003),
        'tunneling_mode': struct.pack('>I', 0x0000003f),
        'ptp_time_properties': struct.pack('>I', 0x0000003f),
        'ptp_gm_clock_quality': struct.pack('>I', 0x06fe2100),
        'stream_flags': struct.pack('>I', 0x00000001),
        'smart_trunc_default': struct.pack('>I', 0x00000001),
        'ptp_offset_from_master': struct.pack('>q', 1234 << 16),
        'ptp_mean_path_delay': struct.pack('>q', 5000000000 << 16),
        'ptp_current_utc_offset': struct.pack('>i', 37),
        'entropy_threshold': struct.pack('>I', 200),
        'initiator_min_entropy': struct.pack('>I', 0),
        'responder_min_entropy': struct.pack('>I', 1),
        'initiator_avg_entropy': struct.pack('>I', 128),
        'responder_avg_entropy': struct.pack('>I', 160),
        'initiator_max_entropy': struct.pack('>I', 255),
        'responder_max_entropy': struct.pack('>I', 254),
        'ext_hdrs_added': struct.pack('>I', (1 << EH_HOST) | (1 << EH_ANCHOR)),
        'ext_hdrs_removed': struct.pack('>II', 0, 1 << 3),
        'if_wwn': bytes(range(16)), 'src_wwn': bytes(range(16, 32)),
        'dest_wwn': bytes(range(32, 48)),
        'if_fc_id': b'\x01\x02\x03', 'src_fc_id': b'\x04\x05\x06',
        'dest_fc_id': b'\x07\x08\x09',
        'ns_host_ipv4': bytes((192, 0, 2, 1)) + b'host-a.example',
        'ns_host_ipv6': bytes.fromhex('20010db8000000000000000000000001') + b'host6.example',
        'ns_host_mac': bytes.fromhex('020000000001') + b'mac-host',
        'ns_host_eui': bytes.fromhex('0200000000000001') + b'eui-host',
        'ns_host_wwn': bytes(range(16)) + b'wwn-host',
        'ns_host_ib_gid': bytes.fromhex('fe800000000000000002c90300000001') + b'ib-host',
        'ns_host_ib_lid': struct.pack('>H', 7) + b'lid-host',
        'ns_host_fc_id': b'\x0a\x0b\x0c' + b'fc-host',
        'ns_dns_ipv4': bytes((192, 0, 2, 53)) + b'dns4.example',
        'ns_dns_ipv6': bytes.fromhex('20010db8000000000000000000000035') + b'dns6.example',
        'gen_time': erf_ts(1700000000, 0x80000000),
        'event_time': erf_ts(1700000001),
        'start_time': erf_ts(1700000000),
        'end_time': erf_ts(1700003600),
        'ts_offset': struct.pack('<q', -(3 << 31)),
        'if_rx_latency': struct.pack('<q', 0x1000),
        'tcp_irtt': struct.pack('<q', 1 << 30),
        'duration': struct.pack('<q', 3600 << 32),
        'clk_phase_error': struct.pack('<q', -0x100),
    }
    if name in special:
        return special[name]
    sizes = {'UINT64': 8, 'UINT32': 4, 'INT32': 4, 'UINT16': 2, 'IPv4': 4,
             'IPv6': 16, 'ETHER': 6, 'EUI64': 8, 'ABSOLUTE_TIME': 8,
             'RELATIVE_TIME': 8}
    if ft == 'STRING':
        return ('%s value' % name).encode()
    if ft in ('IPv4',):
        return bytes((192, 0, 2, i % 250 + 1))
    if ft in ('IPv6',):
        return bytes.fromhex('20010db8') + bytes(11) + bytes((i % 250 + 1,))
    if ft == 'ETHER':
        return bytes((2, 0, 0, 0, 0, i % 250 + 1))
    if ft in ('ABSOLUTE_TIME', 'RELATIVE_TIME'):
        return erf_ts(1700000000 if ft == 'ABSOLUTE_TIME' else 2, 0x40000000)
    if ft in sizes:
        return (i + 1).to_bytes(sizes[ft], 'big')
    return bytes((i & 0xff, 0xa5, 0x5a))


def all_tags_body(skip=()):
    body = b''
    for i, (code, name, ft) in enumerate(TAGS):
        if name in skip:
            continue
        body += tag(code, tag_value(code, name, ft, i))
    return body


def meta_periodic(E, host, src, extra_eh=(), sections=None, n=0):
    """A periodic Provenance record: Capture, Host and Interface
    sections."""
    if sections is None:
        sections = (section(0xFF00, 1, tag(1, b'periodic %d' % n) + tag(2, erf_ts(1700000000 + n))) +
                    section(0xFF01, 1, tag(18, b'capture-host') + tag(6, struct.pack('>Q', host))) +
                    section(0xFF03, src, tag(12, b'dag0:%d' % src) + tag(64, struct.pack('>I', src)) +
                                     tag(76, struct.pack('>I', 2))))
    return E.rec(27, sections, [host_eh(host, src)] + list(extra_eh))


def main_capture():
    E = Erf()
    R = {}
    # 1: periodic Provenance record, Host A Source 1 (sets the implicit Host ID)
    R['meta1'] = meta_periodic(E, HOST_A, 1, n=1)
    # 2: Provenance record with every section and every tag (each section
    #    in turn gets one slice of the tags); a local section ID, a
    #    section header with reserved octets, section ID 0 and a section
    #    length of 0 (not checked)
    body_tags = [tag(code, tag_value(code, name, ft, i)) for i, (code, name, ft) in enumerate(TAGS)]
    per = (len(body_tags) + len(SECTIONS) - 1) // len(SECTIONS)
    sec = b''
    for k, s in enumerate(SECTIONS):
        chunk = b''.join(body_tags[k * per:(k + 1) * per])
        if k == 1:
            sec += section(s, 0x8001, chunk)          # local section
        elif k == 2:
            sec += section(s, 2, chunk, extra=b'\0\0\0\0')  # reserved octets
        elif k == 3:
            sec += section(s, 0, chunk)                # section ID 0
        elif k == 4:
            sec += section(s, 4, chunk, slen=0)        # length 0: no check
        else:
            sec += section(s, k + 1, chunk)
    R['meta_all'] = E.rec(27, sec, [host_eh(HOST_A, 1)])
    # 3: tags before the first section header ("No Section"), an unknown
    #    section, an unknown tag, padding, a zero length string (note)
    R['meta_misc'] = E.rec(27, tag(1, b'before any section') + tag(0, b'', 0) +
                           section(0xFF7E, 3, tag(1, b'in unknown section') + tag(0x7777, b'\x01\x02\x03\x04')) +
                           section(0xFF06, 5, tag(1, b'', 0) + tag(0, b'\0' * 4)),
                           [host_eh(HOST_A, 1)])
    # 4: special tag values: ext_hdrs with all bits, none, unknown bits in
    #    words 2-4; negative and small PTP times; zero entropy
    R['meta_ext'] = E.rec(27, section(0xFF09, 1,
                          tag(57, b'\xff' * 16) + tag(58, b'\0' * 4) +
                          tag(57, struct.pack('>IIII', 1 << 31 | 1 << 16, 1, 1 << 5, 1 << 31)) +
                          tag(58, struct.pack('>III', 0xffffffff, 0xffffffff, 0xffffffff)) +
                          tag(401, struct.pack('>q', -(250 << 16))) +
                          tag(402, struct.pack('>q', -(3000000000 << 16))) +
                          tag(407, struct.pack('>i', -5)) +
                          tag(23, struct.pack('<q', -(5 << 32))) +
                          tag(23, struct.pack('<q', 0x10)) +
                          tag(2, erf_ts(1700000000, 0xffffffff))),
                          [host_eh(HOST_A, 1)])
    # 5-12: Ethernet records of every Ethernet type, flags with every
    #       capture interface, a color, a loss counter (warning)
    E.rec(2, eth(1), sub=eth_sub(0, 0))
    E.rec(2, eth(2), flags=0x05, sub=eth_sub(2, 0))
    E.rec(11, eth(3), flags=0x06, lctr=0x1234, sub=eth_sub())
    E.rec(16, eth(4), flags=0x07, lctr=0x0042, sub=eth_sub())
    E.rec(20, eth(5), flags=0x44, lctr=0x0007, sub=eth_sub())
    E.rec(2, eth(6), flags=0x84, lctr=3, sub=eth_sub())
    # IPv4 and IPv6 records
    E.rec(22, ipv4_udp(7))
    E.rec(23, ipv6_udp(8))
    # 13-18: HDLC POS with Cisco HDLC (first octet 0x0f) and PPP, the
    #        colored and hash POS types
    E.rec(1, chdlc(9))
    E.rec(1, ppp(10))
    E.rec(10, b'\x8f\x00\x08\x00' + ipv4_udp(11), lctr=5)
    E.rec(15, chdlc(12))
    E.rec(19, ppp(13))
    E.rec(17, chdlc(14), sub=struct.pack('>I', 0x00000005))
    # 19: MC HDLC with no error bits, first cell
    E.rec(5, chdlc(15), sub=struct.pack('>I', 0x40000123))
    # 20: MC RAW
    E.rec(6, b'\x01\x02\x03\x04\x05\x06\x07\x08', sub=struct.pack('>I', 0x40000001))
    # 21: MC RAW channel
    E.rec(8, b'\x11' * 16, sub=struct.pack('>I', 0x40000002))
    # 22-27: ATM raw cells (no HEC)
    E.rec(3, atm_hdr(1, 32) + bytes(range(48)))
    E.rec(7, atm_hdr(2, 33) + bytes(range(48)), sub=struct.pack('>I', 0x40010004))
    # AAL5: guessed by VPI/VCI and contents
    E.rec(4, atm_hdr(0, 5) + b'\x00' * 8)                       # signalling VCI 5
    E.rec(4, atm_hdr(0, 16) + ilmi_get())                        # ILMI (SNMP)
    E.rec(4, atm_hdr(1, 100) + b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + ipv4_udp(16))  # LLC/SNAP
    E.rec(4, atm_hdr(1, 101) + struct.pack('>II', 5, 0x0a000007))  # short: SSCOP POLL
    E.rec(4, atm_hdr(1, 102) + b'\x83' + b'\0' * 20)              # MTP3b
    E.rec(4, atm_hdr(1, 103) + b'\xff\x00' + b'\0' * 30)          # LANE LE control
    E.rec(4, atm_hdr(1, 104) + b'\x00\x00' + eth(17)[:-4])        # LANE 802.3
    E.rec(9, atm_hdr(1, 100) + b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + ipv4_udp(18),
          sub=struct.pack('>I', 0x40020000))
    # AAL2 and MC AAL2
    E.rec(18, atm_hdr(1, 200) + b'\x08\x00\x00' + b'\x55' * 8, sub=struct.pack('>I', 0x42000008))
    E.rec(12, atm_hdr(1, 201) + b'\x08\x00\x00' + b'\x55' * 8, sub=struct.pack('>I', 0x09000000))
    # Raw link (SDH STM-1 frame), the rate from a raw link extension
    # header after another extension header, and without one
    stm1 = bytearray(2430)
    stm1[0:3] = b'\xf6\xf6\xf6'
    stm1[3:6] = b'\x28\x28\x28'
    E.rec(24, bytes(stm1), [ehdr(EH_CLASS, 1), ehdr(EH_RAWLINK, (7 << 16) | (1 << 8) | 2)])
    E.rec(24, bytes(stm1))
    # InfiniBand link packet (flow control)
    E.rec(25, b'\x00\x10\x00\x20\x12\x34\x00\x01')
    # Counter and legacy-ish types: nothing to dissect
    E.rec(13, b'\0' * 16)
    E.rec(14, b'\0' * 16)
    # Unknown and internal types: data
    E.rec(30, b'unknown type 30')
    E.rec(33, b'internal type 33')
    # Every extension header type (classification with every flag,
    # intercept, raw link, BFS, channelised, signature, packet ID
    # (unknown), flow ID, entropy, an unknown type)
    E.rec(2, eth(19), [
        ehdr(EH_CLASS, (0xffffff << 32) | 0x12345678),
        ehdr(EH_INTERCEPT, (0x11 << 48) | (0x2233 << 32) | 0x44556677),
        ehdr(EH_RAWLINK, (0xabcdef << 32) | (0x1234 << 16) | (3 << 8) | 1),
        ehdr(EH_BFS, (0x5a << 48) | (0x1234 << 32) | 0xdeadbeef),
        ehdr(EH_SIG, (0x123456 << 32) | (0x78 << 24) | 0x9abcde),
        ehdr(EH_PKTID, 0x0102030405060708),
        ehdr(EH_FLOW, (2 << 48) | (0x81 << 40) | (4 << 32) | 0xcafef00d),
        ehdr(EH_ENTROPY, 200 << 48),
        ehdr(99, 0x55),
    ], sub=eth_sub())
    E.rec(2, eth(20), [ehdr(EH_FLOW, (0 << 48) | (0x05 << 40) | 0x1), ehdr(EH_ENTROPY, 0),
                       ehdr(EH_FLOW, (3 << 48) | (0x7f << 40))], sub=eth_sub())
    # Channelised extension headers: VC sizes and line rates
    for vc_id, vc_size, rate in ((0x1b, 1, 2), (0x00, 2, 1), (0xe4, 3, 4), (0x00, 2, 0),
                                 (0x24, 1, 0), (0x00, 5, 5), (0x55, 4, 5), (0x01, 0, 3),
                                 (0x02, 7, 2), (0x03, 1, 9), (0x00, 4, 0)):
        E.rec(2, eth(30 + vc_id), [ehdr(EH_CHAN, (1 << 55) | (0x123 << 40) | (0x5 << 32) |
                                           (vc_id << 24) | (vc_size << 16) | (rate << 8) | 1)],
              sub=eth_sub())
    # More than 16 extension headers (warning: not all shown)
    E.rec(2, eth(21), [ehdr(EH_SIG, k) for k in range(17)], sub=eth_sub())
    # Host ID / Source ID: records with a Flow ID (Source ID 1 of the
    # implicit Host ID), Source 2 of Host A, Host B (no Provenance yet)
    R['flow_src1'] = E.rec(2, eth(22), [ehdr(EH_FLOW, (1 << 48) | 1)], sub=eth_sub())
    R['host_a2'] = E.rec(2, eth(23), [host_eh(HOST_A, 2)], sub=eth_sub())
    R['host_b'] = E.rec(2, eth(24), [host_eh(HOST_B, 1)], sub=eth_sub())
    # Host ID 0 Source 0 with no Provenance (not tracked)
    E.rec(2, eth(25), [ehdr(EH_SIG, 1)], sub=eth_sub())
    # second periodic record of Host A Source 1, one of Source 2 and one
    # of Host B; Provenance through a Flow ID (implicit Host ID)
    R['meta2'] = meta_periodic(E, HOST_A, 1, n=2)
    R['meta_a2'] = meta_periodic(E, HOST_A, 2, n=3)
    R['meta_b'] = meta_periodic(E, HOST_B, 1, n=4)
    R['meta_flow'] = E.rec(27, section(0xFF00, 1, tag(1, b'flow id provenance')),
                           [ehdr(EH_FLOW, (3 << 48) | 1)])
    R['after'] = E.rec(2, eth(26), [ehdr(EH_FLOW, (1 << 48) | 2)], sub=eth_sub())
    R['after_b'] = E.rec(2, eth(27), [host_eh(HOST_B, 1)], sub=eth_sub())
    R['meta3'] = meta_periodic(E, HOST_A, 1, n=5)
    # Anchor IDs: a packet with an anchor definition and the Provenance
    # comment record for it (as wiretap writes a packet comment)
    R['anchor_def'] = E.rec(2, eth(28), [host_eh(HOST_A, 1), anchor_eh(0x1001, True)], sub=eth_sub())
    R['anchor_comment'] = E.rec(27, section(0xFF06, 0x8001, tag(1, b'packet comment')),
                                [host_eh(HOST_A, 1), anchor_eh(0x1001)])
    # Fix reproducer (ERF: Bound Anchor ID linking): 70 records with the
    # same Anchor ID, then its definition record (64 links and a note)
    # and one more non-definition record (links only to the definition)
    first = None
    for k in range(70):
        n = E.rec(2, eth(100 + k), [host_eh(HOST_A, 1), anchor_eh(0x2002)], sub=eth_sub(), tsstep=1 << 24)
        first = first or n
    R['many_first'] = first
    R['many_def'] = E.rec(27, section(0xFF06, 0x8002, tag(1, b'comment on many')),
                          [host_eh(HOST_A, 1), anchor_eh(0x2002, True)])
    R['many_after'] = E.rec(2, eth(200), [host_eh(HOST_A, 1), anchor_eh(0x2002)], sub=eth_sub())
    # Anchor IDs 0x000000000012 and 0x000100000012 hash the same and were
    # compared with the wrong mask: they must not link to each other
    R['low'] = E.rec(2, eth(201), [host_eh(HOST_A, 1), anchor_eh(0x000000000012, True)], sub=eth_sub())
    R['high'] = E.rec(2, eth(202), [host_eh(HOST_A, 1), anchor_eh(0x000100000012, True)], sub=eth_sub())
    R['low2'] = E.rec(27, section(0xFF06, 0x8003, tag(1, b'comment low')),
                      [host_eh(HOST_A, 1), anchor_eh(0x000000000012)])
    # The same Anchor ID twice in one record (the second is not recorded again)
    R['anchor_twice'] = E.rec(2, eth(205), [host_eh(HOST_A, 1), anchor_eh(0x4004), anchor_eh(0x4004)], sub=eth_sub())
    # Anchor ID on a record without a Host ID (implicit Host ID)
    R['anchor_implicit'] = E.rec(2, eth(203), [anchor_eh(0x3003, True)], sub=eth_sub())
    # Interface 2 and 3 records (flags), OPA SnC
    E.rec(28, struct.pack('<BBHIQ', 1, 0, 0, 0, 0) + b'\0' * 16)
    E.rec(2, eth(204), flags=0x46, sub=eth_sub())
    return E, R


def malformed_capture():
    E = Erf()
    # Error flags: truncation, Rx error, DS error (each and together)
    E.rec(2, eth(1), flags=0x0c, sub=eth_sub())
    E.rec(2, eth(2), flags=0x14, sub=eth_sub())
    E.rec(2, eth(3), flags=0x24, sub=eth_sub())
    E.rec(2, eth(4), flags=0x3c, sub=eth_sub())
    # MC HDLC with every error bit
    for bit in range(24, 30):
        E.rec(5, chdlc(5), sub=struct.pack('>I', 1 << bit))
    # PAD record (wiretap skips them in ERF files, not in pcap) and a
    # legacy record (type 0)
    E.rec(48, b'\0' * 8)
    E.rec(0, b'\0' * 8)
    # Provenance: parent_section shorter than 4 octets (the reproducer of
    # "ERF: ... check parent_section length", lengths 0, 1, 3)
    for L in (0, 1, 3):
        E.rec(27, section(0xFF00, 1, tag(3, b'\xff\x03\x00'[:L], L) + tag(1, b'after')),
              [host_eh(HOST_A, 1)])
    # Tags shorter than their type, zero length fixed-size tags, a tag
    # past the end of the record, a truncated record, a section header
    # with a short value, wrong section length, ext_hdrs not a multiple of 4,
    # the reset tag, an oversized integer tag
    E.rec(27, section(0xFF00, 1, tag(64, b'\x01\x02') + tag(66, b'', 0) + tag(256, b'\x01\x02') +
                      tag(57, b'\xff' * 5) + tag(57, b'\x01\x02\x03') + tag(4, b'\0\0\0\0') +
                      tag(64, b'\0' * 8)), [host_eh(HOST_A, 1)])
    E.rec(27, section(0xFF00, 1, tag(1, b'abc'), slen=40) + struct.pack('>HH', 0xFF01, 2) +
          struct.pack('>HH', 1, 200) + b'abc', [host_eh(HOST_A, 1)])
    E.rec(27, struct.pack('>HH', 0xFF03, 0) + struct.pack('>HHH', 0xFF04, 2, 1) + b'\0\0' + b'\x01\x02',
          [host_eh(HOST_A, 1)])
    # ns_host tags at exactly the address size and shorter
    E.rec(27, section(0xFF0A, 1, tag(256, bytes((192, 0, 2, 9))) + tag(262, b'\x11' * 16) +
                      tag(261, b'\x00\x05') + tag(256, b'\x01\x02')), [host_eh(HOST_A, 1)])
    # AAL5 shorter than 3 octets (guessed as signalling, too short for SSCOP)
    E.rec(4, atm_hdr(1, 105) + b'\x01\x02')
    # Records cut short for the subheaders and the ATM header
    E.rec(3, b'\x00\x10')
    E.rec(4, b'\x00')
    E.rec(1, b'')
    E.rec(2, b'\x01', sub=eth_sub())
    E.rec(22, b'\x45\x00')
    E.rec(23, b'\x60')
    E.rec(21, b'\x00')
    E.rec(29, b'\x00\x01')
    E.rec(25, b'\x30')
    return E


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    E, R = main_capture()
    E.write_erf(os.path.join(out, 'erf-coverage.erf'))
    malformed_capture().write_pcap(os.path.join(out, 'erf-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for k, v in R.items():
            print(k, v)
        print('records', len(E.recs))


if __name__ == '__main__':
    main()
