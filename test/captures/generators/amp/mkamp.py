#!/usr/bin/env python3
# AMP coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AMP (packet-amp.c).

AMP (Asynchronous Management Protocol, draft-birrane-dtn-amp, CBOR
encoding) is reached by default from the Bundle Protocol version 6
dissector: a bundle on UDP port 4556 whose source and destination SSP
offsets are 5 and 6 (either way round) has its payload dissected as AMP
(packet-bpv6.c, dissect_payload_header()). The bundles here use CBHE
(dictionary length 0), so the endpoints are ipn:<node>.5 and ipn:<node>.6.
A manager (10.0.0.1, ipn:1.5) talks to an agent (10.0.0.2, ipn:2.6).

AMP has no UDP port of its own; it is only offered in Decode As. A few
frames on UDP port 40001 cover dissect_amp() itself and need
-d udp.port==40001,amp.

Usage: mkamp.py [<output directory>]

Writes:
  amp-coverage.pcap            every message type, every CBOR head form,
                               every TNVC data item kind with valid sizes
  amp-coverage-malformed.pcap  paths that only malformed input reaches
                               (error expert infos, exceptions), including
                               the TNVC array item reproducer of
                               "AMP: Stop at a TNVC item larger than the
                               packet" (frame 1, UDP port 40001)

Every packet is built here; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from capgen import eth, ipv4, udp, write_pcap  # noqa: E402

MANAGER = (10, 0, 0, 1)
AGENT = (10, 0, 0, 2)
BUNDLE_PORT = 4556
AMP_UDP_PORT = 40001
T_2026 = 1792000000           # a plausible absolute AMP timestamp (2026)


class Pcap:
    def __init__(self):
        self.frames = []

    def udp(self, sport, dport, payload, src=MANAGER, dst=AGENT):
        seg = udp(payload, sport, dport, src=bytes(src), dst=bytes(dst))
        ip = ipv4(seg, 17, src=bytes(src), dst=bytes(dst), ident=len(self.frames) & 0xffff,
                  flags_frag=0x4000)
        self.frames.append(eth(ip, 0x0800, dst='02:00:00:00:00:02', src='02:00:00:00:00:01'))

    def bundle(self, amp, reverse=False, swap_ssp=False):
        """AMP payload in a BPv6 bundle on UDP 4556."""
        if reverse:
            self.udp(BUNDLE_PORT, BUNDLE_PORT, bpv6(amp, swap_ssp, True), src=AGENT, dst=MANAGER)
        else:
            self.udp(BUNDLE_PORT, BUNDLE_PORT, bpv6(amp, swap_ssp))

    def amp_udp(self, amp):
        """AMP directly on UDP (Decode As only)."""
        self.udp(AMP_UDP_PORT - 1, AMP_UDP_PORT, amp)

    def write(self, path):
        write_pcap(path, self.frames, ts=lambda i: (1792000000 + i, 0))


# ---------------------------------------------------------------------------
# Bundle Protocol version 6 (RFC 5050), CBHE dictionary

def sdnv(v):
    out = [v & 0x7f]
    v >>= 7
    while v:
        out.append(0x80 | (v & 0x7f))
        v >>= 7
    return bytes(reversed(out))


_seq = [0]


def bpv6(payload, swap_ssp=False, reverse=False):
    """Bundle from the manager ipn:1.5 to the agent ipn:2.6 (or the
    other way round with reverse; swap_ssp swaps the service numbers)."""
    src_ssp, dst_ssp = (6, 5) if swap_ssp else (5, 6)
    src_node, dst_node = (2, 1) if reverse else (1, 2)
    if reverse:
        src_ssp, dst_ssp = dst_ssp, src_ssp
    _seq[0] += 1
    rest = b''.join(sdnv(v) for v in (
        dst_node, dst_ssp,   # destination
        src_node, src_ssp,   # source
        0, 0,                # report-to dtn:none
        0, 0,                # custodian dtn:none
        830000000,           # creation timestamp (seconds since 2000)
        _seq[0],             # sequence number
        3600,                # lifetime
        0))                  # dictionary length 0: CBHE
    primary = b'\x06' + sdnv(0x10) + sdnv(len(rest)) + rest  # singleton destination
    block = b'\x01' + sdnv(0x08) + sdnv(len(payload)) + payload  # payload, last block
    return primary + block


# ---------------------------------------------------------------------------
# CBOR heads, with a choice of the argument size (24..27 = 1, 2, 4, 8 octets)

def head(major, n, form=None):
    if form is None:
        form = n if n < 24 else 24 if n < 0x100 else 25 if n < 0x10000 else \
            26 if n < 0x100000000 else 27
    b = bytes([(major << 5) | form])
    if form < 24:
        assert n == form
        return b
    return b + n.to_bytes({24: 1, 25: 2, 26: 4, 27: 8}[form], 'big')


def uint(n, form=None):
    return head(0, n, form)


def bstr(b, form=None):
    return head(2, len(b), form) + b


def tstr(s, form=None):
    if isinstance(s, str):
        s = s.encode()
    return head(3, len(s), form) + s


def arr(n, form=None):
    return head(4, n, form)


# ---------------------------------------------------------------------------
# AMP encoding (packet-amp.c's view of it)

def amp(messages, ts=None, outer=None):
    """AMP PDU: a CBOR head whose argument is 1 + the number of messages,
    a timestamp, then the messages. outer and ts are raw CBOR, so that any
    head form can be used."""
    if outer is None:
        outer = arr(len(messages) + 1)
    if ts is None:
        ts = uint(T_2026)
    return outer + ts + b''.join(messages)


def message(hdr, body, form=None):
    """A message: byte string holding the header octet and the body."""
    return bstr(bytes([hdr]) + body, form)


def register(name, hdr=0x00, form=None):
    return message(hdr, tstr(name, form))


def control_only(opcode, body=b''):
    """A message of the header octet alone (Perform Control, Table Set or
    an undefined opcode: the dissector does not go past the header, so
    the following message must start right after it)."""
    return message(opcode, body)


def tnvc(items, types, flags=0x04, count=None):
    """Entries: a byte string holding the TNVC array head (2 + number of
    data items), the flags octet, the types byte string and the items."""
    if count is None:
        count = len(items) + 2
    return bstr(arr(count) + bytes([flags]) + bstr(bytes(types)) + b''.join(items))


def report(ari_flags, ari_rest=b'', ts=None, entries=None, form=None):
    """Report: array(2 or 3) of template (ARI byte string), optional
    timestamp (uint32) and entries."""
    out = arr(3 if ts is not None else 2)
    out += bstr(bytes([ari_flags]) + ari_rest, form)
    if ts is not None:
        out += uint(ts, 26)
    if entries is None:
        entries = tnvc([], [])
    return out + entries


def report_set(rx_names, reports, hdr=0x01, form=None):
    """Report set. The dissector advances past the reports array head by
    the size of the Rx names array head, so both use the same form."""
    body = arr(len(rx_names), form) + b''.join(tstr(n) for n in rx_names)
    body += arr(len(reports), form) + b''.join(reports)
    return message(hdr, body)


# TNVC data items


def it_string(s, form=None):
    return bstr(tstr(s, form))        # type 0x12


def it_uvast(n, form=None):
    return bstr(uint(n, form))        # type 0x16


T_STR, T_UVAST = 0x12, 0x16


# ---------------------------------------------------------------------------
# Main capture

def main_capture():
    c = Pcap()

    # --- Register Agent, with every text string head form and header flag
    c.bundle(amp([register('agent-1')]), reverse=True)                               # 1
    c.bundle(amp([register('agent-2.example', hdr=0xF8, form=24)], ts=uint(0)),
             reverse=True)                                                           # 2
    c.bundle(amp([register('agent-3', hdr=0x20, form=25)], ts=uint(7, 24)),
             reverse=True)                                                           # 3
    c.bundle(amp([register('agent-4', hdr=0x10, form=26)], ts=uint(T_2026 + 1, 25 + 1)),
             reverse=True)                                                           # 4
    c.bundle(amp([register('agent-5', hdr=0x08, form=27)], ts=uint(T_2026 + 2, 27)),
             reverse=True, swap_ssp=True)                                            # 5

    # --- The outer head: its argument is taken as 1 + messages whatever
    # the major type, so every head form of every major type is used
    reg = register('agent-6')
    for outer in (arr(2, 24), arr(2, 25), arr(2, 26), arr(2, 27),                   # 6-9
                  uint(2), uint(2, 24), uint(2, 25), uint(2, 26), uint(2, 27),     # 10-14
                  head(2, 2), head(2, 2, 24), head(2, 2, 25), head(2, 2, 26),      # 15-18
                  head(2, 2, 27),                                                   # 19
                  head(3, 2), head(3, 2, 24), head(3, 2, 25), head(3, 2, 26),      # 20-23
                  head(3, 2, 27),                                                   # 24
                  head(6, 2)):                                                      # 25
        c.bundle(amp([reg], outer=outer), reverse=True)

    # --- The timestamp as other CBOR items: negative integer, map,
    # simple value, tag (small and with a following argument, which the
    # dissector does not read), byte and text strings, array
    # and the additional information values 28-31 (reserved and
    # indefinite length), which leave the value unset
    for ts in (b'\x20', b'\xa0', b'\xf6', b'\xc1', b'\xd8', b'\x40', b'\x58\x00',     # 26-32
               b'\x60', b'\x80',                                                     # 33-34
               b'\x1c', b'\x5f', b'\x7f', b'\x9f'):                                    # 35-38
        c.bundle(amp([reg], ts=ts), reverse=True)

    # --- An AMP PDU with only the timestamp
    c.bundle(amp([]))                                                                # 39

    # --- Several messages in one PDU, with Perform Control, Table Set and
    # undefined opcodes between them
    c.bundle(amp([register('agent-7'), control_only(0x02), register('agent-8'),
                  control_only(0x03), control_only(0x04), control_only(0x05),
                  control_only(0x06), control_only(0x3F), register('agent-9')]))     # 40
    c.bundle(amp([control_only(0x22, b'\x00')]))                                              # 41 Perform Control last
    c.bundle(amp([control_only(0x0B, b'\x00')]))                                              # 42 Table Set last

    # --- Report sets
    # No Rx names, one report with a literal template and no data items
    c.bundle(amp([report_set([], [report(0x03)])]), reverse=True)                    # 43
    # Rx names, two reports, non-literal templates, with and without
    # timestamp (absolute and relative)
    c.bundle(amp([report_set(['mgr-1', 'mgr-2.example'], [
        report(0x82, b'\x01\x02\x03', ts=T_2026,
               entries=tnvc([it_uvast(5)], [T_UVAST])),
        report(0xF9, b'\xaa\xbb', ts=100,
               entries=tnvc([it_string('ok')], [T_STR])),
    ])]), reverse=True)                                                               # 44
    # Rx names and reports arrays with a one octet argument
    c.bundle(amp([report_set(['mgr-3'], [report(0x13, entries=tnvc([it_uvast(9)], [T_UVAST]))],
                             form=24)]), reverse=True)                                # 45
    # Every TNVC data item kind with a valid size
    items = [
        it_string('ifInOctets'),            # 0x12: text string in a byte string
        it_string('x' * 30, 24),            # longer string, 1 octet length
        it_uvast(23),                       # 0x16: uvast, value in the head
        it_uvast(200, 24),                  # uvast, 1 octet
        it_uvast(0x1234, 25),               # uvast, 2 octets
        it_uvast(0x12345678, 26),           # uvast, 4 octets
        it_uvast(0x123456789abcdef0, 27),   # uvast, 8 octets
        bstr(tstr('not-a-uint')),           # 0x16 holding a non-integer
        bstr(b'\x01\x02\x03\x04'),          # byte string of an unhandled type
        tstr('raw'),                        # not a byte string: Report-Data
        uint(3),                            # integer: shown as 3 octets of data
        b'\xaa\xbb\xcc',                    #   (those 3 octets, skipped below)
    ]
    types = [T_STR, T_STR, T_UVAST, T_UVAST, T_UVAST, T_UVAST, T_UVAST, T_UVAST, 0x10, 0, 0, 0x01]
    # uint(3) is one octet long for the dissector, so the 3 octets after it
    # are read as the next item: make them a byte string item instead
    items[-1] = bstr(b'\xcc')
    items[-2] = uint(1)
    c.bundle(amp([report_set(['mgr-1'], [report(0x82, b'\x07', ts=T_2026,
                                                entries=tnvc(items, types, flags=0x0F))])]),
             reverse=True)                                                            # 46
    # Byte strings of every head form as items, and a report with three
    # reports and a semantic tag item
    items = [bstr(b'\x05', 24), bstr(b'\x05', 25), bstr(b'\x05', 26), bstr(b'\x05', 27),
             bstr(b'', 24)]
    c.bundle(amp([report_set([], [
        report(0x03, entries=tnvc(items, [0x01] * 5)),
        report(0x03, entries=tnvc([tstr('a', 25), tstr('b', 26), tstr('c', 27)], [])),
        report(0x03, entries=tnvc([b'\xc1', b'\x00', it_uvast(1)], [0, 0, T_UVAST])),
    ])]), reverse=True)                                                               # 47
    # Items whose CBOR size is zero for the dissector (negative integer,
    # map, simple value, tag 0) end the data items. The first three are
    # shown as Report-Data to the end of the packet (their "length" is
    # (int)-1), which throws if they are the last octet, so one octet
    # follows them
    for last in (b'\x20\x00', b'\xa0\x00', b'\xf6\x00', b'\xc0'):                                 # 48-51
        c.bundle(amp([report_set([], [report(0x03, entries=tnvc([it_uvast(1), last], [T_UVAST]))])]),
                 reverse=True)
    # Rx names that are not an array: the report set is not dissected
    c.bundle(amp([message(0x01, tstr('mgr') + arr(0))]), reverse=True)                # 52
    # A report set followed by a Register Agent in the same PDU
    c.bundle(amp([report_set(['mgr-1'], [report(0x03, entries=tnvc([it_uvast(42)], [T_UVAST]))]),
                  register('agent-10')]), reverse=True)                               # 53

    # --- AMP directly on UDP (Decode As)
    c.amp_udp(amp([register('udp-agent')]))                                           # 54
    c.amp_udp(amp([report_set(['udp-mgr'], [report(0x82, b'\x01', ts=T_2026,
                    entries=tnvc([it_string('udp'), it_uvast(77, 24)], [T_STR, T_UVAST]))])]))  # 55
    c.amp_udp(amp([register('udp-agent-2'), control_only(0x02, b'\x00')]))                     # 56
    return c


# ---------------------------------------------------------------------------
# Malformed capture

def tnvc_raw(items_raw, types=b'\x00', count=3):
    return bstr(arr(count) + b'\x00' + bstr(types) + items_raw)


def rs1(entries, ari=0x03, ari_rest=b''):
    return report_set([], [report(ari, ari_rest, entries=entries)])


def malformed_capture():
    c = Pcap()
    # 1: a TNVC array item larger than the packet
    c.amp_udp(bytes([0x82, 0x00, 0x50, 0x01, 0x80, 0x81, 0x82, 0x41, 0x03, 0x50, 0x83,
                     0x00, 0x41, 0x00, 0x84]) + b'\x00' * 8)
    # 2: the same TNVC array item in a bundle
    c.bundle(amp([rs1(tnvc_raw(b'\x84' + b'\x00' * 8))]))
    # 3: a byte string item longer than the packet
    c.bundle(amp([rs1(tnvc_raw(b'\x58\x40' + b'\x00' * 4))]))
    # 4: a text string item with a length past INT32_MAX
    c.bundle(amp([rs1(tnvc_raw(b'\x7b\x00\x00\x00\x01\x00\x00\x00\x00' + b'\x00' * 4))]))
    # 5: a tag item with a one octet argument (size taken as UINT64_MAX)
    c.bundle(amp([rs1(tnvc_raw(b'\xd8\x01\x00'))]))
    # 6: Register Agent name length that wraps the offset
    c.bundle(amp([message(0x00, b'\x7a\xff\xff\xff\xff' + b'abc')]))
    # 7: Rx name length that wraps the offset
    c.bundle(amp([message(0x01, b'\x81\x7a\xff\xff\xff\xff' + b'abc')]))
    # 8: literal template length that wraps the offset
    c.bundle(amp([message(0x01, b'\x80\x81\x82\x5a\xff\xff\xff\xff\x03' + b'\x00' * 4)]))
    # 9: non-literal template of length 0xffffffff (item length -2)
    c.bundle(amp([message(0x01, b'\x80\x81\x82\x5a\xff\xff\xff\xff\x82' + b'\x00' * 4)]))
    # 10: types byte string length that wraps the offset
    c.bundle(amp([message(0x01, b'\x80\x81\x82\x41\x03\x50\x83\x00\x5a\xff\xff\xff\xff\x00')]))
    # 11: TNVC array of one entry (count - 2 wraps): items until the end
    c.bundle(amp([rs1(tnvc_raw(b'\x00' * 6, count=1))]))
    # 12: TNVC array of zero entries, items that are byte strings
    c.bundle(amp([rs1(tnvc_raw(b'\x41\x05' * 3, types=b'\x16\x16\x16', count=0))]))
    # 13: outer head with a huge count: messages until the end
    c.bundle(amp([register('a')], outer=b'\x9b' + b'\xff' * 8))
    # 14: outer tag with a one octet argument (count taken as UINT64_MAX)
    c.bundle(amp([register('a')], outer=b'\xd8'))
    # 15: truncated register agent
    c.bundle(amp([register('agent-truncated')])[:-6])
    # 16: truncated report timestamp
    c.bundle(amp([report_set([], [report(0x03, ts=T_2026)])])[:12])
    # 17: uvast item whose integer is cut short by the packet
    c.bundle(amp([rs1(tnvc_raw(b'\x42\x1b\x01', types=b'\x16'))]))
    # 18: string item whose text is cut short
    c.bundle(amp([rs1(tnvc_raw(b'\x45\x78\x20\x41', types=b'\x12'))]))
    # 19: AMP PDU of the outer head alone (UDP)
    c.amp_udp(b'\x82')
    # 20: report set with no report data at all
    c.bundle(amp([message(0x01, b'')]))
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'amp-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'amp-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
