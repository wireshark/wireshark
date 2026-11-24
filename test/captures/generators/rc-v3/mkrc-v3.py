#!/usr/bin/env python3
# Generates test/captures/rc-v3_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic E2SM-RC v3 (packet-rc-v3.c) coverage captures.

Usage: mkrc-v3.py <outdir> [<asn1 dir>]

packet-rc-v3.c is generated from asn1/rc-v3 and has no port or heuristic
of its own: E2AP finds it through the RAN function table (the RAN
function's short name ORAN-E2SM-RC and OID, registered by the dissector
as "rc_v3"). So the PDUs are carried in E2AP messages over SCTP (PPID
70, port 37464): an E2setupRequest announcing the RAN function, then
subscription, indication, control and query messages whose service model
octet strings (event trigger, action definition, indication header and
message, call process ID, control header, message and outcome, query
header, definition and outcome, RAN function definition) are encoded
with aper.py from the E2SM-RC v3.05 ASN.1 modules, with every optional
component present and a different CHOICE alternative in each variant.
The E2AP framing and the ASN.1 encoder are those of the E2AP coverage
(mke2ap.py, aper.py, e2ap_perlib.py, copied here). Nothing comes from a
real network.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















import mke2ap as M

OUT = M.OUT
NVARIANTS_RC = int(os.environ.get('RC3_VARIANTS', '120'))


def traffic(g, a, f, ks):
    out = []
    for k in ks:
        out.append(a.frame(g.msg('id-RICsubscription', 0, f, k=k), True))
        out.append(a.frame(g.msg('id-RICsubscription', 1, f, k=k), False))
        out.append(a.frame(g.msg('id-RICindication', 0, f, k=k), False))
        out.append(a.frame(g.msg('id-RICcontrol', 0, f, k=k), True))
        out.append(a.frame(g.msg('id-RICcontrol', 1, f, k=k), False))
        out.append(a.frame(g.msg('id-RICcontrol', 2, f, k=k), False))
        out.append(a.frame(g.msg('id-RICquery', 0, f, k=k), True))
        out.append(a.frame(g.msg('id-RICquery', 1, f, k=k), False))
        out.append(a.frame(g.msg('id-RICquery', 2, f, k=k), False))
    return out


def main():
    g = M.Gen()
    frames = []
    f_rc = M.rf(2, 'RC', M.RC1)
    a = M.Assoc(36422)
    frames.append(a.frame(g.setup([f_rc], 1), False))        # RAN function definition (RC v3.05)
    frames.append(a.frame(g.msg('id-E2setup', 1, f_rc), True))
    frames.extend(traffic(g, a, f_rc, range(NVARIANTS_RC)))
    # a second node announcing the same function: its own mapping
    b = M.Assoc(36423)
    f_rc2 = M.rf(7, 'RC', M.RC1)
    frames.append(b.frame(g.setup([f_rc2], 2), False))
    frames.extend(traffic(g, b, f_rc2, range(NVARIANTS_RC, NVARIANTS_RC + 3)))
    M.write_pcap(os.path.join(OUT, 'rc-v3-coverage.pcap'), frames)

    # malformed: truncated and corrupted copies of the service model messages
    mal = [frames[0]]
    payloads = [fr[14 + 20 + 12 + 16:] for fr in frames[2:2 + 9 * 20]]
    for p in payloads[::5]:
        mal.append(a.frame(p[:max(1, len(p) // 2)], False))
    for p in payloads[2::7]:
        x = bytearray(p)
        x[len(x) // 2] ^= 0xa5
        mal.append(a.frame(bytes(x), True))
    M.write_pcap(os.path.join(OUT, 'rc-v3-coverage-malformed.pcap'), mal)
    print(len(frames), len(mal))


if __name__ == '__main__':
    main()
