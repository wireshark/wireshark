# Generates test/captures/xnap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import sys














import random
import capio

def messages(spec, rng_seed, variants, g_factory):
    """yield (label, pdubytes) for every procedure message, `variants` per message"""
    out = []
    for name, imsg, sout, uout, code, crit in spec.procs:
        for kind, msg in ((0, imsg), (1, sout), (2, uout)):
            if not msg:
                continue
            for v in range(variants):
                g = g_factory(random.Random('%s/%s/%d/%d' % (spec.name, msg, rng_seed, v)), v)
                try:
                    body = g.gen_encode(msg)
                except Exception as e:
                    print('FAIL', msg, v, type(e).__name__, str(e)[:100], file=sys.stderr)
                    continue
                out.append((msg, v, capio.pdu(kind, code, crit, body)))
    return out
