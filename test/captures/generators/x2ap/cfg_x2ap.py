# Helper module for the x2ap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import sys
import asngen
PREFIX = 'X2AP'; PPID = 27; PORT = 36422
HANDOFF = 'TargeteNBtoSource-eNBTransparentContainer RRC-Context UE-HistoryInformationFromTheUE UE-RLF-Report-Container UE-RLF-Report-Container-for-extended-bands NBIoT-RLF-Report-Container MeNBtoSeNBContainer SeNBtoMeNBContainer MeNBtoSgNBContainer SgNBtoMeNBContainer RRCContainer LastVisitedNGRANCellInformation LastVisitedUTRANCellInformation EndcSONConfigurationTransfer EPCHandoverRestrictionListContainer Non-anchorCarrierFrequency TargetCellInNGRAN TDDULDLConfigurationCommonNR MDT-ConfigurationNR NRCellPRACHConfig NRRAReportContainer IntendedTDD-DL-ULConfiguration-NR UERadioCapability PSCellListContainer SCG-FailureReportContainer LastVisitedPSCell-Item'.split()
HANDOFF += ['*/measurementTimingConfiguration', 'ServedNRCell-Information/measurementTimingConfiguration'] + ['NPRACHConfiguration-FDD/' + x for x in 'anchorCarrier-NPRACHConfig anchorCarrier-EDT-NPRACHConfig anchorCarrier-Format2-NPRACHConfig anchorCarrier-Format2-EDT-NPRACHConfig non-anchorCarrier-NPRACHConfig non-anchorCarrier-Format2-NPRACHConfig'.split()] + ['NPRACHConfiguration-TDD/anchorCarrier-NPRACHConfigTDD', 'NPRACHConfiguration-TDD/non-anchorCarrier-NPRACHConfigTDD']
# X2AP-Message is never generated randomly (nesting is built by hand)
SKIP = ['X2AP-Message']

def plmn(g):
    r = g.rng
    d = [r.randint(0, 9) for _ in range(5)]
    m3 = r.choice([r.randint(0, 9), 15])
    return bytes([d[1] << 4 | d[0], m3 << 4 | r.randint(0, 9), d[3] << 4 | d[2]])

def traceid(g):
    # E-UTRAN Trace ID: PLMN (3 octets) + trace ID (3 octets) + recording session reference (2 octets)
    return plmn(g) + bytes(g.rng.randrange(256) for _ in range(5))

def bits(g, n):
    nb = (n + 7) // 8
    data = bytes(g.rng.choice(g.alpha) for _ in range(nb))
    if n % 8:
        data = data[:-1] + bytes([data[-1] & (0xff << (8 - n % 8)) & 0xff])
    return (data, n)

def tla(g):
    # IPv4 (32), IPv6 (128), both (160) and lengths that are none of them
    return bits(g, g.rng.choice([32, 32, 128, 128, 160, 160, 24, 72, 1, 8 * 5 + 3]))

def enc(v):
    if isinstance(v, tuple):
        return ['b', v[0].hex(), v[1]]
    return ['o', v.hex()]

def dec(x):
    return (bytes.fromhex(x[1]), x[2]) if x[0] == 'b' else bytes.fromhex(x[1])

def make_gen(spec, rng, **kw):
    g = asngen.Gen(spec, rng, **kw)
    g.handoff = HANDOFF
    g.override['PLMN-Identity'] = plmn
    g.override['TransportLayerAddress'] = tla
    g.override['TraceCollectionEntityIPAddress'] = tla
    g.override['EUTRANTraceID'] = traceid
    for t in SKIP:
        g.override[t] = lambda g: asngen.NOVALUE
    return g
