# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Aligned PER encoding of the H.450.1 service APDU structure
(H4501SupplementaryService) and of the Remote Operations APDUs (ROS) of
Remote-Operations-Apdus.asn, which the ASN.1 parser of asnper.py cannot
handle (parameterised types and information objects).  Argument, result and
parameter values are open types that the caller encodes with asnper."""
import struct
import asnper
from asnper import PW

class Raw:
    """open type content that is already encoded"""
    def __init__(self, b): self.b = b
    def bytes(self): return self.b

def integer(w, v):
    """unconstrained INTEGER"""
    n = max(1, (v.bit_length() + 8) // 8) if v >= 0 else max(1, ((~v).bit_length() + 8) // 8)
    w.length(n).raw((v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big'))

def code(w, c):
    """Code ::= CHOICE { local INTEGER, global OBJECT IDENTIFIER }; c = ('local', int) or ('global', [arcs])"""
    kind, v = c
    w.cint(0 if kind == 'local' else 1, 0, 1)
    if kind == 'local':
        integer(w, v)
    else:
        o = asnper.oid_bytes(v)
        w.length(len(o)).raw(o)

def open_type(w, data):
    w.length(len(data)).raw(data)      # may be empty

def invoke(w, iid, c, arg=None, linked=None):
    w.cint(0, 0, 3)                      # ROS: invoke
    w.flag(linked is not None); w.flag(arg is not None)
    w.flag(0); w.cint(iid, 0, 65535)     # invokeId (extensible 0..65535)
    if linked is not None:
        integer(w, linked)
    code(w, c)
    if arg is not None:
        open_type(w, arg)

def result(w, iid, c=None, res=None):
    w.cint(1, 0, 3)                      # returnResult
    w.flag(c is not None)
    integer(w, iid)
    if c is not None:
        code(w, c)
        open_type(w, res if res is not None else b'\x00')

def error(w, iid, c, par=None):
    w.cint(2, 0, 3)                      # returnError
    w.flag(par is not None)
    integer(w, iid)
    code(w, c)
    if par is not None:
        open_type(w, par)

def reject(w, iid, kind, problem):
    w.cint(3, 0, 3)                      # reject
    integer(w, iid)
    w.cint(['general', 'invoke', 'returnResult', 'returnError'].index(kind), 0, 3)
    integer(w, problem)

def service(sc, types, apdus, nfe=None, interp=None, ext_service=False):
    """H4501SupplementaryService; apdus: list of callables writing one ROS each;
    nfe: (srcEntity, srcAddr or None, dstEntity, dstAddr or None) with entities 'endpoint'/'anyEntity';
    interp: 0..2 index of InterpretationApdu"""
    w = PW()
    w.flag(0)                            # extension bit
    w.flag(nfe is not None); w.flag(interp is not None)
    if nfe is not None:
        se, sa, de, da = nfe
        w.flag(0); w.flag(sa is not None); w.flag(da is not None)
        w.flag(0); w.cint(['endpoint', 'anyEntity'].index(se), 0, 1)
        if sa is not None:
            sc._enc(w, types['AliasAddress'], sa, None)
        w.flag(0); w.cint(['endpoint', 'anyEntity'].index(de), 0, 1)
        if da is not None:
            sc._enc(w, types['AliasAddress'], da, None)
    if interp is not None:
        w.flag(0); w.cint(interp, 0, 2)
    w.flag(0)                            # ServiceApdus extension bit (rosApdus)
    w.length(len(apdus))
    for a in apdus:
        a(w)
    return w.bytes()
