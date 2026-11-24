#!/usr/bin/env python3
# Generates the windows_common captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for packet-windows-common.c (NT security
descriptors, SIDs, ACLs, ACEs, conditional ACEs, system resource
attribute ACEs, NT time stamps).

The code is reached by SMB2 (SET_INFO and QUERY_INFO of type security,
NEGOTIATE time stamps) over TCP 445 and by LDAP (nTSecurityDescriptor and
objectSid values in a search result entry) over TCP 389. SMB2 passes no
access mask information, LDAP passes the "LDAP" specific rights.

Usage: mkwindows_common.py <output directory> [-v]
Writes windows-common-coverage.pcap (main) and
windows-common-coverage-malformed.pcap. Every packet is built with struct;
nothing comes from a real network.
"""
import os
import struct
import sys
from pcaplib import pcap, Tcp

# ------------------------------------------------------------ NT structures
def sid(auth, subs=(), rev=1, nsub=None):
    return (bytes([rev, len(subs) if nsub is None else nsub]) + auth.to_bytes(6, 'big') +
            b''.join(struct.pack('<I', s) for s in subs))

EVERYONE = sid(1, [0])
ADMINS = sid(5, [32, 544])
SYSTEM = sid(5, [18])
DOM = [21, 1111111111, 2222222222, 3333333333]

def ace(typ, mask, s=EVERYONE, flags=0, extra=b'', size=None, obj=None, guid1=bytes(range(16)), guid2=bytes(range(16, 32))):
    b = struct.pack('<I', mask)
    if obj is not None:
        b += struct.pack('<I', obj)
        if obj & 1: b += guid1
        if obj & 2: b += guid2
    b += s + extra
    return struct.pack('<BBH', typ, flags, 4 + len(b) if size is None else size) + b

def acl(aces, rev=2, count=None, size=None, pad=b''):
    body = b''.join(aces)
    return struct.pack('<HHI', rev, 8 + len(body) if size is None else size,
                       len(aces) if count is None else count) + body + pad

def sd(owner=None, group=None, sacl=None, dacl=None, typ=0x8004, rev=1, offs=None):
    """Self-relative security descriptor. offs overrides the four offsets
    (owner, group, sacl, dacl) as given (None keeps the computed one)."""
    parts = [owner, group, sacl, dacl]
    pos = 20
    o = []
    body = b''
    for p in parts:
        if p is None:
            o.append(0)
        else:
            o.append(pos + len(body)); body += p
    if offs:
        o = [x if y is None else y for x, y in zip(o, offs)]
    return struct.pack('<HHIIII', rev, typ, *o) + body

def sra(name, vtype, values, flags=0, count=None, offs=None):
    """CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1: values are bytes, each stored
    after the name; offsets point at them. Offsets are relative to the start
    of the structure."""
    n = len(values)
    hdr = 4 + 2 + 2 + 4 + 4 + 4 * n
    nm = name.encode('utf-16-le') + b'\0\0'
    pos = hdr + len(nm)
    vo, vb = [], b''
    for v in values:
        vo.append(pos + len(vb)); vb += v
    if offs: vo = [x if y is None else y for x, y in zip(vo, offs)]
    return struct.pack('<IHHII', hdr, vtype, 0, flags, n if count is None else count) + \
        b''.join(struct.pack('<I', x) for x in vo) + nm + vb

def u16(s): return s.encode('utf-16-le') + b'\0\0'

# conditional ACE tokens
def tok_int(t, v, sign=1, base=2): return bytes([t]) + struct.pack('<q', v) + bytes([sign, base])
def tok_str(t, s):
    d = s.encode('utf-16-le'); return bytes([t]) + struct.pack('<I', len(d)) + d
def tok_oct(b): return bytes([0x18]) + struct.pack('<I', len(b)) + b
def tok_sid(s): return bytes([0x51]) + struct.pack('<I', len(s)) + s
def tok_comp(inner): return bytes([0x50]) + struct.pack('<I', len(inner)) + inner
def cond(tokens, pad=b''): return b'artx' + tokens + pad

# ------------------------------------------------------------ SMB2 / LDAP
def smb2_hdr(cmd, msgid, flags=0, status=0, tree=1, sess=1):
    return b'\xfeSMB' + struct.pack('<HHIHHIIQIIQ', 64, 0, status, cmd, 1, flags, 0, msgid, 0, tree, sess) + b'\0' * 16

FID = b'\x11' * 16
def smb2_setinfo(msgid, sdbytes, addinfo=0x0f):
    return smb2_hdr(0x11, msgid) + struct.pack('<HBBIHHI', 33, 3, 0, len(sdbytes), 64 + 32, 0, addinfo) + FID + sdbytes

def smb2_queryinfo_req(msgid, addinfo=0x0f, itype=3):
    return smb2_hdr(0x10, msgid) + struct.pack('<HBBIHHIII', 41, itype, 0, 4096, 0, 0, 0, addinfo, 0) + FID

def smb2_queryinfo_rsp(msgid, sdbytes):
    return smb2_hdr(0x10, msgid, flags=1) + struct.pack('<HHI', 9, 64 + 8, len(sdbytes)) + sdbytes

def smb2_negotiate_rsp(msgid, systime, starttime):
    return smb2_hdr(0x00, msgid, flags=1) + \
        struct.pack('<HHH2s16sIIIIQQHHI', 65, 1, 0x0210, b'\0\0', bytes(16), 1, 0x100000, 0x100000, 0x100000, systime, starttime, 128, 0, 0)

def nbss(b): return struct.pack('!I', len(b)) + b

def ber_len(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big'); return bytes([0x80 | len(b)]) + b
def ber(tag, b): return bytes([tag]) + ber_len(len(b)) + b
def ber_int(n): return ber(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), 'big'))
def ber_os(b): return ber(0x04, b)
def ldap_entry(msgid, dn, attrs):
    al = b''.join(ber(0x30, ber_os(t.encode()) + ber(0x31, b''.join(ber_os(v) for v in vals))) for t, vals in attrs)
    return ber(0x30, ber_int(msgid) + ber(0x64, ber_os(dn.encode()) + ber(0x30, al)))

# ------------------------------------------------------------ the SDs
main, labels = [], []
sds = []     # (label, sd bytes, additional-information flags)
def add_sd(label, b, addinfo=0x0f): sds.append((label, b, addinfo))

# SIDs: one owner/group SID pair per SD
sid_cases = [
    ('Null/Nobody S-1-0-0', sid(0, [0])),
    ('S-1-1 (no subauth: World Authority)', sid(1, [])),
    ('Local Authority S-1-2-1 console logon', sid(2, [1])),
    ('Creator Owner S-1-3-0 and Owner Rights S-1-3-4', sid(3, [4])),
    ('NT Authority without subauth S-1-5', sid(5, [])),
    ('Logon session S-1-5-5-1-2 (level 1 wkwn, locally defined)', sid(5, [5, 111, 222])),
    ('S-1-5-11-7 level 1 well-known + local value', sid(5, [11, 7])),
    ('Domain admins S-1-5-21-a-b-c-512', sid(5, DOM + [512])),
    ('Domain Administrator RID 500', sid(5, DOM + [500])),
    ('Domain RID 1105', sid(5, DOM + [1105])),
    ('Domain SID with 6 subauthorities (locally defined)', sid(5, DOM + [1105, 77])),
    ('Domain SID with 3 subauthorities (corrupt domain SID)', sid(5, [21, 1, 2])),
    ('Domain SID with 2 subauthorities', sid(5, [21, 1])),
    ('Domain SID without RID, 4 subauthorities (S-1-5-21-a-b-c)', sid(5, DOM[:4])[:0] + sid(5, DOM)),
    ('Builtin Administrators S-1-5-32-544', ADMINS),
    ('Builtin S-1-5-32 without RID', sid(5, [32])),
    ('Builtin S-1-5-32-9999 (RID not well-known)', sid(5, [32, 9999])),
    ('Builtin S-1-5-32-544-1 (3 subauthorities)', sid(5, [32, 544, 1])),
    ('NTLM authentication S-1-5-64-10', sid(5, [64, 10])),
    ('Authentication S-1-5-64-99 (not well-known)', sid(5, [64, 99])),
    ('NT Service S-1-5-80-a-b-c-d-e', sid(5, [80, 1, 2, 3, 4, 5])),
    ('S-1-5-84-0-0-0-0-0 User Mode Drivers', sid(5, [84, 0, 0, 0, 0, 0])),
    ('Mandatory level S-1-16 (no subauth)', sid(16, [])),
    ('Mandatory level S-1-16-4096 Low', sid(16, [4096])),
    ('Mandatory level S-1-16-12288 High', sid(16, [12288])),
    ('Mandatory level S-1-16-99 (unknown)', sid(16, [99])),
    ('Central Access Policy S-1-17-1-2', sid(17, [1, 2])),
    ('Authentication authority asserted identity S-1-18-1', sid(18, [1])),
    ('App packages S-1-15-2-1', sid(15, [2, 1])),
    ('Unknown authority S-1-9-1-2', sid(9, [1, 2])),
    ('Large authority 0x010203040506', sid(0x010203040506, [7])),
    ('SID revision 2', sid(5, [18], rev=2)),
    ('SID with 15 subauthorities', sid(5, list(range(100, 115)))),
]
for i in range(0, len(sid_cases), 2):
    a = sid_cases[i]; b = sid_cases[(i + 1) % len(sid_cases)]
    add_sd('owner %s, group %s' % (a[0], b[0]), sd(owner=a[1], group=b[1]), 0x03)

# ACE types
mask_cases = [0x001f01ff, 0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x0f000000, 0x00ff0000, 0x0000ffff, 0x00000001, 0x120089, 0x00100000, 0xe0000000]
obj_flags = [0, 1, 2, 3]
aces = []
for t in range(0, 4):
    aces.append(ace(t, mask_cases[t], EVERYONE, flags=(1 << t)))
aces.append(ace(4, 0x1, SYSTEM, extra=b'\0' * 4))                         # allowed compound
for i, t in enumerate((5, 6, 7, 8)):
    aces.append(ace(t, 0x100, ADMINS, flags=0x12, obj=obj_flags[i]))
add_sd('every non-callback ACE type, object ACEs with flags 0-3, ACE flags',
       sd(owner=ADMINS, group=SYSTEM, dacl=acl(aces[:4] + aces[5:7]), sacl=acl([aces[4]] + aces[7:], rev=4), typ=0x8014 | 0x0010))
add_sd('all ACE flag bits and masks (SACL audit ACEs)', sd(sacl=acl([ace(2, m, EVERYONE, flags=f) for m, f in zip(mask_cases, (0xff, 0xc0, 0x80, 0x40, 0x1f, 0x10, 0x0f, 0x08, 0x04, 0x02, 0x01, 0x00))]), typ=0x8010), 0x08)
add_sd('mandatory label ACE (type 17) with Low and High levels',
       sd(sacl=acl([ace(17, 0x1, sid(16, [4096]), flags=0), ace(17, 0x3, sid(16, [12288]), flags=0x0a), ace(19, 0, sid(17, [1, 2]))]), typ=0x8010), 0x10)
add_sd('unknown ACE type 0x42 and 0x20 (skipped by size)', sd(dacl=acl([ace(0x42, 0, EVERYONE)[:4] + b'\xde\xad\xbe\xef', ace(0x20, 0)[:4] + b'\0' * 12, ace(0, 0x1)])))

cond_tok = [
    tok_int(1, -5), tok_int(2, 300, sign=3, base=3), tok_int(3, -70000, sign=2, base=1), tok_int(4, 1 << 40, sign=1, base=2),
    tok_str(0x10, 'Dept'), tok_oct(b'\xde\xad\xbe\xef'), tok_sid(ADMINS),
    tok_str(0xf8, 'localattr'), tok_str(0xf9, 'userattr'), tok_str(0xfa, 'resattr'), tok_str(0xfb, 'devattr'),
    bytes([0x00]),
] + [bytes([t]) for t in list(range(0x80, 0x94)) + [0xa0, 0xa1, 0xa2, 0xff]]
add_sd('callback ACE with every conditional token (data and operators)',
       sd(dacl=acl([ace(9, 0x1, EVERYONE, extra=cond(b''.join(cond_tok)))])))
add_sd('callback ACE types 9, 10, 11 (object), 12 (object), 13, 15 (object) with expressions',
       sd(dacl=acl([ace(9, 1, extra=cond(tok_str(0xf9, 'a') + tok_str(0x10, 'b') + b'\x80')),
                    ace(10, 1, extra=cond(tok_sid(EVERYONE) + b'\x89')),
                    ace(11, 1, obj=3, extra=cond(tok_int(1, 1) + b'\x87')),
                    ace(12, 1, obj=1, extra=cond(b'\xa2')),
                    ace(13, 1, extra=cond(tok_oct(b'x') + b'\x86')),
                    ace(15, 1, obj=2, extra=cond(b''))]), typ=0x8004))
add_sd('callback ACE types 14 and 16 (alarm callbacks: no condition dissection)',
       sd(sacl=acl([ace(14, 1, extra=cond(b'\x80')), ace(16, 1, obj=0, extra=cond(b'\x80'))]), typ=0x8010), 0x08)
add_sd('callback ACE data without the artx prefix, and shorter than 4 octets',
       sd(dacl=acl([ace(9, 1, extra=b'noxt' + b'\x80\x80'), ace(9, 1, extra=b'ab'), ace(9, 1)])))
add_sd('callback ACE with an empty composite and a composite with content',
       sd(dacl=acl([ace(9, 1, extra=cond(tok_comp(b'') + tok_comp(tok_int(1, 1) + tok_str(0x10, 'x') + tok_sid(EVERYONE)) + b'\xa0'))])))
add_sd('composite whose length exceeds the ACE data (malformed branch)',
       sd(dacl=acl([ace(9, 1, extra=cond(bytes([0x50]) + struct.pack('<I', 1000) + b'\x80\x80'))])))
def nest(n, leaf):
    inner = leaf
    for _ in range(n): inner = tok_comp(inner)
    return inner
add_sd('32 nested composites (the limit, no expert info)',
       sd(dacl=acl([ace(9, 1, extra=cond(nest(32, tok_int(1, 7))))])))
add_sd('33 nested composites (past the limit: expert info "nested too deeply")',
       sd(dacl=acl([ace(9, 1, extra=cond(nest(33, tok_int(1, 7))))])))
add_sd('700 nested composites (the old assertion reproducer)',
       sd(dacl=acl([ace(9, 1, extra=cond(nest(700, b'\x00')))])))
add_sd('conditional ACE with trailing pad octets', sd(dacl=acl([ace(9, 1, extra=cond(b'\x87', pad=b'\0\0\0'))])))

# system resource attribute ACEs
def sra_ace(body, flags=0, size=None): return ace(18, 0, EVERYONE, flags=flags, extra=body, size=size)
add_sd('SRA ACEs: int64 (2 values), uint64, string, sid, boolean, octet string, unknown type',
       sd(sacl=acl([
           sra_ace(sra('i64', 1, [struct.pack('<q', -5), struct.pack('<q', 99)], flags=0x0001)),
           sra_ace(sra('u64', 2, [struct.pack('<Q', 1 << 50)], flags=0x0002 | 0x0004)),
           sra_ace(sra('str', 3, [u16('one'), u16('two'), u16('three')], flags=0x0008 | 0x0010 | 0x0020)),
           sra_ace(sra('sid', 5, [sid(5, [32, 544]), sid(1, [0])], flags=0x0040 | 0x0080)),
           sra_ace(sra('bool', 6, [struct.pack('<Q', 1)], flags=0xffff)),
           sra_ace(sra('bin', 0x10, [struct.pack('<I', 4) + b'\x01\x02\x03\x04'], flags=0)),
           sra_ace(sra('unk', 0x77, [b'\0' * 8])),
           sra_ace(sra('none', 3, [])),
       ]), typ=0x8010), 0x08)
add_sd('SRA ACE with value count past the ACE (expert info), two values',
       sd(sacl=acl([sra_ace(sra('cnt', 3, [u16('a'), u16('b')], count=500))]), typ=0x8010), 0x08)
add_sd('SRA ACE with a value offset past the ACE (expert info)',
       sd(sacl=acl([sra_ace(sra('off', 3, [u16('a'), u16('b'), u16('c')], offs=[None, 9999, None]))]), typ=0x8010), 0x08)

# SD and ACL structure
add_sd('ACEs for SIDs without a well-known name (unlabeled SIDs)',
       sd(dacl=acl([ace(0, 0x1f01ff, sid(9, [1, 2])), ace(1, 0x1, sid(5, [80, 1, 2, 3, 4, 5])), ace(0, 0x2, sid(5, [5, 7, 8])), ace(2, 0x3, sid(0x0a0b0c, [9]))])))
add_sd('SD with no owner/group/ACLs (all offsets 0), type 0xffff', sd(typ=0xffff), 0x0f)
add_sd('SD type bits 0x8000/0x4000/... all clear', sd(owner=EVERYONE, typ=0x0000), 0x01)
add_sd('SD with bogus offsets below 20 (owner 4, group 8, SACL 12, DACL 16)', struct.pack('<HHIIII', 1, 0x8004, 4, 8, 12, 16) + bytes(8), 0x0f)
add_sd('SD revision 2 (nothing else decoded)', sd(owner=EVERYONE, rev=2), 0x0f)
add_sd('ACL revisions 4 and 3 and 5 (5: only the revision)',
       sd(sacl=acl([ace(0, 1)], rev=3), dacl=acl([ace(0, 1)], rev=4), typ=0x8014), 0x0f)
add_sd('DACL revision 5', sd(dacl=acl([ace(0, 1)], rev=5)), 0x04)
add_sd('empty DACL (0 ACEs) and empty SACL', sd(sacl=acl([], rev=2), dacl=acl([]), typ=0x8014), 0x0c)
add_sd('DACL with 20 allow/deny ACEs for different SIDs',
       sd(owner=ADMINS, group=SYSTEM, dacl=acl([ace(i & 1, 0x1200a9 + i, sid(5, [21, 1, 2, 3, 1000 + i])) for i in range(20)])), 0x0f)
add_sd('ACE with spare space after the SID (size larger than needed)',
       sd(dacl=acl([ace(0, 1, size=40, extra=b'\xaa' * 20), ace(0, 2)])))

ERRORS = ('33 nested', '700 nested', 'value count past', 'value offset past')
main_sds = [x for x in sds if not any(e in x[0] for e in ERRORS)]
err_sds = [x for x in sds if any(e in x[0] for e in ERRORS)]

# ---------------------------------------------------------- malformed SDs
msds = list(err_sds)
def add_m(label, b, addinfo=0x0f): msds.append((label, b, addinfo))
add_m('ACE with size 2 (bogus, below 4)', sd(dacl=acl([ace(0, 1, size=2)])))
add_m('ACE size runs beyond the SD', sd(dacl=acl([ace(0, 1, size=400)])))
add_m('ACL announces 5 ACEs but holds 1 (ACE past the data)', sd(dacl=acl([ace(0, 1)], count=5)))
add_m('ACL announces 4000000000 ACEs', sd(dacl=acl([ace(0, 1)], count=4000000000)))
add_m('owner offset past the SD', sd(owner=EVERYONE, offs=[5000, None, None, None]))
add_m('group offset past the SD', sd(group=EVERYONE, offs=[None, 5000, None, None]))
add_m('SACL offset past the SD', sd(sacl=acl([]), offs=[None, None, 5000, None]), 0x08)
add_m('DACL offset past the SD', sd(dacl=acl([]), offs=[None, None, None, 5000]), 0x04)
add_m('owner offset 0x80000000 (out of range)', sd(owner=EVERYONE, offs=[0x80000000, None, None, None]))
add_m('group offset 0x80000000 (out of range)', sd(group=EVERYONE, offs=[None, 0x80000000, None, None]))
add_m('SACL offset 0x80000000 (out of range)', sd(sacl=acl([]), offs=[None, None, 0x80000000, None]), 0x08)
add_m('DACL offset 0x80000000 (out of range)', sd(dacl=acl([]), offs=[None, None, None, 0x80000000]), 0x04)
add_m('SID claims 255 subauthorities but is cut short', sd(owner=sid(5, [1, 2], nsub=255)))
add_m('SD cut after 6 octets', sd(owner=EVERYONE)[:6])
add_m('ACE with a condition token cut short', sd(dacl=acl([ace(9, 1, extra=cond(bytes([0x10]) + struct.pack('<I', 9999) + b'ab'))])))
add_m('ACE with an unknown data token length', sd(dacl=acl([ace(9, 1, extra=cond(bytes([0xf8]) + struct.pack('<I', 7) + b'abc'))])))
add_m('SRA ACE whose name offset is past the ACE', sd(sacl=acl([sra_ace(struct.pack('<IHHII', 9999, 3, 0, 0, 0))]), typ=0x8010), 0x08)
add_m('SRA ACE with an unterminated string value', sd(sacl=acl([sra_ace(sra('s', 3, [b'a\0b\0c\0'][:1]).rstrip(b'\0') + b'x')]), typ=0x8010), 0x08)
add_m('SRA octet string longer than the ACE', sd(sacl=acl([sra_ace(sra('o', 0x10, [struct.pack('<I', 70000) + b'ab']))]), typ=0x8010), 0x08)
add_m('SRA sid value cut short', sd(sacl=acl([sra_ace(sra('s', 5, [bytes([1, 200]) + bytes(8)]))]), typ=0x8010), 0x08)
add_m('object ACE cut after the flags (GUID missing)', sd(dacl=acl([ace(5, 1, obj=3)[:12]], size=None)))

def sd_frames(conn, sdlist, first_id=2):
    f = []
    for i, (label, b, ai) in enumerate(sdlist):
        f += conn.send(nbss(smb2_setinfo(first_id + i, b, ai)), True)[:-1]
        labels.append((len(main) + len(f), 'SMB2 SET_INFO: ' + label))
    return f

c = Tcp(49200, 445)
main += c.handshake()
main += c.send(nbss(smb2_negotiate_rsp(1, 133000000000000000, 133000000000000001)), False)[:-1]; labels.append((len(main), 'SMB2 NEGOTIATE response (time stamps)'))
for tag, t1, t2 in (('0 and infinity', 0, 0x7fffffffffffffff), ('relative infinity and cannot-convert', 0x8000000000000000, 1)):
    main += c.send(nbss(smb2_negotiate_rsp(1, t1, t2)), False)[:-1]; labels.append((len(main), 'SMB2 NEGOTIATE response, time ' + tag))
main += sd_frames(c, main_sds)
# QUERY_INFO pair (request and response; the response needs the request's info type)
q = main_sds[8][1]
main += c.send(nbss(smb2_queryinfo_req(900, 0x07)), True)[:-1]
main += c.send(nbss(smb2_queryinfo_rsp(900, main_sds[0][1])), False)[:-1]; labels.append((len(main), 'SMB2 QUERY_INFO request/response (security)'))
main += c.send(nbss(smb2_queryinfo_req(901, 0x0f)), True)[:-1]
main += c.send(nbss(smb2_queryinfo_rsp(901, [x for x in main_sds if 'every non-callback' in x[0]][0][1])), False)[:-1]
nsmb = len(main)
# the same descriptors over LDAP (access mask with the LDAP specific rights)
l = Tcp(49300, 389, src='192.0.2.1', dst='192.0.2.2')
main += l.handshake()
lmsg = 1
for label, b, ai in main_sds[:44] + [x for x in main_sds if '32 nested' in x[0]]:
    main += l.send(ldap_entry(lmsg, 'CN=Test,DC=example,DC=com', [('nTSecurityDescriptor', [b]), ('objectSid', [sid(5, DOM + [1105])])]), False)[:-1]
    labels.append((len(main), 'LDAP search entry: ' + label)); lmsg += 1
main += l.send(ldap_entry(lmsg, 'CN=Sids,DC=example,DC=com', [('objectSid', [x[1] for x in sid_cases[:8]]), ('nTSecurityDescriptor', [])]), False)[:-1]

# ------------------------------------------------------------ DCE/RPC SAMR
# SAMR SetSecurity/QuerySecurity over TCP 135 (a bind to the SAMR UUID is
# enough, the port is registered for DCE/RPC by default). These reach the
# NDR access-mask path and dissect_nt_security_information().
import uuid
SAMR = uuid.UUID('12345778-1234-abcd-ef00-0123456789ac').bytes_le
NDR = uuid.UUID('8a885d04-1ceb-11c9-9fe8-08002b104860').bytes_le
def dce_pdu(ptype, call_id, body, flags=3):
    return struct.pack('<BBBB4sHHI', 5, 0, ptype, flags, b'\x10\0\0\0', 16 + len(body), 0, call_id) + body
def dce_bind(call_id):
    return dce_pdu(11, call_id, struct.pack('<HHIBxxx', 4280, 4280, 0, 1) +
                   struct.pack('<HBx', 0, 1) + SAMR + struct.pack('<HH', 1, 0) + NDR + struct.pack('<I', 2))
def dce_bind_ack(call_id):
    return dce_pdu(12, call_id, struct.pack('<HHIH', 4280, 4280, 0x1234, 4) + b'135\0' + b'\0\0' +
                   struct.pack('<BxxxHH', 1, 0, 0) + NDR + struct.pack('<I', 2))
def dce_request(call_id, opnum, stub):
    return dce_pdu(0, call_id, struct.pack('<IHH', len(stub), 0, opnum) + stub)
HANDLE = struct.pack('<I', 0) + uuid.UUID('00000000-0000-0000-0000-00000000abcd').bytes_le
def samr_setsec(secinfo, sdb):
    return HANDLE + struct.pack('<II', secinfo, len(sdb)) + struct.pack('<II', 0x20000, len(sdb)) + sdb
d = Tcp(49600, 135, src='192.0.2.1', dst='192.0.2.2')
main += d.handshake()
main += d.send(dce_bind(1), True)[:-1]; labels.append((len(main), 'DCE/RPC bind to SAMR'))
main += d.send(dce_bind_ack(1), False)[:-1]
dce_sds = [x[1] for x in main_sds if 'every non-callback' in x[0] or 'callback ACE types 9' in x[0] or 'owner Null' in x[0] or 'DACL with 20' in x[0]]
for i, (secinfo, sdb) in enumerate(zip((0x0f, 0x07, 0x01, 0x02, 0x04, 0x08, 0x00, 0x0c), dce_sds * 2)):
    main += d.send(dce_request(2 + i, 2, samr_setsec(secinfo, sdb)), True)[:-1]
    labels.append((len(main), 'SAMR SetSecurity, security information 0x%02x' % secinfo))
main += d.send(dce_request(20, 3, HANDLE + struct.pack('<I', 0x0f)), True)[:-1]; labels.append((len(main), 'SAMR QuerySecurity request'))
main += d.send(dce_request(21, 3, HANDLE + struct.pack('<I', 0x03)), True)[:-1]

# LSA QuerySecret responses: NTTIME_hyper values (add_nttime special values)
LSA = uuid.UUID('12345778-1234-abcd-ef00-0123456789ab').bytes_le
def dce_bind_lsa(call_id):
    return dce_pdu(11, call_id, struct.pack('<HHIBxxx', 4280, 4280, 0, 1) +
                   struct.pack('<HBx', 0, 1) + LSA + struct.pack('<HH', 0, 0) + NDR + struct.pack('<I', 2))
def dce_response(call_id, stub):
    return dce_pdu(2, call_id, struct.pack('<IHBx', len(stub), 0, 0) + stub)
e = Tcp(49601, 135, src='192.0.2.1', dst='192.0.2.2')
main += e.handshake()
main += e.send(dce_bind_lsa(1), True)[:-1]; labels.append((len(main), 'DCE/RPC bind to LSA'))
main += e.send(dce_bind_ack(1), False)[:-1]
for i, (t1, t2) in enumerate(((133000000000000000, 0), (0, 0x7fffffffffffffff), (0x8000000000000000, 1), (116444736000000000, 0x00ffffffffffffff))):
    main += e.send(dce_request(2 + i, 30, HANDLE + struct.pack('<IIII', 0, 0, 0, 0)), True)[:-1]
    stub = struct.pack('<II', 0, 0x20000) + struct.pack('<Q', t1) + struct.pack('<II', 0, 0x20004) + struct.pack('<QI', t2, 0)
    main += e.send(dce_response(2 + i, stub), False)[:-1]
    labels.append((len(main), 'LSA QuerySecret request/response, times 0x%x and 0x%x' % (t1, t2)))

# SMB1 NT Create AndX response: four NT time stamps (dissect_nttime)
def smb1_ntcreate_rsp(mid, times):
    hdr = b'\xffSMB' + struct.pack('<BIBHHQHHHHH', 0xa2, 0, 0x80, 0xc801, 0, 0, 0, 1, 100, 1, mid)
    words = struct.pack('<BBHBHI', 0xff, 0, 0, 1, 0x4001, 1) + b''.join(struct.pack('<Q', t) for t in times) + \
        struct.pack('<IQQHHB', 0x20, 4096, 100, 0, 0x7, 0)
    return hdr + bytes([len(words) // 2]) + words + struct.pack('<H', 0)
g = Tcp(49700, 445, src='192.0.2.1', dst='192.0.2.2')
main += g.handshake()
for i, ts in enumerate(((133000000000000000,) * 4, (0, 0x7fffffffffffffff, 0x8000000000000000, 1), (132000000000000000, 131000000000000000, 130000000000000000, 129000000000000000))):
    main += g.send(nbss(smb1_ntcreate_rsp(10 + i, ts)), False)[:-1]
    labels.append((len(main), 'SMB1 NT Create AndX response with time stamps ' + str(i)))
nmain = len(main)

# ------------------------------------------------------------- malformed
mal = []
m = Tcp(49400, 445, src='192.0.2.3', dst='192.0.2.4')
mal += m.handshake()
for i, (label, b, ai) in enumerate(msds):
    mal += m.send(nbss(smb2_setinfo(2 + i, b, ai)), True)[:-1]
ml = Tcp(49500, 389, src='192.0.2.3', dst='192.0.2.4')
mal += ml.handshake()
for i, (label, b, ai) in enumerate(msds):
    mal += ml.send(ldap_entry(1 + i, 'CN=Bad', [('nTSecurityDescriptor', [b]), ('cn', [b'trailing data after the descriptor value'])]), False)[:-1]
# SMB2 message cut before the end of the descriptor (reported length shorter than the SD)
bad = smb2_setinfo(500, sd(owner=ADMINS, dacl=acl([ace(0, 1)] * 3)), 0x07)
mal += m.send(struct.pack('!I', len(bad) - 10) + bad[:-10], True)[:-1]

# frames cut by the snap length inside the descriptor (SMB2, LDAP, SAMR)
cut = Tcp(49800, 445, src='192.0.2.7', dst='192.0.2.8')
mal += cut.handshake()
for i, n in enumerate((40, 80, 100, 120, 140)):
    sdb = sd(owner=ADMINS, group=SYSTEM, dacl=acl([ace(0, 0x1, EVERYONE), ace(0, 0x2, ADMINS)]), sacl=acl([ace(2, 3, EVERYONE)]), typ=0x8014)
    f = cut.send(nbss(smb2_setinfo(700 + i, sdb, 0x0f)), True)[0]
    mal.append((f, len(f) - n))
cl = Tcp(49801, 389, src='192.0.2.7', dst='192.0.2.8')
mal += cl.handshake()
for i, n in enumerate((20, 40, 60, 80)):
    sdb = sd(owner=ADMINS, group=SYSTEM, dacl=acl([ace(0, 0x1, EVERYONE), ace(0, 0x2, ADMINS)]), typ=0x8004)
    f = cl.send(ldap_entry(700 + i, 'CN=Cut', [('nTSecurityDescriptor', [sdb])]), False)[0]
    mal.append((f, len(f) - n))

# the reproducers of the fixes on their own (expert infos at error level):
# small enough to be added to the tree next to the main capture for the test
fix = []
fx = Tcp(49900, 445, src='192.0.2.9', dst='192.0.2.10')
fix += fx.handshake()
for i, (label, b, ai) in enumerate(err_sds):
    fix += fx.send(nbss(smb2_setinfo(2 + i, b, ai)), True)[:-1]

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
pcap(os.path.join(out, 'windows-common-fix.pcap'), fix)
pcap(os.path.join(out, 'windows-common-coverage.pcap'), main)
pcap(os.path.join(out, 'windows-common-coverage-malformed.pcap'), mal)
if '-v' in sys.argv:
    for n, lb in labels: print(n, lb)
    print('main', nmain, 'smb frames end at', nsmb, 'malformed', len(mal))
