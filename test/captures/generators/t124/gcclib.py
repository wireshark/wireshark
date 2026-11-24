# Helper module for the t124 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# T.124 GCC (ConnectGCCPDU) encoders, ALIGNED PER
from perlib import W

def sub(fn, *a):
    """encode with fn into a fresh buffer, return the bytes (for open types)"""
    w = W(); fn(w, *a); return w.bytes()

# ---- simple types ----
def key(w, k):
    kind, v = k
    if kind == 'obj': w.choice(0, 2); w.oid(v)
    else: w.choice(1, 2); w.octstr(v, 4, 255)
def nonstd(w, k, data):
    key(w, k); w.octstr(data)
def text(w, s): w.bmp(s, 0, 255)
def simple_numeric(w, s): w.numeric(s, 1, 255)
def userdata(w, items):
    w.length(len(items))
    for k, v in items:
        w.bit(v is not None)
        key(w, k)
        if v is not None: w.octstr(v)
def name_like(w, numeric, txt=None, unicode_text=None):
    """ConferenceName / Password: SEQUENCE ext {numeric, text OPTIONAL, ..., unicodeText OPTIONAL}"""
    w.bit(unicode_text is not None)
    w.bit(txt is not None)
    simple_numeric(w, numeric)
    if txt is not None: text(w, txt)
    if unicode_text is not None: w.ext_additions([sub(text, unicode_text)])
def selector(w, kind, v):
    """ConferenceNameSelector / PasswordSelector: CHOICE ext {numeric, text, ..., unicodeText}"""
    if kind == 'unicode':
        w.bit(1); w.length_small(0); w.opentype(sub(text, v)); return
    w.choice({'numeric': 0, 'text': 1}[kind], 2, ext=True)
    if kind == 'numeric': simple_numeric(w, v)
    else: text(w, v)
def privileges(w, items):
    w.length(len(items))
    for p in items: w.enum(p, 5, ext=True)
def termination(w, v): w.enum(v, 2, ext=True)
def node_type(w, v): w.enum(v, 3, ext=True)
def node_category(w, v):
    if isinstance(v, int): w.choice(v, 4, ext=True)
    else: w.choice(3, 4, ext=True); nonstd(w, v[0], v[1])
def conf_mode(w, v):
    if isinstance(v, int): w.choice(v, 6, ext=True)
    else: w.choice(5, 6, ext=True); nonstd(w, v[0], v[1])
def conf_priority(w, prio, scheme):
    w.bit(0)                     # extension bit
    w.con_int(prio, 0, 65535)
    w.choice(0, 1, ext=True)     # nonStandardScheme
    nonstd(w, scheme[0], scheme[1])
def asym(w, v):
    if v is None: return
    kind = v[0]
    if kind == 'calling': w.con_int(0, 0, 2)
    elif kind == 'called': w.con_int(1, 0, 2)
    else: w.con_int(2, 0, 2); w.con_int(v[1], 0, 4294967295)
def network_address_item(w, it):
    kind = it[0]
    if kind == 'aggregated':
        _, modes, number, sub_addr, extra, hlc = it
        w.choice(0, 3, ext=True)
        w.bit(0)                                   # sequence extension bit
        w.bit(sub_addr is not None); w.bit(extra is not None); w.bit(hlc is not None)
        w.bit(0)                                   # transferModes extension bit
        for b in modes: w.bit(b)                   # 18 booleans
        w.numeric(number, 1, 16)
        if sub_addr is not None: w.numeric(sub_addr, 1, 40)
        if extra is not None:
            # the dissector reads ExtraDiallingString as a plain BMPString(SIZE(0..255)),
            # not with the 4 bit permitted alphabet of X.691
            w.bmp(extra, 0, 255)
        if hlc is not None:
            w.bit(0)
            for b in hlc: w.bit(b)                 # 7 booleans
    elif kind == 'transport':
        _, nsap, sel = it
        w.choice(1, 3, ext=True)
        w.bit(sel is not None)
        w.octstr(nsap, 1, 20)
        if sel is not None: w.octstr(sel)
    else:
        w.choice(2, 3, ext=True); nonstd(w, it[1], it[2])
def network_address(w, items):
    w.con_int(len(items), 1, 64)
    for it in items: network_address_item(w, it)

# ---- ConnectGCCPDU alternatives ----
def conf_create_request(name, conv_pw=None, pw=None, locked=False, listed=True, conductible=False,
                        term=0, cond_priv=None, conducted_priv=None, nonconducted_priv=None,
                        desc=None, caller=None, ud=None, prio=None, mode=None):
    w = W(); w.choice(0, 8, ext=True)
    adds = [sub(conf_priority, *prio) if prio else None, sub(conf_mode, mode) if mode is not None else None]
    w.bit(any(a is not None for a in adds))
    for v in (conv_pw, pw, cond_priv, conducted_priv, nonconducted_priv, desc, caller, ud):
        w.bit(v is not None)
    name_like(w, *name)
    if conv_pw is not None: name_like(w, *conv_pw)
    if pw is not None: name_like(w, *pw)
    w.boolean(locked); w.boolean(listed); w.boolean(conductible)
    termination(w, term)
    if cond_priv is not None: privileges(w, cond_priv)
    if conducted_priv is not None: privileges(w, conducted_priv)
    if nonconducted_priv is not None: privileges(w, nonconducted_priv)
    if desc is not None: text(w, desc)
    if caller is not None: text(w, caller)
    if ud is not None: userdata(w, ud)
    if any(a is not None for a in adds): w.ext_additions(adds)
    return w.bytes()

def conf_create_response(node_id=1002, tag=1, result_=0, ud=None):
    w = W(); w.choice(1, 8, ext=True)
    w.bit(0); w.bit(ud is not None)
    w.con_int(node_id, 1001, 65535); w.sint(tag); w.enum(result_, 5, ext=True)
    if ud is not None: userdata(w, ud)
    return w.bytes()

def conf_query_request(ntype=0, asy=None, ud=None):
    w = W(); w.choice(2, 8, ext=True)
    w.bit(0); w.bit(asy is not None); w.bit(ud is not None)
    node_type(w, ntype)
    if asy is not None: asym(w, asy)
    if ud is not None: userdata(w, ud)
    return w.bytes()

def conf_descriptor(w, name, modifier=None, desc=None, locked=False, pw_clear=False, netaddr=None,
                    default_flag=None, mode=None):
    adds = [sub(lambda x, v: x.boolean(v), default_flag) if default_flag is not None else None,
            sub(conf_mode, mode) if mode is not None else None]
    w.bit(any(a is not None for a in adds))
    w.bit(modifier is not None); w.bit(desc is not None); w.bit(netaddr is not None)
    name_like(w, *name)
    if modifier is not None: simple_numeric(w, modifier)
    if desc is not None: text(w, desc)
    w.boolean(locked); w.boolean(pw_clear)
    if netaddr is not None: network_address(w, netaddr)
    if any(a is not None for a in adds): w.ext_additions(adds)

def conf_query_response(ntype=0, asy=None, confs=(), result_=0, ud=None, wait=None, nounlisted=None):
    w = W(); w.choice(3, 8, ext=True)
    adds = [sub(lambda x, v: x.boolean(v), wait) if wait is not None else None,
            sub(lambda x, v: x.boolean(v), nounlisted) if nounlisted is not None else None]
    w.bit(any(a is not None for a in adds))
    w.bit(asy is not None); w.bit(ud is not None)
    node_type(w, ntype)
    if asy is not None: asym(w, asy)
    w.length(len(confs))
    for c in confs: conf_descriptor(w, **c)
    w.enum(result_, 2, ext=True)
    if ud is not None: userdata(w, ud)
    if any(a is not None for a in adds): w.ext_additions(adds)
    return w.bytes()

def pwcr(w, v):
    """PasswordChallengeRequestResponse: v = ('clear', (kind, text)) or ('cr', request, response)"""
    if v[0] == 'clear':
        w.choice(0, 2, ext=True); selector(w, *v[1]); return
    w.choice(1, 2, ext=True)
    w.bit(0); w.bit(v[1] is not None); w.bit(v[2] is not None)
    if v[1] is not None:
        tag, items = v[1]
        w.bit(0); w.sint(tag); w.length(len(items))
        for alg, data in items:
            w.bit(0); algorithm(w, alg); userdata(w, data)
    if v[2] is not None:
        tag, alg, item = v[2]
        w.bit(0); w.sint(tag); algorithm(w, alg)
        if item[0] == 'pw': w.choice(0, 2, ext=True); selector(w, *item[1])
        else: w.choice(1, 2, ext=True); userdata(w, item[1])
def algorithm(w, alg):
    if alg == 'clear': w.choice(0, 2, ext=True)
    else: w.choice(1, 2, ext=True); nonstd(w, alg[0], alg[1])

def conf_join_request(name=None, modifier=None, tag=None, pw=None, conv_pw=None, caller=None, ud=None, category=None):
    w = W(); w.choice(4, 8, ext=True)
    w.bit(category is not None)
    for v in (name, modifier, tag, pw, conv_pw, caller, ud): w.bit(v is not None)
    if name is not None: selector(w, *name)
    if modifier is not None: simple_numeric(w, modifier)
    if tag is not None: w.sint(tag)
    if pw is not None: pwcr(w, pw)
    if conv_pw is not None: selector(w, *conv_pw)
    if caller is not None: text(w, caller)
    if ud is not None: userdata(w, ud)
    if category is not None: w.ext_additions([sub(node_category, category)])
    return w.bytes()

def conf_join_response(node_id=None, top=1001, tag=1, alias=None, pw_clear=False, locked=False, listed=True,
                       conductible=False, term=0, cond_priv=None, conducted_priv=None, nonconducted_priv=None,
                       desc=None, pw=None, result_=0, ud=None, category=None, mode=None):
    w = W(); w.choice(5, 8, ext=True)
    adds = [sub(node_category, category) if category is not None else None,
            sub(conf_mode, mode) if mode is not None else None]
    w.bit(any(a is not None for a in adds))
    for v in (node_id, alias, cond_priv, conducted_priv, nonconducted_priv, desc, pw, ud): w.bit(v is not None)
    if node_id is not None: w.con_int(node_id, 1001, 65535)
    w.con_int(top, 1001, 65535); w.sint(tag)
    if alias is not None: selector(w, *alias)
    w.boolean(pw_clear); w.boolean(locked); w.boolean(listed); w.boolean(conductible)
    termination(w, term)
    if cond_priv is not None: privileges(w, cond_priv)
    if conducted_priv is not None: privileges(w, conducted_priv)
    if nonconducted_priv is not None: privileges(w, nonconducted_priv)
    if desc is not None: text(w, desc)
    if pw is not None: pwcr(w, pw)
    w.enum(result_, 7, ext=True)
    if ud is not None: userdata(w, ud)
    if any(a is not None for a in adds): w.ext_additions(adds)
    return w.bytes()

def conf_invite_request(name, node_id=1002, top=1001, tag=1, pw_clear=False, locked=False, listed=True,
                        conductible=False, term=0, cond_priv=None, conducted_priv=None, nonconducted_priv=None,
                        desc=None, caller=None, ud=None, prio=None, category=None, mode=None):
    w = W(); w.choice(6, 8, ext=True)
    adds = [sub(conf_priority, *prio) if prio else None,
            sub(node_category, category) if category is not None else None,
            sub(conf_mode, mode) if mode is not None else None]
    w.bit(any(a is not None for a in adds))
    for v in (cond_priv, conducted_priv, nonconducted_priv, desc, caller, ud): w.bit(v is not None)
    name_like(w, *name)
    w.con_int(node_id, 1001, 65535); w.con_int(top, 1001, 65535); w.sint(tag)
    w.boolean(pw_clear); w.boolean(locked); w.boolean(listed); w.boolean(conductible)
    termination(w, term)
    if cond_priv is not None: privileges(w, cond_priv)
    if conducted_priv is not None: privileges(w, conducted_priv)
    if nonconducted_priv is not None: privileges(w, nonconducted_priv)
    if desc is not None: text(w, desc)
    if caller is not None: text(w, caller)
    if ud is not None: userdata(w, ud)
    if any(a is not None for a in adds): w.ext_additions(adds)
    return w.bytes()

def conf_invite_response(result_=0, ud=None):
    w = W(); w.choice(7, 8, ext=True)
    w.bit(0); w.bit(ud is not None)
    w.enum(result_, 2, ext=True)
    if ud is not None: userdata(w, ud)
    return w.bytes()

def connect_data(pdu_bytes, oid_='0.0.20.124.0.1', length=None):
    """ConnectData: Key + connectPDU OCTET STRING"""
    w = W(); key(w, ('obj', oid_)); w.octstr(pdu_bytes)
    return w.bytes()
