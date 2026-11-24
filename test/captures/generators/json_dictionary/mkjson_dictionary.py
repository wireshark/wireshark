#!/usr/bin/env python3
# Generates test/captures/json_dictionary_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic JSON+ dictionary coverage material.

Usage: mkjson_dictionary.py <outdir>

Writes into <outdir>:
  json_dictionary_coverage.pcap            main capture (HTTP/1.1 and HTTP/2
                                           carrying JSON, decodes cleanly)
  json_dictionary_coverage_malformed.pcap  JSON that only reaches error paths
  cfg/json/                                personal JSON+ dictionaries used
                                           with the main capture (the test
                                           class writes the same files)
  cfg-<name>/json/                         extra and hostile dictionaries

Everything is generated; nothing comes from a real network.
"""
import os
import struct
import sys

# ---------------------------------------------------------------------------
# Dictionaries
# ---------------------------------------------------------------------------

HEAD = '<?xml version="1.0" encoding="UTF-8"?>\n<json-dictionary>\n<base name="%s" version="1.0">\n'
TAIL = '</base>\n</json-dictionary>\n'

MAIN_XML = HEAD % 'Dict Test' + '''\
<typedefn type-name="String" base-type="string"/>
<typedefn type-name="Integer" base-type="int64"/>
<typedefn type-name="Integer" base-type="int64"/>
<typedefn type-name="UInt" base-type="uint64"/>
<typedefn type-name="Float" base-type="double"/>
<typedefn type-name="Boolean" base-type="boolean"/>
<typedefn type-name="Object" base-type="object"/>
<typedefn type-name="Array" base-type="array"/>
<typedefn type-name="IPv4" base-type="string" display="ipv4"/>
<typedefn type-name="IPv6" base-type="string" display="ipv6"/>
<typedefn type-name="Mac" base-type="string" display="ether"/>
<typedefn type-name="Time" base-type="int64" display="absolute_time"/>
<typedefn type-name="TimeU" base-type="uint64" display="absolute_time"/>
<typedefn type-name="Dur" base-type="int64" display="relative_time"/>
<typedefn type-name="DurU" base-type="uint64" display="relative_time"/>
<typedefn type-name="Hex" base-type="string" display="hex2dec"/>
<typedefn type-name="Plain" base-type="string" display="bogus"/>
<typedefn base-type="string"/>
<typedefn type-name="NoBase"/>
<protocol name="Dict Test" displayName="DICTTEST" port="9001, 9002,x,0" transport="tcp">
  <content-type>application/json</content-type>
</protocol>

<field name="Request Id" path="request_id" type="String" description="Request id" info="Request"/>
<field name="User Name" path="userName" type="String" case="insensitive" info="User"/>
<field name="Exact Name" path="exactName" type="String" case="sensitive"/>
<field name="Plain Display" path="plain" type="Plain"/>
<field name="Count" path="count" type="Integer" info="Count"/>
<field name="Bytes" path="bytes" type="UInt" info="Bytes"/>
<field name="Small" path="small" type="int32"/>
<field name="Usmall" path="usmall" type="uint32"/>
<field name="Ratio" path="ratio" type="Float" info="Ratio"/>
<field name="Single" path="single" type="float"/>
<field name="Ok" path="ok" type="Boolean" info="Ok"/>
<field name="Unknown Type" path="unknown_type" type="NoSuchType"/>
<field name="No Type" path="no_type"/>
<field name="" path="empty_name"/>
<field name="Dup" path="dup_field" type="Integer"/>
<field name="Dup" path="dup_field" type="String"/>

<field name="Status" path="status" type="Integer" info="Status">
  <enum name="Success" code="0"/>
  <enum name="Failed" code="1"/>
  <enum name="Pending" code="2" description="Waiting"/>
  <enum name="no code"/>
  <enum code="9"/>
</field>
<field name="Priority" path="priority" type="UInt" info="Priority">
  <enum name="Low" code="0"/>
  <enum name="High" code="5"/>
</field>
<field name="Cell" path="cell" type="Hex" info="Cell">
  <enum name="Primary" code="100"/>
  <enum name="Secondary" code="200"/>
</field>
<field name="Cell Id" path="cellid" type="Hex" info="Cell Id"/>

<field name="Addr4" path="addr4" type="IPv4" info="Addr"/>
<field name="Addr6" path="addr6" type="IPv6"/>
<field name="Mac" path="mac" type="Mac"/>
<field name="Created" path="created" type="Time"/>
<field name="Created U" path="created_u" type="TimeU"/>
<field name="Elapsed" path="elapsed" type="Dur"/>
<field name="Elapsed U" path="elapsed_u" type="DurU"/>

<field name="Profile" path="profile" type="Object" df="prof" info="Profile">
  <field name="Email" path="profile.email" type="String" df="prof.mail"/>
  <field name="Age" path="profile.age" type="Integer"/>
  <field name="Home" type="Object">
    <field name="City" type="String"/>
  </field>
</field>
<field name="Nested Obj" type="Object">
  <field name="Leaf" type="String"/>
  <field name="Num" type="Integer"/>
</field>
<field type="String"/>

<field name="Tags" path="tags" type="Array">
  <array-element type="String" info="Tag"/>
</field>
<field name="Numbers" path="numbers" type="Array">
  <array-element type="Integer"/>
</field>
<field name="Items" path="items" type="Array">
  <array-element type="Object">
    <field name="Id" path="items[].id" type="Integer"/>
    <field name="Price" path="items[].price" type="Float"/>
    <field name="Label" path="items[].label" type="String" info="Item"/>
    <field name="Sub" path="items[].sub" type="Array">
      <array-element type="Object">
        <field name="Sub Id" path="items[].sub[].id" type="Integer"/>
      </array-element>
    </field>
  </array-element>
</field>
<field name="Rows" path="rows" type="Array">
  <array-element type="Object">
    <field name="Row Name"/>
    <field name="Row Value" type="Integer"/>
  </array-element>
</field>
<field name="Matrix" path="matrix" type="Array">
  <array-element type="Array">
    <array-element type="Integer"/>
  </array-element>
</field>
<field name="Root Items" path="[]" type="Object">
  <field name="Root Id" path="[].id" type="Integer"/>
  <field name="Root Name" path="[].name" type="String"/>
</field>

<field name="Odata Type" path="@type" type="String"/>
<field name="Ref" path="$ref" type="String"/>
<field name="Colon" path="a:b" type="String"/>
<field name="Spaced" path="two words" type="String"/>
<field name="Dotted" path="x..y" type="String"/>
<field name="Parsed" path="parsed" type="String" parser="parse.sh" parser-args="--flag 'a b'"/>
<field name="Unbalanced Parser Args" path="parsed2" type="String" parser="parse2.sh" parser-args="'unterminated"/>

<field name="Wc" path="wc" type="Object">
  <wildcardfield name="Top Key" path="wckey" match=".*"/>
</field>
<field name="Dnn" path="dnn" type="Object">
  <wildcardfield name="Apn" path="dnn.apn" displayvalue="name" match=".*\\.com">
    <field name="Session Type" path="dnn.apn.sessionType" type="String"/>
    <field name="Qi" path="dnn.apn.qi" type="Integer"/>
    <array-element type="Object">
      <field name="Apn Item" path="dnn.apn[].item" type="String"/>
    </array-element>
    <wildcardfield name="Slice" path="dnn.apn.slice" displayvalue="id" match="[0-9]+">
      <field name="Sst" path="dnn.apn.slice.sst" type="Integer"/>
    </wildcardfield>
  </wildcardfield>
  <wildcardfield name="Other" path="dnn.other" match="^x-.*">
    <field name="Other Value" path="dnn.other.value" type="String"/>
  </wildcardfield>
  <wildcardfield path="dnn.any" match=".*"/>
</field>
''' + TAIL

# Second file: path based protocols, with their own fields.
PATHS_XML = HEAD % 'Path Test' + '''\
<typedefn type-name="Integer" base-type="int64"/>
<typedefn type-name="Boolean" base-type="boolean"/>
<protocol name="Orders API" displayName="ORDERS" path="^/orders/v[0-9]+/"/>
<protocol name="Tenant API" path="/TENANT/[0-9a-f]+" case="insensitive" displayName="TENANT"/>
<protocol name="Strict API" port="9100" path="^/strict/" condition="and" displayName="STRICT"/>
<protocol name="Loose API" port="9101" path="^/loose/" displayName="LOOSE"/>
<protocol name="Loose Or API" port="9102" path="^/looseor/" condition="or" displayName="LOOSEOR"/>
<protocol name="No Display" path="^/nodisplay"/>
<protocol name="5GC Core" port="9103"/>
<protocol name="---" port="9104"/>
<field name="Order Id" path="order.id" type="Integer" info="Order"/>
<field name="Order Name" path="order.name" type="String"/>
<field name="Strict Flag" path="strict" type="Boolean"/>
''' + TAIL

# Third file: only a protocol, no fields (uses the global field tree).
BARE_XML = HEAD % 'Bare' + '''\
<protocol port="9200" transport="udp"/>
<protocol name="Bare Port" port="9201"/>
''' + TAIL

# Fourth file: fields only, reached through the global tree
FIELDSONLY_XML = HEAD % 'Fields Only' + '''\
<field name="Global Only" path="global_only" type="Integer" info="Global"/>
<field name="Global Obj" path="global_obj" type="Object">
  <field name="Global Leaf" path="global_obj.leaf" type="String"/>
</field>
''' + TAIL

CONFIG_TXT = '''# Personal JSON+ dictionaries for the coverage capture

main.xml
   paths.xml

	bare.xml
fieldsonly.xml
'''

# ---------------------------------------------------------------------------
# Extra and hostile configurations (name -> {filename: content})
# ---------------------------------------------------------------------------

def dict_with(body, proto=''):
    return HEAD % 'x' + proto + body + TAIL

PROTO_9001 = '<protocol name="T" port="8099" transport="tcp"/>\n'

EXTRA_CFGS = {
    # no config.txt, jsonmain.xml is used
    'jsonmain': {
        'jsonmain.xml': dict_with(
            '<field name="Jm" path="jm" type="string"/>\n',
            '<protocol name="Jm Proto" port="8098"/>\n')},
    # no config.txt and no jsonmain.xml
    'empty': {},
    # config.txt without any loadable file
    'nofile': {'config.txt': '# nothing\n\nmissing.xml\n'},
    # warnings: bad regexes, bad case, enums on non-integers, missing
    # attributes, a typedefn with a display on an integer enum, etc.
    'warn': {
        'config.txt': 'warn.xml\n',
        'warn.xml': dict_with(
            '<protocol name="Bad Re" path="[unterminated" port="8097"/>\n'
            '<protocol name="Bad Re2" path="(" case="insensitive"/>\n'
            '<typedefn type-name="IPv4" base-type="string" display="ipv4"/>\n'
            '<typedefn type-name="Hex" base-type="string" display="hex2dec"/>\n'
            '<field name="Weird Case" path="weird_case" case="weird"/>\n'
            '<field name="Bool Enum" path="bool_enum" type="boolean"><enum name="one" code="1"/></field>\n'
            '<field name="Str Enum" path="str_enum" type="string"><enum name="one" code="1"/></field>\n'
            '<field name="Dbl Enum" path="dbl_enum" type="double"><enum name="one" code="1"/></field>\n'
            '<field name="Ip Enum" path="ip_enum" type="IPv4"><enum name="one" code="1"/></field>\n'
            '<field name="Hex Enum" path="hex_enum" type="Hex"><enum name="one" code="1"/></field>\n'
            '<field name="Dnn" path="dnn" type="Object">\n'
            '  <wildcardfield name="No Match" path="dnn.nomatch"/>\n'
            '  <wildcardfield name="No Path" match=".*"/>\n'
            '  <wildcardfield name="Bad Regex" path="dnn.bad" match="[unterminated">\n'
            '    <field name="Never" path="dnn.bad.x" type="string"/>\n'
            '  </wildcardfield>\n'
            '  <wildcardfield name="At" path="dnn.@odata" match="a.*"/>\n'
            '</field>\n'
            '<field path="" name="Empty Path Name"/>\n'
            '<field path="" name=""/>\n',
            '<protocol name="W" port="8096"/>\n')},
    # a config.txt entry that is not valid XML, with a wrong root element,
    # an empty file and a file that does not exist
    'badxml': {
        'config.txt': 'notxml.xml\nwrongroot.xml\nempty.xml\ngone.xml\ngood.xml\n',
        'notxml.xml': '<json-dictionary><base>\n',
        'wrongroot.xml': '<?xml version="1.0"?>\n<other/>\n',
        'empty.xml': '',
        'good.xml': dict_with('<field name="G" path="g" type="string"/>\n',
                              '<protocol name="G" port="8095"/>\n')},
    # a dictionary with no <base> element
    'nobase': {
        'config.txt': 'nobase.xml\nother.xml\n',
        'nobase.xml': '<?xml version="1.0"?>\n<json-dictionary/>\n',
        'other.xml': '<?xml version="1.0"?>\n<json-dictionary><other/><!-- c --><base name="x"><other/>'
                     '<field name="O" path="o" type="string"/></base></json-dictionary>\n'},
    # hostile names (filter names with characters that are not allowed)
    'names': {
        'config.txt': 'names.xml\n',
        'names.xml': dict_with(
            '<field name="A" path="@type" type="string"/>\n'
            '<field name="B" path="$ref" type="string"/>\n'
            '<field name="C" path="a:b/c" type="string"/>\n'
            '<field name="D" path="x..y." type="string"/>\n'
            '<field name="E" path="....." type="string"/>\n'
            '<field name="F" path="f" type="string" df="bad name!"/>\n'
            '<field name="G" path="g" type="array" df="..lead..dots.."><array-element type="string"/></field>\n'
            '<field name="H" path="[]" type="array"><array-element type="string"/></field>\n'
            '<field name="I" path="Name With Spaces" type="object"/>\n'
            '<field name="M" path="m" type="string" df="..."/>\n'
            '<field name="J" path="j" type="object">'
            '<wildcardfield name="K" path="j.@k:l" displayvalue="a b" match=".*"/>'
            '<wildcardfield name="L" path="j.[]" displayvalue="." match=".*"/>'
            '</field>\n',
            '<protocol name="N" port="8094"/>\n<protocol name="" port="8089"/>\n')},
    # duplicate typedefn of different base types and an enum on a boolean
    'dup': {
        'config.txt': 'dup.xml\n',
        'dup.xml': dict_with(
            '<typedefn type-name="Foo" base-type="string"/>\n'
            '<typedefn type-name="Foo" base-type="int64"/>\n'
            '<field name="A" path="a" type="Foo"/>\n<field name="B" path="b" type="Foo"/>\n'
            '<field name="Flag" path="flag" type="boolean"><enum name="one" code="1"/></field>\n',
            '<protocol name="D" port="8093"/>\n')},
    # deep nesting of <field> elements (libxml2 refuses more than 256)
    'deep': {
        'config.txt': 'deep.xml\n',
        'deep.xml': dict_with('<field name="f" path="f">' * 300 + '</field>' * 300 + '\n')},
    'deep2': {
        'config.txt': 'deep2.xml\n',
        'deep2.xml': dict_with('<field name="f" path="f">' * 200 + '</field>' * 200 + '\n',
                               '<protocol name="Deep" port="8092"/>\n')},
    # dictionary objects nested deeper than the JSON+ path limit (32)
    'deepdict': {
        'config.txt': 'deepdict.xml\n',
        'deepdict.xml': dict_with(
            ''.join('<field name="a%d" path="%s" type="object"/>\n' % (n, '.'.join(['a'] * n))
                    for n in range(1, 41)) +
            '<field name="arr" path="%s.arr" type="array"><array-element type="string"/></field>\n'
            % '.'.join(['a'] * 33) +
            '<field name="arr2" path="%s.arr2" type="array"><array-element type="string"/></field>\n'
            % '.'.join(['a'] * 31) +
            '<field name="Ratio" path="ratio" type="double"/>\n',
            '<protocol name="Deep Dict" port="9001"/>\n')},
    # an overlong config.txt line (fgets splits it) and a CRLF file
    'longline': {
        'config.txt': 'a' * 1030 + '.xml\r\ngood.xml\r\n',
        'good.xml': dict_with('<field name="G" path="g" type="string"/>\n',
                              '<protocol name="G" port="8091"/>\n')},
}

# ---------------------------------------------------------------------------
# Capture writer
# ---------------------------------------------------------------------------

class Pcap:
    def __init__(self):
        self.frames = []
        self.ts = 1700000000

    def add(self, data):
        self.ts += 1
        self.frames.append((self.ts, data))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for ts, d in self.frames:
                f.write(struct.pack('<IIII', ts, 0, len(d), len(d)) + d)


def ip_checksum(h):
    s = 0
    for i in range(0, len(h), 2):
        s += (h[i] << 8) + h[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def eth_ip(proto, payload, src, dst, ident):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
                      bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', ip_checksum(hdr)) + hdr[12:]
    return (bytes([2, 0, 0, 0, 0, 2]) + bytes([2, 0, 0, 0, 0, 1]) + b'\x08\x00' + hdr + payload)


class Conn:
    """A TCP connection with correct sequence numbers."""
    ident = 0

    def __init__(self, pcap, cport, sport, syn=True):
        self.p = pcap
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.c = (192, 0, 2, 1)
        self.s = (192, 0, 2, 2)
        if syn:
            self._seg(True, b'', 0x02)
            self.cseq += 1
            self._seg(False, b'', 0x12)
            self.sseq += 1
            self._seg(True, b'', 0x10)

    def _seg(self, client, data, flags):
        Conn.ident += 1
        # MSS option on the SYN and SYN/ACK
        opt = struct.pack('>BBH', 2, 4, 1460) if flags & 0x02 else b''
        off = 0x50 + (len(opt) // 4 << 4)
        if client:
            tcp = struct.pack('>HHIIBBHHH', self.cport, self.sport, self.cseq, self.sseq,
                              off, flags, 65535, 0, 0) + opt + data
            self.p.add(eth_ip(6, tcp, self.c, self.s, Conn.ident))
            self.cseq += len(data)
        else:
            tcp = struct.pack('>HHIIBBHHH', self.sport, self.cport, self.sseq, self.cseq,
                              off, flags, 65535, 0, 0) + opt + data
            self.p.add(eth_ip(6, tcp, self.s, self.c, Conn.ident))
            self.sseq += len(data)

    def to_server(self, data):
        self._seg(True, data, 0x18)
        self._seg(False, b'', 0x10)

    def to_client(self, data):
        self._seg(False, data, 0x18)
        self._seg(True, b'', 0x10)

    def post(self, uri, body, ctype='application/json', method='POST'):
        body = body if isinstance(body, bytes) else body.encode()
        h = ('%s %s HTTP/1.1\r\nHost: example.com\r\nContent-Type: %s\r\n'
             'Content-Length: %d\r\n\r\n' % (method, uri, ctype, len(body))).encode()
        self.to_server(h + body)

    def reply(self, body, ctype='application/json', status='200 OK'):
        body = body if isinstance(body, bytes) else body.encode()
        h = ('HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n'
             % (status, ctype, len(body))).encode()
        self.to_client(h + body)


def udp(pcap, sport, dport, data, ident):
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    pcap.add(eth_ip(17, u, (192, 0, 2, 1), (192, 0, 2, 2), ident))


# ---------------------------------------------------------------------------
# HTTP/2 prior knowledge (HPACK without Huffman coding or indexing)
# ---------------------------------------------------------------------------

def h2_frame(ftype, flags, stream, payload):
    return struct.pack('>I', len(payload))[1:] + bytes([ftype, flags]) + \
        struct.pack('>I', stream) + payload


def hp_lit(index, value, prefix_bits=4):
    """Literal header field without indexing, name from the static table."""
    mask = (1 << prefix_bits) - 1
    if index < mask:
        first = bytes([index])
    else:
        first = bytes([mask]) + bytes([index - mask])
    v = value.encode()
    return first + bytes([len(v)]) + v


def h2_stream(pcap, cport, sport, uri, body, ctype='application/json'):
    c = Conn(pcap, cport, sport)
    c.to_server(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2_frame(4, 0, 0, b''))
    c.to_client(h2_frame(4, 0, 0, b'') + h2_frame(4, 1, 0, b''))
    body = body.encode()
    hdrs = (b'\x83' + b'\x86' + hp_lit(4, uri) + hp_lit(1, 'example.com') +
            hp_lit(31, ctype))
    c.to_server(h2_frame(4, 1, 0, b'') + h2_frame(1, 4, 1, hdrs) + h2_frame(0, 1, 1, body))
    rh = b'\x88' + hp_lit(31, ctype)
    c.to_client(h2_frame(1, 4, 1, rh) + h2_frame(0, 1, 1, body))
    return c


# ---------------------------------------------------------------------------
# Bodies
# ---------------------------------------------------------------------------

import json as _json


def J(o):
    return _json.dumps(o, separators=(',', ':'))


MAIN_BODIES = [
    # plain scalars, info labels
    '{"request_id":"req-1","userName":"alice","exactName":"x","plain":"p","count":42,"bytes":18446744073709551615,'
    '"ratio":19.5,"ok":true,"unknown_type":"u","no_type":"n",'
    '"empty_name":"e","dup_field":"s"}',
    # case-insensitive matching
    '{"USERNAME":"bob","Request_Id":"x","exactname":"no match"}',
    # enums, hex2dec
    '{"status":0,"priority":5,"cell":"64","cellid":"ff"}',
    '{"status":7,"priority":99,"cell":"c8","cellid":"1F4"}',
    '{"status":"1","priority":"2"}',
    # special displays
    '{"addr4":"192.0.2.55","addr6":"2001:db8::1","mac":"00:11:22:33:44:55","created":1700000000,'
    '"created_u":1700000001,"elapsed":90,"elapsed_u":3600}',
    '{"created":"1700000002","elapsed":"1.5","created_u":"1700000003","elapsed_u":"7","addr4":"10.1.2.3"}',
    # objects, df, name-only children
    '{"profile":{"email":"a@example.com","age":33,"Home":{"City":"Oslo"}},'
    '"Nested Obj":{"Leaf":"l","Num":3}}',
    # arrays
    '{"tags":["a","b","c"],"numbers":[1,2,3],"matrix":[[1,2],[3]],'
    '"items":[{"id":1,"price":9.5,"label":"first","sub":[{"id":10},{"id":11}]},'
    '{"id":2,"price":0.25,"label":"second","sub":[]}],'
    '"rows":[{"Row Name":"r0","Row Value":1},{"Row Name":"r1","Row Value":2}]}',
    # odd key names
    '{"@type":"t","$ref":"#/x","a:b":"c","two words":"w","x..y":"z","parsed":"v","parsed2":"v2"}',
    # wildcards
    '{"dnn":{"web.operator.com":{"sessionType":"IPV4","qi":9,"slice":{"1":{"sst":1},"22":{"sst":2}}},'
    '"x-other":{"value":"o"},"plain":{"k":1},"ims.example.com":[{"item":"i0"},{"item":"i1"}]}}',
    # generic values inside arrays and at the top level of an object
    '{"unk_list":[null,true,false,1.5,"s",{"k":null},[2]],"unk_true":true,"unk_false":false,"unk_null":null,"unk_num":2.5}',
    # a root array whose members match the dictionary only without the "[n]." prefix
    '[{"items":[{"id":5}]},{"profile":{"age":4}},{"count":8}]',
    # empty and generic content, nulls, nested anonymous values
    '{"request_id":null,"tags":null,"profile":null,"count":null,"unknown":{"a":[1,{"b":2}],"c":"d","e":true,"f":false,"g":null,"h":1.5}}',
    # value types that do not fit
    '{"count":true,"ok":"yes","profile":"str","tags":{"a":1},"ratio":"x","bytes":-1,"status":1.5}',
    # root level array (path [])
    '[{"id":1,"name":"one"},{"id":2,"name":"two"}]',
    '[1,"two",{"id":3},[4]]',
    # empty containers
    '{}',
    '[]',
    # top level scalars
    '"just a string"',
]

# The reproducers of the "Fix type mismatches" fix, on the shipped GitHub API
# dictionary (port 8080): value types that do not match the registered field
# type must give a type mismatch expert info, not a dissector bug.
REPRO_BODIES = [
    '{"server":{"ip":"not-an-ip"}}',
    '{"user":{"id":"abc"}}',
    '{"user":{"id":1.5}}',
    '{"user":{"active":"yes"}}',
    '{"created_at":"x"}',
    '{"cell":{"id":"zz"}}',
    '{"user":{"score":"x"}}',
    '{"server":{"ipv6":null}}',
    '{"server":{"ipv6":"bad","mac":"zz","ip":4,"mac2":1}}',
    '{"duration":"x","user":{"id":"9223372036854775808"}}',
]

# the same on the personal dictionary (port 9001)
REPRO_MAIN_BODIES = [
    # 32-bit and single precision fields without enums have no typed add function
    '{"small":-5,"usmall":7,"single":1.25}',
    '{"addr4":"x","addr6":"y","mac":"z","created":"c","elapsed":"e","cell":"zz","cellid":"qq"}',
    '{"addr4":null,"addr6":null,"created":null,"cell":null,"ok":null,"count":null,"bytes":null,"ratio":null,"status":null}',
    '{"count":"abc","bytes":"abc","ratio":1e999,"small":"x","usmall":"y","ok":"no","single":"s"}',
    '{"created":"9223372036854775808","bytes":99999999999999999999999}',
]

PATH_REQUESTS = [
    # (port, uri, body)
    (9301, '/orders/v2/list', '{"order":{"id":7,"name":"widget"}}'),
    (9302, '/api/TENANT/ab12cd/x', '{"order":{"id":8,"name":"tenant"}}'),
    (9303, '/tenant/ab12cd', '{"order":{"id":9}}'),
    (9100, '/strict/x', '{"strict":true,"order":{"id":10}}'),         # port and path
    (9100, '/other/x', '{"strict":true}'),                            # port only: no match
    (9304, '/strict/x', '{"strict":true}'),                           # path only: port missing
    (9101, '/loose/x', '{"order":{"id":11}}'),
    (9101, '/other', '{"order":{"id":12}}'),                          # port only, default condition
    (9305, '/loose/x', '{"order":{"id":13}}'),                        # path only
    (9102, '/looseor/x', '{"order":{"id":14}}'),
    (9306, '/nodisplay/x', '{"order":{"id":15}}'),
    (9103, '/anything', '{"order":{"id":16}}'),
    (9104, '/anything', '{"order":{"id":17}}'),
    (9201, '/g', '{"global_only":5,"global_obj":{"leaf":"g"},"request_id":"r"}'),
    (9307, '/nomatch', '{"order":{"id":18}}'),
]


def build_main(path):
    p = Pcap()
    sport = 40000
    # personal dictionary, protocol on tcp/9001 (and a second port)
    c = Conn(p, sport, 9001)
    for i, b in enumerate(MAIN_BODIES):
        c.post('/api/%d' % i, b)
        c.reply(b if i % 3 == 0 else '{"status":0,"request_id":"ok-%d"}' % i)
    c2 = Conn(p, sport + 1, 9002)
    c2.post('/second', MAIN_BODIES[0])
    c2.reply('{"count":1}')
    # reproducers on the personal dictionary
    c3 = Conn(p, sport + 2, 9001)
    for b in REPRO_MAIN_BODIES:
        c3.post('/mismatch', b)
        c3.reply('{"ok":true}')
    # reproducers on the shipped dictionary (port 8080)
    c4 = Conn(p, sport + 3, 8080)
    for b in REPRO_BODIES:
        c4.post('/api', b)
        c4.reply('{"enabled":true}')
    # a normal use of the shipped dictionary
    c4.post('/api', '{"user":{"id":1,"name":"n","score":2.5,"active":true,"profile":{"email":"e","age":3}},'
            '"repository":{"tags":["a"]},"server":{"ip":"10.0.0.1","ipv6":"::1","mac":"aa:bb:cc:dd:ee:ff"},'
            '"created_at":1700000000,"duration":12,"cell":{"id":"64"},"inputs":{"home":"h","name":"n"},'
            '"labels":["x"],"environment_ids":[1,2],"enabled":false}')
    c4.reply('{"state":"ok"}')
    # path and port based protocol selection
    for i, (port, uri, body) in enumerate(PATH_REQUESTS):
        cc = Conn(p, 41000 + i, port)
        cc.post(uri, body)
        cc.reply('{"order":{"id":99}}')
    # HTTP/2 with the path in a HEADERS frame
    h2_stream(p, 42000, 9400, '/orders/v1/h2', '{"order":{"id":21,"name":"h2"}}')
    h2_stream(p, 42001, 9401, '/nomatch/h2', '{"order":{"id":22}}')
    # a boolean true for a field that has an enum in the "dup" dictionary
    # (cfg-dup): the enum on a boolean made tshark crash
    c7 = Conn(p, 43002, 8093)
    c7.post('/flag', '{"flag":true,"a":"x","b":"y"}')
    c7.reply('{"flag":false}')
    # JSON that is not carried with a protocol of the dictionary: generic
    c5 = Conn(p, 43000, 9500)
    c5.post('/plain', '{"count":1,"tags":["z"]}')
    c5.reply('{"ok":true}')
    # media types other than application/json
    c6 = Conn(p, 43001, 9001)
    c6.post('/ct', '{"count":2}', ctype='application/problem+json')
    c6.reply('{"count":3}', ctype='application/json; charset=utf-8')
    # UDP port of the bare protocol (no JSON handler on UDP: only checks that
    # a datagram on a protocol port does not matter)
    udp(p, 50000, 9200, b'{"count":1}', 1)
    p.write(path)
    return len(p.frames)


def deep_obj(n):
    return '{"a":' * n + '1' + '}' * n


def build_malformed(path):
    p = Pcap()
    c = Conn(p, 44000, 9001)
    for b in [
        '{"count":',                                  # truncated
        '{"count":1,}',                               # trailing comma
        '{count:1}',                                  # bare key
        '12.5', 'true', 'false', 'null',                # top level scalars are not accepted
        '{"ratio":-}', '{"ratio":--1}', '{"ratio":+1e}', '[-]',
        '{"a":' * 33 + '{"arr":["x","y"]}' + '}' * 33,
        '{"a":' * 31 + '{"arr2":["x",["y"]]}' + '}' * 31,
        '{"a":' * 40 + '{"arr":["x"]}' + '}' * 40,
        '{"a":[' * 20 + '1' + ']}' * 20,
        '{"a":' * 40 + '1' + '}' * 40,                # deeper than the JSON+ path limit
        '[' * 40 + ']' * 40,
        '{"items":' + '[' * 36 + ']' * 36 + '}',
        '{"dnn":' + '{"x-a":' * 36 + '1' + '}' * 36 + '}',
        '{"profile":' + '{"profile":' * 34 + '1' + '}' * 34 + '}',
        '{"tags":["a",}',
        'not json at all',
        '{"count":1}garbage',
        '{"count":NaN}',
    ]:
        c.post('/bad', b)
        c.reply('{"ok":1}')
    p.write(path)
    return len(p.frames)


def write_cfg(base, name, files):
    d = os.path.join(base, name, 'json') if name else os.path.join(base, 'json')
    os.makedirs(d, exist_ok=True)
    for fn, text in files.items():
        with open(os.path.join(d, fn), 'w') as f:
            f.write(text)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write_cfg(os.path.join(out, 'cfg'), '', {
        'config.txt': CONFIG_TXT, 'main.xml': MAIN_XML, 'paths.xml': PATHS_XML,
        'bare.xml': BARE_XML, 'fieldsonly.xml': FIELDSONLY_XML})
    for name, files in EXTRA_CFGS.items():
        write_cfg(out, 'cfg-' + name, files)
    n = build_main(os.path.join(out, 'json_dictionary_coverage.pcap'))
    m = build_malformed(os.path.join(out, 'json_dictionary_coverage_malformed.pcap'))
    print('main: %d frames, malformed: %d frames' % (n, m))


if __name__ == '__main__':
    main()
