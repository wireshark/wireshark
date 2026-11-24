#!/usr/bin/env python3
# Generates test/captures/snort_config_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Snort configuration parser coverage files. Usage: mksnort_config.py <outdir> [-v]
packet-snort-config.c parses the Snort configuration that the Snort
post-dissector is pointed at (snort.config) and the rule files it includes.
It is reached with -o snort.alerts_source:from-user-comments
-o snort.config:<file> (no snort binary needed). This script writes:
  conf/snort.conf, conf/rules/*.rules, conf/more/*.conf  the configuration files
  snort-config-coverage.pcapng                           one frame per rule, whose packet comment is
                                                         the alert "1:<sid>:<rev> - <msg>"
  conf-long/, conf-ref/                                  the configurations of the two reproducers
  conf-abs/                                              a configuration with absolute paths (written with the absolute path of <outdir>)
Everything is synthetic."""
import os
import struct
import sys
from pcaplib import eth, ip4, udp, write_pcapng

SNORT_CONF = """# top level configuration

var RULE_PATH rules

var EMPTY_VALUE x
ipvar HOME_NET [192.0.2.0/24,198.51.100.0/24]
ipvar EXTERNAL_NET !$HOME_NET
ipvar DNS_SERVERS $HOME_NET
portvar HTTP_PORTS [80,8080]
portvar ORACLE_PORTS 1024:
var onlyname
var
ipvar NOVALUE
portvar
unknownvar something value
config reference: url http://example.invalid/ref/
config reference: CVE http://cve.example.invalid/?id=
config reference: bugtraq http://bugs.example.invalid/id/
config reference: noreplacement
include $RULE_PATH/a.rules
include $RULE_PATH/b.rules
include more/inner.conf
include more/missing.conf
include
include recurse.conf
"""

INNER_CONF = """# a nested include with its own variables and a rule
var NESTED yes
ipvar NESTED_NET 203.0.113.0/24
alert udp any any -> $NESTED_NET any (msg:"Nested include rule"; sid:3001; rev:1;)
"""

RECURSE_CONF = """# includes itself: stops after 8 levels
include recurse.conf
alert udp any any -> any 3002 (msg:"Recursion rule"; sid:3002; rev:1;)
"""

A_RULES = r"""# rules with every option
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"All content options"; content:"GET "; nocase; offset:0; depth:8; fast_pattern; content:"HTTP|2f|1."; distance:1; within:20; rawbytes; content:"|0d 0a|Host"; http_method; content:"cookie"; http_cookie; content:"body"; http_client_body; content:"agent"; http_user_agent; uricontent:"/idx"; uricontent:"/idx2"; http_uri; classtype:web-application-activity; reference:url,example.invalid/one; reference:cve,2021-0001; reference:bugtraq,77; reference:other,thing; reference:missing-comma; sid:4001; rev:2;)
alert udp $DNS_SERVERS 53 -> any $ORACLE_PORTS (msg:"Several variables"; content:"dns"; sid:4002; rev:1;)
alert icmp any any -> any any (msg:"ICMP rule"; itype:8; content:"ping"; sid:4003; rev:1;)
alert udp any any -> any 4004 (msg:"Signed numbers"; content:"abc"; offset:-3; distance:-2; depth:65535; within:65535; sid:4004; rev:1;)
alert udp any any -> any 4005 (msg:"Bad numbers"; content:"abc"; offset:abc; depth:70000; within:-1; distance:xyz; sid:4005x; rev:z;)
alert udp any any -> any 4006 (msg:"Negations and short values"; content:!"no"; content:!"x"; content:"y"; uricontent:"z"; uricontent:!"abc"; pcre:"ab"; sid:4006; rev:1;)
alert udp any any -> any 4007 (msg:"PCRE forms"; pcre:"/^abc/i"; pcre:"/a.b/s"; pcre:"/x\d+/m"; pcre:"/raw/B"; pcre:"/mod/iRU"; pcre:"/noend"; pcre:"abc/"; pcre:"/ab"; sid:4007; rev:1;)
alert udp any any -> any 4008 (msg:"Escapes in content"; content:"a\;b\\d"; content:"|41 42 43|DEF|20|"; content:"|4A4b 4c|"; content:"|4|"; sid:4008; rev:1;)
alert udp any any -> any 4009 (msg:"Unknown options"; flow:to_server; threshold:type limit,track by_src,count 1,seconds 60; metadata:service http; sid:4009; rev:1;)
alert udp any any -> any 4010 (msg:"Option without value"; nocase; fast_pattern; rawbytes; http_uri; http_method; sid:4010; rev:1;)
alert udp any any -> any 4011 (msg:"Spaces after colon"; content: "spaced"; offset: 1; sid: 4011; rev: 1;)
alert udp any any -> any 4012 (msg:"Semi;colon"; content:"semi;colon in quotes"; sid:4012; rev:1;)
alert udp 1 1 -> ! ! (msg:"Short address and port fields"; sid:4013; rev:1;)
alert udp any any -> any 4014 (msg:"Bad sid and rev"; sid:abc; rev:abc;)
alert udp any any -> any 4015 (msg:"Empty values"; content:""; content:!""; uricontent:""; uricontent:!"";  pcre:""; reference:,nothing; sid:4015; rev:1;)
"""

B_RULES = r"""# second rule file
alert tcp any any -> any 80 (msg:"Second file"; content:"second"; sid:5001; rev:1;)
alert tcp any any -> any 80 (msg:"Duplicate sid replaces"; sid:5001; rev:9;)
alert udp any any -> any any (msg:"No options end"; content:"x"; sid:5002; rev:1;
alert udp any any -> any any msg:"No parenthesis"; sid:5003;
alert  udp any any -> any any (msg:"Double space"; sid:5004; rev:1;)
alert  (msg:"No addresses"; sid:5005; rev:1;)
log udp any any -> any any (msg:"Not an alert"; sid:5006;)
alert udp any any -> any any (msg:"Many contents"; CONTENTS; sid:5007; rev:1;)
alert udp any any -> any any (msg:"Many references"; REFERENCES; sid:5008; rev:1;)
alert udp any any -> any any (msg:"Full content table"; CONTENTS30; uricontent:"u"; pcre:"/p/"; sid:5009; rev:1;)
"""

def many(kind, n):
    if kind == 'content':
        return ' '.join('content:"c%d";' % i for i in range(n))
    return ' '.join('reference:url,example.invalid/%d;' % i for i in range(n))

def conf_files():
    b = (B_RULES.replace('CONTENTS;', many('content', 35)).replace('REFERENCES;', many('ref', 25))
         .replace('CONTENTS30;', many('content', 30)))
    return {'snort.conf': SNORT_CONF, 'rules/a.rules': A_RULES, 'rules/b.rules': b,
            'more/inner.conf': INNER_CONF, 'recurse.conf': RECURSE_CONF}

def write_conf(out):
    d = os.path.join(out, 'conf')
    for name, text in conf_files().items():
        p = os.path.join(d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, 'w').write(text)
    # the two reproducers of the fixes: a content longer than 1023 octets and a reference without ","
    d = os.path.join(out, 'conf-long')
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, 'snort.conf'), 'w').write(
        'config reference: foo http://example.invalid/\n'
        'alert udp any any -> any any (msg:"long"; content:"' + 'A' * 1040 + '"; sid:1; rev:1;)\n'
        'alert udp any any -> any any (msg:"long uricontent"; uricontent:"' + 'B' * 1100 + '"; sid:2; rev:1;)\n'
        'alert udp any any -> any any (msg:"long pcre"; pcre:"/' + 'C' * 1100 + '/"; sid:3; rev:1;)\n')
    d = os.path.join(out, 'conf-ref')
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, 'snort.conf'), 'w').write(
        'config reference: foo http://example.invalid/\n'
        'alert udp any any -> any any (msg:"ref"; reference:foo; sid:2; rev:1;)\n'
        'alert udp any any -> any any (msg:"ref2"; reference:foo,x; sid:3; rev:1;)\n')

def write_abs(out):
    d = os.path.join(os.path.abspath(out), 'conf-abs')
    os.makedirs(os.path.join(d, 'rules'), exist_ok=True)
    open(os.path.join(d, 'snort.conf'), 'w').write(ABS_CONF.replace('@DIR@', d))
    open(os.path.join(d, 'rules', 'abs.rules'), 'w').write('alert udp any any -> any 6001 (msg:"Absolute RULE_PATH"; sid:6001; rev:1;)\n')
    open(os.path.join(d, 'other.rules'), 'w').write('alert udp any any -> any 6002 (msg:"Absolute include"; sid:6002; rev:1;)\n')

ABS_CONF = """var RULE_PATH @DIR@/rules
include $RULE_PATH/abs.rules
include @DIR@/other.rules
"""

def frames():
    F = []; R = {}
    def add(name, fr, comment):
        R[name] = len(F) + 1; F.append((fr, comment))
    sids = [4001, 4002, 4003, 4004, 4005, 4006, 4007, 4008, 4009, 4010, 4011, 4012, 3001, 3002, 5001, 5002, 5004, 5007, 5008,
            4005, 7777, 4007, 4013, 4015, 5009, 0]
    for i, sid in enumerate(sids):
        pay = (b'GET /idx/idx2 HTTP/1.1\r\nHost: abc\r\nCookie: cookie\r\nUser-Agent: agent\r\n\r\nbody a;b"c\\dABCDEF abc spaced semi;colon in quotes'
               if i % 2 == 0 else b'dns ping abc xabc123 raw mod c0 c1 second')
        add('sid-%d' % sid if sid not in R else 'sid-%d-again' % sid,
            udp(40000 + i, 4000 + (sid % 100), pay), '1:%d:1 - rule %d' % (sid, sid))
    # an ICMP frame for the ICMP rule: the payload start is the ICMP header itself
    icmp = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + b'ping'
    s = sum(struct.unpack('!%dH' % (len(icmp) // 2), icmp)); s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16)
    icmp = icmp[:2] + struct.pack('!H', (~s) & 0xffff) + icmp[4:]
    add('icmp', eth(0x0800, ip4(1, icmp)), '1:4003:1 - ICMP')
    for sid in (6001, 6002):
        add('abs-%d' % sid, udp(42000 + sid, 6000 + sid % 10, b'x' * 20), '1:%d:1 - absolute %d' % (sid, sid))
    # the reproducers: a long content / reference rule with SID 1, 2 and 3
    for sid in (1, 2, 3):
        add('repro-%d' % sid, udp(41000 + sid, 9, b'A' * 1100 + b'B' * 1100 + b'C' * 50), '1:%d:1 - long enough comment for sid %d' % (sid, sid))
    return F, R

if __name__ == '__main__':
    out = sys.argv[1]
    write_conf(out)
    write_abs(out)
    F, R = frames()
    write_pcapng(os.path.join(out, 'snort-config-coverage.pcapng'), F)
    if '-v' in sys.argv:
        print(len(F), R)
