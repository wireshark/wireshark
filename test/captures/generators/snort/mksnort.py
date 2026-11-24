#!/usr/bin/env python3
# Generates test/captures/snort_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Snort coverage captures. Usage: mksnort.py <outdir> [-v]
Writes snort-coverage.pcapng (main), snort-coverage-malformed.pcapng and the
Snort configuration files in <outdir>/snortconf/ (snort.conf, rules/local.rules,
extra.conf). The Snort post-dissector shows alerts that it reads from packet
comments ("<gen>:<sid>:<rev> - <msg>", the TraceWrangler format) when
snort.alerts_source is "from-user-comments"; snort.config names the
configuration file whose rules it looks up. No snort binary is run, so the
"from running snort" paths are not covered. The comment is only visible to the
post-dissector when a tree is built (-V, -Y snort, ...).
Everything is synthetic (192.0.2.0/24, 198.51.100.0/24)."""
import os
import struct
import sys
from pcaplib import eth, ip4, TcpFlow, udp, write_pcapng

SNORT_CONF = """# Synthetic Snort configuration for the coverage capture
var RULE_PATH rules
ipvar HOME_NET 192.0.2.0/24
ipvar EXTERNAL_NET !$HOME_NET
portvar HTTP_PORTS [80,8080]
var SHELLCODE_PORTS !80
config reference: url http://example.invalid/ref/
config reference: cve http://cve.example.invalid/?id=
include $RULE_PATH/local.rules
include extra.conf
"""

EXTRA_CONF = """# included file with no rules
config checksum_mode: none
"""

LOCAL_RULES = r"""# local rules
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"HTTP GET index"; flow:to_server,established; content:"GET"; http_method; content:"/index"; offset:4; depth:10; nocase; fast_pattern; content:"Host|3a| www"; distance:0; within:30; rawbytes; uricontent:"index.html"; http_uri; classtype:web-application-attack; reference:url,example.invalid/doc; reference:cve,2020-1234; reference:nodef,xyz; sid:2001; rev:3;)
alert udp any any -> any 5354 (msg:"UDP offset depth"; content:"MAGIC"; offset:2; depth:8; classtype:misc-activity; sid:2002; rev:1;)
alert icmp any any -> any any (msg:"ICMP payload"; content:"PINGDATA"; sid:2003; rev:2;)
alert udp any any -> any 9999 (msg:"Binary and negated"; content:"|de ad be ef|"; content:!"forbidden"; content:"tail|20 7a|"; sid:2004; rev:1;)
alert udp any any -> any 9998 (msg:"Chain"; content:"first"; content:"second"; distance:3; within:12; content:"third"; distance:-8; sid:2005; rev:1;)
alert tcp any any -> any 80 (msg:"PCRE flags"; pcre:"/user-agent\x3a\s+CURL/i"; pcre:"/^get.*host/smB"; pcre:"/a(b|c)+d/U"; pcre:"x"; pcre:"no-delimiters/"; sid:2006; rev:1;)
alert tcp any any -> any 80 (msg:"HTTP buffers"; content:"id="; http_client_body; content:"sess"; http_cookie; content:"curl"; http_user_agent; sid:2007; rev:1;)
alert udp any any -> any any (msg:"No contents"; classtype:attempted-recon; sid:2008; rev:1;)
alert tcp any any -> any 80 (msg:"Uricontent only"; uricontent:"/missing"; sid:2009; rev:1;)
alert udp any any -> any 9997 (msg:"Content not in packet"; content:"NOTTHERE"; sid:2010; rev:1;)
alert udp any any -> any 7777 (msg:"Ports and vars"; sid:2011; rev:1; priority:3;)
alert udp any any -> any any (msg:"s16 test"; sid:1; rev:1;)
not a rule line
alert tcp any any -> any any (no closing parenthesis
"""

def pcomment(sid, rev=1, msg='alert', gen=1):
    return '%d:%d:%d - %s' % (gen, sid, rev, msg)

def mkhttp(path=b'/index.html', body=b'', extra=b'', host=b'www.example.invalid'):
    h = b'GET ' + path + b' HTTP/1.1\r\nHost: ' + host + b'\r\nUser-Agent: curl/7.1\r\n' + extra + b'\r\n' + body
    return h

def main_frames():
    F = []; R = {}
    def add(name, fr, comment=None):
        R[name] = len(F) + 1; F.append((fr, comment) if comment is not None else fr)
    EXT = (198, 51, 100, 5); HOME = (192, 0, 2, 10)
    f = TcpFlow(40000, 80, EXT, HOME)
    for fr in f.handshake():
        add('hs', fr)
    add('http-get', f.c2s(mkhttp()), pcomment(2001, 3, 'HTTP GET index'))
    add('http-resp', f.s2c(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'))
    # an alert on the first of two segments; with show_alert_in_reassembled_frame it moves to the second
    req = mkhttp(b'/index.html?x=1', extra=b'Cookie: sess=abc\r\n')
    add('http-split-1', f.c2s(req[:40]), pcomment(2001, 3, 'HTTP GET index'))
    add('http-split-2', f.c2s(req[40:]))
    add('http-resp2', f.s2c(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'))
    post = (b'POST /form HTTP/1.1\r\nHost: www.example.invalid\r\nUser-Agent: curl/7.1\r\nCookie: sess=abc\r\n'
            b'Content-Length: 6\r\n\r\nid=123')
    add('http-post', f.c2s(post), pcomment(2007, 1, 'HTTP buffers'))
    add('http-pcre', f.c2s(b'GET /x HTTP/1.1\r\nHost: h\r\nUser-Agent: CURL/8\r\n\r\n'), pcomment(2006, 1, 'PCRE flags'))
    add('http-uri-missing', f.c2s(mkhttp(b'/other')), pcomment(2009, 1, 'Uricontent only'))
    add('http-unknown-sid', f.c2s(mkhttp(b'/index.html')), pcomment(424242, 7, 'no rule for this sid'))
    for fr in f.fin():
        add('fin', fr)
    # UDP alerts
    add('udp-offset', udp(40001, 5354, b'xxMAGICyyyy'), pcomment(2002, 1, 'UDP offset depth'))
    add('udp-binary', udp(40002, 9999, b'..\xde\xad\xbe\xef..tail z....'), pcomment(2004, 1, 'Binary and negated'))
    add('udp-chain', udp(40003, 9998, b'first___second___third'), pcomment(2005, 1, 'Chain'))
    add('udp-chain-miss', udp(40003, 9998, b'first___seco'), pcomment(2005, 1, 'Chain'))
    add('udp-nocontent', udp(40004, 4444, b'payload'), pcomment(2008, 1, 'No contents'))
    add('udp-notfound', udp(40005, 9997, b'something else entirely'), pcomment(2010, 1, 'Content not in packet'))
    add('udp-vars', udp(40006, 7777, b'v'), pcomment(2011, 1, 'Ports and vars'))
    add('udp-short-comment', udp(40007, 9, b'hello'), '1:1:1 - x')       # reproducer: sid in the config, comment of 9 octets
    add('udp-unknown-sid', udp(40008, 9, b'hello'), '1:4242:1 - not in config')   # reproducer: sid not in the config
    add('udp-repeat', udp(40002, 9999, b'..\xde\xad\xbe\xef..tail z....'), pcomment(2004, 2, 'Binary and negated again'))
    # ICMP echo request with a payload
    icmp = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + b'xxPINGDATAxx'
    csum = sum(struct.unpack('!%dH' % (len(icmp) // 2), icmp))
    csum = (csum & 0xffff) + (csum >> 16)
    csum = (csum & 0xffff) + (csum >> 16)
    icmp = icmp[:2] + struct.pack('!H', (~csum) & 0xffff) + icmp[4:]
    add('icmp', eth(0x0800, ip4(1, icmp, EXT, HOME)), pcomment(2003, 2, 'ICMP payload'))
    # comments that are no alerts, or malformed alerts
    add('plain-comment', udp(40009, 4444, b'x'), 'just a comment')
    add('comment-no-separator', udp(40010, 4444, b'x'), '1:2:3')
    add('comment-bad-numbers', udp(40011, 4444, b'x'), 'a:b:c - text')
    add('no-comment', udp(40012, 4444, b'x'))
    add('comment-gen2', udp(40013, 4444, b'x'), pcomment(2008, 4, 'generator 2', gen=2))
    # a second request split over two segments where both segments carry an alert: with
    # show_alert_in_reassembled_frame the alert of the first one is added to the second one's
    f = TcpFlow(40100, 80, EXT, HOME)
    for fr in f.handshake():
        add('hs2', fr)
    req = mkhttp(b'/index.html?y=2')
    add('http2-split-1', f.c2s(req[:40]), pcomment(2001, 3, 'HTTP GET index'))
    add('http2-split-2', f.c2s(req[40:]), pcomment(2009, 1, 'Uricontent only'))
    add('http2-resp', f.s2c(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'))
    return F, R

def malformed_frames():
    F = []; R = {}
    def add(name, fr, comment=None):
        R[name] = len(F) + 1; F.append((fr, comment) if comment is not None else fr)
    # a content that is longer than the packet: the search loop runs off the end (exception)
    add('content-longer-than-packet', udp(40100, 9999, b'\xde'), pcomment(2004, 1, 'Binary and negated'))
    add('pcre-no-match-short', udp(40101, 80, b'x'), pcomment(2006, 1, 'PCRE flags'))
    add('empty-payload-alert', udp(40102, 5354, b''), pcomment(2002, 1, 'UDP offset depth'))
    # many alerts on one frame number are impossible (one comment per packet): a long comment
    add('long-comment', udp(40103, 4444, b'x'), '1:2008:1 - ' + 'A' * 1500)
    add('huge-sid', udp(40104, 4444, b'x'), '1:99999999999:1 - overflow')
    return F, R

def write_conf(out):
    d = os.path.join(out, 'snortconf')
    os.makedirs(os.path.join(d, 'rules'), exist_ok=True)
    open(os.path.join(d, 'snort.conf'), 'w').write(SNORT_CONF)
    open(os.path.join(d, 'extra.conf'), 'w').write(EXTRA_CONF)
    open(os.path.join(d, 'rules', 'local.rules'), 'w').write(LOCAL_RULES)

if __name__ == '__main__':
    out = sys.argv[1]
    write_conf(out)
    F, R = main_frames()
    write_pcapng(os.path.join(out, 'snort-coverage.pcapng'), F)
    G, RM = malformed_frames()
    write_pcapng(os.path.join(out, 'snort-coverage-malformed.pcapng'), G)
    if '-v' in sys.argv:
        print(len(F), R); print(len(G), RM)
