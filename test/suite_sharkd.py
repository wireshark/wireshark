#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''sharkd tests'''

import json
import subprocess
import unittest
import subprocesstest
import fixtures
from matchers import *


@fixtures.fixture(scope='session')
def cmd_sharkd(program):
    return program('sharkd')


@fixtures.fixture
def run_sharkd_session(cmd_sharkd, request):
    self = request.instance

    def run_sharkd_session_real(sharkd_commands):
        sharkd_proc = self.startProcess(
            (cmd_sharkd, '-'), stdin=subprocess.PIPE)
        sharkd_proc.stdin.write('\n'.join(sharkd_commands).encode('utf8'))
        self.waitProcess(sharkd_proc)

        self.assertIn('Hello in child.', sharkd_proc.stderr_str)

        outputs = []
        for line in sharkd_proc.stdout_str.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                jdata = json.loads(line)
            except json.JSONDecodeError:
                self.fail('Invalid JSON: %r' % line)
            outputs.append(jdata)
        return tuple(outputs)
    return run_sharkd_session_real


@fixtures.fixture
def check_sharkd_session(run_sharkd_session, request):
    self = request.instance

    def check_sharkd_session_real(sharkd_commands, expected_outputs):
        sharkd_commands = [json.dumps(x) for x in sharkd_commands]
        actual_outputs = run_sharkd_session(sharkd_commands)
        self.assertEqual(expected_outputs, actual_outputs)
    return check_sharkd_session_real


@fixtures.mark_usefixtures('base_env')
@fixtures.uses_fixtures
class case_sharkd(subprocesstest.SubprocessTestCase):
    def test_sharkd_req_load_bad_pcap(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('non-existant.pcap')}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"error":{"code":-2001,"message":"Unable to open the file"}},
        ))

    def test_sharkd_req_status_no_pcap(self, check_sharkd_session):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"status"},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"frames":0,"duration":0.000000000}},
        ))

    def test_sharkd_req_status(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"status"},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{"frames": 4, "duration": 0.070345000,
                "filename": "dhcp.pcap", "filesize": 1400}},
        ))

    def test_sharkd_req_analyse(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"analyse"},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{"frames": 4, "protocols": ["frame", "eth", "ethertype", "ip", "udp",
                                        "dhcp"], "first": 1102274184.317452908, "last": 1102274184.387798071}},
        ))

    def test_sharkd_req_info(self, check_sharkd_session):
        matchTapNameList = MatchList(
            {"tap": MatchAny(str), "name": MatchAny(str)})
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"info"},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{
                "version": MatchAny(str),
                "columns": MatchList({"format": MatchAny(str), "name": MatchAny(str)}),
                "stats": matchTapNameList,
                "convs": matchTapNameList,
                "eo": matchTapNameList,
                "srt": matchTapNameList,
                "rtd": matchTapNameList,
                "seqa": matchTapNameList,
                "taps": matchTapNameList,
                "follow": matchTapNameList,
                "ftypes": MatchList(MatchAny(str)),
                "nstat": matchTapNameList,
            }},
        ))

    def test_sharkd_req_check(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"check"},
            {"jsonrpc":"2.0", "id":3, "method":"check", "params":{"filter": "garbage filter"}},
            {"jsonrpc":"2.0", "id":4, "method":"check", "params":{"field": "garbage field"}},
            {"jsonrpc":"2.0", "id":5, "method":"check", "params":{"filter": "ip", "field": "ip"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":3,"error":{"code":-5001,"message":"Filter invalid - \"filter\" was unexpected in this context."}},
            {"jsonrpc":"2.0","id":4,"error":{"code":-5002,"message":"Field garbage field not found"}},
            {"jsonrpc":"2.0","id":5,"result":{"status":"OK"}},
        ))

    def test_sharkd_req_complete_field(self, check_sharkd_session):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"complete"},
            {"jsonrpc":"2.0", "id":2, "method":"complete", "params":{"field": "frame.le"}},
            {"jsonrpc":"2.0", "id":3, "method":"complete", "params":{"field": "garbage.nothing.matches"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{}},
            {"jsonrpc":"2.0","id":2,"result":{"field": MatchList(
                {"f": "frame.len", "t": 7, "n": "Frame length on the wire"}, match_element=any)}
            },
            {"jsonrpc":"2.0","id":3,"result":{"field": []}},
        ))

    def test_sharkd_req_complete_pref(self, check_sharkd_session):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"complete", "params":{"pref": "tcp."}},
            {"jsonrpc":"2.0", "id":2, "method":"complete", "params":{"pref": "garbage.nothing.matches"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"pref": MatchList(
                {"f": "tcp.check_checksum", "d": "Validate the TCP checksum if possible"}, match_element=any)}
            },
            {"jsonrpc":"2.0","id":2,"result":{"pref": []}},
        ))

    def test_sharkd_req_frames(self, check_sharkd_session, capture_file):
        # XXX need test for optional input parameters, ignored/marked/commented
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"frames"},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":
            MatchList({
                "c": MatchList(MatchAny(str)),
                "num": MatchAny(int),
                "bg": MatchAny(str),
                "fg": MatchAny(str),
            })
            },
        ))

    def test_sharkd_req_tap_invalid(self, check_sharkd_session, capture_file):
        # XXX Unrecognized taps result in an empty line, modify
        #     run_sharkd_session such that checking for it is possible.
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"tap"},
            {"jsonrpc":"2.0", "id":3, "method":"tap", "params":{"tap0": "garbage tap"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Mandatory parameter tap0 is missing"}},
            {"jsonrpc":"2.0","id":3,"error":{"code":-11012,"message":"sharkd_session_process_tap() garbage tap not recognized"}},
        ))

    def test_sharkd_req_tap(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"tap"},
            {"jsonrpc":"2.0", "id":3, "method":"tap", "params":{"tap0": "conv:Ethernet", "tap1": "endpt:TCP"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Mandatory parameter tap0 is missing"}},
            {"jsonrpc":"2.0","id":3,"result":{
                "taps": [
                    {
                        "tap": "endpt:TCP",
                        "type": "host",
                        "proto": "TCP",
                        "geoip": MatchAny(bool),
                        "hosts": [],
                    },
                    {
                        "tap": "conv:Ethernet",
                        "type": "conv",
                        "proto": "Ethernet",
                        "geoip": MatchAny(bool),
                        "convs": [
                            {
                                "saddr": MatchAny(str),
                                "daddr": "Broadcast",
                                "txf": 2,
                                "txb": 628,
                                "rxf": 0,
                                "rxb": 0,
                                "start": 0,
                                "stop": 0.070031,
                                "filter": "eth.addr==00:0b:82:01:fc:42 && eth.addr==ff:ff:ff:ff:ff:ff",
                            },
                            {
                                "saddr": MatchAny(str),
                                "daddr": MatchAny(str),
                                "rxf": 0,
                                "rxb": 0,
                                "txf": 2,
                                "txb": 684,
                                "start": 0.000295,
                                "stop": 0.070345,
                                "filter": "eth.addr==00:08:74:ad:f1:9b && eth.addr==00:0b:82:01:fc:42",
                            }
                        ],
                    },
                ]
            }},
        ))

    def test_sharkd_req_follow_bad(self, check_sharkd_session, capture_file):
        # Unrecognized taps currently produce no output (not even err).
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"follow"},
            {"jsonrpc":"2.0", "id":3, "method":"follow",
            "params":{"follow": "garbage follow", "filter": "ip"}
            },
            {"jsonrpc":"2.0", "id":4, "method":"follow",
            "params":{"follow": "HTTP", "filter": "garbage filter"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Mandatory parameter follow is missing"}},
            {"jsonrpc":"2.0","id":3,"error":{"code":-12001,"message":"sharkd_session_process_follow() follower=garbage follow not found"}},
            {"jsonrpc":"2.0","id":4,
            "error":{"code":-12002,"message":"sharkd_session_process_follow() name=HTTP error=Filter \"garbage filter\" is invalid - \"filter\" was unexpected in this context."}
            },
        ))

    def test_sharkd_req_follow_no_match(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"follow",
            "params":{"follow": "HTTP", "filter": "ip"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,
            "result":{"shost": "NONE", "sport": "0", "sbytes": 0,
             "chost": "NONE", "cport": "0", "cbytes": 0}
            },
        ))

    def test_sharkd_req_follow_udp(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"follow",
            "params":{"follow": "UDP", "filter": "frame.number==1"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,
            "result":{
             "shost": "255.255.255.255", "sport": "67", "sbytes": 272,
             "chost": "0.0.0.0", "cport": "68", "cbytes": 0,
             "payloads": [
                 {"n": 1, "d": MatchRegExp(r'AQEGAAAAPR0A[a-zA-Z0-9]{330}AANwQBAwYq/wAAAAAAAAA=')}]}
            },
        ))

    def test_sharkd_req_iograph_bad(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"iograph"},
            {"jsonrpc":"2.0", "id":3, "method":"iograph",
            "params":{"graph0": "garbage graph name"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Mandatory parameter graph0 is missing"}},
            {"jsonrpc":"2.0","id":3,"result":{"iograph": []}},
        ))

    def test_sharkd_req_iograph_basic(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":1, "method":"iograph",
            "params":{"graph0": "max:udp.length", "filter0": "udp.length"}
            },
            {"jsonrpc":"2.0", "id":2, "method":"iograph",
            "params":{"graph0": "packets", "graph1": "bytes"}
            },
            {"jsonrpc":"2.0", "id":3, "method":"iograph",
            "params":{"graph0": "packets", "filter0": "garbage filter"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":1,"result":{"iograph": [{"items": [308.000000]}]}},
            {"jsonrpc":"2.0","id":2,"result":{"iograph": [{"items": [4.000000]}, {"items": [1312.000000]}]}},
            {"jsonrpc":"2.0","id":3,"error":{"code":-6001,"message":"Filter \"garbage filter\" is invalid - \"filter\" was unexpected in this context."}},
        ))

    def test_sharkd_req_intervals_bad(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"intervals",
            "params":{"filter": "garbage filter"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-7001,"message":"Invalid filter parameter: garbage filter"}},
        ))

    def test_sharkd_req_intervals_basic(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"intervals"},
            {"jsonrpc":"2.0", "id":3, "method":"intervals",
            "params":{"interval": 1}
            },
            {"jsonrpc":"2.0", "id":4, "method":"intervals",
            "params":{"filter": "frame.number <= 2"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{"intervals":[[0,4,1312]],"last":0,"frames":4,"bytes":1312}},
            {"jsonrpc":"2.0","id":3,"result":{"intervals":[[0,2,656],[70,2,656]],"last":70,"frames":4,"bytes":1312}},
            {"jsonrpc":"2.0","id":4,"result":{"intervals":[[0,2,656]],"last":0,"frames":2,"bytes":656}},
        ))

    def test_sharkd_req_frame_basic(self, check_sharkd_session, capture_file):
        # XXX add more tests for other options (ref_frame, prev_frame, columns, color, bytes, hidden)
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"frame",
            "params":{"frame": 2}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{"fol": [["UDP", "udp.stream eq 1"]]}},
        ))

    def test_sharkd_req_frame_proto(self, check_sharkd_session, capture_file):
        # Check proto tree output (including an UTF-8 value).
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"frame",
            "params":{"frame": 2, "proto": True}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":
            MatchObject({
                "tree": MatchList({
                    "l": "Dynamic Host Configuration Protocol (Offer)",
                    "t": "proto",
                    "f": "dhcp",
                    "e": MatchAny(int),
                    "n": MatchList({
                        "l": "Padding: 0000000000000000000000000000000000000000000000000000",
                        "h": [316, 26],
                        "f": "dhcp.option.padding == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
                    }, match_element=any),  # match one element from 'n'
                    "h": [42, 300],
                }, match_element=any),  # match one element from 'tree'
            })
            },
        ))

    def test_sharkd_req_setcomment(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"setcomment",
            "params":{"frame": 99999, "comment": "meh\nbaz"}
            },
            {"jsonrpc":"2.0", "id":3, "method":"setcomment",
            "params":{"frame": 3, "comment": "foo\nbar"}
            },
            {"jsonrpc":"2.0", "id":4, "method":"frame",
            "params":{"frame": 3}
            },

        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-3002,"message":"Frame number is out of range"}},
            {"jsonrpc":"2.0","id":3,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":4,"result":{"comment":"foo\nbar","fol": MatchAny(list)}},
        ))

    def test_sharkd_req_setconf_bad(self, check_sharkd_session):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"setconf",
            "params":{"name": "uat:garbage-pref", "value": "\"\""}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"error":{"code":-4005,"message":"Unable to set the preference"}},
        ))

    def test_sharkd_req_dumpconf_bad(self, check_sharkd_session):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"dumpconf",
            "params":{"pref": "bad.preference"}
            },
            {"jsonrpc":"2.0", "id":2, "method":"dumpconf",
            "params":{"pref": "invalid-garbage-preference"}
            },
            {"jsonrpc":"2.0", "id":3, "method":"dumpconf",
            "params":{"pref": "uat:custom_http_header_fields"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"error":{"code":-9001,"message":"Invalid pref bad.preference."}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-9002,"message":"Invalid pref invalid-garbage-preference."}},
            {"jsonrpc":"2.0","id":3,"error":{"code":-9002,"message":"Invalid pref uat:custom_http_header_fields."}},
        ))

    def test_sharkd_req_dumpconf_all(self, check_sharkd_session):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"dumpconf"},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"prefs": MatchObject({"tcp.check_checksum": {"b": 0}})}
            },
        ))

    def test_sharkd_req_download_tls_secrets(self, check_sharkd_session, capture_file):
        # XXX test download for eo: and rtp: too
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('tls12-dsb.pcapng')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"download",
            "params":{"token": "ssl-secrets"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            # TODO remove "RSA Session-ID:" support and support "CLIENT_RANDOM "... only
            {"jsonrpc":"2.0","id":2,"result":{"file": "keylog.txt", "mime": "text/plain",
                "data": MatchRegExp(r'UlNBIFNlc3Npb24tSUQ6.+')}
            },
        ))

    def test_sharkd_req_bye(self, check_sharkd_session):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"bye"},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
        ))

    def test_sharkd_bad_request(self, check_sharkd_session):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"dud"},
        ), (
            {'jsonrpc': '2.0', 'id': 1, 'error': {'code': -32601, 'message': 'The method dud is not supported'}},
        ))

    def test_sharkd_config(self, check_sharkd_session):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"setconf",
            "params":{"name": "uat:custom_http_header_fields", "value": "\"X-Header-Name\", \"Description\""}
            },
            {"jsonrpc":"2.0", "id":2, "method":"setconf",
            "params":{"name": "tcp.check_checksum", "value": "true"}
            },
            {"jsonrpc":"2.0", "id":3, "method":"dumpconf",
            "params":{"pref": "tcp.check_checksum"}
            },
            {"jsonrpc":"2.0", "id":4, "method":"setconf",
            "params":{"name": "tcp.check_checksum", "value": "false"}
            },
            {"jsonrpc":"2.0", "id":5, "method":"dumpconf",
            "params":{"pref": "tcp.check_checksum"}
            },
        ), (
            # Check that the UAT preference is set. There is no way to query it
            # (other than testing for side-effects in dissection).
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":3,"result":{"prefs":{"tcp.check_checksum":{"b":1}}}},
            {"jsonrpc":"2.0","id":4,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":5,"result":{"prefs":{"tcp.check_checksum":{"b":0}}}},
        ))

    def test_sharkd_config_enum(self, check_sharkd_session):
        '''Dump default enum preference value, change it and restore it.'''
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"dumpconf",
            "params":{"pref": "wlan.ignore_wep"}
            },
            {"jsonrpc":"2.0", "id":2, "method":"setconf",
            "params":{"name": "wlan.ignore_wep", "value": "Yes - with IV"}
            },
            {"jsonrpc":"2.0", "id":3, "method":"dumpconf",
            "params":{"pref": "wlan.ignore_wep"}
            },
            {"jsonrpc":"2.0", "id":4, "method":"setconf",
            "params":{"name": "wlan.ignore_wep", "value": "No"}
            },
            {"jsonrpc":"2.0", "id":5, "method":"dumpconf",
            "params":{"pref": "wlan.ignore_wep"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"prefs":{"wlan.ignore_wep":{"e":[{"v":0,"s":1,"d":"No"},{"v":1,"d":"Yes - without IV"},{"v":2,"d":"Yes - with IV"}]}}}},
            {"jsonrpc":"2.0","id":2,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":3,"result":{"prefs":{"wlan.ignore_wep":{"e":[{"v":0,"d":"No"},{"v":1,"d":"Yes - without IV"},{"v":2,"s":1,"d":"Yes - with IV"}]}}}},
            {"jsonrpc":"2.0","id":4,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":5,"result":{"prefs":{"wlan.ignore_wep":{"e":[{"v":0,"s":1,"d":"No"},{"v":1,"d":"Yes - without IV"},{"v":2,"d":"Yes - with IV"}]}}}},
        ))

    def test_sharkd_nested_file(self, check_sharkd_session, capture_file):
        '''Request a frame from a file with a deep level of nesting.'''
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file("http2-data-reassembly.pcap")}
            },
            {"jsonrpc":"2.0", "id":2, "method":"frame",
            "params":{"frame": "4", "proto": "yes"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            MatchAny(),
        ))
