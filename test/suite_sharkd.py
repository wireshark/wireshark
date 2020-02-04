#
# -*- coding: utf-8 -*-
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
            {"req": "load", "file": capture_file('non-existant.pcap')},
        ), (
            {"err": 2},
        ))

    def test_sharkd_req_status_no_pcap(self, check_sharkd_session):
        check_sharkd_session((
            {"req": "status"},
        ), (
            {"frames": 0, "duration": 0.0},
        ))

    def test_sharkd_req_status(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "status"},
        ), (
            {"err": 0},
            {"frames": 4, "duration": 0.070345000,
                "filename": "dhcp.pcap", "filesize": 1400},
        ))

    def test_sharkd_req_analyse(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "analyse"},
        ), (
            {"err": 0},
            {"frames": 4, "protocols": ["frame", "eth", "ethertype", "ip", "udp",
                                        "dhcp"], "first": 1102274184.317452908, "last": 1102274184.387798071},
        ))

    def test_sharkd_req_info(self, check_sharkd_session):
        matchTapNameList = MatchList(
            {"tap": MatchAny(str), "name": MatchAny(str)})
        check_sharkd_session((
            {"req": "info"},
        ), (
            {
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
            },
        ))

    def test_sharkd_req_check(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "check"},
            {"req": "check", "filter": "garbage filter"},
            {"req": "check", "field": "garbage field"},
            {"req": "check", "filter": "ip", "field": "ip"},
        ), (
            {"err": 0},
            {"err": 0},
            {"err": 0, "filter": '"filter" was unexpected in this context.'},
            {"err": 0, "field": "notfound"},
            {"err": 0, "filter": "ok", "field": "ok"},
        ))

    def test_sharkd_req_complete_field(self, check_sharkd_session):
        check_sharkd_session((
            {"req": "complete"},
            {"req": "complete", "field": "frame.le"},
            {"req": "complete", "field": "garbage.nothing.matches"},
        ), (
            {"err": 0},
            {"err": 0, "field": MatchList(
                {"f": "frame.len", "t": 7, "n": "Frame length on the wire"}, match_element=any)},
            {"err": 0, "field": []},
        ))

    def test_sharkd_req_complete_pref(self, check_sharkd_session):
        check_sharkd_session((
            {"req": "complete", "pref": "tcp."},
            {"req": "complete", "pref": "garbage.nothing.matches"},
        ), (
            {"err": 0, "pref": MatchList(
                {"f": "tcp.check_checksum", "d": "Validate the TCP checksum if possible"}, match_element=any)},
            {"err": 0, "pref": []},
        ))

    def test_sharkd_req_frames(self, check_sharkd_session, capture_file):
        # XXX need test for optional input parameters, ignored/marked/commented
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "frames"},
        ), (
            {"err": 0},
            MatchList({
                "c": MatchList(MatchAny(str)),
                "num": MatchAny(int),
                "bg": MatchAny(str),
                "fg": MatchAny(str),
            }),
        ))

    def test_sharkd_req_tap_invalid(self, check_sharkd_session, capture_file):
        # XXX Unrecognized taps result in an empty line, modify
        #     run_sharkd_session such that checking for it is possible.
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "tap"},
            {"req": "tap", "tap0": "garbage tap"},
        ), (
            {"err": 0},
        ))

    def test_sharkd_req_tap(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "tap"},
            {"req": "tap", "tap0": "conv:Ethernet", "tap1": "endpt:TCP"},
        ), (
            {"err": 0},
            {
                "err": 0,
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
            },
        ))

    def test_sharkd_req_follow_bad(self, check_sharkd_session, capture_file):
        # Unrecognized taps currently produce no output (not even err).
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "follow"},
            {"req": "follow", "follow": "garbage follow", "filter": "ip"},
            {"req": "follow", "follow": "HTTP", "filter": "garbage filter"},
        ), (
            {"err": 0},
        ))

    def test_sharkd_req_follow_no_match(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "follow", "follow": "HTTP", "filter": "ip"},
        ), (
            {"err": 0},
            {"err": 0, "shost": "NONE", "sport": "0", "sbytes": 0,
             "chost": "NONE", "cport": "0", "cbytes": 0},
        ))

    def test_sharkd_req_follow_udp(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "follow", "follow": "UDP", "filter": "frame.number==1"},
        ), (
            {"err": 0},
            {"err": 0,
             "shost": "255.255.255.255", "sport": "67", "sbytes": 272,
             "chost": "0.0.0.0", "cport": "68", "cbytes": 0,
             "payloads": [
                 {"n": 1, "d": MatchRegExp(r'AQEGAAAAPR0A[a-zA-Z0-9]{330}AANwQBAwYq/wAAAAAAAAA=')}]},
        ))

    def test_sharkd_req_iograph_bad(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "iograph"},
            {"req": "iograph", "graph0": "garbage graph name"},
        ), (
            {"err": 0},
            {"iograph": []},
            {"iograph": []},
        ))

    def test_sharkd_req_iograph_basic(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "iograph", "graph0": "max:udp.length", "filter0": "udp.length"},
            {"req": "iograph", "graph0": "packets", "graph1": "bytes"},
            {"req": "iograph", "graph0": "packets", "filter0": "garbage filter"},
        ), (
            {"err": 0},
            {"iograph": [{"items": [308.000000]}]},
            {"iograph": [{"items": [4.000000]}, {"items": [1312.000000]}]},
            {"iograph": [
                {"errmsg": 'Filter "garbage filter" is invalid - "filter" was unexpected in this context.'}]},
        ))

    def test_sharkd_req_intervals_bad(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "intervals", "filter": "garbage filter"},
        ), (
            {"err": 0},
        ))

    def test_sharkd_req_intervals_basic(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "intervals"},
            {"req": "intervals", "interval": 1},
            {"req": "intervals", "filter": "frame.number <= 2"},
        ), (
            {"err": 0},
            {"intervals": [[0, 4, 1312]], "last": 0,
                "frames": 4, "bytes": 1312},
            {"intervals": [[0, 2, 656], [70, 2, 656]],
                "last": 70, "frames": 4, "bytes": 1312},
            {"intervals": [[0, 2, 656]], "last": 0, "frames": 2, "bytes": 656},
        ))

    def test_sharkd_req_frame_basic(self, check_sharkd_session, capture_file):
        # XXX add more tests for other options (ref_frame, prev_frame, columns, color, bytes, hidden)
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "frame", "frame": 2},
        ), (
            {"err": 0},
            {"err": 0, "fol": [["UDP", "udp.stream eq 1"]]},
        ))

    def test_sharkd_req_frame_proto(self, check_sharkd_session, capture_file):
        # Check proto tree output (including an UTF-8 value).
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            {"req": "frame", "frame": 2, "proto": True},
        ), (
            {"err": 0},
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
            }),
        ))

    def test_sharkd_req_setcomment(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"req": "load", "file": capture_file('dhcp.pcap')},
            # invalid frame number returns early.
            {"req": "setcomment", "frame": 99999, "comment": "meh\nbaz"},
            {"req": "setcomment", "frame": 3, "comment": "foo\nbar"},
            {"req": "frame", "frame": 3},

        ), (
            {"err": 0},
            {"err": 0},
            {"err": 0, "comment": "foo\nbar", "fol": MatchAny(list)},
        ))

    def test_sharkd_req_setconf_bad(self, check_sharkd_session):
        check_sharkd_session((
            {"req": "setconf", "name": "uat:garbage-pref", "value": "\"\""},
        ), (
            {"err": 1, "errmsg": "Unknown preference"},
        ))

    def test_sharkd_req_dumpconf_bad(self, check_sharkd_session):
        check_sharkd_session((
            {"req": "dumpconf", "pref": "invalid-garbage-preference"},
            {"req": "dumpconf", "pref": "uat:custom_http_header_fields"},
        ), ())

    def test_sharkd_req_dumpconf_all(self, check_sharkd_session):
        check_sharkd_session((
            {"req": "dumpconf"},
        ), (
            {"prefs": MatchObject({"tcp.check_checksum": {"b": 0}})},
        ))

    def test_sharkd_req_download_tls_secrets(self, check_sharkd_session, capture_file):
        # XXX test download for eo: and rtp: too
        check_sharkd_session((
            {"req": "load", "file": capture_file('tls12-dsb.pcapng')},
            {"req": "download", "token": "ssl-secrets"},
        ), (
            {"err": 0},
            # TODO remove "RSA Session-ID:" support and support "CLIENT_RANDOM "... only
            {"file": "keylog.txt", "mime": "text/plain",
                "data": MatchRegExp(r'UlNBIFNlc3Npb24tSUQ6.+')},
        ))

    def test_sharkd_req_bye(self, check_sharkd_session):
        check_sharkd_session((
            {"req": "bye"},
        ), (
        ))

    def test_sharkd_bad_request(self, check_sharkd_session):
        check_sharkd_session((
            {"req": 1337},
        ), (
        ))

    def test_sharkd_config(self, check_sharkd_session):
        check_sharkd_session((
            {"req": "setconf", "name": "uat:custom_http_header_fields",
                "value": "\"X-Header-Name\", \"Description\""},
            {"req": "setconf", "name": "tcp.check_checksum", "value": "TRUE"},
            {"req": "dumpconf", "pref": "tcp.check_checksum"},
            {"req": "setconf", "name": "tcp.check_checksum", "value": "FALSE"},
            {"req": "dumpconf", "pref": "tcp.check_checksum"},
        ), (
            # Check that the UAT preference is set. There is no way to query it
            # (other than testing for side-effects in dissection).
            {"err": 0},
            {"err": 0},
            {"prefs": {"tcp.check_checksum": {"b": 1}}},
            {"err": 0},
            {"prefs": {"tcp.check_checksum": {"b": 0}}},
        ))

    def test_sharkd_config_enum(self, check_sharkd_session):
        '''Dump default enum preference value, change it and restore it.'''
        check_sharkd_session((
            {"req": "dumpconf", "pref": "wlan.ignore_wep"},
            {"req": "setconf", "name": "wlan.ignore_wep", "value": "Yes - with IV"},
            {"req": "dumpconf", "pref": "wlan.ignore_wep"},
            {"req": "setconf", "name": "wlan.ignore_wep", "value": "No"},
            {"req": "dumpconf", "pref": "wlan.ignore_wep"},
        ), (
            {"prefs": {"wlan.ignore_wep": {"e": [
                {"v": 0, "s": 1, "d": "No"},
                {"v": 1, "d": "Yes - without IV"},
                {"v": 2, "d": "Yes - with IV"}
            ]}}},
            {"err": 0},
            {"prefs": {"wlan.ignore_wep": {"e": [
                {"v": 0, "d": "No"},
                {"v": 1, "d": "Yes - without IV"},
                {"v": 2, "s": 1, "d": "Yes - with IV"}
            ]}}},
            {"err": 0},
            {"prefs": {"wlan.ignore_wep": {"e": [
                {"v": 0, "s": 1, "d": "No"},
                {"v": 1, "d": "Yes - without IV"},
                {"v": 2, "d": "Yes - with IV"}
            ]}}},
        ))

    def test_sharkd_nested_file(self, check_sharkd_session, capture_file):
        '''Request a frame from a file with a deep level of nesting.'''
        check_sharkd_session((
            {"req": "load", "file": capture_file("http2-data-reassembly.pcap")},
            {"req": "frame", "frame": "4", "proto": "yes"},
        ), (
            {"err": 0},
            MatchAny(),
        ))