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
import pytest
from matchers import *


@pytest.fixture(scope='session')
def cmd_sharkd(program):
    return program('sharkd')


@pytest.fixture
def run_sharkd_session(cmd_sharkd, base_env):
    def run_sharkd_session_real(sharkd_commands):
        sharkd_proc = subprocess.Popen(
            (cmd_sharkd, '-'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', env=base_env)
        sharkd_proc.stdin.write('\n'.join(sharkd_commands))
        stdout, stderr = sharkd_proc.communicate()

        assert 'Hello in child.' in stderr

        outputs = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                jdata = json.loads(line)
            except json.JSONDecodeError:
                pytest.fail('Invalid JSON: %r' % line)
            outputs.append(jdata)
        return tuple(outputs)
    return run_sharkd_session_real


@pytest.fixture
def check_sharkd_session(run_sharkd_session):
    def check_sharkd_session_real(sharkd_commands, expected_outputs):
        sharkd_commands = [json.dumps(x) for x in sharkd_commands]
        actual_outputs = run_sharkd_session(sharkd_commands)
        assert expected_outputs == actual_outputs
    return check_sharkd_session_real


class TestSharkd:
    def test_sharkd_req_load_bad_pcap(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('non-existant.pcap')}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"error":{"code":-2001,"message":"Unable to open the file"}},
        ))

    def test_sharkd_req_load_truncated_pcap(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('trunc.pcap')}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"Less data was read than was expected","err":-12}},
        ))

    def test_sharkd_req_status_no_pcap(self, check_sharkd_session):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"status"},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"frames":0,"duration":0.000000000,"columns":["No.","Time","Source","Destination","Protocol","Length","Info"],
                "column_info":[{
                    "title":"No.","format": "%m","visible":True, "resolved":True
                },{
                    "title": "Time", "format": "%t", "visible":True, "resolved":True
                },{
                    "title": "Source", "format": "%s", "visible":True, "resolved":True
                },{
                    "title": "Destination", "format": "%d", "visible":True, "resolved":True
                },{
                    "title": "Protocol", "format": "%p", "visible":True, "resolved":True
                },{
                    "title": "Length", "format": "%L", "visible":True, "resolved":True
                },{
                    "title": "Info", "format": "%i", "visible":True, "resolved":True
                }]
            }},
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
                "filename": "dhcp.pcap", "filesize": 1400,
                "columns":["No.","Time","Source","Destination","Protocol","Length","Info"],
                "column_info":[{
                    "title":"No.","format": "%m","visible":True, "resolved":True
                },{
                    "title": "Time", "format": "%t", "visible":True, "resolved":True
                },{
                    "title": "Source", "format": "%s", "visible":True, "resolved":True
                },{
                    "title": "Destination", "format": "%d", "visible":True, "resolved":True
                },{
                    "title": "Protocol", "format": "%p", "visible":True, "resolved":True
                },{
                    "title": "Length", "format": "%L", "visible":True, "resolved":True
                },{
                    "title": "Info", "format": "%i", "visible":True, "resolved":True
                }]
            }},
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
        matchNameDescriptionList = MatchList(
            {"name": MatchAny(str), "description": MatchAny(str)})
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
                "capture_types": matchNameDescriptionList,
                "encap_types": matchNameDescriptionList,
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

    def test_sharkd_req_frames_delta_times(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('logistics_multicast.pcapng')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"frames","params":{"filter":"frame.number==1||frame.number==800","column0":"frame.time_relative:1","column1":"frame.time_delta:1","column2":"frame.time_delta_displayed:1"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":
                [
                    {"c":["0.000000000","0.000000000","0.000000000"],"num":1,"bg":"feffd0","fg":"12272e"},
                    {"c":["191.872111000","0.193716000","191.872111000"],"num":800,"bg":"feffd0","fg":"12272e"},
                ],
            },
        ))

    def test_sharkd_req_frames_comments(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('comments.pcapng')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"frames","params":{"filter":"frame.number==3||frame.number==4||frame.number==5"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":
                [
                    {"c":["3","0.610021","::","ff02::1:ffdc:6277","ICMPv6","78","Neighbor Solicitation for fe80::c2c1:c0ff:fedc:6277"],"num":3,"ct":True,"comments":["hello hello"],"bg":"fce0ff","fg":"12272e"},
                    {"c":["4","0.760023","::","ff02::1:ffdc:6277","ICMPv6","78","Neighbor Solicitation for fec0::c2c1:c0ff:fedc:6277"],"num":4,"ct":True,"comments":["goodbye goodbye"],"bg":"fce0ff","fg":"12272e"},
                    {"c":["5","0.802338","10.0.0.1","224.0.0.251","MDNS","138","Standard query response 0x0000 A, cache flush 10.0.0.1 PTR, cache flush Cisco29401.local NSEC, cache flush Cisco29401.local"],"num":5,"bg":"daeeff","fg":"12272e"}
                ],
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
            {"jsonrpc":"2.0", "id":4, "method":"tap", "params":{"tap0": "conv:Ethernet", "filter": "garbage filter"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Mandatory parameter tap0 is missing"}},
            {"jsonrpc":"2.0","id":3,"error":{"code":-11012,"message":"sharkd_session_process_tap() garbage tap not recognized"}},
            {"jsonrpc":"2.0","id":4,"error":{"code":-11013,"message":"sharkd_session_process_tap() name=conv:Ethernet error=Filter \"garbage filter\" is invalid - \"filter\" was unexpected in this context."}},
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

    def test_sharkd_req_tap_rtp_streams(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('sip-rtp.pcapng')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"tap", "params":{"tap0": "rtp-streams"}},
            {"jsonrpc":"2.0", "id":2, "method":"tap", "params":{"tap0": "rtp-analyse:200.57.7.204_8000_200.57.7.196_40376_0xd2bd4e3e"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{
                "taps":[{
                    "tap":"rtp-streams",
                    "type":"rtp-streams",
                    "streams":[{
                        "ssrc":"0xd2bd4e3e",
                        "payload":"g711A",
                        "saddr":"200.57.7.204",
                        "sport":8000,
                        "daddr":"200.57.7.196",
                        "dport":40376,
                        "start_time":8.479371,
                        "duration": 24.124055,
                        "pkts":548,
                        "lost":0,
                        "lost_percent":0.0,
                        "max_delta":5843.742000,
                        "min_delta":0.159,
                        "mean_delta":44.102477,
                        "min_jitter":0.388213,
                        "max_jitter":7.406751,
                        "mean_jitter":2.517173,
                        "expectednr":548,
                        "totalnr":548,
                        "problem":False,
                        "ipver":4
                    }]
                }]
            }},
            {"jsonrpc":"2.0","id":2,"result":
                {"taps":[{
                    "tap":"rtp-analyse:200.57.7.204_8000_200.57.7.196_40376_0xd2bd4e3e",
                    "type":"rtp-analyse",
                    "ssrc":"0xd2bd4e3e",
                    "max_delta":5843.742000,
                    "max_delta_nr":168,
                    "max_jitter":7.406751,
                    "mean_jitter":2.517173,
                    "max_skew":319.289000,
                    "total_nr":548,
                    "seq_err":0,
                    "duration":24124.055000,
                    "items": MatchAny()
                }]
            }},
        ))

    def test_sharkd_req_tap_phs(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('protohier-with-comments.pcapng')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"tap", "params":{"tap0": "phs"}},
            {"jsonrpc":"2.0", "id":3, "method":"load",
             "params":{"file": capture_file('protohier-without-comments.pcapng')}
             },
            {"jsonrpc":"2.0", "id":4, "method":"tap", "params":{"tap0": "phs"}},
            {"jsonrpc":"2.0", "id":5, "method":"tap", "params":{"tap0": "phs", "filter": "ipv6"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{
                "taps":[{
                    "tap":"phs",
                    "type":"phs",
                    "filter":"",
                    "protos":[{
                        "proto":"eth",
                        "frames":115,
                        "bytes":22186,
                        "protos":[{
                            "proto":"ipv6",
                            "frames":39,
                            "bytes":7566,
                            "protos":[{
                                "proto":"icmpv6",
                                "frames":36,
                                "bytes":3684
                            },{
                                "proto":"udp",
                                "frames":3,
                                "bytes":3882,
                                "protos":[{
                                    "proto":"data",
                                    "frames":3,
                                    "bytes":3882
                                }]
                            }]
                        },{
                            "proto":"ip",
                            "frames":70,
                            "bytes":14260,
                            "protos":[{
                                "proto":"udp",
                                "frames":60,
                                "bytes":13658,
                                "protos":[{
                                    "proto":"mdns",
                                    "frames":1,
                                    "bytes":138
                                },{
                                    "proto":"ssdp",
                                    "frames":30,
                                    "bytes":8828
                                },{
                                    "proto":"nbns",
                                    "frames":20,
                                    "bytes":2200
                                },{
                                    "proto":"nbdgm",
                                    "frames":1,
                                    "bytes":248,
                                    "protos":[{
                                        "proto":"smb",
                                        "frames":1,
                                        "bytes":248,
                                        "protos":[{
                                            "proto":"mailslot",
                                            "frames":1,
                                            "bytes":248,
                                            "protos":[{
                                                "proto":"browser",
                                                "frames":1,
                                                "bytes":248
                                            }]
                                        }]
                                    }]
                                },{"proto":"dhcp",
                                   "frames":4,
                                   "bytes":1864
                                   },{
                                    "proto":"dns",
                                    "frames":4,
                                    "bytes":380
                                }]
                            },{
                                "proto":"igmp",
                                "frames":10,
                                "bytes":602
                            }]
                        },{
                            "proto":"arp",
                            "frames":6,
                            "bytes":360
                        }]
                    }]
                }]
            }},
            {"jsonrpc":"2.0","id":3,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":4,"result":{
                "taps":[{
                    "tap":"phs",
                    "type":"phs",
                    "filter":"",
                    "protos":[{
                        "proto":"eth",
                        "frames":115,
                        "bytes":22186,
                        "protos":[{
                            "proto":"ipv6",
                            "frames":39,
                            "bytes":7566,
                            "protos":[{
                                "proto":"icmpv6",
                                "frames":36,
                                "bytes":3684
                            },{
                                "proto":"udp",
                                "frames":3,
                                "bytes":3882,
                                "protos":[{
                                    "proto":"data",
                                    "frames":3,
                                    "bytes":3882
                                }]
                            }]
                        },{
                            "proto":"ip",
                            "frames":70,
                            "bytes":14260,
                            "protos":[{
                                "proto":"udp",
                                "frames":60,
                                "bytes":13658,
                                "protos":[{
                                    "proto":"mdns",
                                    "frames":1,
                                    "bytes":138
                                },{
                                    "proto":"ssdp",
                                    "frames":30,
                                    "bytes":8828
                                },{
                                    "proto":"nbns",
                                    "frames":20,
                                    "bytes":2200
                                },{
                                    "proto":"nbdgm",
                                    "frames":1,
                                    "bytes":248,
                                    "protos":[{
                                        "proto":"smb",
                                        "frames":1,
                                        "bytes":248,
                                        "protos":[{
                                            "proto":"mailslot",
                                            "frames":1,
                                            "bytes":248,
                                            "protos":[{
                                                "proto":"browser",
                                                "frames":1,
                                                "bytes":248
                                            }]
                                        }]
                                    }]
                                },{"proto":"dhcp",
                                   "frames":4,
                                   "bytes":1864
                                   },{
                                    "proto":"dns",
                                    "frames":4,
                                    "bytes":380
                                }]
                            },{
                                "proto":"igmp",
                                "frames":10,
                                "bytes":602
                            }]
                        },{
                            "proto":"arp",
                            "frames":6,
                            "bytes":360
                        }]
                    }]
                }]
            }},
            {"jsonrpc": "2.0", "id": 5, "result": {
                "taps": [{
                    "tap": "phs",
                    "type": "phs",
                    "filter": "ipv6",
                    "protos": [{
                        "bytes": 7566,
                        "frames": 39,
                        "proto": "eth",
                        "protos": [{
                            "bytes": 7566,
                            "frames": 39,
                            "proto": "ipv6",
                            "protos": [{
                                "bytes": 3684,
                                "frames": 36,
                                "proto": "icmpv6"
                            },{
                                "bytes": 3882,
                                "frames": 3,
                                "proto": "udp",
                                "protos": [{
                                    "bytes": 3882,
                                    "frames": 3,
                                    "proto": "data"
                                }]
                            }]
                        }]
                    }]
                }]
            }},
        ))

    def test_sharkd_req_tap_voip_calls(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('sip-rtp.pcapng')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"tap", "params":{"tap0": "voip-calls"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{
                "taps":[{
                    "tap":"voip-calls",
                    "type":"voip-calls",
                    "calls":[{
                        "call":0,
                        "start_time":0.000000,
                        "stop_time":8.524137,
                        "initial_speaker":"200.57.7.195",
                        "from":"<sip:200.57.7.195:55061;user=phone>",
                        "to":"\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>",
                        "protocol":"SIP",
                        "packets":5,
                        "state":"IN CALL",
                        "comment":"INVITE 200"
                    },{
                        "call":1,
                        "start_time":24.665953,
                        "stop_time":24.692752,
                        "initial_speaker":"200.57.7.195",
                        "from":"\"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>",
                        "to":"\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>",
                        "protocol":"SIP",
                        "packets":3,
                        "state":"CALL SETUP",
                        "comment":"INVITE"
                    }]
                }]
            }},
        ))

    def test_sharkd_req_tap_voip_convs(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('sip-rtp.pcapng')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"tap", "params":{"tap0": "voip-convs:"}},
            {"jsonrpc":"2.0", "id":3, "method":"tap", "params":{"tap0": "voip-convs:0"}},
            {"jsonrpc":"2.0", "id":4, "method":"tap", "params":{"tap0": "voip-convs:0-1"}},
            {"jsonrpc":"2.0", "id":5, "method":"tap", "params":{"tap0": "voip-convs:garbage"}},
            {"jsonrpc":"2.0", "id":6, "method":"tap", "params":{"tap0": "voip-convs:999"}},
            {"jsonrpc":"2.0", "id":7, "method":"tap", "params":{"tap0": "voip-convs:0,999,0-1,999-999,1,1"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{
                "taps":[{
                    "tap":"voip-convs:",
                    "type":"voip-convs",
                    "convs":[{
                        "frame":1,
                        "call":0,
                        "time":"0.000000",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,
                        "label":"INVITE SDP (g711A g729 g723 g711U)",
                        "comment":"SIP INVITE From: <sip:200.57.7.195:55061;user=phone> To:\"francisco@bestel.com\" <sip:francisco@bestel.com:55060> Call-ID:12013223@200.57.7.195 CSeq:1"
                    },{
                        "frame":2,
                        "call":0,
                        "time":"0.007889",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"100 Trying",
                        "comment":"SIP Status 100 Trying"
                    },{
                        "frame":3,
                        "call":0,
                        "time":"0.047524",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"180 Ringing",
                        "comment":"SIP Status 180 Ringing"
                    },{
                        "frame":6,
                        "call":0,
                        "time":"8.477925",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"200 Ok SDP (g711A g711U GSM iLBC speex telephone-event)",
                        "comment":"SIP Status 200 Ok"
                    },{
                        "frame":7,
                        "call":0,
                        "time":"8.479371",
                        "dst_addr":"200.57.7.196",
                        "dst_port":40376,
                        "src_addr":"200.57.7.204",
                        "src_port":8000,
                        "label":"RTP (g711A) ",
                        "comment":"RTP, 548 packets. Duration: 24.12s SSRC: 0xD2BD4E3E"
                    },{
                        "frame":10,
                        "call":0,
                        "time":"8.524137",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,
                        "label":"ACK",
                        "comment":"SIP Request INVITE ACK 200 CSeq:1"
                    },{
                        "frame":352,
                        "call":1,
                        "time":"24.665953",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,
                        "label":"INVITE SDP (g711A g729 g723)",
                        "comment":"SIP INVITE From: \"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone> To:\"francisco@bestel.com\" <sip:francisco@bestel.com:55060> Call-ID:12015624@200.57.7.195 CSeq:1"
                    },{
                        "frame":353,
                        "call":1,
                        "time":"24.674680",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"100 Trying",
                        "comment":"SIP Status 100 Trying"
                    },{
                        "frame":354,
                        "call":1,
                        "time":"24.692752",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"180 Ringing",
                        "comment":"SIP Status 180 Ringing"
                    }]
                }]
            }},
            {"jsonrpc":"2.0","id":3,"result":{
                "taps":[{
                    "tap":"voip-convs:0",
                    "type":"voip-convs",
                    "convs":[{
                        "frame":1,
                        "call":0,
                        "time":"0.000000",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,
                        "label":"INVITE SDP (g711A g729 g723 g711U)",
                        "comment":"SIP INVITE From: <sip:200.57.7.195:55061;user=phone> To:\"francisco@bestel.com\" <sip:francisco@bestel.com:55060> Call-ID:12013223@200.57.7.195 CSeq:1"
                    },{
                        "frame":2,
                        "call":0,
                        "time":"0.007889",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"100 Trying",
                        "comment":"SIP Status 100 Trying"
                    },{
                        "frame":3,
                        "call":0,
                        "time":"0.047524",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"180 Ringing",
                        "comment":"SIP Status 180 Ringing"
                    },{
                        "frame":6,
                        "call":0,
                        "time":"8.477925",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"200 Ok SDP (g711A g711U GSM iLBC speex telephone-event)",
                        "comment":"SIP Status 200 Ok"
                    },{
                        "frame":7,
                        "call":0,
                        "time":"8.479371",
                        "dst_addr":"200.57.7.196",
                        "dst_port":40376,
                        "src_addr":"200.57.7.204",
                        "src_port":8000,
                        "label":"RTP (g711A) ",
                        "comment":"RTP, 548 packets. Duration: 24.12s SSRC: 0xD2BD4E3E"
                    },{
                        "frame":10,
                        "call":0,
                        "time":"8.524137",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,"label":"ACK","comment":"SIP Request INVITE ACK 200 CSeq:1"
                    }]
                }]
            }},
            {"jsonrpc":"2.0","id":4,"result":{
                "taps":[{
                    "tap":"voip-convs:0-1",
                    "type":"voip-convs",
                    "convs":[{
                        "frame":1,
                        "call":0,
                        "time":"0.000000",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,
                        "label":"INVITE SDP (g711A g729 g723 g711U)",
                        "comment":"SIP INVITE From: <sip:200.57.7.195:55061;user=phone> To:\"francisco@bestel.com\" <sip:francisco@bestel.com:55060> Call-ID:12013223@200.57.7.195 CSeq:1"
                    },{
                        "frame":2,
                        "call":0,
                        "time":"0.007889",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"100 Trying",
                        "comment":"SIP Status 100 Trying"
                    },{
                        "frame":3,
                        "call":0,
                        "time":"0.047524",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"180 Ringing",
                        "comment":"SIP Status 180 Ringing"
                    },{
                        "frame":6,
                        "call":0,
                        "time":"8.477925",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"200 Ok SDP (g711A g711U GSM iLBC speex telephone-event)",
                        "comment":"SIP Status 200 Ok"
                    },{
                        "frame":7,
                        "call":0,
                        "time":"8.479371",
                        "dst_addr":"200.57.7.196",
                        "dst_port":40376,
                        "src_addr":"200.57.7.204",
                        "src_port":8000,
                        "label":"RTP (g711A) ",
                        "comment":"RTP, 548 packets. Duration: 24.12s SSRC: 0xD2BD4E3E"
                    },{
                        "frame":10,
                        "call":0,
                        "time":"8.524137",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,
                        "label":"ACK",
                        "comment":"SIP Request INVITE ACK 200 CSeq:1"
                    },{
                        "frame":352,
                        "call":1,
                        "time":"24.665953",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,
                        "label":"INVITE SDP (g711A g729 g723)",
                        "comment":"SIP INVITE From: \"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone> To:\"francisco@bestel.com\" <sip:francisco@bestel.com:55060> Call-ID:12015624@200.57.7.195 CSeq:1"
                    },{
                        "frame":353,
                        "call":1,
                        "time":"24.674680",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"100 Trying",
                        "comment":"SIP Status 100 Trying"
                    },{
                        "frame":354,
                        "call":1,
                        "time":"24.692752",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"180 Ringing",
                        "comment":"SIP Status 180 Ringing"
                    }]
                }]
            }},
            {"jsonrpc":"2.0","id":5,"error":{
                "code":-11014,"message":"sharkd_session_process_tap() voip-convs=voip-convs:garbage invalid 'convs' parameter"
            }},
            {"jsonrpc":"2.0","id":6,"result":{
                "taps":[{
                    "tap":"voip-convs:999",
                    "type":"voip-convs",
                    "convs":[]
                }]
            }},
            {"jsonrpc":"2.0","id":7,"result":{
                "taps":[{
                    "tap":"voip-convs:0,999,0-1,999-999,1,1",
                    "type":"voip-convs",
                    "convs":[{
                        "frame":1,
                        "call":0,
                        "time":"0.000000",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,
                        "label":"INVITE SDP (g711A g729 g723 g711U)",
                        "comment":"SIP INVITE From: <sip:200.57.7.195:55061;user=phone> To:\"francisco@bestel.com\" <sip:francisco@bestel.com:55060> Call-ID:12013223@200.57.7.195 CSeq:1"
                    },{
                        "frame":2,
                        "call":0,
                        "time":"0.007889",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"100 Trying",
                        "comment":"SIP Status 100 Trying"
                    },{
                        "frame":3,
                        "call":0,
                        "time":"0.047524",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"180 Ringing",
                        "comment":"SIP Status 180 Ringing"
                    },{
                        "frame":6,
                        "call":0,
                        "time":"8.477925",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"200 Ok SDP (g711A g711U GSM iLBC speex telephone-event)",
                        "comment":"SIP Status 200 Ok"
                    },{
                        "frame":7,
                        "call":0,
                        "time":"8.479371",
                        "dst_addr":"200.57.7.196",
                        "dst_port":40376,
                        "src_addr":"200.57.7.204",
                        "src_port":8000,
                        "label":"RTP (g711A) ",
                        "comment":"RTP, 548 packets. Duration: 24.12s SSRC: 0xD2BD4E3E"
                    },{
                        "frame":10,
                        "call":0,
                        "time":"8.524137",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,
                        "label":"ACK",
                        "comment":"SIP Request INVITE ACK 200 CSeq:1"
                    },{
                        "frame":352,
                        "call":1,
                        "time":"24.665953",
                        "dst_addr":"200.57.7.204",
                        "dst_port":5061,
                        "src_addr":"200.57.7.195",
                        "src_port":5060,
                        "label":"INVITE SDP (g711A g729 g723)",
                        "comment":"SIP INVITE From: \"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone> To:\"francisco@bestel.com\" <sip:francisco@bestel.com:55060> Call-ID:12015624@200.57.7.195 CSeq:1"
                    },{
                        "frame":353,
                        "call":1,
                        "time":"24.674680",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"100 Trying",
                        "comment":"SIP Status 100 Trying"
                    },{
                        "frame":354,
                        "call":1,
                        "time":"24.692752",
                        "dst_addr":"200.57.7.195",
                        "dst_port":5060,
                        "src_addr":"200.57.7.204",
                        "src_port":5061,
                        "label":"180 Ringing",
                        "comment":"SIP Status 180 Ringing"
                    }]
                }]
            }},
        ))

    def test_sharkd_req_tap_hosts(self, check_sharkd_session, capture_file):
        matchAddrNameList = MatchList(
            {"name": MatchAny(str), "addr": MatchAny(str)})
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('dns-mdns.pcap')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"tap", "params":{"tap0": "hosts:"}},
            {"jsonrpc":"2.0", "id":3, "method":"tap", "params":{"tap0": "hosts:ip"}},
            {"jsonrpc":"2.0", "id":4, "method":"tap", "params":{"tap0": "hosts:ipv4"}},
            {"jsonrpc":"2.0", "id":5, "method":"tap", "params":{"tap0": "hosts:ipv6"}},
            {"jsonrpc":"2.0", "id":6, "method":"tap", "params":{"tap0": "hosts:invalid"}},
            {"jsonrpc":"2.0", "id":7, "method":"tap", "params":{"tap0": "hosts:ipv4,ipv6"}},
            {"jsonrpc":"2.0", "id":8, "method":"tap", "params":{"tap0": "hosts:ipv4,ipv6,invalid"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{
                "taps":[{
                    "tap":"hosts:",
                    "type":"hosts",
                    "ipv4_hosts":matchAddrNameList,
                    "ipv6_hosts":matchAddrNameList,
                }]
            }},
            {"jsonrpc":"2.0","id":3,"result":{
                "taps":[{
                    "tap":"hosts:ip",
                    "type":"hosts",
                    "ipv4_hosts":matchAddrNameList,
                }]
            }},
            {"jsonrpc":"2.0","id":4,"result":{
                "taps":[{
                    "tap":"hosts:ipv4",
                    "type":"hosts",
                    "ipv4_hosts":matchAddrNameList,
                }]
            }},
            {"jsonrpc":"2.0","id":5,"result":{
                "taps":[{
                    "tap":"hosts:ipv6",
                    "type":"hosts",
                    "ipv6_hosts":matchAddrNameList,
                }]
            }},
            {"jsonrpc":"2.0","id":6,"error":{"code":-11015,"message":"sharkd_session_process_tap() hosts=hosts:invalid invalid 'protos' parameter"}},
            {"jsonrpc":"2.0","id":7,"result":{
                "taps":[{
                    "tap":"hosts:ipv4,ipv6",
                    "type":"hosts",
                    "ipv4_hosts":matchAddrNameList,
                    "ipv6_hosts":matchAddrNameList,
                }]
            }},
            {"jsonrpc":"2.0","id":8,"error":{"code":-11015,"message":"sharkd_session_process_tap() hosts=hosts:ipv4,ipv6,invalid invalid 'protos' parameter"}},
        ))

    def test_sharkd_req_tap_eo_http(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('http-ooo.pcap')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"tap", "params":{"tap0": "eo:http"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{
                "taps":[{
                    "tap":"eo:http",
                    "type":"eo",
                    "proto":"HTTP",
                    "objects":[{
                        "pkt":11,
                        "filename":"4",
                        "_download":"eo:http_0",
                        "len":5,
                        "sha1":"4a4121ecd766ed16943a0c7b54c18f743e90c3f6"
                    },{
                        "pkt":13,
                        "_download":"eo:http_1",
                        "len":5,
                        "sha1":"29a51e7382d06ff40467272f02e413ca7b51636e"
                    },{
                        "pkt":14,
                        "_download":"eo:http_2",
                        "len":5,
                        "sha1":"f6d0c643351580307b2eaa6a7560e76965496bc7"}]
                }]
            }}
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
            {"jsonrpc":"2.0", "id":5, "method":"follow",
             "params":{"follow": "HTTP", "filter": "http", "sub_stream": "garbage sub_stream"}
             },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Mandatory parameter follow is missing"}},
            {"jsonrpc":"2.0","id":3,"error":{"code":-12001,"message":"sharkd_session_process_follow() follower=garbage follow not found"}},
            {"jsonrpc":"2.0","id":4,
            "error":{"code":-12002,"message":"sharkd_session_process_follow() name=HTTP error=Filter \"garbage filter\" is invalid - \"filter\" was unexpected in this context."}
            },
            {"jsonrpc":"2.0","id":5,
             "error":{"code":-32600,"message":"The data type for member sub_stream is not valid"}
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

    def test_sharkd_req_follow_http2(self, check_sharkd_session, capture_file, features):
        # If we don't have nghttp2, we output the compressed headers.
        # We could test against the expected output in that case, but
        # just skip for now.
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')

        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('quic-with-secrets.pcapng')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"follow",
             "params":{"follow": "HTTP2", "filter": "tcp.stream eq 0 and http2.streamid eq 1", "sub_stream": 1}
             },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,
             "result":{
                 "shost": "2606:4700:10::6816:826", "sport": "443", "sbytes": 656,
                 "chost": "2001:db8:1::1", "cport": "57098", "cbytes": 109643,
                 "payloads": [
                     {"n": 12, "d": MatchRegExp(r'^.*VuLVVTLGVuO3E9MC45Cgo.*$')},
                     {"n": 19, "s": 1, "d": MatchRegExp(r'^.*7IG1hPTg2NDAwCgo.*$')},
                     {"n": 44, "s": 1, "d": MatchRegExp(r'^.*Pgo8L2h0bWw.*$')},
                 ]}
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
            {"jsonrpc":"2.0", "id":4, "method":"iograph",
             "params":{"graph0": "max:udp.length", "filter0": "udp.length", "interval": 0}},
            {"jsonrpc":"2.0", "id":5, "method":"iograph",
             "params":{"graph0": "max:udp.length", "filter0": "udp.length", "interval_units": "garbage units"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Mandatory parameter graph0 is missing"}},
            {"jsonrpc":"2.0","id":3,"result":{"iograph": []}},
            {"jsonrpc":"2.0","id":4,"error":{"code":-32600,"message":"The value for interval must be a positive integer"}},
            {"jsonrpc":"2.0","id":5,"error":{"code":-7003,"message":"Invalid interval_units parameter: 'garbage units', must be 's', 'ms' or 'us'"}},
        ))

    def test_sharkd_req_iograph_basic(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('dhcp.pcap')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"iograph",
            "params":{"graph0": "max:udp.length", "filter0": "udp.length"}
            },
            {"jsonrpc":"2.0", "id":3, "method":"iograph",
            "params":{"graph0": "packets", "graph1": "bytes"}
            },
            {"jsonrpc":"2.0", "id":4, "method":"iograph",
            "params":{"graph0": "packets", "filter0": "garbage filter"}
            },
            {"jsonrpc":"2.0", "id":5, "method":"iograph",
             "params":{"graph0": "packets", "graph1": "bytes", "interval": 1, "interval_units": "us"}
             },
            {"jsonrpc":"2.0", "id":6, "method":"iograph",
             "params":{"graph0": "packets", "graph1": "bytes", "interval": 1, "interval_units": "ms"}
             },
            {"jsonrpc":"2.0", "id":7, "method":"iograph",
             "params":{"graph0": "packets", "graph1": "bytes", "interval": 1, "interval_units": "s"}
             },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{"iograph": [{"items": [308.000000]}]}},
            {"jsonrpc":"2.0","id":3,"result":{"iograph": [{"items": [4.000000]}, {"items": [1312.000000]}]}},
            {"jsonrpc":"2.0","id":4,"error":{"code":-6001,"message":"Filter \"garbage filter\" is invalid - \"filter\" was unexpected in this context."}},
            {"jsonrpc":"2.0","id":5,"result":{"iograph": [
                {"items": [1.0, '127', 1.0, '1118f', 1.0, '112c9', 1.0]},
                {"items": [314.0, '127', 342.0, '1118f', 314.0, '112c9', 342.0]},
            ]}},
            {"jsonrpc":"2.0","id":6,"result":{"iograph": [
                {"items": [2.0, '46', 2.0]},
                {"items": [656.0, '46', 656.0]},
            ]}},
            {"jsonrpc":"2.0","id":7,"result":{"iograph": [
                {"items": [4.0]},
                {"items": [1312.0]},
            ]}},
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
            {"jsonrpc":"2.0","id":2,"result":{
                "fol": [["UDP", "udp.stream eq 1"]],
                "followers": [{"protocol": "UDP","filter": "udp.stream eq 1","stream": 1}]
            }},
        ))

    def test_sharkd_req_frame_http2(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('quic-with-secrets.pcapng')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"frame",
             "params":{"frame": 12}
             },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{
                "fol": [["HTTP2", "tcp.stream eq 0 and http2.streamid eq 1"],["TCP","tcp.stream eq 0"],["TLS","tcp.stream eq 0"]],
                "followers": [
                    {"protocol": "HTTP2","filter": "tcp.stream eq 0 and http2.streamid eq 1","stream": 0, "sub_stream": 1},
                    {"protocol": "TCP","filter": "tcp.stream eq 0","stream": 0},
                    {"protocol": "TLS","filter": "tcp.stream eq 0","stream": 0},
                ]
            }},
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
                    "fn": "dhcp",
                    "e": MatchAny(int),
                    "n": MatchList({
                        "l": "Padding: 0000000000000000000000000000000000000000000000000000",
                        "h": [316, 26],
                        "f": "dhcp.option.padding == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
                        "fn": "dhcp.option.padding"
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
            {"jsonrpc":"2.0","id":4,"result":{"comment":["foo\nbar"],"fol": MatchAny(list), "followers": MatchAny(list)}},
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
        # XXX test download for eo: too
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('tls12-dsb.pcapng')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"download",
            "params":{"token": "ssl-secrets"}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{"file": "keylog.txt", "mime": "text/plain",
                "data": MatchRegExp(r'Q0xJRU5UX1JBTkRPTSBm.+')}
            },
        ))

    def test_sharkd_req_download_rtp_stream(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('sip-rtp.pcapng')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"download",
            "params":{"token": "rtp:200.57.7.204_8000_200.57.7.196_40376_0xd2bd4e3e"}},
            {"jsonrpc":"2.0", "id":3, "method":"download",
            "params":{"token": "rtp:1.1.1.1_8000_1.1.1.2_9000_0xdddddddd"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{
                "file":"rtp:200.57.7.204_8000_200.57.7.196_40376_0xd2bd4e3e",
                "mime":"audio/x-wav",
                "data":MatchRegExp(r'UklGRv.+')}
            },
            {"jsonrpc":"2.0","id":3,"error":{"code":-10003,"message":"no rtp data available"}},
        ))

    def test_sharkd_req_download_bad_tokens(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
            "params":{"file": capture_file('tls12-dsb.pcapng')}
            },
            {"jsonrpc":"2.0", "id":2, "method":"download",
            "params":{"token": "BOGUSTOKEN"}
            },
            {"jsonrpc":"2.0", "id":3, "method":"download",
            "params":{}
            },
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"error":{"code":-10004,"message":"unrecognized token"}},
            {"jsonrpc":"2.0","id":3,"error":{"code":-10005,"message":"missing token"}},
        ))

    def test_sharkd_req_download_eo_http_with_prior_tap_eo_http(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('http-ooo.pcap')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"tap", "params":{"tap0": "eo:http"}},
            {"jsonrpc":"2.0", "id":3, "method":"download",
             "params":{"token": "eo:http_0"}},
            {"jsonrpc":"2.0", "id":4, "method":"download",
             "params":{"token": "eo:http_1"}},
            {"jsonrpc":"2.0", "id":5, "method":"download",
             "params":{"token": "eo:http_2"}},
            {"jsonrpc":"2.0", "id":6, "method":"download",
             "params":{"token": "eo:http_999"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{
                "taps":[{
                    "tap":"eo:http",
                    "type":"eo",
                    "proto":"HTTP",
                    "objects":[{
                        "pkt":11,
                        "filename":"4",
                        "_download":"eo:http_0",
                        "len":5,
                        "sha1":"4a4121ecd766ed16943a0c7b54c18f743e90c3f6"
                    },{
                        "pkt":13,
                        "_download":"eo:http_1",
                        "len":5,
                        "sha1":"29a51e7382d06ff40467272f02e413ca7b51636e"
                    },{
                        "pkt":14,
                        "_download":"eo:http_2",
                        "len":5,
                        "sha1":"f6d0c643351580307b2eaa6a7560e76965496bc7"}]
                }]
            }},
            {"jsonrpc":"2.0","id":3,"result":{
                "file":"4","mime":"application/octet-stream","data":"Zm91cgo="}},
            {"jsonrpc":"2.0","id":4,"result":{
                "file":"eo:http_1","mime":"application/octet-stream","data":"QVRBDQo="}},
            {"jsonrpc":"2.0","id":5,"result":{
                "file":"eo:http_2","mime":"application/octet-stream","data":"MA0KDQo="}},
            {"jsonrpc":"2.0","id":6,"result":{}},
        ))
    def test_sharkd_req_download_eo_http_without_prior_tap_eo_http(self, check_sharkd_session, capture_file):
        check_sharkd_session((
            {"jsonrpc":"2.0", "id":1, "method":"load",
             "params":{"file": capture_file('http-ooo.pcap')}
             },
            {"jsonrpc":"2.0", "id":2, "method":"download",
             "params":{"token": "eo:http_0"}},
            {"jsonrpc":"2.0", "id":3, "method":"download",
             "params":{"token": "eo:http_1"}},
            {"jsonrpc":"2.0", "id":4, "method":"download",
             "params":{"token": "eo:http_2"}},
            {"jsonrpc":"2.0", "id":5, "method":"download",
             "params":{"token": "eo:http_999"}},
        ), (
            {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},
            {"jsonrpc":"2.0","id":2,"result":{
                "file":"4","mime":"application/octet-stream","data":"Zm91cgo="}},
            {"jsonrpc":"2.0","id":3,"result":{
                "file":"eo:http_1","mime":"application/octet-stream","data":"QVRBDQo="}},
            {"jsonrpc":"2.0","id":4,"result":{
                "file":"eo:http_2","mime":"application/octet-stream","data":"MA0KDQo="}},
            {"jsonrpc":"2.0","id":5,"result":{}},
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
