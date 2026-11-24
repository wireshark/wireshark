#!/usr/bin/env python3
# A2A coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Valid and nearly valid A2A (agent-to-agent) messages over HTTP/JSON, one TCP
connection each: every message type and field, numeric enums, camelCase and
snake_case names, and malformed variants that exercise the structure warnings.

Usage: mka2a.py [<output directory>]

Writes a2a_coverage.pcap and a2a-coverage-malformed.pcap (odd JSON). Every packet is built here; nothing comes from a
real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import json

from capgen import eth, ipv4, tcp, write_pcap  # noqa: E402

CLI, SRV = '192.0.2.1', '192.0.2.2'
C_MAC, S_MAC = '02:00:00:00:00:01', '02:00:00:00:00:02'
SYN_OPTIONS = bytes.fromhex('020405b401030307')  # MSS, NOP, window scale


def tcp_pkt(src, dst, sport, dport, seq, ack, flags, payload=b''):
    seg = tcp(payload, sport, dport, seq=seq, ack=ack, flags=flags,
              options=SYN_OPTIONS if flags & 0x02 else b'', src=src, dst=dst)
    ip = ipv4(seg, 6, src=src, dst=dst, ident=0, flags_frag=0x4000)
    # The MAC addresses are the same in both directions: the capture was
    # built this way and is kept byte for byte.
    if src == SRV:
        return eth(ip, 0x0800, dst=S_MAC, src=C_MAC)
    return eth(ip, 0x0800, dst=C_MAC, src=S_MAC)


class Cap:
    def __init__(self):
        self.pkts = []
        self.port = 40000

    def exchange(self, body, response=False, path='/message:send', ctype='application/json'):
        """One TCP connection: handshake, then the body as an HTTP request
        (or, with response=True, a request without body followed by a 200 response)."""
        if isinstance(body, str):
            body = body.encode()
        self.port += 1
        sp = self.port
        c, s = 1000, 5000
        self.pkts.append(tcp_pkt(CLI, SRV, sp, 80, c, 0, 0x02))
        self.pkts.append(tcp_pkt(SRV, CLI, 80, sp, s, c + 1, 0x12))
        c += 1
        s += 1
        if response:
            req = b'GET %s HTTP/1.1\r\nHost: agent.example\r\n\r\n' % path.encode()
            self.pkts.append(tcp_pkt(CLI, SRV, sp, 80, c, s, 0x18, req))
            c += len(req)
            resp = (b'HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n'
                    % (ctype.encode(), len(body))) + body
            self.pkts.append(tcp_pkt(SRV, CLI, 80, sp, s, c, 0x18, resp))
        else:
            req = (b'POST %s HTTP/1.1\r\nHost: agent.example\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n'
                   % (path.encode(), ctype.encode(), len(body))) + body
            self.pkts.append(tcp_pkt(CLI, SRV, sp, 80, c, s, 0x18, req))


def J(o):
    return json.dumps(o, separators=(',', ':'))


USER = {"messageId": "m-1", "role": "ROLE_USER", "parts": [{"text": "hello"}]}
TASK_WORKING = {"id": "t-1", "contextId": "c-1", "status": {"state": "TASK_STATE_WORKING"}}
ART = {"artifactId": "a-1", "name": "result", "description": "the result",
       "parts": [{"text": "42"}], "extensions": ["urn:x"], "metadata": {"k": 1}}
PUSH = {"id": "p-1", "taskId": "t-1", "url": "https://hook.example/n", "token": "tok",
        "tenant": "acme", "authentication": {"scheme": "Bearer", "credentials": "c"}}


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = Cap()
    # 1: SendMessageRequest with every Part kind, configuration, push config, camelCase
    m.exchange(J({"message": {
        "messageId": "m-1", "contextId": "c-1", "taskId": "t-1", "role": "ROLE_USER",
        "parts": [{"text": "hello", "mediaType": "text/plain", "metadata": {"a": 1}},
                  {"raw": "aGVsbG8=", "filename": "h.bin", "media_type": "application/octet-stream"},
                  {"url": "https://files.example/x.png", "filename": "x.png"},
                  {"data": {"k": [1, 2]}},
                  "not an object"],
        "extensions": ["urn:ext:1", "urn:ext:2", 7],
        "referenceTaskIds": ["t-0", "t-00"], "metadata": {"src": "test"}},
        "configuration": {"acceptedOutputModes": ["text/plain", "application/json"],
                          "returnImmediately": True, "historyLength": 5,
                          "taskPushNotificationConfig": PUSH},
        "tenant": "acme", "metadata": {"trace": "abc"}}))
    # 2: the same in snake_case, number formats of the enums, false boolean, history length as string
    m.exchange(J({"message": {
        "message_id": "m-2", "context_id": "c-1", "task_id": "t-1", "role": 1,
        "parts": [{"text": "snake"}], "reference_task_ids": ["t-9"]},
        "configuration": {"accepted_output_modes": ["text/plain"], "return_immediately": False,
                          "history_length": "10",
                          "task_push_notification_config": {"task_id": "t-1", "url": "u"}}}))
    # 3: an agent message as a request body is a SendMessageResponse; number role 2
    m.exchange(J({"message": {"messageId": "m-3", "role": 2, "parts": [{"text": "reply"}]}}), response=True)
    # 4: SendMessageResponse with a Task: artifacts, history, status message and timestamp
    m.exchange(J({"task": {
        "id": "t-1", "contextId": "c-1",
        "status": {"state": "TASK_STATE_COMPLETED", "timestamp": "2026-11-13T11:55:17.435289Z",
                   "message": {"messageId": "m-4", "role": "ROLE_AGENT", "parts": [{"text": "done"}]}},
        "artifacts": [ART, {"artifact_id": "a-2", "parts": []}, "junk"],
        "history": [USER, {"messageId": "m-5", "role": "ROLE_AGENT", "parts": [{"text": "r"}]}, 3],
        "metadata": {"m": True}}}), response=True)
    # 5: bare Task (GetTask), numeric state
    m.exchange(J({"id": "t-2", "context_id": "c-2", "status": {"state": 2}}), response=True, path='/tasks/t-2')
    # 6: ListTasksResponse with tasks
    m.exchange(J({"tasks": [TASK_WORKING, {"id": "t-3", "status": {"state": "TASK_STATE_FAILED"}}],
                  "totalSize": 2, "pageSize": 50, "nextPageToken": "next"}), response=True, path='/tasks')
    # 7: empty ListTasksResponse identified by its pagination fields
    m.exchange(J({"tasks": [], "total_size": 0, "page_size": 50}), response=True, path='/tasks')
    # 8: StreamResponse with a status update, as one SSE-less JSON body; with an artifact update
    m.exchange(J({"statusUpdate": {"taskId": "t-1", "contextId": "c-1",
                                   "status": {"state": "TASK_STATE_WORKING"}}}),
               response=True, path='/message:stream')
    m.exchange(J({"artifact_update": {"task_id": "t-1", "context_id": "c-1", "artifact": ART,
                                      "append": True, "last_chunk": False}}),
               response=True, path='/message:stream')
    # 10: both updates; a stream response carrying a message, a task and a config next to the update
    m.exchange(J({"status_update": {"task_id": "t-1", "context_id": "c-1",
                                    "status": {"state": "TASK_STATE_COMPLETED"}},
                  "artifactUpdate": {"taskId": "t-1", "contextId": "c-1", "artifact": ART,
                                     "append": False, "lastChunk": True},
                  "message": USER, "task": TASK_WORKING, "metadata": {"s": 1}}),
               response=True, path='/message:stream')
    # 11: a status update whose artifact_update is malformed: no artifact object
    m.exchange(J({"statusUpdate": {"taskId": "t-1", "contextId": "c-1",
                                   "status": {"state": 3}},
                  "artifactUpdate": {"taskId": "t-1"}}), response=True, path='/message:stream')
    # 12: TaskStatusUpdateEvent on its own, with metadata
    m.exchange(J({"taskId": "t-1", "contextId": "c-1",
                  "status": {"state": "TASK_STATE_INPUT_REQUIRED", "timestamp": "2026-11-13T12:00:00+01:00"},
                  "metadata": {"final": False}}), path='/events')
    # 13: TaskArtifactUpdateEvent on its own (artifact without parts)
    m.exchange(J({"task_id": "t-1", "context_id": "c-1",
                  "artifact": {"artifactId": "a-3", "name": "n"}, "append": False,
                  "lastChunk": True, "metadata": {"final": True}}), path='/events')
    # 14: bare Message
    m.exchange(J({"messageId": "m-6", "role": "ROLE_AGENT", "parts": [{"text": "x"}], "extensions": []}),
               response=True, path='/messages/m-6')
    # 15: bare Message without parts
    m.exchange(J({"message_id": "m-7", "role": "ROLE_USER"}), path='/messages')
    # 16: AgentCard with everything
    m.exchange(J({
        "name": "Echo Agent", "description": "echoes", "version": "1.0.0",
        "provider": {"organization": "Example Org", "url": "https://example.org"},
        "capabilities": {"streaming": True, "pushNotifications": False, "extendedAgentCard": True,
                         "extensions": [{"uri": "urn:ext:1", "required": True}, 5,
                                        {"uri": "urn:ext:2", "required": False}]},
        "supportedInterfaces": [{"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0",
                                 "url": "http://agent.example/", "tenant": "acme"},
                                {"protocol_binding": "JSONRPC", "protocol_version": "1.0", "url": "x"}],
        "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [{"id": "echo", "name": "Echo", "description": "echo back",
                    "tags": ["echo", "test"], "examples": ["say hi"],
                    "inputModes": ["text/plain"], "outputModes": ["text/plain"]},
                   {"id": "s2", "name": "S2", "description": "d",
                    "input_modes": ["a/b"], "output_modes": ["c/d"]}],
        "signatures": [{"signature": "c2ln", "protected": "x"}, {"signature": "c2lnMg"}]}),
        response=True, path='/.well-known/agent-card.json')
    # 17: minimal AgentCard: snake_case collections, no capabilities
    m.exchange(J({"name": "N", "description": "D", "version": "2",
                  "supported_interfaces": [], "default_input_modes": [], "default_output_modes": []}),
               response=True, path='/.well-known/agent-card.json')
    # 18: TaskPushNotificationConfig, by task id; 19 by its authentication scheme only
    m.exchange(J(PUSH), path='/tasks/t-1/pushNotificationConfigs')
    m.exchange(J({"url": "https://hook.example/2", "authentication": {"scheme": "Basic"}}),
               path='/tasks/t-1/pushNotificationConfigs')
    # 20: ListTaskPushNotificationConfigsResponse, 21: empty with a next page token
    m.exchange(J({"configs": [PUSH, {"id": "p-2", "task_id": "t-1", "url": "u2"}, 5],
                  "nextPageToken": "n"}), response=True, path='/tasks/t-1/pushNotificationConfigs')
    m.exchange(J({"configs": [], "next_page_token": ""}), response=True,
               path='/tasks/t-1/pushNotificationConfigs')
    # 22: JSON that is not A2A: a health body, an array, an empty configs list, a task
    # without a status, a message with a wrong parts type, an agent card with one collection
    m.exchange(J({"status": "ok"}), response=True, path='/health')
    m.exchange('[1,2,3]', response=True, path='/health')
    m.exchange(J({"configs": []}), response=True, path='/tasks/t-1/pushNotificationConfigs')
    m.exchange(J({"id": "t", "status": {"state": "NOT_A_STATE"}}), response=True)
    m.exchange(J({"messageId": "m", "role": "ROLE_USER", "parts": "x"}), response=True)
    m.exchange(J({"name": "N", "description": "D", "version": "1", "skills": []}), response=True)
    m.exchange(J({"id": "t", "status": {"state": 99}}), response=True)
    # frames after the clean part: the structure warnings
    # unknown enum names and numbers, a bad timestamp
    m.exchange(J({"task": {"id": "t-9", "status": {
        "state": "TASK_STATE_WORKING", "timestamp": "yesterday",
        "message": {"messageId": "m", "role": "ROLE_FOREIGN", "parts": [{"text": "x"}]}}}}), response=True)
    m.exchange(J({"task": {"id": "t-9", "status": {
        "state": "TASK_STATE_WORKING",
        "message": {"messageId": "m", "role": 77, "parts": []}}}}), response=True)
    m.exchange(J({"id": "t-10", "status": {"state": 3, "message": {"messageId": "m", "role": "x"}}}),
               response=True)
    write_pcap(os.path.join(out, 'a2a_coverage.pcap'), m.pkts, snaplen=65535,
               ts=lambda i: (1767225600 + i, 0))

    # a second capture with odd JSON that is not valid A2A
    x = Cap()
    msg = '{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"hi"}]}'
    bodies = [
        msg + '}',
        '{"message":{"messageId":"m1","role":NaN,"parts":[{"text":NaN}]},"x":NaN}',
        msg + '} trailing text \xff\xfe',
        msg + '}{"id":"t","status":{"state":3}} 5 {"id":"u"}',
        '{"id":"\xff\xfe\x80","status":{"state":99999999999999999999,"timestamp":"\xc3\x28",'
        '"message":{"messageId":"\xed\xa0\x80","role":4294967296}},"history":[1,"a",{"messageId":"x","role":2}]}',
        '{"name":"n","description":"d","version":"1","capabilities":{"streaming":tru,"extensions":[1,{"uri":5}]},'
        '"skills":[1,"x",[],{"id":{},"tags":[1,[2],{}]}],"supportedInterfaces":[null],"signatures":[{"signature":[]}]}',
        '{"tasks":[],"pageSize":"-1","totalSize":-5,"nextPageToken":{}}',
        '{"configs":[{"url":"http://198.51.100.1/","taskId":"t","authentication":{"scheme":"B","credentials":[]}}],"nextPageToken":""}',
        '{"message":{"messageId":"m","role":1,"metadata":' + '[' * 3000 + ']' * 3000 + '}}',
        '{"message":{"messageId":"m","role":1,"parts":[{"text":5,"raw":{},"url":[],"filename":null,"data":1}]},'
        '"configuration":{"acceptedOutputModes":"x","returnImmediately":"yes","historyLength":{}}}',
        '{"task":{"id":"t","status":{"state":"TASK_STATE_WORKING"},"artifacts":{},"history":{}}}',
        '{"statusUpdate":{"taskId":"t","contextId":"c","status":{"state":3}},"artifactUpdate":{"artifact":{"artifactId":"a"}}}',
        '{"messageId":"m","role":"ROLE_USER","parts":[{"text":"a"}],"extensions":"x","referenceTaskIds":{}}',
        # role of an object or a non-number primitive where only the status message is not checked
        '{"id":"t","status":{"state":3,"message":{"messageId":"m","role":{}}}}',
        '{"id":"t","status":{"state":3,"message":{"messageId":"m","role":true}}}',
        # a status whose state is an object; an artifact event with an artifact that is not one
        '{"id":"t","status":{"state":{}}}',
        '{"taskId":"t","contextId":"c","artifact":5}',
        '{"taskId":"t","contextId":"c","artifact":{"name":"no id"}}',
        # empty task lists identified by one pagination field each
        '{"tasks":[],"nextPageToken":"n"}',
        '{"tasks":[],"pageSize":1}',
    ]
    for b in bodies:
        x.exchange(b.encode('latin-1') if all(ord(ch) < 256 for ch in b) else b.encode(), response=False)
    write_pcap(os.path.join(out, 'a2a-coverage-malformed.pcap'), x.pkts, snaplen=65535,
               ts=lambda i: (1767225600 + i, 0))


if __name__ == '__main__':
    main()
