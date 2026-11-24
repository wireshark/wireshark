#!/usr/bin/env python3
# Generates test/captures/gsm_a_rp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic GSM A RP coverage captures. Usage: mkgsm_a_rp.py <outdir>

RP-DATA, RP-ACK, RP-ERROR and RP-SMMA messages in SMS CP-DATA messages on the
A interface (Ethernet/IPv4/SCTP/M3UA/SCCP/BSSAP DTAP; SCTP port 2905 and PPID
3 are registered by default, the SCCP connection is opened with a CR whose
called party address has SSN 254), and in SIP MESSAGE requests with the
content type application/vnd.3gpp.sms and in an HTTP multipart body.
"""
import random
import struct
import sys

# ---------------------------------------------------------------- transport
def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def sctp_data(payload, tsn, ppid=3):
    ch = struct.pack("!BBHIHHI", 0, 3, 16 + len(payload), tsn, 0, tsn, ppid) + payload
    ch += b"\0" * (-len(ch) % 4)
    hdr = struct.pack("!HHII", 2905, 2905, 0x1234, 0)
    return hdr[:8] + struct.pack("<I", crc32c(hdr + ch)) + ch


def ip_eth(proto, l4):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return bytes.fromhex("020000000002020000000001") + b"\x08\x00" + ip + l4


def m3ua_data(sccp, opc=1, dpc=2):
    prot = struct.pack("!IIBBBB", opc, dpc, 3, 2, 0, 0) + sccp
    p = struct.pack("!HH", 0x0210, 4 + len(prot)) + prot
    p += b"\0" * (-len(p) % 4)
    return struct.pack("!BBBBI", 1, 0, 1, 1, 8 + len(p)) + p


_tsn = [100]


def wrap(sccp):
    _tsn[0] += 1
    return ip_eth(132, sctp_data(m3ua_data(sccp), _tsn[0]))


def sccp_cr(src, ssn=254):
    return bytes([1]) + src + bytes([2, 2, 0]) + bytes([2, 0x42, ssn])


def sccp_cc(dst, src):
    return bytes([2]) + dst + src + bytes([2, 0])


def sccp_dt1(dst, data):
    return bytes([6]) + dst + bytes([0, 1, len(data)]) + data


def bssap_dtap(dtap, dlci=0):
    return bytes([1, dlci, len(dtap)]) + dtap


def write_pcap(path, pkts):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack("<IIII", 1700000000 + i // 1000, (i % 1000) * 1000, len(p), len(p)))
            f.write(p)
    print("wrote %d packets to %s" % (len(pkts), path))


SRC_REF = b"\x00\x00\x01"
DST_REF = b"\x00\x00\x02"


def dtap_frame(dtap):
    return wrap(sccp_dt1(DST_REF, bssap_dtap(dtap)))


def open_conn():
    return [wrap(sccp_cr(SRC_REF)), wrap(sccp_cc(SRC_REF, DST_REF))]




# ---------------------------------------------------------------- SMS pieces
def bcd(digits):
    d = [int(c) for c in digits]
    if len(d) % 2:
        d.append(0xf)
    return bytes(d[i] | (d[i + 1] << 4) for i in range(0, len(d), 2))


def lv(b):
    return bytes([len(b)]) + b


def rdigits(rng, n):
    return "".join(rng.choice("0123456789") for _ in range(n))


def sc_addr(rng):
    """RP address: type of number/numbering plan octet and the BCD digits"""
    return bytes([rng.choice([0x91, 0x81, 0xa1, 0x90])]) + bcd(rdigits(rng, rng.choice([8, 11, 12])))


def tp_addr(rng):
    n = rng.choice([7, 10, 11, 12])
    return bytes([n, 0x91]) + bcd(rdigits(rng, n))


UD = bytes([5, 0xe8, 0x32, 0x9b, 0xfd, 0x06])         # "hello" in the GSM 7 bit alphabet


def tp_submit(rng):
    return bytes([0x01, rng.getrandbits(8)]) + tp_addr(rng) + bytes([0, 0]) + UD


def tp_deliver(rng):
    return bytes([0x00]) + tp_addr(rng) + bytes([0, 0]) + bytes([0x62, 0x70, 0x21, 0x41, 0x52, 0x03, 0x00]) + UD


def tp_deliver_report(rng):
    return bytes([0x00, 0x00])


def tp_submit_report(rng):
    return bytes([0x01, 0x00]) + bytes([0x62, 0x70, 0x21, 0x41, 0x52, 0x03, 0x00])


def tp_deliver_report_err(rng):
    return bytes([0x00, 0xd3, 0x00])


def tp_submit_report_err(rng):
    return bytes([0x01, 0x80, 0x00]) + bytes([0x62, 0x70, 0x21, 0x41, 0x52, 0x03, 0x00])


RP_NAMES = {0: "RP-DATA (MS to Network)", 1: "RP-DATA (Network to MS)", 2: "RP-ACK (MS to Network)",
            3: "RP-ACK (Network to MS)", 4: "RP-ERROR (MS to Network)", 5: "RP-ERROR (Network to MS)",
            6: "RP-SMMA (MS to Network)"}

CAUSES = [1, 8, 10, 11, 21, 22, 27, 28, 29, 30, 38, 41, 42, 47, 50, 69, 81, 95, 96, 97, 98, 99, 111, 127, 3, 100]


def rp_msg(kind, k):
    """One RP message of type `kind`, variant k (a seed)."""
    rng = random.Random("rp-%d-%d" % (kind, k))
    mr = bytes([rng.getrandbits(8)])
    if kind == 0:       # MS to network: no originator address
        return bytes([0]) + mr + lv(b"") + lv(sc_addr(rng)) + lv(tp_submit(rng))
    if kind == 1:       # network to MS: no destination address
        return bytes([1]) + mr + lv(sc_addr(rng)) + lv(b"") + lv(tp_deliver(rng))
    if kind in (2, 3):
        out = bytes([kind]) + mr
        if k % 3:
            tp = tp_deliver_report(rng) if kind == 2 else tp_submit_report(rng)
            out += bytes([0x41]) + lv(tp)
        return out
    if kind in (4, 5):
        c = CAUSES[k % len(CAUSES)]
        cause = bytes([0x80 | c]) if k % 2 else bytes([c, rng.getrandbits(8), rng.getrandbits(8)])
        out = bytes([kind]) + mr + lv(cause)
        if k % 4 == 0:
            out += bytes([0x41]) + lv(tp_deliver_report_err(rng) if kind == 4 else tp_submit_report_err(rng))
        return out
    return bytes([6]) + mr


def cp_data(rp, ti=0x00):
    return bytes([ti | 9, 0x01]) + lv(rp)


def dtap_sms(rp, ti=0x00):
    return wrap(sccp_dt1(DST_REF, bssap_dtap(cp_data(rp, ti))))


def open_conn():
    return [wrap(sccp_cr(SRC_REF)), wrap(sccp_cc(SRC_REF, DST_REF))]


# --------------------------------------------------------- UDP / TCP carriers
def udp_eth(sport, dport, payload, n=0):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ip_eth(17, udp)


def tcp_eth(sport, dport, payload, seq):
    src, dst = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
    t = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 0x50, 0x18, 65535, 0, 0) + payload
    ps = src + dst + struct.pack("!BBH", 0, 6, len(t))
    t = t[:16] + struct.pack("!H", csum(ps + t)) + t[18:]
    return ip_eth(6, t)


def sip_message(body, n):
    h = ("MESSAGE sip:+4917900000%02d@ims.example.com SIP/2.0\r\n"
         "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKsms%d\r\n"
         "Max-Forwards: 70\r\n"
         "From: <sip:+491700000002@ims.example.com>;tag=%d\r\n"
         "To: <sip:+4917900000%02d@ims.example.com>\r\n"
         "Call-ID: sms%d@192.0.2.1\r\n"
         "CSeq: %d MESSAGE\r\n"
         "Content-Type: application/vnd.3gpp.sms\r\n"
         "Content-Length: %d\r\n\r\n") % (n, n, n, n, n, n, len(body))
    return udp_eth(5060, 5060, h.encode() + body)


def nf_post(cp, content_id="sms1", seq=1000, json_id=None, js=None, no_json=False):
    jid = content_id if json_id is None else json_id
    if js is None:
        js = '{"smsRecordId":"1","smsPayload":{"contentId":"%s"}}' % jid
    part1 = b"" if no_json else b"--B\r\nContent-Type: application/json\r\n\r\n" + js.encode() + b"\r\n"
    body = (part1 +
            b"--B\r\nContent-Type: application/vnd.3gpp.sms\r\nContent-Id: " + content_id.encode() +
            b"\r\n\r\n" + cp + b"\r\n--B--\r\n")
    h = ("POST /nsmsf-sms/v2/ue-contexts/imsi-262011234567890/sendsms HTTP/1.1\r\n"
         "Host: smsf.example.com\r\n"
         "Content-Type: multipart/related; boundary=B; type=application/json\r\n"
         "Content-Length: %d\r\n\r\n") % len(body)
    return tcp_eth(40000, 80, h.encode() + body, seq)


# ------------------------------------------------------------------ main
def main_frames():
    fr = open_conn()
    for kind in range(7):
        for k in range(6 if kind in (4, 5) else 3):
            fr.append(dtap_sms(rp_msg(kind, k), [0x00, 0x80][k % 2]))
    # CP-ACK and CP-ERROR carry no RP message
    fr.append(wrap(sccp_dt1(DST_REF, bssap_dtap(bytes([0x09, 0x04])))))
    fr.append(wrap(sccp_dt1(DST_REF, bssap_dtap(bytes([0x09, 0x10, 0x11])))))
    # RP message without elements, with extraneous data, unknown types
    fr.append(dtap_sms(bytes([6])))
    fr.append(dtap_sms(rp_msg(6, 0) + b"\x55"))
    fr.append(dtap_sms(rp_msg(2, 1) + b"\xaa\xbb"))
    fr.append(dtap_sms(bytes([7, 1, 2, 3])))
    fr.append(dtap_sms(bytes([0x3f])))
    # RP in SIP MESSAGE (3GPP IMS SMS)
    for n, kind in enumerate([0, 1, 2, 3, 4, 5, 6], 1):
        fr.append(sip_message(rp_msg(kind, 1), n))
    # NF (SMSF) multipart: the SMS payload is a CP-DATA message handed to the DTAP dissector
    seq = 1000
    for cp, cid, jid in [(cp_data(rp_msg(0, 5)), "sms1", None), (cp_data(rp_msg(1, 5)), "sms2", "other"),
                         (cp_data(rp_msg(3, 5)), "sms3", None), (cp_data(rp_msg(6, 0)), "sms4", "NOJSON"),
                         (cp_data(rp_msg(6, 1)), "sms5", "NOPART")]:
        f = nf_post(cp, content_id=cid, json_id=jid, seq=seq,
                    js='{"smsRecordId":"1"}' if jid == "NOJSON" else None, no_json=(jid == "NOPART"))
        seq += len(f) - 14 - 20 - 20
        fr.append(f)
    return fr


def malformed_frames():
    fr = open_conn()
    fr.append(dtap_sms(bytes([0, 0x12])))                              # RP-DATA, nothing after the reference
    fr.append(dtap_sms(bytes([0, 0x12, 0x05, 0x91])))                  # originator address longer than the message
    fr.append(dtap_sms(bytes([1, 0x12, 0x00, 0x00, 0x09, 0x01])))      # user data longer than the message
    fr.append(dtap_sms(bytes([4, 0x12])))                              # RP-ERROR without cause
    fr.append(dtap_sms(bytes([4, 0x12, 0x00])))                        # RP-ERROR with an empty cause
    fr.append(dtap_sms(bytes([2])))                                    # RP-ACK without reference
    fr.append(sip_message(bytes([1, 0x12, 0x03]), 9))
    fr.append(nf_post(cp_data(rp_msg(6, 2)), content_id="sms6", seq=1000, js='{"smsPayload":'))     # invalid JSON
    return fr


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(out + "/gsm_a_rp-coverage.pcap", main_frames())
    write_pcap(out + "/gsm_a_rp-coverage-malformed.pcap", malformed_frames())
