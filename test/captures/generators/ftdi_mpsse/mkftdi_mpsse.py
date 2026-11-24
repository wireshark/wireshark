#!/usr/bin/env python3
# Generates test/captures/ftdi_mpsse_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the FTDI MPSSE coverage captures (Linux usbmon, LINKTYPE 220).

ftdi-mpsse-coverage.pcap            all 256 command bytes on every MPSSE capable chip
                                    (and in MCU host bus mode), responses, reassembly
ftdi-mpsse-coverage-malformed.pcap  paths that need malformed input
Usage: mkftdi_mpsse.py <outdir>
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from ftdi_usbmon import Cap

FT232B, FT2232D, FT232R, FT2232H, FT4232H, FT232H = 0x0400, 0x0500, 0x0600, 0x0700, 0x0800, 0x0900

# Mirror of the command tables of packet-ftdi-mpsse.c ----------------------------------
COMMON = {0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B, 0x20, 0x22, 0x24, 0x26, 0x28, 0x29, 0x2A, 0x2B,
          0x2C, 0x2E, 0x31, 0x33, 0x34, 0x36, 0x39, 0x3B, 0x3C, 0x3E, 0x4A, 0x4B, 0x6A, 0x6B, 0x6E, 0x6F,
          0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x87, 0x88, 0x89}
H_ONLY = {0x86, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x94, 0x95, 0x96, 0x97, 0x9C, 0x9D}
CPUMODE = {0x90, 0x91, 0x92, 0x93}
NOT_SHIFTING = set(list(range(0x00, 0x10)) + list(range(0x40, 0x4A)) + [0x4C, 0x4D] + list(range(0x50, 0x5A)) +
                   [0x5C, 0x5D, 0x60, 0x61, 0x64, 0x65, 0x68, 0x69, 0x6C, 0x6D, 0x70, 0x71, 0x74, 0x75, 0x78,
                    0x79, 0x7C, 0x7D])


def is_shifting(cmd):
    return cmd not in NOT_SHIFTING and cmd & 0x80 == 0


def valid(cmd, chip, mcu):
    if cmd in COMMON or is_shifting(cmd):
        return True
    if chip == FT2232D and cmd == 0x86:
        return True
    if chip == FT232H and cmd == 0x9E:
        return True
    if chip in (FT232H, FT2232H, FT4232H) and cmd in H_ONLY:
        return True
    return mcu and cmd in CPUMODE


def encode(cmd, chip, mcu, k=1):
    """TX and RX octets of one command. k varies the data length."""
    if not valid(cmd, chip, mcu):
        return bytes([cmd]), bytes([0xFA, cmd])
    data = lambda n: bytes((cmd + 3 * i) & 0x7f for i in range(n))
    if is_shifting(cmd):
        read = bool(cmd & 0x20)
        write_tdi = bool(cmd & 0x10)
        write_tms = bool(cmd & 0x40)
        if not cmd & 0x02:                                  # byte mode
            n = (cmd % 3) + k
            tx = bytes([cmd, (n - 1) & 0xff, (n - 1) >> 8]) + (data(n) if write_tdi else b'')
            rx = data(n) if read and not mcu else b''
        else:                                               # bit mode
            tx = bytes([cmd, cmd % 8])
            if write_tms and read and not cmd & 0x08:
                pass                                        # these do not take the data octet
            elif write_tdi or write_tms:
                tx += b'\x55'
            rx = b'\x2a' if read and not mcu else b''
        return tx, rx
    tx, rx = bytes([cmd]), b''
    if cmd in (0x80, 0x82):
        tx += bytes([0xa5, 0x0f])
    elif cmd in (0x81, 0x83):
        rx = b'\xc3'
    elif cmd == 0x86:
        tx += bytes([0x05, 0x00])
    elif cmd == 0x8E:
        tx += b'\x07'
    elif cmd in (0x8F, 0x9C, 0x9D):
        tx += bytes([0x10, 0x00])
    elif cmd == 0x9E:
        tx += bytes([0x0f, 0xf0])
    elif cmd == 0x90:
        tx += b'\x12'
        rx = b'\x77'
    elif cmd == 0x91:
        tx += bytes([0x12, 0x34])
        rx = b'\x78'
    elif cmd == 0x92:
        tx += bytes([0x12, 0x99])
    elif cmd == 0x93:
        tx += bytes([0x12, 0x34, 0x99])
    return tx, rx


def burst(chip, mcu, cmds=range(256), k=1):
    tx = rx = b''
    for cmd in cmds:
        t, r = encode(cmd, chip, mcu, k)
        tx += t
        rx += r
    return tx, rx


def exchange(c, dev, chip, mcu, ep_out, ep_in, cmds=range(256), k=1, tx_chunk=0, rx_chunk=0):
    tx, rx = burst(chip, mcu, cmds, k)
    if tx_chunk:
        for i in range(0, len(tx), tx_chunk):
            c.bulk_out(tx[i:i + tx_chunk], ep=ep_out, dev=dev)
    else:
        c.bulk_out(tx, ep=ep_out, dev=dev)
    if rx_chunk:
        for i in range(0, len(rx), rx_chunk):
            c.bulk_in(rx[i:i + rx_chunk], ep=ep_in, dev=dev)
    elif rx:
        c.bulk_in(rx, ep=ep_in, dev=dev)


def main_capture():
    c = Cap()
    # ---- FT2232H (dev 2): port A with readable sequences, then everything --
    c.enumerate(FT2232H, dev=2)
    c.set_bitmode(0x02, 1, 0xff, dev=2)
    # Typical start-up: loopback off, clock divisor, GPIO, Send Immediate
    c.bulk_out(bytes([0x85, 0x8A, 0x97, 0x8D, 0x86, 0x05, 0x00, 0x80, 0x08, 0x0b, 0x82, 0xff, 0x00, 0x87]), ep=0x02, dev=2)
    # JTAG-like exchange: TMS and TDI shifting, read back
    c.bulk_out(bytes([0x4b, 0x05, 0x1f, 0x39, 0x03, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x6b, 0x02, 0x07, 0x87]), ep=0x02, dev=2)
    c.bulk_in(bytes([0x11, 0x22, 0x33, 0x44]), ep=0x81, dev=2)
    c.bulk_in(bytes([0x80]), ep=0x81, dev=2)                         # the TMS read back
    c.bulk_out(bytes([0x81, 0x83, 0x87]), ep=0x02, dev=2)
    c.bulk_in(bytes([0x0b, 0xf0]), ep=0x81, dev=2)
    exchange(c, 2, FT2232H, False, 0x02, 0x81)
    exchange(c, 2, FT2232H, False, 0x02, 0x81, k=300)               # long transfers
    # Port B: pin names of the second interface
    c.set_bitmode(0x02, 2, 0xff, dev=2)
    exchange(c, 2, FT2232H, False, 0x04, 0x83, cmds=[0x80, 0x81, 0x82, 0x83, 0x86, 0x9E, 0x8E, 0x20, 0x31, 0xaa])
    # Clock divisors: the maximum clock is shown in MHz, kHz and Hz
    c.bulk_out(bytes([0x86, 0x00, 0x00, 0x86, 0x05, 0x00, 0x86, 0x00, 0x01, 0x86, 0x00, 0x10, 0x86, 0xff, 0xff]), ep=0x04, dev=2)
    # An interface of the FT2232H that has no MPSSE pin names (the dissector knows A and B)
    c.set_bitmode(0x02, 3, 0xff, dev=2)
    exchange(c, 2, FT2232H, False, 0x06, 0x85, cmds=[0x80, 0x81, 0x82, 0x83])
    # FT2232H port B in MCU host bus emulation mode (set after the MPSSE use of the same port)
    c.set_bitmode(0x08, 2, 0xff, dev=2)
    exchange(c, 2, FT2232H, True, 0x04, 0x83)
    exchange(c, 2, FT2232H, True, 0x04, 0x83, k=4)

    # ---- FT232H (dev 3) -----------------------------------------------------
    c.enumerate(FT232H, dev=3)
    c.set_bitmode(0x02, 1, 0xff, dev=3)
    exchange(c, 3, FT232H, False, 0x02, 0x81)
    c.set_bitmode(0x08, 1, 0xff, dev=3)
    exchange(c, 3, FT232H, True, 0x02, 0x81, cmds=range(0x80, 0xa0))

    # ---- FT2232D (dev 4) ----------------------------------------------------
    c.enumerate(FT2232D, dev=4)
    c.set_bitmode(0x02, 1, 0xff, dev=4)
    exchange(c, 4, FT2232D, False, 0x02, 0x81)
    c.set_bitmode(0x02, 2, 0xff, dev=4)                              # interface B: no pin names
    exchange(c, 4, FT2232D, False, 0x04, 0x83, cmds=[0x80, 0x82, 0x81, 0x83])
    c.bulk_out(bytes([0x86, 0x00, 0x00, 0x86, 0xff, 0xff]), ep=0x02, dev=4)   # TCK/SK Max

    # ---- FT4232H (dev 5): ports A, B, C, D ----------------------------------
    c.enumerate(FT4232H, dev=5)
    for iface, ep_o, ep_i in ((1, 0x02, 0x81), (2, 0x04, 0x83), (3, 0x06, 0x85), (4, 0x08, 0x87)):
        c.set_bitmode(0x02, iface, 0xff, dev=5)
        exchange(c, 5, FT4232H, False, ep_o, ep_i, cmds=range(256) if iface == 1 else [0x80, 0x81, 0x82, 0x83, 0x86, 0x8e])

    # ---- FT232R (dev 6): no chip specific commands; the stream is cut into
    # small URBs, so commands and responses are reassembled ----------------
    c.enumerate(FT232R, dev=6)
    c.set_bitmode(0x02, 1, 0xff, dev=6)
    exchange(c, 6, FT232R, False, 0x02, 0x81, tx_chunk=7, rx_chunk=5)
    # FT232B without MPSSE-specific commands, whole stream
    c.enumerate(FT232B, dev=7)
    c.set_bitmode(0x02, 1, 0xff, dev=7)
    exchange(c, 7, FT232B, False, 0x02, 0x81, cmds=range(0x80, 0xa0))

    # ---- more reassembly cases on FT2232H (dev 8), interface A ---------------
    c.enumerate(FT2232H, dev=8)
    c.set_bitmode(0x02, 1, 0xff, dev=8)
    # response arrives before all output is sent (preliminary command record)
    c.bulk_out(bytes([0x31, 0x03, 0x00, 0x01, 0x02]), ep=0x02, dev=8)
    c.bulk_in(bytes([0x0a]), ep=0x81, dev=8)                         # first response octet only
    c.bulk_out(bytes([0x03, 0x04]), ep=0x02, dev=8)
    c.bulk_in(bytes([0x0b, 0x0c, 0x0d]), ep=0x81, dev=8)
    # Bad Command with junk before the response (Skipped response data)
    c.bulk_out(bytes([0xaa, 0xab]), ep=0x02, dev=8)
    c.bulk_in(bytes([0x01, 0x02, 0xfa, 0xaa, 0xfa, 0xab]), ep=0x81, dev=8)
    c.bulk_out(bytes([0xac]), ep=0x02, dev=8)
    c.bulk_in(bytes([0x55]), ep=0x81, dev=8)                         # junk only
    c.bulk_in(bytes([0xfa]), ep=0x81, dev=8)                         # FA at the end
    c.bulk_in(bytes([0xac]), ep=0x81, dev=8)
    # Bad Command response split: FA | cmd
    c.bulk_out(bytes([0xad]), ep=0x02, dev=8)
    c.bulk_in(bytes([0xfa]), ep=0x81, dev=8)
    c.bulk_in(bytes([0xad]), ep=0x81, dev=8)
    # the Bad Command reproducer of the reassembly assertion: 0x00, RX FA, RX FA, RX 00
    c.bulk_out(bytes([0x00]), ep=0x02, dev=8)
    c.bulk_in(bytes([0xfa]), ep=0x81, dev=8)
    c.bulk_in(bytes([0xfa]), ep=0x81, dev=8)
    c.bulk_in(bytes([0x00]), ep=0x81, dev=8)

    # ---- reproducers --------------------------------------------------------
    # "2pass_cmd": Read Low Byte, a partial 0x31, then its end
    c.enumerate(FT2232H, dev=9)
    c.set_bitmode(0x02, 1, 0xff, dev=9)
    c.bulk_out(bytes([0x81, 0x31, 0x03, 0x00, 0xAA]), ep=0x02, dev=9)
    c.bulk_out(bytes([0xBB, 0xCC, 0xDD]), ep=0x02, dev=9)
    # "prelim_stale": a preliminary 0x31 is left when the device is re-enumerated as another chip
    c.enumerate(FT2232H, dev=10)
    c.set_bitmode(0x02, 1, 0xff, dev=10)
    c.bulk_out(bytes([0x81, 0x31, 0x03, 0x00, 0xAA]), ep=0x02, dev=10)
    c.enumerate(FT2232D, dev=10)
    c.bulk_out(bytes([0xBB, 0xCC, 0xDD]), ep=0x02, dev=10)
    c.enumerate(FT2232H, dev=10)
    c.bulk_out(bytes([0x81]), ep=0x02, dev=10)
    # "len_wrap": Clock Data Bytes In with length 0xFFFF
    c.enumerate(FT2232H, dev=11)
    c.set_bitmode(0x02, 1, 0xff, dev=11)
    c.bulk_out(bytes([0x20, 0xff, 0xff]), ep=0x02, dev=11)
    return c


def malformed_capture():
    c = Cap()
    c.enumerate(FT2232H, dev=2)
    c.set_bitmode(0x02, 1, 0xff, dev=2)
    # a response without a command
    c.bulk_in(bytes([1, 2, 3]), ep=0x81, dev=2)
    # more response data than commands
    c.bulk_out(bytes([0x81]), ep=0x02, dev=2)
    c.bulk_in(bytes([0x11, 0x22, 0x33]), ep=0x81, dev=2)
    # response of a Bad Command that never comes, a second command pushes
    c.bulk_out(bytes([0xaa]), ep=0x02, dev=2)
    c.bulk_out(bytes([0x81]), ep=0x02, dev=2)
    c.bulk_in(bytes([0x7f, 0x7e, 0x7d, 0x7c]), ep=0x81, dev=2)
    # a command whose response is 0x10000 octets, answered with a short response
    c.bulk_out(bytes([0x20, 0xff, 0xff]), ep=0x02, dev=2)
    c.bulk_in(bytes([0x01] * 100), ep=0x81, dev=2)
    # MCU mode on a chip that is not the one the commands were sent to
    c.set_bitmode(0x08, 2, 0xff, dev=2)
    c.bulk_out(bytes([0x93, 0x01]), ep=0x04, dev=2)
    c.bulk_in(bytes([0x01]), ep=0x83, dev=2)
    # SetBitMode back to serial: the payload is no longer MPSSE
    c.set_bitmode(0x00, 1, 0x00, dev=2)
    c.bulk_out(bytes([0x81]), ep=0x02, dev=2)
    return c


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    main_capture().write(os.path.join(out, 'ftdi-mpsse-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'ftdi-mpsse-coverage-malformed.pcap'))
