#!/usr/bin/env python
"""
Retrieve a packet from a wireshark/tshark core file
and save it in a packet-capture file.
"""

# Copyright (C) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

# TODO: update to python3

import getopt
import os
import re
import sys
import tempfile

exec_file = None
core_file = None
output_file = None

verbose = 0
debug = 0

class BackTrace:
    re_frame = re.compile(r"^#(?P<num>\d+) ")
    re_func1 = re.compile(r"^#\d+\s+(?P<func>\w+) \(")
    re_func2 = re.compile(r"^#\d+\s+0x[A-Fa-f\d]+ in (?P<func>\w+) \(")

    def __init__(self, lines):

        # In order; each item is the function name.
        self.frames = []
        found_non_bt_frame = 0
        frame_will_be = 0

        for line in lines:
            m = self.re_frame.search(line)
            if m:
                # Skip the first frame that gdb shows,
                # which is not part of the backtrace.
                if not found_non_bt_frame:
                    found_non_bt_frame = 1
                    continue

                # Get the frame number and make sure it's
                # what we expect it should be.
                frame_num = int(m.group("num"))
                if frame_num != frame_will_be:
                    sys.exit(f"Found frame {frame_num} instead of {frame_will_be}")

                # Find the function name. XXX - need to handle '???'
                n = self.re_func1.search(line)
                if not n:
                    n = self.re_func2.search(line)

                if n:
                    func = n.group("func")
                else:
                    sys.exit(f"Function name not found in {line}")

                # Save the info
                self.frames.append(func)
                frame_will_be += 1

    def Frames(self):
        return self.frames


    def HasFunction(self, func):
        return func in self.frames

    def Frame(self, func):
        return self.frames.index(func)


# Some values from wiretap; wiretap should be a shared
# libray and a Python module should be created for it so
# this program could just write a libpcap file directly.
WTAP_ENCAP_NONE                       = -2
WTAP_ENCAP_PER_PACKET                 = -1
WTAP_ENCAP_UNKNOWN                    = 0
WTAP_ENCAP_ETHERNET                   = 1
WTAP_ENCAP_TOKEN_RING                 = 2
WTAP_ENCAP_SLIP                       = 3
WTAP_ENCAP_PPP                        = 4
WTAP_ENCAP_FDDI                       = 5
WTAP_ENCAP_FDDI_BITSWAPPED            = 6
WTAP_ENCAP_RAW_IP                     = 7
WTAP_ENCAP_ARCNET                     = 8
WTAP_ENCAP_ATM_RFC1483                = 9
WTAP_ENCAP_LINUX_ATM_CLIP             = 10
WTAP_ENCAP_LAPB                       = 11
WTAP_ENCAP_ATM_SNIFFER                = 12
WTAP_ENCAP_NULL                       = 13
WTAP_ENCAP_ASCEND                     = 14
WTAP_ENCAP_LAPD                       = 15
WTAP_ENCAP_V120                       = 16
WTAP_ENCAP_PPP_WITH_PHDR              = 17
WTAP_ENCAP_IEEE_802_11                = 18
WTAP_ENCAP_SLL                        = 19
WTAP_ENCAP_FRELAY                     = 20
WTAP_ENCAP_CHDLC                      = 21
WTAP_ENCAP_CISCO_IOS                  = 22
WTAP_ENCAP_LOCALTALK                  = 23
WTAP_ENCAP_PRISM_HEADER               = 24
WTAP_ENCAP_PFLOG                      = 25
WTAP_ENCAP_AIROPEEK                   = 26
WTAP_ENCAP_HHDLC                      = 27
# last WTAP_ENCAP_ value + 1
WTAP_NUM_ENCAP_TYPES                  = 28

wtap_to_pcap_map = {
        WTAP_ENCAP_NULL                 : 0,
        WTAP_ENCAP_ETHERNET             : 1,
        WTAP_ENCAP_TOKEN_RING           : 6,
        WTAP_ENCAP_ARCNET               : 7,
        WTAP_ENCAP_SLIP                 : 8,
        WTAP_ENCAP_PPP                  : 9,
        WTAP_ENCAP_FDDI_BITSWAPPED      : 10,
        WTAP_ENCAP_FDDI                 : 10,
        WTAP_ENCAP_ATM_RFC1483          : 11,
        WTAP_ENCAP_RAW_IP               : 12,
        WTAP_ENCAP_LINUX_ATM_CLIP       : 16, # or 18, or 19...
        WTAP_ENCAP_CHDLC                : 104,
        WTAP_ENCAP_IEEE_802_11          : 105,
        WTAP_ENCAP_SLL                  : 113,
        WTAP_ENCAP_LOCALTALK            : 114,
        WTAP_ENCAP_PFLOG                : 117,
        WTAP_ENCAP_CISCO_IOS            : 118,
        WTAP_ENCAP_PRISM_HEADER         : 119,
        WTAP_ENCAP_HHDLC                : 121,
}


wtap_name = {
        WTAP_ENCAP_NONE                       : "None",
        WTAP_ENCAP_UNKNOWN                    : "Unknown",
        WTAP_ENCAP_ETHERNET                   : "Ethernet",
        WTAP_ENCAP_TOKEN_RING                 : "Token-Ring",
        WTAP_ENCAP_SLIP                       : "SLIP",
        WTAP_ENCAP_PPP                        : "PPP",
        WTAP_ENCAP_FDDI                       : "FDDI",
        WTAP_ENCAP_FDDI_BITSWAPPED            : "FDDI (Bitswapped)",
        WTAP_ENCAP_RAW_IP                     : "Raw IP",
        WTAP_ENCAP_ARCNET                     : "ARCNET",
        WTAP_ENCAP_ATM_RFC1483                : "ATM RFC1483",
        WTAP_ENCAP_LINUX_ATM_CLIP             : "Linux ATM CLIP",
        WTAP_ENCAP_LAPB                       : "LAPB",
        WTAP_ENCAP_ATM_SNIFFER                : "ATM Sniffer",
        WTAP_ENCAP_NULL                       : "Null",
        WTAP_ENCAP_ASCEND                     : "Ascend",
        WTAP_ENCAP_LAPD                       : "LAPD",
        WTAP_ENCAP_V120                       : "V.120",
        WTAP_ENCAP_PPP_WITH_PHDR              : "PPP (with PHDR)",
        WTAP_ENCAP_IEEE_802_11                : "IEEE 802.11",
        WTAP_ENCAP_SLL                        : "SLL",
        WTAP_ENCAP_FRELAY                     : "Frame Relay",
        WTAP_ENCAP_CHDLC                      : "Cisco HDLC",
        WTAP_ENCAP_CISCO_IOS                  : "Cisco IOS",
        WTAP_ENCAP_LOCALTALK                  : "LocalTalk",
        WTAP_ENCAP_PRISM_HEADER               : "Prism Header",
        WTAP_ENCAP_PFLOG                      : "PFLog",
        WTAP_ENCAP_AIROPEEK                   : "AiroPeek",
        WTAP_ENCAP_HHDLC                      : "HHDLC",
}

def wtap_to_pcap(wtap):
    if not wtap_to_pcap_map.has_key(wtap):
        sys.exit(f"Don't know how to convert wiretap encoding {wtap} to libpcap.")

    return wtap_to_pcap_map[wtap]


def run_gdb(*commands):
    if len(commands) == 0:
        return []

    # Create a temporary file
    fname = tempfile.mktemp()
    try:
        fh = open(fname, "w")
    except OSError as err:
        sys.exit(f"Cannot open {fname} for writing: {err}")

    # Put the commands in it
    for cmd in commands:
        fh.write(cmd)
        fh.write("\n")

    fh.write("quit\n")
    try:
        fh.close()
    except OSError as err:
        try:
            os.unlink(fname)
        except FileNotFoundError:
            pass
        sys.exit(f"Cannot close {fname}: {err}")


    # Run gdb
    cmd = f"gdb --nw --quiet --command={fname} {exec_file} {core_file}"
    if verbose:
        print(f"Invoking {cmd}")
    try:
        pipe = os.popen(cmd)
    except OSError as err:
        try:
            os.unlink(fname)
        except FileNotFoundError:
            pass
        sys.exit(f"Cannot run gdb: {err}")

    # Get gdb's output
    result = pipe.readlines()
    error = pipe.close()
    if error is not None:
        try:
            os.unlink(fname)
        except FileNotFoundError:
            pass
        sys.exit(f"gdb returned an exit value of {error}")


    # Remove the temp file and return the results
    try:
        os.unlink(fname)
    except FileNotFoundError:
        pass
    return result

def get_value_from_frame(frame_num, variable, fmt=""):
    cmds = []
    if frame_num > 0:
        cmds.append(f"up {frame_num}")

    cmds.append(f"print {fmt} {variable}")
    lines = run_gdb(cmds)

    LOOKING_FOR_START = 0
    READING_VALUE = 1
    state = LOOKING_FOR_START
    result = ""
    for line in lines:
        if line[-1] == "\n":
            line = line[0:-1]
        if line[-1] == "\r":
            line = line[0:-1]

        if state == LOOKING_FOR_START:
            if len(line) < 4:
                continue
            else:
                if line[0:4] == "$1 =":
                    result = line[4:]
                    state = READING_VALUE

        elif state == READING_VALUE:
            result += line

    return result

def get_int_from_frame(frame_num, variable):
    text = get_value_from_frame(frame_num, variable)
    try:
        integer = int(text)
    except ValueError:
        sys.exit(f"Could not convert '{text}' to integer.")
    return integer


def get_byte_array_from_frame(frame_num, variable, length):
    cmds = []
    if frame_num > 0:
        cmds.append(f"up {frame_num}")

    cmds.append(f"print {variable}")
    cmds.append(f"x/{length}xb {variable}")
    lines = run_gdb(cmds)
    if debug:
        print(lines)

    bytes = []

    LOOKING_FOR_START = 0
    BYTES = 1
    state = LOOKING_FOR_START

    for line in lines:
        if state == LOOKING_FOR_START:
            if len(line) < 3:
                continue
            elif line[0:3] == "$1 ":
                state = BYTES
        elif state == BYTES:
            line.rstrip()
            fields = line.split('\t')
            if fields[0][-1] != ":":
                print("Failed to parse byte array from gdb:")
                print(line)
                sys.exit(1)

            for field in fields[1:]:
                val = int(field, 16)
                bytes.append(val)
        else:
            assert 0

    return bytes

def make_cap_file(pkt_data, lnk_t):

    pcap_lnk_t = wtap_to_pcap(lnk_t)

    # Create a temporary file
    fname = tempfile.mktemp()
    try:
        fh = open(fname, "w")
    except OSError as err:
        sys.exit(f"Cannot open {fname} for writing: {err}")

    print("Packet Data:")

    # Put the hex dump in it
    offset = 0
    BYTES_IN_ROW = 16
    for offset, byte in enumerate(pkt_data):
        if (offset % BYTES_IN_ROW) == 0:
            print(f"\n{offset:08x}", file=fh)
            print(f"\n{offset:08x}")

        print(f"{byte:02x}", file=fh)
        print(f"{byte:02x}")

    print("\n", file=fh)
    print("\n")

    try:
        fh.close()
    except OSError as err:
        try:
            os.unlink(fname)
        except FileNotFoundError:
            pass
        sys.exit(f"Cannot close {fname}: {err}")


    # Run text2pcap
    cmd = f"text2pcap -q -l {pcap_lnk_t} {fname} {output_file}"
#       print f"Command is {cmd}"
    try:
        retval = os.system(cmd)
    except OSError as err:
        try:
            os.unlink(fname)
        except FileNotFoundError:
            pass
        sys.exit(f"Cannot run text2pcap: {err}")

    # Remove the temp file
    try:
        os.unlink(fname)
    except FileNotFoundError:
        pass

    if retval == 0:
        print(f"{output_file} created with {len(pkt_data)} bytes in packet, and {wtap_name[lnk_t]} encoding.")
    else:
        sys.exit("text2pcap did not run successfully.")




def try_frame(func_text, cap_len_text, lnk_t_text, data_text):

    # Get the back trace
    bt_text = run_gdb("bt")
    bt = BackTrace(bt_text)
    if not bt.HasFunction(func_text):
        print(f"{func_text}() not found in backtrace.")
        return 0
    else:
        print(f"{func_text}() found in backtrace.")

    # Figure out where the call to epan_dissect_run is.
    frame_num = bt.Frame(func_text)

    # Get the capture length
    cap_len = get_int_from_frame(frame_num, cap_len_text)

    # Get the encoding type
    lnk_t = get_int_from_frame(frame_num, lnk_t_text)

    # Get the packet data
    pkt_data = get_byte_array_from_frame(frame_num, data_text, cap_len)

    if verbose:
        print(f"Length={cap_len}")
        print(f"Encoding={lnk_t}")
        print(f"Data ({len(pkt_data)} bytes) = {pkt_data}")
    make_cap_file(pkt_data, lnk_t)
    return 1

def run():
    if try_frame("epan_dissect_run",
            "fd->cap_len", "fd->lnk_t", "data") or try_frame("add_packet_to_packet_list",
            "fdata->cap_len", "fdata->lnk_t", "buf"):
        return
    else:
        sys.exit("A packet cannot be pulled from this core.")


def usage():
    print("pkt-from-core.py [-v] -w capture_file executable-file (core-file or process-id)")
    print()
    print("\tGiven an executable file and a core file, this tool")
    print("\tuses gdb to retrieve the packet that was being dissected")
    print("\tat the time wireshark/tshark stopped running. The packet")
    print("\tis saved in the capture_file specified by the -w option.")
    print()
    print("\t-v : verbose")
    sys.exit(1)

def main():
    global exec_file
    global core_file
    global output_file
    global verbose
    global debug

    optstring = "dvw:"
    try:
        opts, args = getopt.getopt(sys.argv[1:], optstring)
    except getopt.error:
        usage()

    for opt, arg in opts:
        if opt == "-w":
            output_file = arg
        elif opt == "-v":
            verbose = 1
        elif opt == "-d":
            debug = 1
        else:
            assert 0

    if output_file is None:
        usage()

    if len(args) != 2:
        usage()

    exec_file = args[0]
    core_file = args[1]

    run()

if __name__ == '__main__':
    main()

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 expandtab:
# :indentSize=4:noTabs=true:
#
