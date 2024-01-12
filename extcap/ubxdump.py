#!/usr/bin/env python3

# Extcap for u-blox GNSS receiver
# By Timo Warns <timo.warns@gmail.com>
# Copyright 2024 Timo Warns
#
# The extcap is based on Wireshark's extcap_example.py with
# Copyright 2014 Roland Knall <rknall [AT] gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

"""
Extcap for UBX messages from an u-blox GNSS receiver.
Tested with UBX protocol version 18. 
"""

import argparse, serial.tools.list_ports, serial, struct, sys, time
from threading import Thread

VERSION  = "0.1"


################################
# u-blox / UBX related constants
################################

UBLOX_DEV_DESCRIPTION = 'u-blox GNSS receiver'

# UBX message structure-related definitions
UBX_PREAMBLE_1 = 0xb5
UBX_PREAMBLE_2 = 0x62
UBX_HEADER_SIZE = 6
UBX_CHKSUM_SIZE = 2
UBX_PAYLOAD_LEN_OFFSET = 4

# UBX GNSS Identifiers
UBX_GNSS_ID_GPS     = 0
UBX_GNSS_ID_SBAS    = 1
UBX_GNSS_ID_GALILEO = 2
UBX_GNSS_ID_BEIDOU  = 3
UBX_GNSS_ID_IMES    = 4
UBX_GNSS_ID_QZSS    = 5
UBX_GNSS_ID_GLONASS = 6

# UBX message class and identifiers
UBX_NAV         = 0x01
UBX_NAV_POSECEF = [UBX_NAV, 0x01]
UBX_NAV_DOP     = [UBX_NAV, 0x04]
UBX_NAV_PVT     = [UBX_NAV, 0x07]
UBX_NAV_ODO     = [UBX_NAV, 0x09]
UBX_NAV_VELECEF = [UBX_NAV, 0x11]
UBX_NAV_TIMEGPS = [UBX_NAV, 0x20]
UBX_NAV_TIMEUTC = [UBX_NAV, 0x21]
UBX_NAV_TIMELS  = [UBX_NAV, 0x26]
UBX_NAV_SBAS    = [UBX_NAV, 0x32]
UBX_NAV_SAT     = [UBX_NAV, 0x35]
UBX_NAV_EOE     = [UBX_NAV, 0x61]

UBX_RXM       = 0x02
UBX_RXM_SFRBX = [UBX_RXM, 0x13]
UBX_RXM_MEASX = [UBX_RXM, 0x14]
UBX_RXM_RAWX  = [UBX_RXM, 0x15]

UBX_CFG      = 0x06
UBX_CFG_MSG  = [UBX_CFG, 0x01]
UBX_CFG_SBAS = [UBX_CFG, 0x16]
UBX_CFG_GNSS = [UBX_CFG, 0x3e]

UBX_NMEA     = 0xf0
UBX_NMEA_GGA = [UBX_NMEA, 0x00]
UBX_NMEA_GLL = [UBX_NMEA, 0x01]
UBX_NMEA_GSA = [UBX_NMEA, 0x02]
UBX_NMEA_GSV = [UBX_NMEA, 0x03]
UBX_NMEA_RMC = [UBX_NMEA, 0x04]
UBX_NMEA_VTG = [UBX_NMEA, 0x05]
UBX_NMEA_GRS = [UBX_NMEA, 0x06]
UBX_NMEA_GST = [UBX_NMEA, 0x07]
UBX_NMEA_ZDA = [UBX_NMEA, 0x08]
UBX_NMEA_GBS = [UBX_NMEA, 0x09]
UBX_NMEA_TXT = [UBX_NMEA, 0x41]


# Defines the desired rate per UBX message type.
# NMEA messages are disabled by setting their rate to 0.
#
# Eventually, this could be made configurable / controllable via the extcap
# config interface.
UBX_MSG_RATES = [
    (UBX_NAV_POSECEF, 0x01),
    (UBX_NAV_DOP,     0x01),
    (UBX_NAV_PVT,     0x01),
    (UBX_NAV_ODO,     0x01),
    (UBX_NAV_VELECEF, 0x01),
    (UBX_NAV_TIMEGPS, 0x01),
    (UBX_NAV_TIMEUTC, 0x01),
    (UBX_NAV_TIMELS,  0xff),
    (UBX_NAV_SBAS,    0x01),
    (UBX_NAV_SAT,     0x01),
    (UBX_NAV_EOE,     0x01),
    (UBX_RXM_SFRBX,   0x01),
    (UBX_RXM_MEASX,   0x01),
    (UBX_RXM_RAWX,    0x01),
    (UBX_NMEA_GGA,    0x00),
    (UBX_NMEA_GLL,    0x00),
    (UBX_NMEA_GSA,    0x00),
    (UBX_NMEA_GSV,    0x00),
    (UBX_NMEA_RMC,    0x00),
    (UBX_NMEA_VTG,    0x00),
    (UBX_NMEA_GRS,    0x00),
    (UBX_NMEA_GST,    0x00),
    (UBX_NMEA_ZDA,    0x00),
    (UBX_NMEA_GBS,    0x00),
    (UBX_NMEA_TXT,    0x00),
        ]

# Defines the desired GNSS config.
# Format is (GNSS ID, resTrkCh, maxTrkCh, enable, sigCfgMask).
#
# Eventually, this could be made configurable / controllable via the extcap
# config interface.
UBX_GNSS_CONFIGS = [
        (UBX_GNSS_ID_GPS,     8, 14, True,  0x01),
        (UBX_GNSS_ID_GLONASS, 0,  0, False, 0x00),
        (UBX_GNSS_ID_SBAS,    2,  4, True,  0x01),
        (UBX_GNSS_ID_GALILEO, 8, 14, True,  0x01)
        ]

########################
# PCAP-related constants
########################

DLT      = "147"
DLT_NAME = "DLT_USER0"

PCAP_MAGIC         = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_THISZONE      = 0
PCAP_SIGFIGS       = 0
PCAP_SNAPLEN       = 0xffffffff

##########################
# extcap-related constants
##########################

ERROR_USAGE          = 0
ERROR_ARG            = 1
ERROR_INTERFACE      = 2
ERROR_FIFO           = 3

CTRL_CMD_INITIALIZED   = 0
CTRL_CMD_SET           = 1
CTRL_CMD_ADD           = 2
CTRL_CMD_REMOVE        = 3
CTRL_CMD_ENABLE        = 4
CTRL_CMD_DISABLE       = 5
CTRL_CMD_STATUSBAR_MSG = 6
CTRL_CMD_INFO_MSG      = 7
CTRL_CMD_WARN_MSG      = 8
CTRL_CMD_ERROR_MSG     = 9

CTRL_ARG_LOGGER        = 0

initialized = False
fn_out = None

def extcap_config(option):
    # not options implemented for the moment
    return

def extcap_version():
    print(f"extcap {{version={VERSION}}}{{help=https://www.wireshark.org}}{{display=u-blox UBX extcap interface}}")

def extcap_interfaces():
    extcap_version()
    for i in serial.tools.list_ports.grep(UBLOX_DEV_DESCRIPTION):
        print(f"interface {{value={i.device}}}{{display=u-blox UBX capture}}")

    print(f"control {{number={CTRL_ARG_LOGGER}}}{{type=button}}{{role=logger}}{{display=Log}}{{tooltip=Show capture log}}")

def extcap_dlts():
    print(f"dlt {{number={DLT}}}{{name={DLT_NAME}}}{{display=UBX DLT ({DLT_NAME})}}")

def log(msg):
    control_write(CTRL_ARG_LOGGER, CTRL_CMD_ADD, msg)

def pcap_header():
    return struct.pack(
            "!IHHiIII",
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            PCAP_THISZONE,
            PCAP_SIGFIGS,
            PCAP_SNAPLEN,
            int(DLT))

def pcap_packet(ubx_msg):
    pcap = bytearray()

    caplength = len(ubx_msg)
    timestamp = int(time.time())

    pcap += struct.pack("!IIII", int(timestamp), 0, caplength, caplength)
    pcap += ubx_msg

    return pcap

def ubxChecksum(msg):
    ck_a = 0
    ck_b = 0

    for b in msg:
        ck_a += b
        ck_b += ck_a

    return [ck_a & 0xff, ck_b & 0xff]

def ubxMsg(ubxClassId, payload):

    payloadLength = len(payload)

    msg = bytearray(UBX_HEADER_SIZE + payloadLength + UBX_CHKSUM_SIZE)

    # add preamble
    msg[0:2] = [UBX_PREAMBLE_1, UBX_PREAMBLE_2]

    # add class/id
    msg[2:4] = ubxClassId

    # add payload length
    struct.pack_into('<H', msg, UBX_PAYLOAD_LEN_OFFSET, payloadLength)

    # add payload
    msg[UBX_HEADER_SIZE:-UBX_CHKSUM_SIZE] = payload

    # add checksum
    msg[-UBX_CHKSUM_SIZE:] = ubxChecksum(msg[2:-UBX_CHKSUM_SIZE])

    return msg

def sendUbxMsg(receiver, msg):
    log("Sending UBX message: " + msg.hex() + "\n")
    receiver.write(msg)

def ubxCfgMsg(ubxMsgClassId, rate):
    return ubxMsg(UBX_CFG_MSG, ubxMsgClassId + [rate])

def ubxCfgGnss(gnssId, resTrkCh, maxTrkCh, enable, sigCfgMask):

    msgVer          = 0x00
    numTrkChHw      = 0x00 # read only
    numTrkChUse     = 0xff
    numConfigBlocks = 0x01 # one config block only

    payload = bytearray(12)

    payload[0]  = msgVer
    payload[1]  = numTrkChHw
    payload[2]  = numTrkChUse
    payload[3]  = numConfigBlocks

    payload[4]  = gnssId
    payload[5]  = resTrkCh
    payload[6]  = maxTrkCh
    payload[7]  = 0 # reserved1
    payload[8]  = 1 if enable else 0
    payload[9]  = 0 # flags, reserved
    payload[10] = sigCfgMask
    payload[11] = 0 # flags, reserved

    return ubxMsg(UBX_CFG_GNSS, payload)
    

def control_read(fn):
    try:
        header = fn.read(6)
        sp, _, length, arg, typ = struct.unpack('>sBHBB', header)
        if length > 2:
            payload = fn.read(length - 2).decode('utf-8', 'replace')
        else:
            payload = ''
        return arg, typ, payload
    except Exception:
        return None, None, None

def control_read_thread(control_in):
    global initialized
    with open(control_in, 'rb', 0) as fn:
        arg = 0
        while arg is not None:
            arg, typ, payload = control_read(fn)

            if typ == CTRL_CMD_INITIALIZED:
                initialized = True

def control_write(arg, typ, payload):
    global fn_out

    if fn_out is not None:
        packet = bytearray()
        packet += struct.pack('>sBHBB', b'T', 0, len(payload) + 2, arg, typ)
        if sys.version_info[0] >= 3 and isinstance(payload, str):
            packet += payload.encode('utf-8')
        else:
            packet += payload

        fn_out.write(packet)

def extcap_capture(interface, fifo, control_in, control_out):
    global fn_out
    
    counter = 1

    with open(fifo, 'wb', 0) as fh:

        fh.write(pcap_header())

        if control_out is not None:
            fn_out = open(control_out, 'wb', 0)
            control_write(CTRL_ARG_LOGGER, CTRL_CMD_SET, "Log started at " + time.strftime("%c") + "\n")

        if control_in is not None:
            # Start reading thread
            thread = Thread(target=control_read_thread, args=(control_in,))
            thread.start()

        with serial.Serial(baudrate=9600,
                        bytesize=serial.EIGHTBITS,
                        parity=serial.PARITY_NONE,
                        port=interface,
                        stopbits=serial.STOPBITS_ONE,
                        timeout = 0.1) as receiver:

            # set GNSS config
            log("Configuring GNSS constellations:\n")
            for (gnssId, resTrkCh, maxTrkCh, enable, sigCfgMask) in UBX_GNSS_CONFIGS:
                sendUbxMsg(receiver, ubxCfgGnss(gnssId, resTrkCh, maxTrkCh, enable, sigCfgMask))

            # query GNSS config
            log("Querying GNSS constellation config:\n")
            sendUbxMsg(receiver, ubxMsg(UBX_CFG_GNSS, []))

            # query SBAS config
            log("Querying SBAS config:\n")
            sendUbxMsg(receiver, ubxMsg(UBX_CFG_SBAS, []))

            # set the message rates
            log("Setting UBX msg rates:\n")
            for (ubxClassId, rate) in UBX_MSG_RATES:
                sendUbxMsg(receiver, ubxCfgMsg(ubxClassId, rate))

            ubx_in_data = bytearray()

            while True:
                ubx_in_data += receiver.read(8192)

                i = 0

                # Is there enough data remaining for a packet of min. possible size?
                while i < len(ubx_in_data) - UBX_HEADER_SIZE - UBX_CHKSUM_SIZE + 1:

                    if ubx_in_data[i] == UBX_PREAMBLE_1 and ubx_in_data[i+1] == UBX_PREAMBLE_2:

                        (payload_len,) = struct.unpack("<H", ubx_in_data[i + UBX_PAYLOAD_LEN_OFFSET : i + UBX_PAYLOAD_LEN_OFFSET + 2])

                        # Is there enough data remaining for the complete message?
                        if i + UBX_HEADER_SIZE + payload_len + UBX_CHKSUM_SIZE <= len(ubx_in_data):
                            ubx_frame = ubx_in_data[i : i + UBX_HEADER_SIZE + payload_len + UBX_CHKSUM_SIZE]

                            log("Emitting UBX PCAP packet with header " + ubx_frame[0:6].hex() + "\n")

                            fh.write(pcap_packet(ubx_frame))

                            i = i + UBX_HEADER_SIZE + payload_len + UBX_CHKSUM_SIZE
                            
                        else:
                            break

                    else:
                        i += 1

                ubx_in_data = ubx_in_data[i:]

    thread.join()
    if fn_out is not None:
        fn_out.close()

def extcap_close_fifo(fifo):
    # This is apparently needed to workaround an issue on Windows/macOS
    # where the message cannot be read. (really?)
    fh = open(fifo, 'wb', 0)
    fh.close()

def usage():
    print("Usage: %s <--extcap-interfaces | --extcap-dlts | --extcap-interface | --extcap-config | --capture | --extcap-capture-filter | --fifo>" % sys.argv[0] )

if __name__ == '__main__':
    option = ""

    parser = argparse.ArgumentParser(description="u-blox UBX extcap")

    # Extcap Arguments
    parser.add_argument("--capture", help="Start the capture routine", action="store_true" )
    parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
    parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
    parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
    parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface", action="store_true")
    parser.add_argument("--extcap-capture-filter", help="Used together with capture to provide a capture filter")
    parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")
    parser.add_argument("--extcap-control-in", help="Used to get control messages from toolbar")
    parser.add_argument("--extcap-control-out", help="Used to send control messages to toolbar")
    parser.add_argument("--extcap-version", help="Shows the version of this utility", nargs='?', default="")
    parser.add_argument("--extcap-reload-option", help="Reload elements for the given option")

    try:
        args, unknown = parser.parse_known_args()
    except argparse.ArgumentError as exc:
        print("%s: %s" % (exc.argument.dest, exc.message), file=sys.stderr)
        fifo_found = 0
        fifo = ""
        for arg in sys.argv:
            if arg == "--fifo" or arg == "--extcap-fifo":
                fifo_found = 1
            elif fifo_found == 1:
                fifo = arg
                break
        extcap_close_fifo(fifo)
        sys.exit(ERROR_ARG)

    if len(sys.argv) <= 1:
        parser.exit("No arguments given!")

    if args.extcap_version and not args.extcap_interfaces:
        extcap_version()
        sys.exit(0)

    if not args.extcap_interfaces and args.extcap_interface is None:
        parser.exit("An interface must be provided or the selection must be displayed")

    if args.extcap_interfaces or args.extcap_interface is None:
        extcap_interfaces()
        sys.exit(0)

    if len(unknown) > 1:
        print(f"{len(unknown)} unknown arguments given")

    if args.extcap_reload_option and len(args.extcap_reload_option) > 0:
        option = args.extcap_reload_option

    if args.extcap_config:
        extcap_config(option)
    elif args.extcap_dlts:
        extcap_dlts()
    elif args.capture:
        if args.fifo is None:
            sys.exit(ERROR_FIFO)
        try:
            extcap_capture(args.extcap_interface, args.fifo, args.extcap_control_in, args.extcap_control_out)
        except KeyboardInterrupt:
            pass
    else:
        usage()
        sys.exit(ERROR_USAGE)
